// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

func newPyPIProxyController(packageEvaluator *proxyPackageEvaluator) ecosystemProxyController {
	controller, err := newPyPIProxyControllerWithOptions(packageEvaluator, ecosystem.PyPIRequestClassifierOptions{})
	if err != nil {
		panic(err)
	}
	return controller
}

// newPyPIProxyControllerWithOptions is the future Python-adapter integration
// surface for arbitrary index bases and direct artifact URLs. Existing package
// managers are deliberately not wired to this controller in this change.
func newPyPIProxyControllerWithOptions(
	packageEvaluator *proxyPackageEvaluator,
	classifierOptions ecosystem.PyPIRequestClassifierOptions,
) (ecosystemProxyController, error) {
	classifier, err := ecosystem.NewPyPIRequestClassifier(classifierOptions)
	if err != nil {
		return nil, err
	}
	packageEvaluator.classifier = classifier
	return func(runContext context.Context, upstream httpproxy.Config) proxy.Options {
		packageEvaluator.runContext = runContext
		client := newPublicationHTTPClient(upstream)
		packageEvaluator.metadataClient = client
		packageEvaluator.resolveDate = func(ctx context.Context, packageEcosystem ecosystem.Ecosystem, name, version, source string) (time.Time, error) {
			if packageEcosystem != ecosystem.PYPI {
				return time.Time{}, fmt.Errorf("unsupported proxy ecosystem: %s", packageEcosystem)
			}
			return ecosystem.ResolvePyPIPublishDateWithClient(ctx, client, name, version, source)
		}
		return proxy.Options{
			RequestHooks: []proxy.RequestHook{packageEvaluator.HandleRequest},
		}
	}, nil
}

// proxyPackageEvaluator evaluates PyPI artifacts immediately before the proxy
// forwards them. decisions is scoped to one command and also acts as a
// singleflight table for concurrent requests with identical policy inputs.
type proxyPackageEvaluator struct {
	runContext       context.Context
	installTimestamp time.Time
	command          []string
	packageManager   string
	executable       string
	repository       string
	output           io.Writer
	evaluator        evaluation.Evaluator
	reporter         evaluation.Reporter
	resolveDate      func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error)
	metadata         ecosystem.PyPIMetadataCache
	metadataClient   *http.Client
	classifier       *ecosystem.PyPIRequestClassifier

	mutex     sync.Mutex
	decisions map[pm.Package]*proxyPackageDecision
}

type proxyPackageDecision struct {
	done     chan struct{}
	err      error
	complete bool
}

func newProxyPackageEvaluator(
	runContext context.Context,
	installTimestamp time.Time,
	command []string,
	packageManager, executable, repository string,
	evaluator evaluation.Evaluator,
	reporter evaluation.Reporter,
	output io.Writer,
) *proxyPackageEvaluator {
	if output == nil {
		output = io.Discard
	}
	if runContext == nil {
		runContext = context.Background()
	}
	classifier, err := ecosystem.NewPyPIRequestClassifier(ecosystem.PyPIRequestClassifierOptions{})
	if err != nil {
		panic(err)
	}
	return &proxyPackageEvaluator{
		runContext:       runContext,
		installTimestamp: installTimestamp,
		command:          redactCommandArguments(command),
		packageManager:   packageManager,
		executable:       executable,
		repository:       repository,
		output:           output,
		evaluator:        evaluator,
		reporter:         reporter,
		resolveDate:      ecosystem.ResolvePublishDate,
		classifier:       classifier,
		decisions:        make(map[pm.Package]*proxyPackageDecision),
	}
}

// HandleRequest evaluates an artifact before the proxy sends its request
// upstream. Metadata candidates attach a response hook so their headers can
// select body inspection; artifact and core-metadata bodies keep streaming.
func (e *proxyPackageEvaluator) HandleRequest(requestContext context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if request.Method != http.MethodGet {
		return nil, nil
	}
	if e.metadata.IsCoreMetadataURL(&request.URL) {
		return nil, nil
	}
	artifact, advertised := e.metadata.ArtifactForURL(&request.URL)
	if !advertised {
		kind, classified := e.classifier.ClassifyRequest(request.Method, &request.URL)
		if kind == ecosystem.PyPIRequestJSONAPI || kind == ecosystem.PyPIRequestSimpleAPI {
			// Redirect context identifies the requested project more reliably
			// than a destination path. Capture its own request credentials
			// without replacing that context with the destination's name.
			project, tentative, registered := e.metadata.ProjectForURL(&request.URL)
			if !registered {
				project, _ = e.classifier.SimpleProject(&request.URL, nil)
			}
			if tentative {
				e.metadata.RegisterProjectCandidate(request.URL, project, request.Header)
			} else if project != "" {
				e.metadata.RegisterProject(request.URL, project, request.Header)
			} else {
				e.metadata.Register(request.URL, request.Header)
			}
			return e.ObserveMetadataHeaders, nil
		}
		if kind == ecosystem.PyPIRequestCoreMetadata {
			return nil, nil
		}
		if kind != ecosystem.PyPIRequestArtifact {
			project, endpoints, discoverable := e.classifier.MetadataDiscovery(&request.URL)
			if discoverable && e.metadataClient != nil {
				if err := e.metadata.Discover(
					e.runContext, e.metadataClient, project, endpoints, &request.URL, request.Header,
				); isContextError(err) {
					return nil, err
				}
				artifact, advertised = e.metadata.ArtifactForURL(&request.URL)
			}
			if !advertised {
				return e.ObserveMetadataHeaders, nil
			}
		} else {
			artifact = classified
		}
	}

	return nil, e.evaluateArtifactRequest(requestContext, artifact)
}

func (e *proxyPackageEvaluator) evaluateArtifactRequest(requestContext context.Context, artifact ecosystem.PyPIArtifact) error {
	// Resolve each file's publication data before consulting the decision cache.
	// Files from the same release can have different sources and upload times.
	pkg, publishErr := e.resolveArtifact(e.runContext, artifact)
	if isContextError(publishErr) {
		return publishErr
	}
	key := pkg
	for {
		e.mutex.Lock()
		decision, exists := e.decisions[key]
		if !exists {
			decision = &proxyPackageDecision{done: make(chan struct{})}
			e.decisions[key] = decision
		}
		e.mutex.Unlock()

		if exists {
			select {
			case <-decision.done:
				if decision.complete {
					return decision.err
				}
				continue
			case <-requestContext.Done():
				return requestContext.Err()
			}
		}

		decision.err, decision.complete = e.evaluateArtifact(e.runContext, pkg, publishErr)
		e.mutex.Lock()
		if !decision.complete && e.decisions[key] == decision {
			delete(e.decisions, key)
		}
		close(decision.done)
		e.mutex.Unlock()
		return decision.err
	}
}

// ObserveMetadataHeaders records metadata endpoints and resolves an uncached
// 304 through an independent request before the package manager can issue a
// download from metadata held only in its own cache.
func (e *proxyPackageEvaluator) ObserveMetadataHeaders(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	kind, project, tentative := e.classifyMetadataResponse(response)
	if kind != ecosystem.PyPIRequestJSONAPI && kind != ecosystem.PyPIRequestSimpleAPI {
		return nil, nil
	}
	if tentative {
		e.metadata.RegisterProjectCandidate(response.Request.URL, project, response.Request.Header)
	} else if project != "" {
		e.metadata.RegisterProject(response.Request.URL, project, response.Request.Header)
	} else {
		e.metadata.Register(response.Request.URL, response.Request.Header)
	}
	switch response.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		e.metadata.RegisterRedirect(response.Request.URL, response.Header.Get("Location"))
	case http.StatusNotModified:
		if !e.metadata.HasObserved(response.Request.URL) && e.metadataClient != nil {
			if err := e.metadata.Refresh(ctx, e.metadataClient, response.Request.URL); err != nil {
				return nil, err
			}
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, nil
	}
	return &proxy.ResponseBodyHook{
		MaxBytes: ecosystem.MaxPyPIMetadataBytes,
		Handle: func(_ context.Context, response proxy.Response) error {
			return e.metadata.Observe(response.Request.URL, response.Header, response.Body)
		},
	}, nil
}

func (e *proxyPackageEvaluator) classifyMetadataResponse(response proxy.Response) (ecosystem.PyPIRequestKind, string, bool) {
	kind, _ := e.classifier.ClassifyResponse(response.Request.Method, &response.Request.URL, response.Header)
	if response.Request.Method == http.MethodGet && (kind == ecosystem.PyPIRequestUnrelated || kind == ecosystem.PyPIRequestSimpleAPI) {
		if project, tentative, found := e.metadata.ProjectForURL(&response.Request.URL); found {
			if !tentative || (response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
				ecosystem.IsPyPIMetadataContentType(response.Header)) {
				return ecosystem.PyPIRequestSimpleAPI, project, false
			}
			if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
				return ecosystem.PyPIRequestSimpleAPI, project, true
			}
		}
		// An archive-shaped Simple path is ambiguous until response headers
		// arrive. Bodyless redirects/304s can still establish project context;
		// successful responses must supply metadata media-type evidence first.
		if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
			if project, found := e.classifier.SimpleProject(&response.Request.URL, nil); found {
				return ecosystem.PyPIRequestSimpleAPI, project, true
			}
		}
	}
	project, _ := e.classifier.SimpleProject(&response.Request.URL, response.Header)
	return kind, project, false
}

func (e *proxyPackageEvaluator) resolveArtifact(ctx context.Context, artifact ecosystem.PyPIArtifact) (pm.Package, error) {
	pkg := pm.Package{
		Ecosystem: ecosystem.PYPI,
		Name:      artifact.Name,
		Version:   artifact.Version,
		Source:    artifact.Source,
	}
	if err := ctx.Err(); err != nil {
		return pkg, err
	}
	publishDate, found := e.metadata.PublishDate(artifact)
	var publishErr error
	if !found && e.metadataClient != nil {
		publishDate, publishErr = e.metadata.ResolvePublishDate(ctx, e.metadataClient, artifact)
		if isContextError(publishErr) {
			return pkg, publishErr
		}
		found = !publishDate.IsZero()
	}
	if !found {
		fallbackDate, fallbackErr := e.resolveDate(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.Source)
		if !fallbackDate.IsZero() || fallbackErr != nil || publishErr == nil {
			publishDate, publishErr = fallbackDate, fallbackErr
		}
	}
	if isContextError(publishErr) {
		return pkg, publishErr
	}
	if err := ctx.Err(); err != nil {
		return pkg, err
	}
	if publishErr == nil && publishDate.IsZero() {
		publishErr = errors.New("publication date unavailable")
	}
	if publishErr == nil {
		// Strip location and monotonic-clock details so equal instants produce
		// equal cache keys while retaining the exact upload timestamp.
		pkg.PublishDate = publishDate.UTC()
	}
	return pkg, publishErr
}

func (e *proxyPackageEvaluator) evaluateArtifact(ctx context.Context, pkg pm.Package, publishErr error) (error, bool) {
	if err := ctx.Err(); err != nil {
		return err, false
	}
	var publicationFailure *evaluation.Failure
	if publishErr != nil {
		publicationFailure = &evaluation.Failure{Verifier: "publication", Error: publishErr.Error()}
		_, _ = fmt.Fprintf(e.output, "Could not resolve publication data for PyPI %s@%s: %v\n", pkg.Name, pkg.Version, publishErr)
	}
	targets := pm.NewSet(pkg)
	report, err := e.evaluator.EvaluateInstallTargets(ctx, false, targets)
	if err != nil {
		if isContextError(err) {
			return err, false
		}
		failures := []evaluation.Failure{{Verifier: "evaluation", Error: err.Error()}}
		if publicationFailure != nil {
			failures = append([]evaluation.Failure{*publicationFailure}, failures...)
		}
		reportErr := e.allowEvaluationFailures(ctx, pkg, failures)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr, false
		}
		return reportErr, true
	}
	if publicationFailure != nil {
		addPackageFailure(&report, pkg, *publicationFailure)
	}
	if err := ctx.Err(); err != nil {
		return err, false
	}

	if details := formatEvaluationDetails(report); details != "" {
		_, _ = fmt.Fprint(e.output, details)
	}
	// Artifact downloads never prompt: WARN and ERROR continue. Only an
	// explicit BLOCK returned by policy rejects the upstream request.
	resolved := evaluation.OutcomeAllow
	if report.Outcome == evaluation.OutcomeBlock {
		resolved = evaluation.OutcomeBlock
	}
	e.report(ctx, targets, report, resolved)
	if err := ctx.Err(); err != nil {
		return err, false
	}
	if resolved == evaluation.OutcomeBlock {
		return fmt.Errorf("supply chain firewall blocked %s %s", pkg.Name, pkg.Version), true
	}
	return nil, true
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (e *proxyPackageEvaluator) allowEvaluationFailures(ctx context.Context, pkg pm.Package, failures []evaluation.Failure) error {
	report := evaluation.ScfwPolicyEvaluationReport{
		Outcome: evaluation.OutcomeError,
		Results: []evaluation.PackageEvaluationResult{{
			Ecosystem:      string(pkg.Ecosystem),
			PackageName:    pkg.Name,
			PackageVersion: pkg.Version,
			Outcome:        evaluation.OutcomeError,
			Failures:       failures,
		}},
	}
	_, _ = fmt.Fprint(e.output, formatEvaluationDetails(report))
	e.report(ctx, pm.NewSet(pkg), report, evaluation.OutcomeAllow)
	return nil
}

func addPackageFailure(report *evaluation.ScfwPolicyEvaluationReport, pkg pm.Package, failure evaluation.Failure) {
	for index := range report.Results {
		result := &report.Results[index]
		if result.Ecosystem == string(pkg.Ecosystem) &&
			ecosystem.NormalizePyPIName(result.PackageName) == pkg.Name &&
			result.PackageVersion == pkg.Version {
			result.Failures = append(result.Failures, failure)
			return
		}
	}
	report.Results = append(report.Results, evaluation.PackageEvaluationResult{
		Ecosystem:      string(pkg.Ecosystem),
		PackageName:    pkg.Name,
		PackageVersion: pkg.Version,
		Outcome:        report.Outcome,
		Failures:       []evaluation.Failure{failure},
	})
}

func (e *proxyPackageEvaluator) report(
	ctx context.Context,
	targets *pm.Set[pm.Package],
	report evaluation.ScfwPolicyEvaluationReport,
	resolved evaluation.Outcome,
) {
	if err := e.reporter.ReportFirewallOutcome(
		ctx,
		e.installTimestamp,
		e.command,
		e.packageManager,
		e.executable,
		e.repository,
		targets,
		report,
		resolved,
	); err != nil {
		slog.Warn("failed to report proxy firewall outcome", "error", err)
	}
}
