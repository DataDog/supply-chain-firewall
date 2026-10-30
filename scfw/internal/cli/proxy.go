// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// proxyEnabledVar is the feature flag that routes `scfw run` through the
// package manager proxy. Only the exact value "1" enables it.
const proxyEnabledVar = "SCFW_PROXY_ENABLED"

func proxyEnabled() bool {
	return os.Getenv(proxyEnabledVar) == "1"
}

// runThroughProxy runs command through a proxy created for this invocation
// alone, chained to the package manager's pre-existing upstream proxy. The proxy
// is stopped once the command exits, whatever the outcome.
// commandErr is the command's own failure; setupErr means the command never ran.
func runThroughProxy(
	ctx context.Context,
	runner pm.ProxyRunner,
	command []string,
	controller proxyController,
) (commandErr, setupErr error) {
	// SIGINT already cancels ctx (see main). Also treat SIGTERM as cancellation
	// here, rather than letting it end the process before the proxy is cleaned up.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer stop()

	upstream, err := runner.UpstreamProxy(command)
	if err != nil {
		return nil, fmt.Errorf("resolve upstream proxy: %w", err)
	}
	options := proxy.Options{Upstream: upstream}
	if controller != nil {
		options = controller(ctx, upstream)
		options.Upstream = upstream
	}

	server, err := proxy.Start(ctx, options)
	if err != nil {
		return nil, err
	}
	// Deferred so the proxy is also stopped if the command panics.
	defer func() {
		if err := server.Close(); err != nil {
			slog.Warn("failed to stop package manager proxy cleanly", "error", err)
		}
	}()

	slog.Debug("running package manager command through proxy")
	return runner.RunCommandThroughProxy(ctx, command, server.ClientConfig()), nil
}

// proxyController is the narrow CLI integration boundary between a concrete
// package-manager ProxyRunner and ecosystem-specific proxy behavior. Generic
// ProxyRunners pass nil; future Python adapter wiring can opt into PyPI without
// moving registry parsing or policy orchestration into the adapter.
type proxyController func(context.Context, httpproxy.Config) proxy.Options

func newPyPIProxyController(packageEvaluator *proxyPackageEvaluator) proxyController {
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
) (proxyController, error) {
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
			RequestHooks:          []proxy.RequestHook{packageEvaluator.HandleRequest},
			ResponseHooks:         []proxy.ResponseHook{packageEvaluator.ObserveMetadataHeaders},
			ResponseBodyObservers: []proxy.ResponseBodyObserver{packageEvaluator.ObserveMetadataResponse},
		}
	}, nil
}

func newPublicationHTTPClient(upstream httpproxy.Config) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxyFunc := upstream.ProxyFunc()
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		return proxyFunc(request.URL)
	}
	return &http.Client{Transport: transport}
}

// proxyPackageEvaluator evaluates PyPI artifacts immediately before the proxy
// forwards them. decisions is scoped to one command and also acts as a
// singleflight table for concurrent compatible-wheel requests and retries.
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
	decisions map[string]*proxyPackageDecision
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
		decisions:        make(map[string]*proxyPackageDecision),
	}
}

// redactCommandArguments returns a reporting/logging copy of a command with
// credentials removed from absolute HTTP(S) URL arguments. The package manager
// still receives the original arguments.
func redactCommandArguments(command []string) []string {
	redacted := make([]string, len(command))
	for index, argument := range command {
		redacted[index] = commandURLPattern.ReplaceAllStringFunc(argument, redactCommandURL)
	}
	return redacted
}

var commandURLPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)

func redactCommandURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return value
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

// HandleRequest evaluates an artifact before the proxy sends its request
// upstream. Metadata and unrelated traffic are left untouched.
func (e *proxyPackageEvaluator) HandleRequest(requestContext context.Context, request proxy.Request) error {
	if request.Method != http.MethodGet {
		return nil
	}
	if e.metadata.IsCoreMetadataURL(&request.URL) {
		return nil
	}
	artifact, advertised := e.metadata.ArtifactForURL(&request.URL)
	if !advertised {
		kind, classified := e.classifier.ClassifyRequest(request.Method, &request.URL)
		if kind == ecosystem.PyPIRequestJSONAPI || kind == ecosystem.PyPIRequestSimpleAPI {
			if project, ok := e.classifier.SimpleProject(&request.URL, nil); ok {
				e.metadata.RegisterProject(request.URL, project, request.Header)
			} else {
				e.metadata.Register(request.URL, request.Header)
			}
			return nil
		}
		if kind == ecosystem.PyPIRequestCoreMetadata {
			return nil
		}
		if kind != ecosystem.PyPIRequestArtifact {
			project, endpoints, discoverable := e.classifier.MetadataDiscovery(&request.URL)
			if !discoverable || e.metadataClient == nil {
				return nil
			}
			if err := e.metadata.Discover(
				e.runContext, e.metadataClient, project, endpoints, &request.URL, request.Header,
			); isContextError(err) {
				return err
			}
			artifact, advertised = e.metadata.ArtifactForURL(&request.URL)
			if !advertised {
				return nil
			}
		} else {
			artifact = classified
		}
	}

	key := artifact.Name + "\x00" + ecosystem.PyPIVersionIdentity(artifact.Version)
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

		decision.err, decision.complete = e.evaluateArtifact(e.runContext, artifact)
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
func (e *proxyPackageEvaluator) ObserveMetadataHeaders(ctx context.Context, response proxy.Response) {
	kind, _ := e.classifier.ClassifyResponse(response.Request.Method, &response.Request.URL, response.Header)
	if kind != ecosystem.PyPIRequestJSONAPI && kind != ecosystem.PyPIRequestSimpleAPI {
		return
	}
	if project, ok := e.classifier.SimpleProject(&response.Request.URL, response.Header); ok {
		e.metadata.RegisterProject(response.Request.URL, project, response.Request.Header)
	} else {
		e.metadata.Register(response.Request.URL, response.Request.Header)
	}
	if response.StatusCode == http.StatusNotModified && !e.metadata.HasObserved(response.Request.URL) && e.metadataClient != nil {
		// Failure is intentionally deferred to artifact evaluation, where the
		// normal resolver records it without changing the metadata response.
		_ = e.metadata.Refresh(ctx, e.metadataClient, response.Request.URL)
	}
}

// ObserveMetadataResponse mirrors successful JSON API and Simple API response
// bodies into the per-run metadata cache. 304 responses deliberately retain
// whatever the run already observed and otherwise leave artifact lookup to the
// independent resolver.
func (e *proxyPackageEvaluator) ObserveMetadataResponse(_ context.Context, response proxy.Response) io.WriteCloser {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil
	}
	kind, _ := e.classifier.ClassifyResponse(response.Request.Method, &response.Request.URL, response.Header)
	if kind != ecosystem.PyPIRequestJSONAPI && kind != ecosystem.PyPIRequestSimpleAPI {
		return nil
	}
	if project, ok := e.classifier.SimpleProject(&response.Request.URL, response.Header); ok {
		e.metadata.RegisterProject(response.Request.URL, project, response.Request.Header)
	}
	return e.metadata.Observe(response.Request.URL, response.Header)
}

func (e *proxyPackageEvaluator) evaluateArtifact(ctx context.Context, artifact ecosystem.PyPIArtifact) (error, bool) {
	if err := ctx.Err(); err != nil {
		return err, false
	}
	pkg := pm.Package{
		Ecosystem: ecosystem.PYPI,
		Name:      artifact.Name,
		Version:   artifact.Version,
		Source:    artifact.Source,
	}
	publishDate, found := e.metadata.PublishDate(artifact)
	var publishErr error
	if !found && e.metadataClient != nil {
		publishDate, publishErr = e.metadata.ResolvePublishDate(ctx, e.metadataClient, artifact)
		if isContextError(publishErr) {
			return publishErr, false
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
		return publishErr, false
	}
	if err := ctx.Err(); err != nil {
		return err, false
	}
	var publicationFailure *evaluation.Failure
	if publishErr != nil || publishDate.IsZero() {
		if publishErr == nil {
			publishErr = errors.New("publication date unavailable")
		}
		publicationFailure = &evaluation.Failure{Verifier: "publication", Error: publishErr.Error()}
		_, _ = fmt.Fprintf(e.output, "Could not resolve publication data for PyPI %s@%s: %v\n", pkg.Name, pkg.Version, publishErr)
	} else {
		pkg.PublishDate = publishDate
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
