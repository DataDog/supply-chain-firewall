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
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

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
	metadata         pypi.MetadataCache
	metadataClient   *http.Client
	classifier       *pypi.RequestClassifier

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
	classifier, err := pypi.NewRequestClassifier(pypi.RequestClassifierOptions{})
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

func (e *proxyPackageEvaluator) evaluateArtifactRequest(requestContext context.Context, artifact pypi.Artifact) error {
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

func (e *proxyPackageEvaluator) resolveArtifact(ctx context.Context, artifact pypi.Artifact) (pm.Package, error) {
	pkg := pm.Package{
		Ecosystem: ecosystem.PYPI,
		Name:      artifact.Name,
		Version:   artifact.Version,
		Source:    artifact.Source,
	}
	publishDate, err := e.metadata.ResolveArtifactPublishDate(ctx, e.metadataClient, artifact,
		func(ctx context.Context, name, version, source string) (time.Time, error) {
			return e.resolveDate(ctx, ecosystem.PYPI, name, version, source)
		},
	)
	if err == nil {
		// Equal instants must produce equal policy-cache keys.
		pkg.PublishDate = publishDate.UTC()
	}
	return pkg, err
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
			pypi.NormalizeName(result.PackageName) == pkg.Name &&
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
