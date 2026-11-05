// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

type proxyEvaluatorFunc func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error)

func (f proxyEvaluatorFunc) EvaluateInstallTargets(ctx context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
	return f(ctx, interactive, targets)
}

type proxyReporterFunc func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error

func (f proxyReporterFunc) ReportFirewallOutcome(
	ctx context.Context,
	timestamp time.Time,
	command []string,
	manager, executable, repository string,
	targets *pm.Set[pm.Package],
	report evaluation.ScfwPolicyEvaluationReport,
	resolved evaluation.Outcome,
) error {
	return f(ctx, timestamp, command, manager, executable, repository, targets, report, resolved)
}

// Exercise the shared evaluator directly, without constructing an ecosystem
// handler or making registry requests.
func TestProxyPackageEvaluatorAcceptsPackagesFromDifferentEcosystems(t *testing.T) {
	var output bytes.Buffer
	calls := make(map[ecosystem.Ecosystem]int)
	reports := make(map[ecosystem.Ecosystem]int)
	publicationErr := errors.New("publication service unavailable")
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), []string{"install", "project"}, "manager", "manager", "",
		proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			if interactive || targets.Len() != 1 {
				t.Fatal("expected one non-interactive package evaluation")
			}
			for pkg := range targets.Items() {
				calls[pkg.Ecosystem]++
				outcome := evaluation.OutcomeWarn
				if pkg.Ecosystem == ecosystem.NPM {
					outcome = evaluation.OutcomeBlock
				}
				return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome, Results: []evaluation.PackageEvaluationResult{{Ecosystem: string(pkg.Ecosystem), PackageName: pkg.Name, PackageVersion: pkg.Version, Outcome: outcome}}}, nil
			}
			panic("empty targets")
		}),
		proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], report evaluation.ScfwPolicyEvaluationReport, action evaluation.Outcome) error {
			for pkg := range targets.Items() {
				reports[pkg.Ecosystem]++
				wantAction := evaluation.OutcomeAllow
				if pkg.Ecosystem == ecosystem.NPM {
					wantAction = evaluation.OutcomeBlock
				}
				if action != wantAction || len(report.Results) != 1 || len(report.Results[0].Failures) != 1 || report.Results[0].Failures[0].Verifier != "publication" {
					t.Fatalf("unexpected action/report for %s: %s %+v", pkg.Ecosystem, action, report)
				}
			}
			return nil
		}), &output)
	date := time.Date(2025, 4, 3, 2, 1, 0, 0, time.UTC)
	for _, packageEcosystem := range []ecosystem.Ecosystem{ecosystem.PYPI, ecosystem.NPM, "future-ecosystem"} {
		pkg := pm.Package{Ecosystem: packageEcosystem, Name: "project", Version: "1.0", Source: "https://registry.example/project", PublishDate: date}
		for _, location := range []*time.Location{time.UTC, time.FixedZone("offset", 3600)} {
			pkg.PublishDate = date.In(location)
			err := handler.evaluatePackage(context.Background(), pkg, publicationErr)
			if (err != nil) != (packageEcosystem == ecosystem.NPM) {
				t.Fatalf("unexpected decision for %s: %v", packageEcosystem, err)
			}
		}
		if calls[packageEcosystem] != 1 || reports[packageEcosystem] != 1 {
			t.Fatalf("decision was not cached for %s: calls=%d reports=%d", packageEcosystem, calls[packageEcosystem], reports[packageEcosystem])
		}
		if !strings.Contains(output.String(), "Could not resolve publication data for "+string(packageEcosystem)+" project@1.0") {
			t.Fatalf("missing ecosystem in diagnostic: %s", &output)
		}
	}
}

func TestAddPackageFailureUsesEcosystemNameIdentity(t *testing.T) {
	for _, test := range []struct {
		ecosystem      ecosystem.Ecosystem
		name, reported string
		matches        bool
	}{
		{ecosystem.PYPI, "my-package", "My_Package", true},
		{ecosystem.NPM, "@scope/my_package", "@scope/my_package", true},
		{ecosystem.NPM, "@scope/my_package", "@scope/my-package", false},
	} {
		t.Run(string(test.ecosystem)+"/"+test.reported, func(t *testing.T) {
			report := evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeWarn, Results: []evaluation.PackageEvaluationResult{{Ecosystem: string(test.ecosystem), PackageName: test.reported, PackageVersion: "1.0"}}}
			pkg := pm.Package{Ecosystem: test.ecosystem, Name: test.name, Version: "1.0"}
			addPackageFailure(&report, pkg, evaluation.Failure{Verifier: "publication", Error: "missing date"})
			if test.matches {
				if len(report.Results) != 1 || len(report.Results[0].Failures) != 1 {
					t.Fatalf("failure did not attach to matching result: %+v", report)
				}
			} else if len(report.Results) != 2 || len(report.Results[0].Failures) != 0 || len(report.Results[1].Failures) != 1 {
				t.Fatalf("failure attached to another package: %+v", report)
			}
		})
	}
}
