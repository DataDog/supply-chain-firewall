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

	"github.com/spf13/cobra"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	httpsproxy "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestValidateProxyArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "package manager command", args: []string{"--", "npm", "install"}},
		{name: "missing separator", args: []string{"npm", "install"}, wantErr: "missing \"--\" separator"},
		{name: "argument before separator", args: []string{"unexpected", "--", "npm"}, wantErr: "unexpected argument"},
		{name: "missing command", args: []string{"--"}, wantErr: "no command specified"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "proxy -- <command>"}
			command.SetArgs(test.args)
			if err := command.ParseFlags(test.args); err != nil {
				t.Fatalf("ParseFlags() returned error: %v", err)
			}
			err := validateProxyArgs(command, command.Flags().Args())
			if test.wantErr == "" && err != nil {
				t.Fatalf("validateProxyArgs() returned error: %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("validateProxyArgs() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

type evaluatorFunc func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error)

func (f evaluatorFunc) EvaluateInstallTargets(ctx context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
	return f(ctx, interactive, targets)
}

type reporterFunc func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error

func (f reporterFunc) ReportFirewallOutcome(
	ctx context.Context,
	installTimestamp time.Time,
	command []string,
	packageManagerName, executable, repository string,
	installTargets *pm.Set[pm.Package],
	evaluationReport evaluation.ScfwPolicyEvaluationReport,
	resolvedOutcome evaluation.Outcome,
) error {
	return f(ctx, installTimestamp, command, packageManagerName, executable, repository, installTargets, evaluationReport, resolvedOutcome)
}

func TestProxyPackagePolicyEvaluatesAndReportsEachPackageOnce(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	published := time.Date(2020, 4, 29, 17, 16, 59, 466000000, time.UTC)
	resolveCalls := 0
	evaluateCalls := 0
	reportCalls := 0
	installTimestamp := time.Date(2026, 9, 23, 10, 30, 0, 0, time.UTC)
	artifactURL := "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"
	wantPackage := pm.Package{
		Ecosystem: ecosystem.NPM,
		Name:      "is-number", Version: "7.0.0",
		Source: artifactURL, PublishDate: published,
	}
	report := evaluation.ScfwPolicyEvaluationReport{
		Outcome: evaluation.OutcomeAllow,
		Results: []evaluation.PackageEvaluationResult{{
			Ecosystem: "npm", PackageName: "is-number", PackageVersion: "7.0.0", Outcome: evaluation.OutcomeAllow,
		}},
	}
	policy := &proxyPackagePolicy{
		cmd: command,
		evaluator: evaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluateCalls++
			if interactive {
				t.Error("EvaluateInstallTargets() interactive = true, want false")
			}
			if targets.Len() != 1 || !targets.Contains(wantPackage) {
				t.Errorf("EvaluateInstallTargets() targets do not contain %#v", wantPackage)
			}
			return report, nil
		}),
		reporter: reporterFunc(func(
			_ context.Context,
			gotTimestamp time.Time,
			gotCommand []string,
			manager, executable, repository string,
			targets *pm.Set[pm.Package],
			gotReport evaluation.ScfwPolicyEvaluationReport,
			action evaluation.Outcome,
		) error {
			reportCalls++
			if !gotTimestamp.Equal(installTimestamp) || strings.Join(gotCommand, " ") != "npm add is-number" {
				t.Errorf("report run metadata = (%v, %v)", gotTimestamp, gotCommand)
			}
			if manager != "npm" || executable != "/usr/local/bin/npm" || repository != "https://example.test/repo.git" {
				t.Errorf("report command metadata = (%q, %q, %q)", manager, executable, repository)
			}
			if targets.Len() != 1 || !targets.Contains(wantPackage) || gotReport.Outcome != evaluation.OutcomeAllow || action != evaluation.OutcomeAllow {
				t.Errorf("report policy data = (%#v, %#v, %q)", targets, gotReport, action)
			}
			return nil
		}),
		resolvePublishDate: func(_ context.Context, gotEcosystem ecosystem.Ecosystem, name, version, source string) (time.Time, error) {
			resolveCalls++
			if gotEcosystem != ecosystem.NPM || name != "is-number" || version != "7.0.0" || source != artifactURL {
				t.Errorf("resolve publish date arguments = (%q, %q, %q, %q)", gotEcosystem, name, version, source)
			}
			return published, nil
		},
		installTimestamp:   installTimestamp,
		command:            []string{"npm", "add", "is-number"},
		packageManagerName: "npm",
		executable:         "/usr/local/bin/npm",
		repository:         "https://example.test/repo.git",
		decisions:          make(map[packageVersion]packageDecision),
	}

	options := proxyOptions(policy)
	if err := options.OnRequest(httpsproxy.Request{Method: "GET", URL: "https://registry.npmjs.org/is-number"}); err != nil {
		t.Fatalf("metadata request returned error: %v", err)
	}
	request := httpsproxy.Request{Method: "GET", URL: "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"}
	if err := options.OnRequest(request); err != nil {
		t.Fatalf("artifact request returned error: %v", err)
	}
	if err := options.OnRequest(request); err != nil {
		t.Fatalf("duplicate artifact request returned error: %v", err)
	}
	if resolveCalls != 1 || evaluateCalls != 1 || reportCalls != 1 {
		t.Errorf("calls = resolve:%d evaluate:%d report:%d, want one each", resolveCalls, evaluateCalls, reportCalls)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("proxy policy unexpectedly logged output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if policyErr, blocked := policy.result(); policyErr != nil || blocked {
		t.Errorf("policy result = (%v, %v), want (nil, false)", policyErr, blocked)
	}
}

func TestProxyPackagePolicyBlocksRejectedPackageAfterReporting(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	reportCalls := 0
	policy := &proxyPackagePolicy{
		cmd: command,
		evaluator: evaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{
				Outcome: evaluation.OutcomeBlock,
				Results: []evaluation.PackageEvaluationResult{{
					Ecosystem: "npm", PackageName: "bad", PackageVersion: "1.0.0", Outcome: evaluation.OutcomeBlock,
				}},
			}, nil
		}),
		reporter: reporterFunc(func(
			_ context.Context, _ time.Time, _ []string, _, _, _ string, _ *pm.Set[pm.Package],
			_ evaluation.ScfwPolicyEvaluationReport, action evaluation.Outcome,
		) error {
			reportCalls++
			if action != evaluation.OutcomeBlock {
				t.Errorf("reported action = %q, want BLOCK", action)
			}
			return nil
		}),
		resolvePublishDate: func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
			return time.Time{}, nil
		},
		decisions: make(map[packageVersion]packageDecision),
	}

	err := policy.handleRequest(httpsproxy.Request{Method: "GET", URL: "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz"})
	if err == nil || !strings.Contains(err.Error(), "package blocked") {
		t.Fatalf("handleRequest() error = %v, want package blocked", err)
	}
	if reportCalls != 1 {
		t.Fatalf("reporter called %d times, want 1", reportCalls)
	}
	if got, want := stdout.String(), "BLOCK npm bad@1.0.0\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if !strings.Contains(stderr.String(), "Policy evaluation outcome: BLOCK") || !strings.Contains(stderr.String(), "bad@1.0.0") {
		t.Errorf("stderr = %q, want blocking policy details", stderr.String())
	}
	if policyErr, blocked := policy.result(); policyErr != nil || !blocked {
		t.Errorf("policy result = (%v, %v), want (nil, true)", policyErr, blocked)
	}
}

func TestProxyPackagePolicyPrintsWarningToStdout(t *testing.T) {
	var stdout bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	onWarning = evaluation.OutcomeAllow
	t.Cleanup(func() { onWarning = evaluation.OutcomeWarn })

	policy := &proxyPackagePolicy{
		cmd: command,
		evaluator: evaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{
				Outcome: evaluation.OutcomeWarn,
				Results: []evaluation.PackageEvaluationResult{{
					Ecosystem: "PyPI", PackageName: "risky", PackageVersion: "2.0.0", Outcome: evaluation.OutcomeWarn,
				}},
			}, nil
		}),
		reporter: reporterFunc(func(
			_ context.Context, _ time.Time, _ []string, _, _, _ string, _ *pm.Set[pm.Package],
			_ evaluation.ScfwPolicyEvaluationReport, action evaluation.Outcome,
		) error {
			if action != evaluation.OutcomeAllow {
				t.Errorf("reported action = %q, want ALLOW", action)
			}
			return nil
		}),
		resolvePublishDate: func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
			return time.Time{}, nil
		},
		decisions: make(map[packageVersion]packageDecision),
	}

	err := policy.handleRequest(httpsproxy.Request{
		Method: "GET",
		URL:    "https://files.pythonhosted.org/packages/risky-2.0.0.tar.gz",
	})
	if err != nil {
		t.Fatalf("handleRequest() returned error: %v", err)
	}
	if got, want := stdout.String(), "WARN PyPI risky@2.0.0\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestProxyPackagePolicyRejectsArtifactWhenEvaluationFails(t *testing.T) {
	command := &cobra.Command{}
	policy := &proxyPackagePolicy{
		cmd: command,
		evaluator: evaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{}, errors.New("API unavailable")
		}),
		reporter: reporterFunc(func(
			context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package],
			evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome,
		) error {
			t.Fatal("reporter called after evaluation failure")
			return nil
		}),
		resolvePublishDate: func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
			return time.Time{}, nil
		},
		decisions: make(map[packageVersion]packageDecision),
	}

	err := policy.handleRequest(httpsproxy.Request{Method: "GET", URL: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"})
	if err == nil || err.Error() != "package evaluation failed" {
		t.Fatalf("handleRequest() error = %v, want package evaluation failed", err)
	}
	policyErr, blocked := policy.result()
	if policyErr == nil || !strings.Contains(policyErr.Error(), "API unavailable") || blocked {
		t.Errorf("policy result = (%v, %v), want evaluation error and not blocked", policyErr, blocked)
	}
}
