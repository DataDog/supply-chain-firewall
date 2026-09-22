// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestProxyCommandValidation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "missing separator", args: []string{"npm", "install"}, wantErr: "missing"},
		{name: "argument before separator", args: []string{"unexpected", "--", "npm", "install"}, wantErr: "unexpected"},
		{name: "missing command", args: []string{"--"}, wantErr: "no command"},
		{name: "unsupported command", args: []string{"--", "twine", "upload"}, wantErr: "supported package managers"},
		{name: "explicit zero status", args: []string{"--http-status", "0", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "status below final response range", args: []string{"--http-status", "199", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "status above response range", args: []string{"--http-status=600", "--", "npm", "install"}, wantErr: "between 200 and 599"},
		{name: "npm accepted", args: []string{"--", "npm", "install"}},
		{name: "synthetic status accepted", args: []string{"--http-status", "503", "--", "npm", "install"}},
		{name: "npm path accepted", args: []string{"--", "/usr/local/bin/npm", "install"}},
		{name: "all managers accepted", args: []string{"--", "uv", "sync"}},
		{name: "pip accepted", args: []string{"--", "pip", "install", "requests"}},
		{name: "publish accepted", args: []string{"--", "npm", "publish"}},
		{name: "missing operation accepted", args: []string{"--", "npm"}},
		{name: "twine rejected", args: []string{"--", "twine", "upload"}, wantErr: "supported package managers"},
		{name: "index override rejected", args: []string{"--", "pip", "install", "--index-url", "https://example", "requests"}, wantErr: "registry option"},
		{name: "short index override rejected", args: []string{"--", "pip", "install", "-i", "https://example", "requests"}, wantErr: "registry option"},
		{name: "npm run accepted", args: []string{"--", "npm", "run", "install"}},
		{name: "bare yarn defaults to install", args: []string{"--", "yarn"}},
		{name: "yarn add accepted", args: []string{"--", "yarn", "add", "react"}},
		{name: "uv run accepted", args: []string{"--", "uv", "run", "pip", "install", "requests"}},
		{name: "unknown operation accepted", args: []string{"--", "pnpm", "future-command"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := &cobra.Command{Use: "proxy -- npm <args...>", Args: validateProxyArgs, Run: func(_ *cobra.Command, _ []string) {}}
			command.Flags().Int("http-status", 0, "")
			command.SetArgs(test.args)
			command.SilenceErrors = true
			command.SilenceUsage = true
			err := command.Execute()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("Execute(%v) returned unexpected error: %v", test.args, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Execute(%v) error = %v, want it to contain %q", test.args, err, test.wantErr)
			}
		})
	}
}

func TestProxyPackageEvaluatorReportsAllowedPackage(t *testing.T) {
	installTimestamp := time.Date(2026, 9, 22, 10, 11, 12, 0, time.UTC)
	pkg := pm.Package{
		Ecosystem:   ecosystem.NPM,
		Name:        "left-pad",
		Version:     "1.3.0",
		Source:      "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
		PublishDate: time.Date(2018, 4, 9, 1, 10, 45, 796000000, time.UTC),
	}
	evaluationReport := ddapi.ScfwPolicyEvaluationReport{
		Outcome: ddapi.OutcomeAllow,
		Results: []ddapi.PackageEvaluationResult{{
			Ecosystem:      string(ecosystem.NPM),
			PackageName:    pkg.Name,
			PackageVersion: pkg.Version,
			Outcome:        ddapi.OutcomeAllow,
		}},
	}
	var output strings.Builder
	evaluator := newProxyPackageEvaluator(installTimestamp, "npm", &output)
	evaluator.evaluate = func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (ddapi.ScfwPolicyEvaluationReport, error) {
		if interactive {
			t.Error("proxy evaluation is interactive")
		}
		if !targets.Contains(pkg) {
			t.Errorf("evaluation targets do not contain %+v", pkg)
		}
		return evaluationReport, nil
	}
	reported := false
	evaluator.report = func(
		_ context.Context,
		gotTimestamp time.Time,
		command []string,
		manager, executable, repository string,
		targets *pm.Set[pm.Package],
		gotReport ddapi.ScfwPolicyEvaluationReport,
		outcome ddapi.Outcome,
	) error {
		reported = true
		if !gotTimestamp.Equal(installTimestamp) {
			t.Errorf("report timestamp = %s, want %s", gotTimestamp, installTimestamp)
		}
		if strings.Join(command, " ") != "npm" || manager != "npm" || executable != "npm" || repository != "" {
			t.Errorf("report context = %v/%q/%q/%q", command, manager, executable, repository)
		}
		if !targets.Contains(pkg) || gotReport.Outcome != ddapi.OutcomeAllow || outcome != ddapi.OutcomeAllow {
			t.Errorf("report package/outcome = %+v/%s/%s", targets, gotReport.Outcome, outcome)
		}
		return nil
	}

	if err := evaluator.Evaluate(context.Background(), pkg); err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !reported {
		t.Fatal("allowed proxy package was not reported")
	}
	for _, want := range []string{
		`scfw proxy: POST /evaluate`,
		`scfw proxy: POST /report outcome=ALLOW`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("stdout = %q, want %q", output.String(), want)
		}
	}
}

func TestProxyPackageEvaluatorReportsBlockedPackage(t *testing.T) {
	pkg := pm.Package{Ecosystem: ecosystem.NPM, Name: "blocked", Version: "1.0.0", PublishDate: time.Now()}
	var output strings.Builder
	evaluator := newProxyPackageEvaluator(time.Now(), "npm", &output)
	evaluator.evaluate = func(context.Context, bool, *pm.Set[pm.Package]) (ddapi.ScfwPolicyEvaluationReport, error) {
		return ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.OutcomeBlock}, nil
	}
	reported := false
	evaluator.report = func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], report ddapi.ScfwPolicyEvaluationReport, outcome ddapi.Outcome) error {
		reported = true
		if !targets.Contains(pkg) || report.Outcome != ddapi.OutcomeBlock || outcome != ddapi.OutcomeBlock {
			t.Errorf("blocked report package/outcome = %+v/%s/%s", targets, report.Outcome, outcome)
		}
		return nil
	}

	if err := evaluator.Evaluate(context.Background(), pkg); err == nil {
		t.Fatal("Evaluate() error = nil, want blocked package error")
	}
	if !reported {
		t.Fatal("blocked proxy package was not reported")
	}
	if !strings.Contains(output.String(), "POST /evaluate") || !strings.Contains(output.String(), "POST /report") || !strings.Contains(output.String(), "outcome=BLOCK") {
		t.Errorf("stdout = %q, want evaluation and blocked report logs", output.String())
	}
	if strings.Contains(output.String(), pkg.Name) || strings.Contains(output.String(), pkg.Version) {
		t.Errorf("stdout leaks package coordinates: %q", output.String())
	}
}

func TestProxyPackageEvaluatorReportFailureDoesNotBlock(t *testing.T) {
	pkg := pm.Package{Ecosystem: ecosystem.PYPI, Name: "example", Version: "1.0.0", PublishDate: time.Now()}
	evaluator := newProxyPackageEvaluator(time.Now(), "pip", nil)
	evaluator.evaluate = func(context.Context, bool, *pm.Set[pm.Package]) (ddapi.ScfwPolicyEvaluationReport, error) {
		return ddapi.ScfwPolicyEvaluationReport{Outcome: ddapi.OutcomeAllow}, nil
	}
	evaluator.report = func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], ddapi.ScfwPolicyEvaluationReport, ddapi.Outcome) error {
		return errors.New("report unavailable")
	}

	if err := evaluator.Evaluate(context.Background(), pkg); err != nil {
		t.Fatalf("Evaluate() error = %v, want report failure to be non-blocking", err)
	}
}

func TestProxyPackageEvaluatorDoesNotReportEvaluationFailure(t *testing.T) {
	pkg := pm.Package{Ecosystem: ecosystem.PYPI, Name: "example", Version: "1.0.0", PublishDate: time.Now()}
	var output strings.Builder
	evaluator := newProxyPackageEvaluator(time.Now(), "pip", &output)
	evaluator.evaluate = func(context.Context, bool, *pm.Set[pm.Package]) (ddapi.ScfwPolicyEvaluationReport, error) {
		return ddapi.ScfwPolicyEvaluationReport{}, errors.New("evaluation unavailable")
	}
	evaluator.report = func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], ddapi.ScfwPolicyEvaluationReport, ddapi.Outcome) error {
		t.Fatal("failed evaluation was reported as a policy decision")
		return nil
	}

	if err := evaluator.Evaluate(context.Background(), pkg); err == nil {
		t.Fatal("Evaluate() error = nil, want evaluation failure")
	}
	if !strings.Contains(output.String(), "POST /evaluate") || strings.Contains(output.String(), "POST /report") {
		t.Errorf("stdout = %q, want only evaluation log", output.String())
	}
}
