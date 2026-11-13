// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	localevaluation "github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation/local"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

func TestArtifactGatePreservesOrBlocksPolicyDecision(t *testing.T) {
	pkg := pm.Package{Ecosystem: "npm", Name: "fixture", Version: "1.0.0"}
	for _, tc := range []struct {
		name   string
		policy evaluation.Outcome
		status pm.ArtifactStatus
		reason string
		want   evaluation.Outcome
	}{
		{"matching artifact", evaluation.OutcomeAllow, pm.ArtifactMatched, "manifest-confusion", evaluation.OutcomeAllow},
		{"mismatched artifact", evaluation.OutcomeAllow, pm.ArtifactMismatched, "manifest-confusion", evaluation.OutcomeBlock},
		{"unverified artifact", evaluation.OutcomeWarn, pm.ArtifactUnverifiable, "manifest-confusion", evaluation.OutcomeBlock},
		{"other policy block", evaluation.OutcomeBlock, pm.ArtifactMatched, "manifest-confusion", evaluation.OutcomeBlock},
		{"not applicable", evaluation.OutcomeWarn, pm.ArtifactNotApplicable, "manifest-confusion", evaluation.OutcomeWarn},
		{"integrity mismatch", evaluation.OutcomeAllow, pm.ArtifactMismatched, "integrity", evaluation.OutcomeBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := evaluation.ScfwPolicyEvaluationReport{Outcome: tc.policy, Results: []evaluation.PackageEvaluationResult{{Ecosystem: "npm", PackageName: pkg.Name, PackageVersion: pkg.Version, Outcome: tc.policy}}}
			mergeArtifactResults(&report, []pm.ArtifactResult{{Package: pkg, Status: tc.status, Reason: tc.reason, Detail: `"/scripts/install"`}})
			if report.Outcome != tc.want || report.Results[0].Outcome != tc.want {
				t.Fatalf("report=%+v; want %s", report, tc.want)
			}
			if tc.want == evaluation.OutcomeBlock && decideFirewallAction(false, report.Outcome) != evaluation.OutcomeBlock {
				t.Fatal("mandatory artifact block was bypassed")
			}
			var wantPolicies []evaluation.MatchedPolicy
			if tc.status == pm.ArtifactMismatched && tc.reason == "manifest-confusion" {
				wantPolicies = []evaluation.MatchedPolicy{{Type: "datadog_policy", Rule: `manifest confusion : "/scripts/install" are different from the artifact and the registry metadatas`, Outcome: evaluation.OutcomeBlock}}
			}
			if !slices.Equal(report.Results[0].MatchedPolicy, wantPolicies) {
				t.Fatalf("matched policies=%+v, want %+v", report.Results[0].MatchedPolicy, wantPolicies)
			}
		})
	}
}

type artifactTestTransport func(*http.Request) (*http.Response, error)

func (f artifactTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestArtifactGateRealReporters(t *testing.T) {
	pkg := pm.Package{Ecosystem: "npm", Name: "fixture", Version: "1.0.0"}
	ctx := context.Background()
	const differences = `"/dependencies/extra", "/scripts/install"`
	const manifestRule = `manifest confusion : "/dependencies/extra", "/scripts/install" are different from the artifact and the registry metadatas`
	previous := http.DefaultClient
	defer func() { http.DefaultClient = previous }()
	t.Setenv("DD_API_KEY", "fixture-api-key")
	t.Setenv("DD_APP_KEY", "fixture-app-key")
	for _, backend := range []string{"local", "datadog"} {
		for _, status := range []pm.ArtifactStatus{pm.ArtifactMatched, pm.ArtifactMismatched, pm.ArtifactUnverifiable} {
			t.Run(backend+"/"+string(status), func(t *testing.T) {
				want := evaluation.OutcomeAllow
				if status != pm.ArtifactMatched {
					want = evaluation.OutcomeBlock
				}
				initial := evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow, Results: []evaluation.PackageEvaluationResult{{
					Ecosystem: "npm", PackageName: pkg.Name, PackageVersion: pkg.Version, Outcome: evaluation.OutcomeAllow,
					MatchedPolicy: []evaluation.MatchedPolicy{{Type: "org_policy", Rule: "allow-fixture", Outcome: evaluation.OutcomeAllow}},
				}}}
				reply, _ := json.Marshal(map[string]any{"data": map[string]any{"attributes": initial}})
				var remote []byte
				http.DefaultClient = &http.Client{Transport: artifactTestTransport(func(request *http.Request) (*http.Response, error) {
					response := reply
					if strings.HasSuffix(request.URL.Path, "/report") {
						remote, _ = io.ReadAll(request.Body)
						response = []byte(`{}`)
					} else if !strings.HasSuffix(request.URL.Path, "/evaluate") {
						return nil, errors.New("unexpected request")
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
				})}
				log := filepath.Join(t.TempDir(), "report.jsonl")
				t.Setenv("SCFW_LOG_FILE", log)
				var evaluator evaluation.Evaluator = &localevaluation.Evaluator{}
				var reporter evaluation.Reporter = localevaluation.NewFileReporter()
				if backend == "datadog" {
					evaluator = ddapi.Evaluator{}
					reporter = ddapi.Reporter{}
				}
				report, err := evaluator.EvaluateInstallTargets(ctx, false, pm.NewSet(pkg))
				if err != nil {
					t.Fatal(err)
				}
				mergeArtifactResults(&report, []pm.ArtifactResult{{Package: pkg, Status: status, Reason: "manifest-confusion", Detail: differences}})
				if err = reporter.ReportFirewallOutcome(ctx, time.Now(), nil, "npm", "npm", "", pm.NewSet(pkg), report, report.Outcome); err != nil {
					t.Fatal(err)
				}
				var observed map[string]any
				var policies []evaluation.MatchedPolicy
				var failures []evaluation.Failure
				if backend == "local" {
					data, err := os.ReadFile(log)
					if err != nil {
						t.Fatal(err)
					}
					if err = json.Unmarshal(data, &observed); err != nil {
						t.Fatal(err)
					}
					packages, ok := observed["packages"].([]any)
					if !ok || len(packages) != 1 {
						t.Fatal("local package evidence missing")
					}
					if _, present := packages[0].(map[string]any)["artifact_checks"]; present {
						t.Fatal("local package result contains an unsupported artifact_checks field")
					}
					var localRecord struct {
						Packages []evaluation.PackageEvaluationResult `json:"packages"`
					}
					if err = json.Unmarshal(data, &localRecord); err != nil {
						t.Fatal(err)
					}
					policies = localRecord.Packages[0].MatchedPolicy
					failures = localRecord.Packages[0].Failures
				} else {
					var envelope struct {
						Data struct{ Attributes map[string]any }
					}
					if err = json.Unmarshal(remote, &envelope); err != nil {
						t.Fatal(err)
					}
					observed = envelope.Data.Attributes
					var remoteRecord struct {
						Data struct {
							Attributes struct {
								Reports []struct {
									MatchedPolicies []evaluation.MatchedPolicy `json:"matched_policies"`
									Failures        []evaluation.Failure
								}
							}
						}
					}
					if err = json.Unmarshal(remote, &remoteRecord); err != nil {
						t.Fatal(err)
					}
					if len(remoteRecord.Data.Attributes.Reports) != 1 {
						t.Fatal("remote package report missing")
					}
					policies = remoteRecord.Data.Attributes.Reports[0].MatchedPolicies
					failures = remoteRecord.Data.Attributes.Reports[0].Failures
					if bytes.Contains(remote, []byte(`"findings"`)) || bytes.Contains(remote, []byte(`"artifact_checks"`)) {
						t.Fatal("unsupported fields sent to Datadog")
					}
				}
				if observed["outcome"] != string(want) {
					t.Fatalf("%s reporter outcome=%v; want %s", backend, observed["outcome"], want)
				}
				wantPolicies := []evaluation.MatchedPolicy{}
				if backend == "datadog" {
					wantPolicies = append(wantPolicies, initial.Results[0].MatchedPolicy...)
				}
				if status == pm.ArtifactMismatched {
					wantPolicies = append(wantPolicies, evaluation.MatchedPolicy{Type: "datadog_policy", Rule: manifestRule, Outcome: evaluation.OutcomeBlock})
				}
				if !slices.Equal(policies, wantPolicies) {
					t.Fatalf("%s reported policies=%+v; want %+v", backend, policies, wantPolicies)
				}
				var wantFailures []evaluation.Failure
				if status == pm.ArtifactUnverifiable {
					wantFailures = []evaluation.Failure{{Verifier: "manifest-confusion", Error: differences}}
				}
				if !slices.Equal(failures, wantFailures) {
					t.Fatalf("%s reported failures=%+v; want %+v", backend, failures, wantFailures)
				}
				if status == pm.ArtifactMismatched {
					details := formatEvaluationDetails(report)
					if strings.Count(details, "manifest confusion") != 1 || !strings.Contains(details, manifestRule) {
						t.Fatalf("manifest mismatch diagnostics=%q", details)
					}
				}
			})
		}
	}
}
