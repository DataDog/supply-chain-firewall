// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http/httpproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/evaluation"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
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

func TestPyPIProxyControllerExposesEcosystemHooks(t *testing.T) {
	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}),
		nopReporter{}, io.Discard,
	)
	controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{
		SimpleIndexURLs: []string{
			"https://index.example/python-packages/",
			"https://index.example/simple/v1+json/",
		},
		DirectArtifactURLs: []string{"https://cdn.example/direct-1.0.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	options := controller(runContext, httpproxy.Config{HTTPSProxy: "http://upstream.example:8080"})
	if handler.runContext != runContext || handler.metadataClient == nil {
		t.Fatal("PyPI controller did not bind the run lifecycle and publication client")
	}
	if len(options.RequestHooks) != 1 {
		t.Fatalf("PyPI controller request hooks = %d; want 1", len(options.RequestHooks))
	}
	for _, rawURL := range []string{
		"https://index.example/python-packages/project/",
		"https://index.example/simple/v1+json/project/",
	} {
		requestURL, parseErr := url.Parse(rawURL)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		kind, _ := handler.classifier.ClassifyRequest(http.MethodGet, requestURL)
		if kind != ecosystem.PyPIRequestSimpleAPI {
			t.Fatalf("configured base %q classified as %v, want Simple API", rawURL, kind)
		}
	}
}

func TestConfiguredPyPISimpleBasesCacheOpaqueArtifacts(t *testing.T) {
	for _, base := range []string{
		"https://index.example/python-packages/",
		"https://index.example/simple/v1+json/",
	} {
		t.Run(base, func(t *testing.T) {
			var evaluations atomic.Int32
			handler := newProxyPackageEvaluator(
				context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
				proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					evaluations.Add(1)
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}),
				nopReporter{}, io.Discard,
			)
			if _, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{
				SimpleIndexURLs: []string{base},
			}); err != nil {
				t.Fatal(err)
			}
			metadataURL := mustParseURL(t, base+"project/")
			request := proxy.Request{Method: http.MethodGet, URL: metadataURL}
			if _, err := handler.HandleRequest(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			response := proxy.Response{
				Request: request, StatusCode: http.StatusOK,
				Header: http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}},
			}
			bodyHook, err := handler.ObserveMetadataHeaders(context.Background(), response)
			if err != nil || bodyHook == nil {
				t.Fatal("configured Simple response was not observed")
			}
			response.Body = []byte(`{"files":[{"filename":"project-1.0.tar.gz","url":"/objects/opaque","upload-time":"2025-01-02T03:04:05Z"}]}`)
			if err := bodyHook.Handle(context.Background(), response); err != nil {
				t.Fatal(err)
			}
			artifactURL := mustParseURL(t, "https://index.example/objects/opaque")
			if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: artifactURL}); err == nil {
				t.Fatal("opaque artifact was not blocked before forwarding")
			}
			if evaluations.Load() != 1 {
				t.Fatalf("evaluations = %d, want 1", evaluations.Load())
			}
		})
	}
}

func TestPyPIProxyDiscoversConfiguredIndexArtifactsBeforeForwarding(t *testing.T) {
	var cdnArtifactHits, indexArtifactHits, projectMetadataHits, bearerMetadataHits, toolMetadataHits, evaluations atomic.Int32
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cdnArtifactHits.Add(1)
		_, _ = io.WriteString(w, "blocked CDN bytes")
	}))
	defer cdn.Close()

	var index *httptest.Server
	index = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/python-packages/project/":
			projectMetadataHits.Add(1)
			username, password, ok := request.BasicAuth()
			if !ok || username != "index-user" || password != "index-password" {
				http.Error(w, "missing configured index credentials", http.StatusUnauthorized)
				return
			}
			if request.Header.Get("Cookie") != "" || request.Header.Get("X-Api-Key") != "" {
				http.Error(w, "cross-origin artifact credentials leaked to index", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = fmt.Fprintf(w, `{"files":[`+
				`{"filename":"project-1.0-py3-none-any.whl","url":%q,"upload-time":"2025-01-01T01:00:00Z"},`+
				`{"filename":"project-2.0.tar.gz","url":"/packages/project-2.0.tar.gz","upload-time":"2025-02-02T02:00:00Z"}`+
				`]}`, cdn.URL+"/objects/project-1.0-py3-none-any.whl?id=project&token=artifact-secret")
		case "/python-packages/bearer/":
			bearerMetadataHits.Add(1)
			if request.Header.Get("Authorization") != "Bearer same-origin-secret" ||
				request.Header.Get("Cookie") != "session=same-origin" || request.Header.Get("X-Api-Key") != "same-origin-api-key" {
				http.Error(w, "missing same-origin artifact authentication", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, `{"files":[{"filename":"bearer-1.0.tar.gz","url":"/packages/bearer-1.0.tar.gz","upload-time":"2025-03-03T03:00:00Z"}]}`)
		case "/python-packages/tool/":
			toolMetadataHits.Add(1)
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, `{"files":[]}`)
		case "/packages/project-2.0.tar.gz", "/packages/bearer-1.0.tar.gz":
			indexArtifactHits.Add(1)
			_, _ = io.WriteString(w, "blocked index bytes")
		case "/releases/tool-2026.zip":
			indexArtifactHits.Add(1)
			_, _ = io.WriteString(w, "unrelated archive")
		default:
			http.NotFound(w, request)
		}
	}))
	defer index.Close()

	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			for target := range targets.Items() {
				if strings.Contains(target.Source, "index-password") || strings.Contains(target.Source, "artifact-secret") {
					t.Fatalf("evaluated source exposes credentials: %q", target.Source)
				}
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		nopReporter{}, io.Discard,
	)
	indexURL, err := url.Parse(index.URL)
	if err != nil {
		t.Fatal(err)
	}
	indexURL.User = url.UserPassword("index-user", "index-password")
	indexURL.Path = "/python-packages/"
	controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{
		SimpleIndexURLs: []string{indexURL.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	for _, artifact := range []struct {
		url    string
		header http.Header
	}{
		{
			url: cdn.URL + "/objects/project-1.0-py3-none-any.whl?id=project&token=artifact-secret",
			header: http.Header{
				"Authorization": []string{"Bearer cross-origin-secret"},
				"Cookie":        []string{"session=cross-origin"},
				"X-Api-Key":     []string{"cross-origin-api-key"},
			},
		},
		{url: index.URL + "/packages/project-2.0.tar.gz"},
		{
			url: index.URL + "/packages/bearer-1.0.tar.gz",
			header: http.Header{
				"Authorization": []string{"Bearer same-origin-secret"},
				"Cookie":        []string{"session=same-origin"},
				"X-Api-Key":     []string{"same-origin-api-key"},
			},
		},
	} {
		request, requestErr := http.NewRequest(http.MethodGet, artifact.url, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header = artifact.header
		response, requestErr := client.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("discovered artifact %q status = %d, want 403", artifact.url, response.StatusCode)
		}
	}

	unrelated, err := client.Get(index.URL + "/releases/tool-2026.zip")
	if err != nil {
		t.Fatal(err)
	}
	unrelatedBody, _ := io.ReadAll(unrelated.Body)
	_ = unrelated.Body.Close()
	if unrelated.StatusCode != http.StatusOK || string(unrelatedBody) != "unrelated archive" {
		t.Fatalf("unadvertised archive response = %d %q, want unchanged", unrelated.StatusCode, unrelatedBody)
	}
	if cdnArtifactHits.Load() != 0 || indexArtifactHits.Load() != 1 || evaluations.Load() != 3 ||
		projectMetadataHits.Load() != 1 || bearerMetadataHits.Load() != 1 || toolMetadataHits.Load() != 1 {
		t.Fatalf("hits: CDN artifacts=%d index artifacts=%d evaluations=%d project metadata=%d bearer metadata=%d tool metadata=%d; want 0, 1, 3, 1, 1, 1",
			cdnArtifactHits.Load(), indexArtifactHits.Load(), evaluations.Load(), projectMetadataHits.Load(), bearerMetadataHits.Load(), toolMetadataHits.Load())
	}
}

func TestPyPIProxyDiscoversArchiveShapedSimpleDownloads(t *testing.T) {
	for _, base := range []string{"/simple/", "/python-packages/"} {
		for _, advertised := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/advertised=%t", base, advertised), func(t *testing.T) {
				var metadataHits, artifactHits, evaluations atomic.Int32
				artifactPath := base + "project-1.0.tar.gz"
				index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case base + "project/":
						metadataHits.Add(1)
						w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
						if advertised {
							_, _ = fmt.Fprintf(w, `{"files":[{"filename":"project-1.0.tar.gz","url":%q,"upload-time":"2025-01-02T03:04:05Z"}]}`, artifactPath)
						} else {
							_, _ = io.WriteString(w, `{"files":[]}`)
						}
					case artifactPath:
						artifactHits.Add(1)
						_, _ = io.WriteString(w, "archive bytes")
					default:
						http.NotFound(w, request)
					}
				}))
				defer index.Close()
				handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
					proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
						evaluations.Add(1)
						return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
					}), nopReporter{}, io.Discard)
				controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{SimpleIndexURLs: []string{index.URL + base}})
				if err != nil {
					t.Fatal(err)
				}
				server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				proxyURL, _ := url.Parse(server.ClientConfig().URL)
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				// No metadata request: the installer already has its own cached listing.
				response, err := client.Get(index.URL + artifactPath)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				wantStatus, wantArtifacts, wantEvaluations := http.StatusOK, int32(1), int32(0)
				if advertised {
					wantStatus, wantArtifacts, wantEvaluations = http.StatusForbidden, 0, 1
				}
				if response.StatusCode != wantStatus || metadataHits.Load() != 1 || artifactHits.Load() != wantArtifacts || evaluations.Load() != wantEvaluations {
					t.Fatalf("status=%d metadata=%d artifacts=%d evaluations=%d; want %d, 1, %d, %d",
						response.StatusCode, metadataHits.Load(), artifactHits.Load(), evaluations.Load(), wantStatus, wantArtifacts, wantEvaluations)
				}
			})
		}
	}
}

func TestPyPIProxyKeepsUnadvertisedArchiveRedirectsTentative(t *testing.T) {
	var artifactHits, evaluations atomic.Int32
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/simple/project/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, `{"files":[]}`)
		case "/simple/project-1.0.tar.gz":
			// Redirect helpers supply text/html even for binary download redirects.
			http.Redirect(w, request, "/hop", http.StatusFound)
		case "/hop":
			w.Header().Set("Location", "/objects/opaque")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/objects/opaque":
			artifactHits.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "archive bytes")
		default:
			http.NotFound(w, request)
		}
	}))
	defer index.Close()
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}), nopReporter{}, io.Discard)
	controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{SimpleIndexURLs: []string{index.URL + "/simple/"}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(index.URL + "/simple/project-1.0.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "archive bytes" || artifactHits.Load() != 1 || evaluations.Load() != 0 {
		t.Fatalf("response=%d %q error=%v artifacts=%d evaluations=%d; want original unadvertised binary", response.StatusCode, body, err, artifactHits.Load(), evaluations.Load())
	}
}

func TestPyPIProxyPreservesTentativeBinaryNotModified(t *testing.T) {
	for _, redirected := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirected=%t", redirected), func(t *testing.T) {
			var refreshes atomic.Int32
			index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/simple/project/" {
					w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
					_, _ = io.WriteString(w, `{"files":[]}`)
					return
				}
				if redirected && request.URL.Path == "/simple/project-1.0.tar.gz" {
					http.Redirect(w, request, "/objects/opaque", http.StatusFound)
					return
				}
				if request.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				refreshes.Add(1)
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = io.WriteString(w, "archive bytes")
			}))
			defer index.Close()
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					t.Error("unadvertised binary was evaluated")
					return evaluation.ScfwPolicyEvaluationReport{}, nil
				}), nopReporter{}, io.Discard)
			controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{SimpleIndexURLs: []string{index.URL + "/simple/"}})
			if err != nil {
				t.Fatal(err)
			}
			server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for _, conditional := range []bool{true, false} {
				request, _ := http.NewRequest(http.MethodGet, index.URL+"/simple/project-1.0.tar.gz", nil)
				if conditional {
					request.Header.Set("If-None-Match", `"cached-binary"`)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				wantStatus, wantBody := http.StatusOK, "archive bytes"
				if conditional {
					wantStatus, wantBody = http.StatusNotModified, ""
				}
				if err != nil || response.StatusCode != wantStatus || string(body) != wantBody {
					t.Fatalf("conditional=%t response=%d %q, %v; want %d %q", conditional, response.StatusCode, body, err, wantStatus, wantBody)
				}
			}
			if refreshes.Load() != 2 {
				t.Fatalf("binary responses=%d; want one refresh and one normal download", refreshes.Load())
			}
		})
	}
}

func TestPyPIProxyPreservesArchiveShapedProjectContext(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect=%t", redirect), func(t *testing.T) {
			const projectPath = "/simple/project-1.0.tar.gz/"
			const filename = "project_1_0_tar_gz-1.0.tar.gz"
			artifactPath := "/objects/opaque"
			if redirect {
				artifactPath = "/files/" + filename
			}
			var artifactHits, evaluations atomic.Int32
			index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/simple/project/":
					w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
					_, _ = io.WriteString(w, `{"files":[]}`)
				case projectPath:
					if redirect {
						w.Header().Set("Location", "/catalog/opaque/")
						w.WriteHeader(http.StatusFound)
					} else if request.Header.Get("If-None-Match") != "" {
						w.WriteHeader(http.StatusNotModified)
					} else {
						w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
						_, _ = fmt.Fprintf(w, `{"files":[{"filename":%q,"url":%q,"upload-time":"2025-05-06T07:08:09Z"}]}`, filename, artifactPath)
					}
				case "/catalog/opaque/":
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprintf(w, `<a href="../../files/%s" data-upload-time="2025-05-06T07:08:09Z">project</a>`, filename)
				case artifactPath:
					artifactHits.Add(1)
					_, _ = io.WriteString(w, "blocked artifact bytes")
				default:
					http.NotFound(w, request)
				}
			}))
			defer index.Close()
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					evaluations.Add(1)
					for target := range targets.Items() {
						if target.Name != "project-1-0-tar-gz" || target.Version != "1.0" {
							t.Errorf("wrong project identity: %#v", target)
						}
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}), nopReporter{}, io.Discard)
			controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{SimpleIndexURLs: []string{index.URL + "/simple/"}})
			if err != nil {
				t.Fatal(err)
			}
			server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, index.URL+projectPath, nil)
			request.Header.Set("If-None-Match", `"cached-listing"`)
			metadata, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, metadata.Body)
			_ = metadata.Body.Close()
			wantMetadataStatus := http.StatusNotModified
			if redirect {
				wantMetadataStatus = http.StatusOK
			}
			if metadata.StatusCode != wantMetadataStatus {
				t.Fatalf("metadata status=%d, want %d", metadata.StatusCode, wantMetadataStatus)
			}
			artifact, err := client.Get(index.URL + artifactPath)
			if err != nil {
				t.Fatal(err)
			}
			_ = artifact.Body.Close()
			if artifact.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || evaluations.Load() != 1 {
				t.Fatalf("status=%d hits=%d evaluations=%d; want 403, 0, 1", artifact.StatusCode, artifactHits.Load(), evaluations.Load())
			}
		})
	}
}

func TestPyPIProxyRetainsAgeEvidenceAcrossMetadataRepresentations(t *testing.T) {
	now := time.Now().UTC()
	var serveHTML atomic.Bool
	var artifactHits, evaluations, metadataHits atomic.Int32
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/simple/project/":
			metadataHits.Add(1)
			if serveHTML.Load() {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, `<a href="/files/project-1.0.tar.gz">project</a>`)
			} else {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				_, _ = fmt.Fprintf(w, `{"files":[{"filename":"project-1.0.tar.gz","url":"/files/project-1.0.tar.gz","upload-time":%q}]}`, now.Add(-time.Hour).Format(time.RFC3339Nano))
			}
		case "/files/project-1.0.tar.gz":
			artifactHits.Add(1)
			_, _ = io.WriteString(w, "recent archive bytes")
		default:
			http.NotFound(w, request)
		}
	}))
	defer index.Close()
	handler := newProxyPackageEvaluator(context.Background(), now, nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			for target := range targets.Items() {
				if !target.PublishDate.IsZero() && now.Sub(target.PublishDate) < 24*time.Hour {
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}), nopReporter{}, io.Discard)
	options := newPyPIProxyController(handler)(context.Background(), httpproxy.Config{})
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Time{}, nil
	}
	server, err := proxy.Start(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, html := range []bool{false, true} {
		serveHTML.Store(html)
		for _, request := range []struct {
			path   string
			status int
		}{
			{path: "/simple/project/", status: http.StatusOK},
			{path: "/files/project-1.0.tar.gz", status: http.StatusForbidden},
		} {
			response, err := client.Get(index.URL + request.path)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != request.status {
				t.Fatalf("HTML=%t %s status=%d, want %d", html, request.path, response.StatusCode, request.status)
			}
		}
	}
	if metadataHits.Load() != 2 || artifactHits.Load() != 0 || evaluations.Load() != 1 {
		t.Fatalf("metadata=%d artifacts=%d evaluations=%d; want 2, 0, 1", metadataHits.Load(), artifactHits.Load(), evaluations.Load())
	}
}

func TestPyPIProxyBlocksHTMLBaseArtifactBeforeForwarding(t *testing.T) {
	for _, observeMetadata := range []bool{true, false} {
		t.Run(fmt.Sprintf("observeMetadata=%t", observeMetadata), func(t *testing.T) {
			var artifactHits, evaluations, reports atomic.Int32
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				artifactHits.Add(1)
				_, _ = io.WriteString(w, "blocked wheel bytes")
			}))
			defer cdn.Close()
			const filename = "project-1.0-py3-none-any.whl"
			metadataBody := fmt.Sprintf(`<html><head><base href="%s/files/"></head><body><a href="%s?token=secret">%s</a></body></html>`, cdn.URL, filename, filename)
			index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/simple/project/" {
					http.NotFound(w, request)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, metadataBody)
			}))
			defer index.Close()
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					evaluations.Add(1)
					for target := range targets.Items() {
						if target.Name != "project" || target.Version != "1.0" || target.Source != cdn.URL+"/files/"+filename {
							t.Errorf("unexpected evaluated package: %#v", target)
						}
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}),
				proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, _ *pm.Set[pm.Package], report evaluation.ScfwPolicyEvaluationReport, resolved evaluation.Outcome) error {
					reports.Add(1)
					if report.Outcome != evaluation.OutcomeBlock || resolved != evaluation.OutcomeBlock {
						t.Errorf("reported outcome = %s, resolved = %s; want BLOCK", report.Outcome, resolved)
					}
					return nil
				}), io.Discard)
			controller, err := newPyPIProxyControllerWithOptions(handler, ecosystem.PyPIRequestClassifierOptions{
				SimpleIndexURLs: []string{index.URL + "/simple/"},
			})
			if err != nil {
				t.Fatal(err)
			}
			server, err := proxy.Start(context.Background(), controller(context.Background(), httpproxy.Config{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport}
			if observeMetadata {
				metadata, requestErr := client.Get(index.URL + "/simple/project/")
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				body, readErr := io.ReadAll(metadata.Body)
				_ = metadata.Body.Close()
				if readErr != nil || metadata.StatusCode != http.StatusOK || string(body) != metadataBody {
					t.Fatalf("metadata response = %d %q, %v; want original HTML", metadata.StatusCode, body, readErr)
				}
			}
			artifact, err := client.Get(cdn.URL + "/files/" + filename + "?token=secret")
			if err != nil {
				t.Fatal(err)
			}
			_ = artifact.Body.Close()
			if artifact.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || evaluations.Load() != 1 || reports.Load() != 1 {
				t.Fatalf("status=%d artifact hits=%d evaluations=%d reports=%d; want 403, 0, 1, 1",
					artifact.StatusCode, artifactHits.Load(), evaluations.Load(), reports.Load())
			}
		})
	}
}

func TestPyPIProxyBlocksArtifactsFromRedirectedSimpleHTML(t *testing.T) {
	for _, test := range []struct {
		name        string
		crossOrigin bool
		credentials bool
		root        bool
	}{
		{name: "same-origin"},
		{name: "cross-origin", crossOrigin: true},
		{name: "credentialed-cross-origin", crossOrigin: true, credentials: true},
		{name: "cross-origin-root", crossOrigin: true, root: true},
	} {
		for _, notModified := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/notModified=%t", test.name, notModified), func(t *testing.T) {
				const filename = "project-1.0-py3-none-any.whl"
				const body = `<html><a href="../../files/` + filename + `?signature=secret" data-upload-time="2025-05-06T07:08:09Z">wheel</a></html>`
				var artifactHits, metadataHits, evaluations atomic.Int32
				final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					switch request.URL.Path {
					case "/simple/project/":
						http.Redirect(w, request, "/metadata-hop/", http.StatusFound)
					case "/metadata-hop/":
						http.Redirect(w, request, "../catalog/opaque/", http.StatusPermanentRedirect)
					case "/catalog/opaque/", "/":
						if test.credentials {
							username, password, ok := request.BasicAuth()
							if !ok || username != "redirect-user" || password != "redirect-password" {
								http.Error(w, "missing destination credentials", http.StatusUnauthorized)
								return
							}
						}
						metadataHits.Add(1)
						w.Header().Set("Content-Type", "text/html")
						if request.Header.Get("If-None-Match") != "" {
							w.WriteHeader(http.StatusNotModified)
							return
						}
						_, _ = io.WriteString(w, body)
					case "/files/" + filename:
						artifactHits.Add(1)
						_, _ = io.WriteString(w, "wheel bytes")
					case "/unrelated/":
						w.Header().Set("Content-Type", "text/html")
						_, _ = io.WriteString(w, `<a href="/files/unrelated-1.0.tar.gz">unrelated archive</a>`)
					default:
						http.NotFound(w, request)
					}
				}))
				defer final.Close()
				indexURL := final.URL
				if test.crossOrigin {
					location := mustParseURL(t, final.URL+"/metadata-hop/")
					if test.root {
						location = mustParseURL(t, final.URL+"?token=root-secret")
					}
					if test.credentials {
						location.User = url.UserPassword("redirect-user", "redirect-password")
					}
					index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
						http.Redirect(w, request, location.String(), http.StatusTemporaryRedirect)
					}))
					defer index.Close()
					indexURL = index.URL
				}

				handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
					proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
						evaluations.Add(1)
						for target := range targets.Items() {
							wantDate := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
							if target.Name != "project" || target.Version != "1.0" ||
								target.Source != final.URL+"/files/"+filename || !target.PublishDate.Equal(wantDate) {
								t.Errorf("unexpected evaluated package: %#v", target)
							}
						}
						return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
					}), nopReporter{}, io.Discard)
				// The default controller has no configured indexes to discover an
				// artifact if observation of the redirected listing is missed.
				options := newPyPIProxyController(handler)(context.Background(), httpproxy.Config{})
				server, err := proxy.Start(context.Background(), options)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				proxyURL, _ := url.Parse(server.ClientConfig().URL)
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, indexURL+"/simple/project/", nil)
				if notModified {
					request.Header.Set("If-None-Match", `"cached-project"`)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				gotBody, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				wantStatus, wantBody, wantMetadataHits := http.StatusOK, body, int32(1)
				if notModified {
					wantStatus, wantBody, wantMetadataHits = http.StatusNotModified, "", 2
				}
				if readErr != nil || response.StatusCode != wantStatus || string(gotBody) != wantBody || metadataHits.Load() != wantMetadataHits {
					t.Fatalf("metadata status=%d body=%q hits=%d error=%v; want %d, %q, %d, nil",
						response.StatusCode, gotBody, metadataHits.Load(), readErr, wantStatus, wantBody, wantMetadataHits)
				}

				unrelated, err := client.Get(final.URL + "/unrelated/")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, unrelated.Body)
				_ = unrelated.Body.Close()
				unrelatedURL := mustParseURL(t, final.URL+"/files/unrelated-1.0.tar.gz")
				if _, found := handler.metadata.ArtifactForURL(&unrelatedURL); found {
					t.Fatal("unrelated HTML on the same origin was treated as package metadata")
				}
				artifact, err := client.Get(final.URL + "/files/" + filename + "?signature=secret")
				if err != nil {
					t.Fatal(err)
				}
				_ = artifact.Body.Close()
				if artifact.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || evaluations.Load() != 1 {
					t.Fatalf("artifact status=%d hits=%d evaluations=%d; want 403, 0, 1",
						artifact.StatusCode, artifactHits.Load(), evaluations.Load())
				}
			})
		}
	}
}

func TestProxyPackageEvaluatorTracksOnlyMetadataRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusOK, http.StatusNotModified,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", nil, nil, io.Discard)
			source := mustParseURL(t, "https://index.example/simple/project/")
			target := mustParseURL(t, "https://index.example/catalog/opaque/")
			handler.ObserveMetadataHeaders(context.Background(), proxy.Response{
				Request: proxy.Request{Method: http.MethodGet, URL: source}, StatusCode: status,
				Header: http.Header{"Location": []string{"/catalog/opaque/"}},
			})
			_, _, found := handler.metadata.ProjectForURL(&target)
			if want := status >= 300 && status != http.StatusNotModified; found != want {
				t.Fatalf("redirect registered = %t, want %t", found, want)
			}
		})
	}
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", nil, nil, io.Discard)
	source := mustParseURL(t, "https://index.example/unrelated/")
	target := mustParseURL(t, "https://index.example/catalog/opaque/")
	handler.ObserveMetadataHeaders(context.Background(), proxy.Response{
		Request: proxy.Request{Method: http.MethodGet, URL: source}, StatusCode: http.StatusFound,
		Header: http.Header{"Location": []string{target.String()}},
	})
	if _, _, found := handler.metadata.ProjectForURL(&target); found {
		t.Fatal("redirect from an unrelated endpoint registered a Simple project")
	}
}

func TestRunThroughProxyCancelsArtifactWorkWithLifecycleContext(t *testing.T) {
	for _, phase := range []string{"publication", "evaluation", "reporting"} {
		t.Run(phase, func(t *testing.T) {
			started := make(chan struct{})
			waitForCancellation := func(ctx context.Context) error {
				close(started)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					return errors.New("lifecycle context was not canceled by SIGTERM")
				}
			}

			evaluator := proxyEvaluatorFunc(func(ctx context.Context, _ bool, _ *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
				if phase == "evaluation" {
					return evaluation.ScfwPolicyEvaluationReport{}, waitForCancellation(ctx)
				}
				return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
			})
			reporter := proxyReporterFunc(func(ctx context.Context, _ time.Time, _ []string, _, _, _ string, _ *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
				if phase == "reporting" {
					return waitForCancellation(ctx)
				}
				return nil
			})
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", evaluator, reporter, io.Discard)
			handler.resolveDate = func(ctx context.Context, _ ecosystem.Ecosystem, _, _, _ string) (time.Time, error) {
				if phase == "publication" {
					return time.Time{}, waitForCancellation(ctx)
				}
				return time.Now(), nil
			}

			var lifecycleContext context.Context
			manager := &fakeProxyPackageManager{runProxied: func(ctx context.Context, _ []string, _ proxy.ClientConfig) error {
				if lifecycleContext == nil || ctx != lifecycleContext {
					return errors.New("command and artifact work did not receive the same lifecycle context")
				}
				requestURL, _ := url.Parse("https://files.pythonhosted.org/packages/project-1.0-py3-none-any.whl")
				request := proxy.Request{Method: http.MethodGet, URL: *requestURL}
				result := make(chan error, 1)
				go func() { _, err := handler.HandleRequest(context.Background(), request); result <- err }()
				<-started
				if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
					return err
				}
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						return fmt.Errorf("artifact work returned %v, want context canceled", err)
					}
				case <-time.After(5 * time.Second):
					return errors.New("artifact work did not stop after SIGTERM")
				}
				handler.mutex.Lock()
				decisionCount := len(handler.decisions)
				handler.mutex.Unlock()
				if decisionCount != 0 {
					return fmt.Errorf("incomplete decision count = %d, want 0 so a later attempt can retry", decisionCount)
				}
				return ctx.Err()
			}}

			configure := func(ctx context.Context, _ httpproxy.Config) proxy.Options {
				lifecycleContext = ctx
				handler.runContext = ctx
				return proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}}
			}
			commandErr, setupErr := runThroughProxy(context.Background(), manager, []string{"install", "project"}, configure)
			if setupErr != nil {
				t.Fatalf("runThroughProxy() setup error = %v", setupErr)
			}
			if !errors.Is(commandErr, context.Canceled) {
				t.Fatalf("runThroughProxy() command error = %v, want context canceled", commandErr)
			}
		})
	}
}

func TestProxyPackageEvaluatorDecisions(t *testing.T) {
	tests := []struct {
		name           string
		outcome        evaluation.Outcome
		evaluationErr  error
		publicationErr error
		reportErr      error
		wantBlocked    bool
		wantResolved   evaluation.Outcome
		wantReport     evaluation.Outcome
		wantDiagnostic string
	}{
		{name: "allow", outcome: evaluation.OutcomeAllow, wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeAllow},
		{name: "warn prints and continues", outcome: evaluation.OutcomeWarn, wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeWarn, wantDiagnostic: "Policy evaluation outcome: WARN"},
		{name: "explicit block", outcome: evaluation.OutcomeBlock, wantBlocked: true, wantResolved: evaluation.OutcomeBlock, wantReport: evaluation.OutcomeBlock, wantDiagnostic: "Policy evaluation outcome: BLOCK"},
		{name: "error outcome continues", outcome: evaluation.OutcomeError, wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeError, wantDiagnostic: "Policy evaluation outcome: ERROR"},
		{name: "evaluation failure continues", evaluationErr: errors.New("service unavailable"), wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeError, wantDiagnostic: "failed to evaluate (service unavailable)"},
		{name: "missing publication data still evaluates and blocks", outcome: evaluation.OutcomeBlock, publicationErr: errors.New("custom index has no upload time"), wantBlocked: true, wantResolved: evaluation.OutcomeBlock, wantReport: evaluation.OutcomeBlock, wantDiagnostic: "custom index has no upload time"},
		{name: "missing publication data allows non-block outcome", outcome: evaluation.OutcomeAllow, publicationErr: errors.New("custom index has no upload time"), wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeAllow, wantDiagnostic: "custom index has no upload time"},
		{name: "reporting failure does not change allow", outcome: evaluation.OutcomeAllow, reportErr: errors.New("report failed"), wantResolved: evaluation.OutcomeAllow, wantReport: evaluation.OutcomeAllow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			var reported evaluation.ScfwPolicyEvaluationReport
			var resolved evaluation.Outcome
			evaluator := proxyEvaluatorFunc(func(_ context.Context, interactive bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
				if interactive {
					t.Error("proxy evaluation was interactive")
				}
				if targets.Len() != 1 {
					t.Fatalf("targets length = %d, want 1", targets.Len())
				}
				if tt.evaluationErr != nil {
					return evaluation.ScfwPolicyEvaluationReport{}, tt.evaluationErr
				}
				return evaluation.ScfwPolicyEvaluationReport{
					Outcome: tt.outcome,
					Results: []evaluation.PackageEvaluationResult{{
						Ecosystem: "PyPI", PackageName: "requests", PackageVersion: "2.32.3", Outcome: tt.outcome,
					}},
				}, nil
			})
			reporter := proxyReporterFunc(func(_ context.Context, _ time.Time, command []string, _, _, _ string, targets *pm.Set[pm.Package], report evaluation.ScfwPolicyEvaluationReport, final evaluation.Outcome) error {
				if strings.Contains(strings.Join(command, " "), "secret") {
					t.Errorf("reported command exposes credentials: %q", command)
				}
				for target := range targets.Items() {
					if strings.Contains(target.Source, "secret") || strings.Contains(target.Source, "user") {
						t.Errorf("reported source exposes credentials: %q", target.Source)
					}
				}
				reported, resolved = report, final
				return tt.reportErr
			})
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), []string{"pip", "install", "--index-url=https://user:secret@index.example/simple?token=secret"}, "pip", "pip", "", evaluator, reporter, &output)
			handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
				if tt.publicationErr != nil {
					return time.Time{}, tt.publicationErr
				}
				return time.Date(2024, 5, 29, 15, 37, 49, 0, time.UTC), nil
			}
			requestURL, err := url.Parse("https://user:secret@files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl?token=secret")
			if err != nil {
				t.Fatal(err)
			}
			_, err = handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: *requestURL})
			if (err != nil) != tt.wantBlocked {
				t.Fatalf("HandleRequest() error = %v, want blocked %v", err, tt.wantBlocked)
			}
			if resolved != tt.wantResolved || reported.Outcome != tt.wantReport {
				t.Errorf("reported outcome %q, resolved %q; want %q, %q", reported.Outcome, resolved, tt.wantReport, tt.wantResolved)
			}
			if tt.publicationErr != nil && (len(reported.Results) == 0 || len(reported.Results[0].Failures) == 0 || reported.Results[0].Failures[0].Verifier != "publication") {
				t.Errorf("reported result does not retain publication failure: %#v", reported.Results)
			}
			if !strings.Contains(output.String(), tt.wantDiagnostic) {
				t.Errorf("diagnostic = %q, want substring %q", output.String(), tt.wantDiagnostic)
			}
		})
	}
}

func TestProxyPackageEvaluatorDoesNotReuseOtherArtifactPolicyInputs(t *testing.T) {
	now := time.Now().UTC()
	oldDate := now.Add(-48 * time.Hour)
	recentDate := now.Add(-time.Hour)
	for _, test := range []struct {
		name        string
		firstFile   string
		secondFile  string
		firstURL    string
		secondURL   string
		firstDate   time.Time
		secondDate  time.Time
		blockSource bool
	}{
		{
			name: "recent compatible wheel", firstFile: "project-1.0-py3-none-any.whl", secondFile: "project-1.0-cp313-cp313-manylinux_2_17_x86_64.whl",
			firstURL: "https://cdn.example/old.whl", secondURL: "https://cdn.example/new.whl", secondDate: recentDate,
		},
		{
			name: "equivalent versions on distinct wheels", firstFile: "project-01.0RC01-py3-none-any.whl", secondFile: "project-1.0.0rc1-cp313-cp313-manylinux_2_17_x86_64.whl",
			firstURL: "https://cdn.example/old.whl", secondURL: "https://cdn.example/new.whl", secondDate: recentDate,
		},
		{
			name: "recent sdist", firstFile: "project-1.0-py3-none-any.whl", secondFile: "project-1.0.tar.gz",
			firstURL: "https://cdn.example/old.whl", secondURL: "https://cdn.example/project-1.0.tar.gz", secondDate: recentDate,
		},
		{
			name: "same source with changed timestamp", firstFile: "project-1.0-py3-none-any.whl", secondFile: "project-1.0-py3-none-any.whl",
			firstURL: "https://cdn.example/project.whl", secondURL: "https://cdn.example/project.whl",
			firstDate: now.Add(-24*time.Hour - time.Nanosecond), secondDate: now.Add(-24*time.Hour + time.Nanosecond),
		},
		{
			name: "source-specific policy with matching timestamp", firstFile: "project-1.0-py3-none-any.whl", secondFile: "project-1.0-py3-none-any.whl",
			firstURL: "https://trusted.example/project.whl", secondURL: "https://blocked.example/project.whl", secondDate: oldDate, blockSource: true,
		},
		{
			name: "query variants share a redacted source", firstFile: "project-1.0-py3-none-any.whl", secondFile: "project-1.0-py3-none-any.whl",
			firstURL: "https://cdn.example/project.whl?variant=old", secondURL: "https://cdn.example/project.whl?variant=new", secondDate: recentDate,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var evaluations, reports atomic.Int32
			handler := newProxyPackageEvaluator(context.Background(), now, nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					evaluations.Add(1)
					for target := range targets.Items() {
						if now.Sub(target.PublishDate) < 24*time.Hour || (test.blockSource && strings.Contains(target.Source, "blocked.example")) {
							return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
						}
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
				}),
				proxyReporterFunc(func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error {
					reports.Add(1)
					return nil
				}), io.Discard)
			handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
				t.Fatal("exact artifact date should come from observed metadata")
				return time.Time{}, nil
			}
			observe := func(filename, source string, date time.Time) {
				t.Helper()

				if err := handler.metadata.Observe(mustParseURL(t, "https://index.example/simple/project/"), http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(fmt.Sprintf(`{"files":[{"filename":%q,"url":%q,"upload-time":%q}]}`, filename, source, date.Format(time.RFC3339Nano)))); err != nil {
					t.Fatal(err)
				}
			}
			firstDate := test.firstDate
			if firstDate.IsZero() {
				firstDate = oldDate
			}
			observe(test.firstFile, test.firstURL, firstDate)
			first := proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, test.firstURL)}
			if _, err := handler.HandleRequest(context.Background(), first); err != nil {
				t.Fatalf("old artifact was blocked: %v", err)
			}
			observe(test.secondFile, test.secondURL, test.secondDate)
			second := proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, test.secondURL)}
			for range 2 {
				if _, err := handler.HandleRequest(context.Background(), second); err == nil {
					t.Fatal("second artifact inherited the first artifact's allowance")
				}
			}
			if evaluations.Load() != 2 || reports.Load() != 2 {
				t.Fatalf("evaluations=%d reports=%d; want one decision per distinct policy input", evaluations.Load(), reports.Load())
			}
		})
	}
}

func TestPyPIProxyDoesNotForwardRecentArtifactAfterAllowingOlderWheel(t *testing.T) {
	now := time.Now().UTC()
	oldDate, recentDate := now.Add(-48*time.Hour), now.Add(-time.Hour)
	var oldHits, recentHits, evaluations atomic.Int32
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/simple/project/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = fmt.Fprintf(w, `{"files":[{"filename":"project-1.0-py3-none-any.whl","url":"/files/old","upload-time":%q},{"filename":"project-1.0.tar.gz","url":"/files/recent","upload-time":%q}]}`,
				oldDate.Format(time.RFC3339Nano), recentDate.Format(time.RFC3339Nano))
		case "/files/old":
			oldHits.Add(1)
			_, _ = io.WriteString(w, "old wheel")
		case "/files/recent":
			recentHits.Add(1)
			_, _ = io.WriteString(w, "recent sdist")
		default:
			http.NotFound(w, request)
		}
	}))
	defer index.Close()
	handler := newProxyPackageEvaluator(context.Background(), now, nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			for target := range targets.Items() {
				if now.Sub(target.PublishDate) < 24*time.Hour {
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}), nopReporter{}, io.Discard)
	options := newPyPIProxyController(handler)(context.Background(), httpproxy.Config{})
	server, err := proxy.Start(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, test := range []struct {
		path   string
		status int
	}{
		{path: "/simple/project/", status: http.StatusOK},
		{path: "/files/old", status: http.StatusOK},
		{path: "/files/recent", status: http.StatusForbidden},
	} {
		response, requestErr := client.Get(index.URL + test.path)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("%s returned %d, want %d", test.path, response.StatusCode, test.status)
		}
	}
	if oldHits.Load() != 1 || recentHits.Load() != 0 || evaluations.Load() != 2 {
		t.Fatalf("old hits=%d recent hits=%d evaluations=%d; want 1, 0, 2", oldHits.Load(), recentHits.Load(), evaluations.Load())
	}
}

func TestProxyPackageEvaluatorMatchesExactUploadInstants(t *testing.T) {
	date := time.Now().UTC()
	dates := []time.Time{date, date.In(time.FixedZone("offset", 3600)), date.Add(time.Nanosecond)}
	var lookups, evaluations atomic.Int32
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}), nopReporter{}, io.Discard)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return dates[lookups.Add(1)-1], nil
	}
	request := proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, "https://files.pythonhosted.org/project-1.0.tar.gz")}
	for index := range dates {
		if _, err := handler.HandleRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		wantEvaluations := int32(1)
		if index == 2 {
			wantEvaluations = 2
		}
		if evaluations.Load() != wantEvaluations {
			t.Fatalf("date %d: evaluations=%d, want %d", index, evaluations.Load(), wantEvaluations)
		}
	}
}

func TestProxyPackageEvaluatorResolvesPublicationBeforeReusingDecision(t *testing.T) {
	now := time.Now().UTC()
	var lookups, evaluations atomic.Int32
	handler := newProxyPackageEvaluator(context.Background(), now, nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			for target := range targets.Items() {
				if !target.PublishDate.IsZero() && now.Sub(target.PublishDate) < 24*time.Hour {
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}), nopReporter{}, io.Discard)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		if lookups.Add(1) == 1 {
			return time.Time{}, errors.New("publication lookup temporarily unavailable")
		}
		return now.Add(-time.Hour), nil
	}
	request := proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, "https://files.pythonhosted.org/project-1.0.tar.gz")}
	if _, err := handler.HandleRequest(context.Background(), request); err != nil {
		t.Fatalf("initial lookup failure unexpectedly blocked: %v", err)
	}
	if _, err := handler.HandleRequest(context.Background(), request); err == nil {
		t.Fatal("recovered publication lookup reused the decision with an unknown date")
	}
	if lookups.Load() != 2 || evaluations.Load() != 2 {
		t.Fatalf("lookups=%d evaluations=%d; want 2 each", lookups.Load(), evaluations.Load())
	}
}

func TestProxyPackageEvaluatorDeduplicatesConcurrentRequests(t *testing.T) {
	var resolves, evaluations, reports atomic.Int32
	const resolvedSource = "https://files.pythonhosted.org/packages/project-1.0-py3-none-any.whl"
	resolvedDate := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	var reportedSource string
	var reportedDate time.Time
	releaseEvaluation := make(chan struct{})
	evaluator := proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		evaluations.Add(1)
		<-releaseEvaluation
		return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
	})
	reporter := proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
		reports.Add(1)
		for target := range targets.Items() {
			reportedSource, reportedDate = target.Source, target.PublishDate
		}
		return nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), []string{"uv", "pip", "install"}, "uv", "uv", "", evaluator, reporter, io.Discard)
	handler.resolveDate = func(_ context.Context, _ ecosystem.Ecosystem, _, _, source string) (time.Time, error) {
		resolves.Add(1)
		if source != resolvedSource {
			t.Errorf("resolved source = %q, want %q", source, resolvedSource)
		}
		return resolvedDate, nil
	}

	const requestCount = 20
	start := make(chan struct{})
	var group sync.WaitGroup
	errorsSeen := make(chan error, requestCount)
	for range requestCount {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			requestURL, _ := url.Parse(resolvedSource)
			_, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: *requestURL})
			errorsSeen <- err
		}()
	}
	close(start)
	for evaluations.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(releaseEvaluation)
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if resolves.Load() != requestCount || evaluations.Load() != 1 || reports.Load() != 1 {
		t.Fatalf("resolves=%d evaluations=%d reports=%d; want %d, 1, 1", resolves.Load(), evaluations.Load(), reports.Load(), requestCount)
	}
	if reportedSource != resolvedSource || !reportedDate.Equal(resolvedDate) {
		t.Fatalf("reported source/date = %q %v, resolved = %q %v", reportedSource, reportedDate, resolvedSource, resolvedDate)
	}
}

func TestProxyPackageEvaluatorRequestCancellationDoesNotCancelRunDecision(t *testing.T) {
	var resolves, evaluations, reports atomic.Int32
	publishDate := time.Now().UTC()
	resolveStarted, releaseResolve := make(chan struct{}), make(chan struct{})
	evaluator := proxyEvaluatorFunc(func(ctx context.Context, _ bool, _ *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		if ctx.Err() != nil {
			t.Fatalf("evaluation received canceled request context: %v", ctx.Err())
		}
		evaluations.Add(1)
		return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
	})
	reporter := proxyReporterFunc(func(ctx context.Context, _ time.Time, _ []string, _, _, _ string, _ *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
		if ctx.Err() != nil {
			t.Fatalf("report received canceled request context: %v", ctx.Err())
		}
		reports.Add(1)
		return nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", evaluator, reporter, io.Discard)
	handler.resolveDate = func(ctx context.Context, _ ecosystem.Ecosystem, _, _, _ string) (time.Time, error) {
		if resolves.Add(1) == 1 {
			close(resolveStarted)
		}
		select {
		case <-releaseResolve:
			return publishDate, nil
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
	}
	requestURL, _ := url.Parse("https://files.pythonhosted.org/packages/project-1.0-py3-none-any.whl")
	request := proxy.Request{Method: http.MethodGet, URL: *requestURL}
	requestContext, cancelRequest := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := handler.HandleRequest(requestContext, request); result <- err }()
	<-resolveStarted
	cancelRequest()
	close(releaseResolve)
	if err := <-result; err != nil {
		t.Fatalf("leader response returned error after request cancellation: %v", err)
	}
	if _, err := handler.HandleRequest(context.Background(), request); err != nil {
		t.Fatalf("retry returned error: %v", err)
	}
	if resolves.Load() != 2 || evaluations.Load() != 1 || reports.Load() != 1 {
		t.Fatalf("resolves=%d evaluations=%d reports=%d; want 2, 1, 1: resolve each request and share one completed decision", resolves.Load(), evaluations.Load(), reports.Load())
	}
}

func TestProxyPackageEvaluatorRetriesIncompleteCanceledDecision(t *testing.T) {
	var resolves, evaluations, reports atomic.Int32
	evaluator := proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		evaluations.Add(1)
		return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
	})
	reporter := proxyReporterFunc(func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error {
		reports.Add(1)
		return nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", evaluator, reporter, io.Discard)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		if resolves.Add(1) == 1 {
			return time.Time{}, context.Canceled
		}
		return time.Now(), nil
	}
	requestURL, _ := url.Parse("https://files.pythonhosted.org/packages/project-1.0-py3-none-any.whl")
	request := proxy.Request{Method: http.MethodGet, URL: *requestURL}
	if _, err := handler.HandleRequest(context.Background(), request); !errors.Is(err, context.Canceled) {
		t.Fatalf("first incomplete decision error = %v, want context canceled", err)
	}
	if _, err := handler.HandleRequest(context.Background(), request); err != nil {
		t.Fatalf("retry returned error: %v", err)
	}
	if resolves.Load() != 2 || evaluations.Load() != 1 || reports.Load() != 1 {
		t.Fatalf("resolves=%d evaluations=%d reports=%d; want 2, 1, 1", resolves.Load(), evaluations.Load(), reports.Load())
	}
}

func TestProxyPackageEvaluatorUsesObservedMetadataBeforeArtifactRequest(t *testing.T) {
	wantDate := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	var gotDate time.Time
	evaluator := proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		for target := range targets.Items() {
			gotDate = target.PublishDate
		}
		return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", evaluator, nopReporter{}, io.Discard)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		t.Fatal("independent publication lookup called despite exact cached metadata")
		return time.Time{}, nil
	}

	metadataURL, _ := url.Parse("https://index.example/simple/project/")
	metadataResponse := proxy.Response{
		Request:    proxy.Request{Method: http.MethodGet, URL: *metadataURL},
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}},
	}
	bodyHook, err := handler.ObserveMetadataHeaders(context.Background(), metadataResponse)
	if err != nil || bodyHook == nil {
		t.Fatal("successful Simple response was not observed")
	}
	metadataResponse.Body = []byte(`{"files":[{"filename":"project-1.0-py3-none-any.whl","url":"https://cdn.example/project-1.0-py3-none-any.whl","upload-time":"2025-04-05T06:07:08Z"}]}`)
	if err := bodyHook.Handle(context.Background(), metadataResponse); err != nil {
		t.Fatal(err)
	}
	metadataResponse.StatusCode = http.StatusNotModified
	if bodyHook, err := handler.ObserveMetadataHeaders(context.Background(), metadataResponse); bodyHook != nil || err != nil {
		t.Fatal("metadata 304 unexpectedly replaced the per-run cache")
	}

	artifactURL, _ := url.Parse("https://cdn.example/project-1.0-py3-none-any.whl")
	if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: *artifactURL}); err != nil {
		t.Fatal(err)
	}
	if !gotDate.Equal(wantDate) {
		t.Fatalf("evaluated publish date = %v, want cached exact-file date %v", gotDate, wantDate)
	}
}

func TestProxyPackageEvaluatorFallsBackAfterUncachedMetadata304(t *testing.T) {
	var lookups atomic.Int32
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}),
		nopReporter{}, io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		lookups.Add(1)
		return time.Now(), nil
	}
	metadataURL, _ := url.Parse("https://index.example/simple/project/")
	if bodyHook, err := handler.ObserveMetadataHeaders(context.Background(), proxy.Response{
		Request:    proxy.Request{Method: http.MethodGet, URL: *metadataURL},
		StatusCode: http.StatusNotModified,
	}); bodyHook != nil || err != nil {
		t.Fatal("metadata 304 returned an observer")
	}
	artifactURL, _ := url.Parse("https://cdn.example/project-1.0.tar.gz")
	classifier, err := ecosystem.NewPyPIRequestClassifier(ecosystem.PyPIRequestClassifierOptions{
		DirectArtifactURLs: []string{artifactURL.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.classifier = classifier
	if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: *artifactURL}); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 {
		t.Fatalf("independent publication lookups = %d, want 1", lookups.Load())
	}
}

func TestProxyPackageEvaluatorUsesJSONFallbackForOrdinarySimpleHTML(t *testing.T) {
	var lookups atomic.Int32
	var gotDate time.Time
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			for target := range targets.Items() {
				gotDate = target.PublishDate
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}),
		nopReporter{}, io.Discard,
	)
	wantDate := time.Date(2025, 4, 3, 2, 1, 0, 0, time.UTC)
	handler.resolveDate = func(_ context.Context, packageEcosystem ecosystem.Ecosystem, name, version, source string) (time.Time, error) {
		lookups.Add(1)
		if packageEcosystem != ecosystem.PYPI || name != "project" || version != "1.0" || source != "https://files.pythonhosted.org/project-1.0.tar.gz" {
			t.Fatalf("JSON fallback arguments = %s %s@%s %q", packageEcosystem, name, version, source)
		}
		return wantDate, nil
	}
	metadataURL := mustParseURL(t, "https://pypi.org/simple/project/")
	response := proxy.Response{
		Request:    proxy.Request{Method: http.MethodGet, URL: metadataURL},
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+html"}},
	}
	bodyHook, err := handler.ObserveMetadataHeaders(context.Background(), response)
	if err != nil || bodyHook == nil {
		t.Fatal("ordinary Simple HTML response was not observed")
	}
	response.Body = []byte(`<a href="https://files.pythonhosted.org/project-1.0.tar.gz">project</a>`)
	if err := bodyHook.Handle(context.Background(), response); err != nil {
		t.Fatal(err)
	}
	artifactURL := mustParseURL(t, "https://files.pythonhosted.org/project-1.0.tar.gz")
	if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: artifactURL}); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 || !gotDate.Equal(wantDate) {
		t.Fatalf("fallback lookups=%d evaluated date=%v; want 1, %v", lookups.Load(), gotDate, wantDate)
	}
}

func TestProxyPackageEvaluatorLeavesMetadataAndUnrelatedTrafficAlone(t *testing.T) {
	var calls atomic.Int32
	evaluator := proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		calls.Add(1)
		return evaluation.ScfwPolicyEvaluationReport{}, nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "", evaluator, nopReporter{}, io.Discard)
	for _, rawURL := range []string{
		"https://pypi.org/pypi/requests/json",
		"https://pypi.org/simple/requests/",
		"https://example.test/unrelated.json",
	} {
		requestURL, _ := url.Parse(rawURL)
		if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodGet, URL: *requestURL}); err != nil {
			t.Fatal(err)
		}
	}
	headURL, _ := url.Parse("https://files.pythonhosted.org/packages/requests-2.32.3-py3-none-any.whl")
	if _, err := handler.HandleRequest(context.Background(), proxy.Request{Method: http.MethodHead, URL: *headURL}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("evaluation calls = %d, want 0", calls.Load())
	}
}

func TestProxyPackageEvaluatorClassifiesRangesAndPassesCoreMetadata(t *testing.T) {
	var calls atomic.Int32
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			calls.Add(1)
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeAllow}, nil
		}),
		nopReporter{}, io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Now(), nil
	}
	classifier, err := ecosystem.NewPyPIRequestClassifier(ecosystem.PyPIRequestClassifierOptions{
		SimpleIndexURLs:    []string{"https://index.example/python-packages/"},
		DirectArtifactURLs: []string{"https://index.example/files/project-1.0.tar.lz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.classifier = classifier
	metadataEndpoint := mustParseURL(t, "https://index.example/python-packages/opaque/")

	if err := handler.metadata.Observe(metadataEndpoint, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(`{"files":[{"filename":"opaque-3.0-py3-none-any.whl","url":"/objects/wheel?id=3"}]}`)); err != nil {
		t.Fatal(err)
	}

	requests := []proxy.Request{
		{Method: http.MethodGet, URL: mustParseURL(t, "https://index.example/files/project-1.0.tar.lz"), Header: http.Header{"Range": []string{"bytes=0-1023"}}},
		{Method: http.MethodGet, URL: mustParseURL(t, "https://index.example/files/project-2.0-py3-none-any.whl.metadata")},
		{Method: http.MethodGet, URL: mustParseURL(t, "https://index.example/objects/wheel.metadata?id=3")},
		{Method: http.MethodGet, URL: mustParseURL(t, "https://unrelated.example/report-2026.zip")},
	}
	for _, request := range requests {
		if _, err := handler.HandleRequest(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("evaluation calls = %d, want only the ranged artifact evaluated", calls.Load())
	}
}

func mustParseURL(t *testing.T, value string) url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *parsed
}

func TestPyPIProxyBlocksArtifactBeforeForwardingAndPassesMetadata(t *testing.T) {
	expectedMetadata := `{"meta":{"api-version":"1.4"},"files":[{"filename":"project-1.0-py3-none-any.whl","url":"../../packages/project-1.0-py3-none-any.whl","upload-time":"2025-05-06T07:08:09Z"}]}`
	var upstreamHits, artifactHits, evaluationCalls, reportCalls, lookupCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
		if request.URL.Path == "/simple/project/" {
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, expectedMetadata)
			return
		}
		if strings.HasSuffix(request.URL.Path, ".whl") {
			artifactHits.Add(1)
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer upstream.Close()

	evaluator := proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
		evaluationCalls.Add(1)
		return evaluation.ScfwPolicyEvaluationReport{
			Outcome: evaluation.OutcomeBlock,
			Results: []evaluation.PackageEvaluationResult{{
				Ecosystem: "PyPI", PackageName: "project", PackageVersion: "1.0", Outcome: evaluation.OutcomeBlock,
			}},
		}, nil
	})
	var reportedSource string
	var reportedDate time.Time
	reporter := proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
		reportCalls.Add(1)
		for target := range targets.Items() {
			reportedSource, reportedDate = target.Source, target.PublishDate
		}
		return nil
	})
	handler := newProxyPackageEvaluator(context.Background(), time.Now(), []string{"pip", "install", "project"}, "pip", "pip", "", evaluator, reporter, io.Discard)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		lookupCalls.Add(1)
		return time.Time{}, errors.New("unexpected fallback")
	}
	server, err := proxy.Start(context.Background(), proxy.Options{
		RequestHooks: []proxy.RequestHook{handler.HandleRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	proxyURL, err := url.Parse(server.ClientConfig().URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	metadata, err := client.Get(upstream.URL + "/simple/project/")
	if err != nil {
		t.Fatal(err)
	}
	metadataBody, _ := io.ReadAll(metadata.Body)
	_ = metadata.Body.Close()
	if metadata.StatusCode != http.StatusOK || string(metadataBody) != expectedMetadata {
		t.Fatalf("metadata response = %d %q, want 200 unmodified metadata", metadata.StatusCode, metadataBody)
	}
	unrelated, err := client.Get(upstream.URL + "/unrelated")
	if err != nil {
		t.Fatal(err)
	}
	_ = unrelated.Body.Close()
	if unrelated.StatusCode != http.StatusOK || evaluationCalls.Load() != 0 || reportCalls.Load() != 0 {
		t.Fatalf("unrelated status=%d evaluations=%d reports=%d; want 200, 0, 0", unrelated.StatusCode, evaluationCalls.Load(), reportCalls.Load())
	}

	successfulURL := upstream.URL + "/packages/project-1.0-py3-none-any.whl"
	artifact, err := client.Get(successfulURL)
	if err != nil {
		t.Fatal(err)
	}
	artifactBody, _ := io.ReadAll(artifact.Body)
	_ = artifact.Body.Close()
	if artifact.StatusCode != http.StatusForbidden {
		t.Fatalf("artifact status = %d, want 403", artifact.StatusCode)
	}
	if strings.Contains(string(artifactBody), "artifact") || artifactHits.Load() != 0 {
		t.Fatalf("blocked artifact reached upstream or returned bytes: hits=%d body=%q", artifactHits.Load(), artifactBody)
	}
	if upstreamHits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want only metadata and unrelated traffic", upstreamHits.Load())
	}
	wantDate := time.Date(2025, 5, 6, 7, 8, 9, 0, time.UTC)
	if evaluationCalls.Load() != 1 || reportCalls.Load() != 1 || lookupCalls.Load() != 0 || reportedSource != successfulURL || !reportedDate.Equal(wantDate) {
		t.Fatalf("evaluations=%d reports=%d lookups=%d source=%q date=%v; want 1, 1, 0, %q, %v",
			evaluationCalls.Load(), reportCalls.Load(), lookupCalls.Load(), reportedSource, reportedDate, successfulURL, wantDate)
	}
}

func TestPyPIProxyEvaluatesLegacySdistUsingMetadataProject(t *testing.T) {
	for _, test := range []struct{ format, destination string }{
		{"html", "/catalog/opaque"}, {"json", "/catalog/opaque"},
		{"html", "/simple/alias/"}, {"json", "/simple/alias/"},
	} {
		t.Run(test.format+test.destination, func(t *testing.T) {
			artifactPath := "/files/project-1.0-1.tar.gz"
			if test.format == "json" {
				artifactPath = "/objects/download"
			}
			var hits, evaluations, reports atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/simple/project/":
					http.Redirect(w, request, test.destination, http.StatusFound)
				case test.destination:
					w.Header().Set("Content-Type", "text/html")
					body := `<base href="/files/"><a href="project-1.0-1.tar.gz" data-upload-time="2025-01-02T03:04:05Z">project</a>`
					if test.format == "json" {
						w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
						body = `{"files":[{"filename":"project-1.0-1.tar.gz","url":"/objects/download","upload-time":"2025-01-02T03:04:05Z"}]}`
					}
					_, _ = io.WriteString(w, body)
				case artifactPath:
					hits.Add(1)
					_, _ = io.WriteString(w, "blocked artifact")
				default:
					t.Errorf("unexpected upstream request: %s", request.URL.Path)
					http.NotFound(w, request)
				}
			}))
			defer upstream.Close()
			checkTarget := func(targets *pm.Set[pm.Package]) bool {
				for target := range targets.Items() {
					if target.Name != "project" || target.Version != "1.0.post1" || target.PublishDate.IsZero() {
						t.Errorf("incorrect policy identity: %#v", target)
						return false
					}
				}
				return true
			}
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					evaluations.Add(1)
					outcome := evaluation.OutcomeAllow
					if checkTarget(targets) {
						outcome = evaluation.OutcomeBlock
					}
					return evaluation.ScfwPolicyEvaluationReport{Outcome: outcome}, nil
				}),
				proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
					reports.Add(1)
					checkTarget(targets)
					return nil
				}), io.Discard)
			server, err := proxy.Start(context.Background(), newPyPIProxyController(handler)(context.Background(), httpproxy.Config{}))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for _, request := range []struct {
				path   string
				status int
			}{{"/simple/project/", http.StatusOK}, {artifactPath, http.StatusForbidden}} {
				response, err := client.Get(upstream.URL + request.path)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != request.status {
					t.Fatalf("%s status = %d, want %d", request.path, response.StatusCode, request.status)
				}
			}
			if hits.Load() != 0 || evaluations.Load() != 1 || reports.Load() != 1 {
				t.Fatalf("artifact upstream hits=%d evaluations=%d reports=%d; want 0, 1, 1", hits.Load(), evaluations.Load(), reports.Load())
			}
		})
	}
}

func TestPyPIProxyWarnsBeforeForwardingArtifact(t *testing.T) {
	var evaluated, reported, upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if evaluated.Load() != 1 || reported.Load() != 1 {
			t.Error("artifact reached upstream before evaluation and reporting completed")
		}
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "artifact bytes")
	}))
	defer upstream.Close()

	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluated.Add(1)
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeWarn}, nil
		}),
		proxyReporterFunc(func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error {
			reported.Add(1)
			return nil
		}),
		io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Now(), nil
	}
	classifier, err := ecosystem.NewPyPIRequestClassifier(ecosystem.PyPIRequestClassifierOptions{
		DirectArtifactURLs: []string{upstream.URL + "/project-1.0.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.classifier = classifier
	server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(upstream.URL + "/project-1.0.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "artifact bytes" || upstreamHits.Load() != 1 {
		t.Fatalf("warned artifact response=%d %q upstream hits=%d; want 200, artifact bytes, 1", response.StatusCode, body, upstreamHits.Load())
	}
}

func TestPyPIProxyProcessesStreamingMetadataBeforeExposingLinks(t *testing.T) {
	for _, format := range []string{"html", "json"} {
		for _, knownLength := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/knownLength=%t", format, knownLength), func(t *testing.T) {
				var artifactHits, evaluations, reports atomic.Int32
				cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					artifactHits.Add(1)
					_, _ = io.WriteString(w, "blocked artifact")
				}))
				defer cdn.Close()
				artifactURL := cdn.URL + "/files/project-1.0.tar.gz?token=secret"
				metadataPath := "/simple/project/"
				if format == "json" {
					artifactURL = cdn.URL + "/objects/opaque?token=secret"
					// This endpoint is recognizable only from its response media type.
					metadataPath = "/catalog/project/"
				}
				prefix := fmt.Sprintf(`<html><a href=%q data-upload-time="2025-06-07T08:09:10Z">project-1.0.tar.gz</a>`, artifactURL) + "\n"
				tail := "</html>"
				contentType := "text/html"
				if format == "json" {
					prefix = fmt.Sprintf(`{"files":[{"filename":"project-1.0.tar.gz","url":%q,"upload-time":"2025-06-07T08:09:10Z"}`, artifactURL) + "\n"
					tail, contentType = "]}", "application/vnd.pypi.simple.v1+json"
				}
				// Exceed HTTP write buffers so the old streaming observer exposes
				// the first link while the rest of the listing remains unavailable.
				prefix += strings.Repeat(" ", 64<<10)
				prefixSent, releaseTail := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(releaseTail) }) }
				index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					w.Header().Set("Content-Type", contentType)
					if knownLength {
						w.Header().Set("Content-Length", fmt.Sprint(len(prefix)+len(tail)))
					}
					_, _ = io.WriteString(w, prefix)
					w.(http.Flusher).Flush()
					close(prefixSent)
					select {
					case <-releaseTail:
						_, _ = io.WriteString(w, tail)
					case <-request.Context().Done():
					}
				}))
				defer index.Close()
				defer release()
				handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
					proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
						evaluations.Add(1)
						for target := range targets.Items() {
							if target.Name != "project" || target.Version != "1.0" || target.PublishDate.IsZero() {
								t.Errorf("incomplete metadata at evaluation: %#v", target)
							}
						}
						return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
					}),
					proxyReporterFunc(func(context.Context, time.Time, []string, string, string, string, *pm.Set[pm.Package], evaluation.ScfwPolicyEvaluationReport, evaluation.Outcome) error {
						reports.Add(1)
						return nil
					}), io.Discard)
				server, err := proxy.Start(context.Background(), newPyPIProxyController(handler)(context.Background(), httpproxy.Config{}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = server.Close() })
				proxyURL, _ := url.Parse(server.ClientConfig().URL)
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				result := make(chan error, 1)
				go func() {
					metadata, err := client.Get(index.URL + metadataPath)
					if err != nil {
						result <- err
						return
					}
					defer metadata.Body.Close()
					reader := bufio.NewReader(metadata.Body)
					line, err := reader.ReadString('\n')
					if err != nil || !strings.Contains(line, artifactURL) {
						result <- fmt.Errorf("first metadata line = %q, %v", line, err)
						return
					}
					// Start the download immediately after reading the link, without
					// consuming the remaining metadata response.
					artifact, err := client.Get(artifactURL)
					if err != nil {
						result <- err
						return
					}
					_ = artifact.Body.Close()
					if artifact.StatusCode != http.StatusForbidden {
						result <- fmt.Errorf("artifact status = %d; want 403", artifact.StatusCode)
						return
					}
					rest, err := io.ReadAll(reader)
					if err != nil || line+string(rest) != prefix+tail {
						result <- fmt.Errorf("metadata bytes changed: %v", err)
						return
					}
					result <- nil
				}()
				select {
				case <-prefixSent:
				case <-time.After(5 * time.Second):
					t.Fatal("upstream did not send metadata prefix")
				}
				select {
				case err := <-result:
					t.Fatalf("installer received a link before metadata inspection completed: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				release()
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("installer did not complete")
				}
				if artifactHits.Load() != 0 || evaluations.Load() != 1 || reports.Load() != 1 {
					t.Fatalf("upstream=%d evaluations=%d reports=%d; want 0, 1, 1", artifactHits.Load(), evaluations.Load(), reports.Load())
				}
			})
		}
	}
}

func TestPyPIProxyRejectsUnreadableMetadataBeforeForwarding(t *testing.T) {
	for _, test := range []struct {
		name, encoding, body string
	}{
		{name: "invalid JSON", body: `{"files":[secret`},
		{name: "invalid gzip", encoding: "gzip", body: "secret"},
		{name: "unsupported encoding", encoding: "unsupported", body: "secret"},
	} {
		t.Run(test.name, func(t *testing.T) {
			index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				w.Header().Set("Content-Encoding", test.encoding)
				_, _ = io.WriteString(w, test.body)
			}))
			defer index.Close()
			handler := newProxyPackageEvaluator(context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					t.Error("metadata request evaluated as an artifact")
					return evaluation.ScfwPolicyEvaluationReport{}, nil
				}), nopReporter{}, io.Discard)
			server, err := proxy.Start(context.Background(), newPyPIProxyController(handler)(context.Background(), httpproxy.Config{}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(index.URL + "/simple/project/")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "secret") {
				t.Fatalf("response = %d %q, %v; want 502 without metadata bytes", response.StatusCode, body, err)
			}
		})
	}
}

func TestPyPIProxyBlocksOpaqueAdvertisedArtifactBeforeUpstream(t *testing.T) {
	var artifactHits, lookupCalls atomic.Int32
	// Python HTTP clients decode unreserved percent escapes before requesting
	// the URL advertised by the index.
	metadataBody := `{"files":[{"filename":"project-1.0.tar.gz","url":"/objects/%61bc?token=%73ecret","upload-time":"2025-06-07T08:09:10Z"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/artifactory/api/pypi/repo/simple/project/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, metadataBody)
		case "/objects/abc":
			artifactHits.Add(1)
			_, _ = io.WriteString(w, "blocked bytes")
		default:
			http.NotFound(w, request)
		}
	}))
	defer upstream.Close()

	var reportedDate time.Time
	var reportedSource string
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
			for target := range targets.Items() {
				reportedDate, reportedSource = target.PublishDate, target.Source
			}
			return nil
		}),
		io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		lookupCalls.Add(1)
		return time.Time{}, errors.New("unexpected fallback")
	}
	server, err := proxy.Start(context.Background(), proxy.Options{
		RequestHooks: []proxy.RequestHook{handler.HandleRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	metadata, err := client.Get(upstream.URL + "/artifactory/api/pypi/repo/simple/project/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, metadata.Body)
	_ = metadata.Body.Close()

	artifact, err := client.Get(upstream.URL + "/objects/abc?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	_ = artifact.Body.Close()
	wantDate := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	if artifact.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || lookupCalls.Load() != 0 ||
		!reportedDate.Equal(wantDate) || reportedSource != upstream.URL+"/objects/abc" {
		t.Fatalf("opaque artifact status=%d hits=%d lookups=%d date=%v source=%q; want 403, 0, 0, %v, %q",
			artifact.StatusCode, artifactHits.Load(), lookupCalls.Load(), reportedDate, reportedSource, wantDate, upstream.URL+"/objects/abc")
	}
}

func TestPyPIProxyBlocksAdvertisedAbsoluteUserinfoURL(t *testing.T) {
	var artifactHits, evaluations atomic.Int32
	var observedUserinfoFree atomic.Bool
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		artifactHits.Add(1)
		_, _ = io.WriteString(w, "blocked bytes")
	}))
	defer cdn.Close()
	artifactURL, err := url.Parse(cdn.URL + "/packages/project-1.0-py3-none-any.whl?token=artifact-secret")
	if err != nil {
		t.Fatal(err)
	}
	artifactURL.User = url.UserPassword("artifact-user", "artifact-password")

	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "future-python-manager", "python-manager", "",
		proxyEvaluatorFunc(func(_ context.Context, _ bool, targets *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			for target := range targets.Items() {
				if strings.Contains(target.Source, "artifact-user") || strings.Contains(target.Source, "artifact-password") ||
					strings.Contains(target.Source, "artifact-secret") {
					t.Fatalf("evaluated source exposes credentials: %q", target.Source)
				}
			}
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		nopReporter{}, io.Discard,
	)
	metadataURL := mustParseURL(t, "https://index.example/simple/project/")

	if err := handler.metadata.Observe(metadataURL, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(fmt.Sprintf(`{"files":[{"filename":"project-1.0-py3-none-any.whl","url":%q,"upload-time":"2025-04-04T04:00:00Z"}]}`, artifactURL.String()))); err != nil {
		t.Fatal(err)
	}
	server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{
		func(ctx context.Context, request proxy.Request) (proxy.ResponseHook, error) {
			observedUserinfoFree.Store(request.URL.User == nil)
			return handler.HandleRequest(ctx, request)
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(artifactURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || evaluations.Load() != 1 || !observedUserinfoFree.Load() {
		t.Fatalf("userinfo artifact status=%d hits=%d evaluations=%d userinfo-free=%v; want 403, 0, 1, true",
			response.StatusCode, artifactHits.Load(), evaluations.Load(), observedUserinfoFree.Load())
	}
}

func TestPyPIProxyBlocksOpaqueArtifactWithoutAdvertisedUploadTime(t *testing.T) {
	var upstreamHits, evaluations atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "blocked bytes")
	}))
	defer upstream.Close()
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			evaluations.Add(1)
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		nopReporter{}, io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Time{}, errors.New("upload time unavailable")
	}
	metadataURL, _ := url.Parse(upstream.URL + "/simple/project/")

	if err := handler.metadata.Observe(*metadataURL, http.Header{"Content-Type": []string{"application/vnd.pypi.simple.v1+json"}}, []byte(`{"files":[{"filename":"project-1.0.tar.gz","url":"/download?id=wheel-a&token=secret"}]}`)); err != nil {
		t.Fatal(err)
	}
	server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(upstream.URL + "/download?id=wheel-a&token=secret")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 || evaluations.Load() != 1 {
		t.Fatalf("opaque no-time artifact status=%d upstream hits=%d evaluations=%d; want 403, 0, 1",
			response.StatusCode, upstreamHits.Load(), evaluations.Load())
	}
}

func TestPyPIProxyBlocksArtifactUnderSimplePathBeforeUpstream(t *testing.T) {
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "blocked bytes")
	}))
	defer upstream.Close()
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "pip", "pip", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		nopReporter{}, io.Discard,
	)
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Now(), nil
	}
	classifier, err := ecosystem.NewPyPIRequestClassifier(ecosystem.PyPIRequestClassifierOptions{
		DirectArtifactURLs: []string{upstream.URL + "/simple/files/project-1.0.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler.classifier = classifier
	server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(upstream.URL + "/simple/files/project-1.0.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || upstreamHits.Load() != 0 {
		t.Fatalf("Simple-path artifact status=%d upstream hits=%d; want 403, 0", response.StatusCode, upstreamHits.Load())
	}
}

func TestPyPIProxyRefreshesAuthenticatedArtifactoryMetadataOn304BeforeOpaqueArtifact(t *testing.T) {
	var refreshHits, artifactHits atomic.Int32
	metadataBody := `{"files":[{"filename":"project-2.0-py3-none-any.whl","url":"objects/artifact?id=wheel&token=artifact-secret","upload-time":"2025-07-08T09:10:11Z"}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/artifactory/api/pypi/repo/simple/project/":
			if request.Header.Get("Authorization") != "Bearer auth-secret" ||
				request.Header.Get("Cookie") != "session=cookie-secret" ||
				request.Header.Get("X-Jfrog-Art-Api") != "jfrog-secret" {
				http.Error(w, "missing authentication", http.StatusUnauthorized)
				return
			}
			if request.Header.Get("If-None-Match") != "" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			http.Redirect(w, request, "/redirected/metadata/", http.StatusFound)
		case "/redirected/metadata/":
			if request.Header.Get("Authorization") != "Bearer auth-secret" ||
				request.Header.Get("Cookie") != "session=cookie-secret" ||
				request.Header.Get("X-Jfrog-Art-Api") != "jfrog-secret" {
				http.Error(w, "missing redirected authentication", http.StatusUnauthorized)
				return
			}
			refreshHits.Add(1)
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = io.WriteString(w, metadataBody)
		case "/redirected/metadata/objects/artifact":
			artifactHits.Add(1)
			_, _ = io.WriteString(w, "blocked bytes")
		default:
			http.NotFound(w, request)
		}
	}))
	defer upstream.Close()

	var reportedDate time.Time
	var reportedSource string
	handler := newProxyPackageEvaluator(
		context.Background(), time.Now(), nil, "uv", "uv", "",
		proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
			return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
		}),
		proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
			for target := range targets.Items() {
				reportedDate, reportedSource = target.PublishDate, target.Source
			}
			return nil
		}),
		io.Discard,
	)
	handler.metadataClient = upstream.Client()
	handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
		return time.Time{}, errors.New("unexpected fallback")
	}
	previousLogger := slog.Default()
	var diagnostics bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	server, err := proxy.Start(context.Background(), proxy.Options{
		RequestHooks: []proxy.RequestHook{handler.HandleRequest},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	proxyURL, _ := url.Parse(server.ClientConfig().URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/artifactory/api/pypi/repo/simple/project/?access_token=query-secret", nil)
	request.Header.Set("If-None-Match", `"cached"`)
	request.Header.Set("Authorization", "Bearer auth-secret")
	request.Header.Set("Cookie", "session=cookie-secret")
	request.Header.Set("X-JFrog-Art-Api", "jfrog-secret")
	metadata, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = metadata.Body.Close()
	if metadata.StatusCode != http.StatusNotModified {
		t.Fatalf("metadata status = %d, want 304", metadata.StatusCode)
	}
	artifact, err := client.Get(upstream.URL + "/redirected/metadata/objects/artifact?id=wheel&token=artifact-secret")
	if err != nil {
		t.Fatal(err)
	}
	_ = artifact.Body.Close()
	wantDate := time.Date(2025, 7, 8, 9, 10, 11, 0, time.UTC)
	if artifact.StatusCode != http.StatusForbidden || refreshHits.Load() != 1 || artifactHits.Load() != 0 ||
		!reportedDate.Equal(wantDate) || reportedSource != upstream.URL+"/redirected/metadata/objects/artifact" {
		t.Fatalf("Artifactory artifact status=%d refreshes=%d hits=%d date=%v source=%q; want 403, 1, 0, %v, %q",
			artifact.StatusCode, refreshHits.Load(), artifactHits.Load(), reportedDate, reportedSource, wantDate, upstream.URL+"/redirected/metadata/objects/artifact")
	}
	for _, secret := range []string{"auth-secret", "cookie-secret", "jfrog-secret", "query-secret", "artifact-secret"} {
		if strings.Contains(diagnostics.String(), secret) {
			t.Fatalf("proxy diagnostics expose %q: %s", secret, diagnostics.String())
		}
	}
}

func TestPyPIProxyObservesModernCompressedMetadataWithoutChangingBytes(t *testing.T) {
	for _, encoding := range []string{"br", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			metadataBody := []byte(`{"files":[{"filename":"project-4.0.tar.gz","url":"/objects/` + encoding + `?id=artifact-secret","upload-time":"2025-11-12T13:14:15Z"}]}`)
			compressed := compressPyPIMetadata(t, encoding, metadataBody)
			var artifactHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/simple/project/":
					w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
					w.Header().Set("Content-Encoding", encoding)
					_, _ = w.Write(compressed)
				case "/objects/" + encoding:
					artifactHits.Add(1)
					_, _ = io.WriteString(w, "blocked bytes")
				default:
					http.NotFound(w, request)
				}
			}))
			defer upstream.Close()

			var reportedDate time.Time
			handler := newProxyPackageEvaluator(
				context.Background(), time.Now(), nil, "pip", "pip", "",
				proxyEvaluatorFunc(func(context.Context, bool, *pm.Set[pm.Package]) (evaluation.ScfwPolicyEvaluationReport, error) {
					return evaluation.ScfwPolicyEvaluationReport{Outcome: evaluation.OutcomeBlock}, nil
				}),
				proxyReporterFunc(func(_ context.Context, _ time.Time, _ []string, _, _, _ string, targets *pm.Set[pm.Package], _ evaluation.ScfwPolicyEvaluationReport, _ evaluation.Outcome) error {
					for target := range targets.Items() {
						reportedDate = target.PublishDate
					}
					return nil
				}),
				io.Discard,
			)
			handler.resolveDate = func(context.Context, ecosystem.Ecosystem, string, string, string) (time.Time, error) {
				return time.Time{}, errors.New("unexpected fallback")
			}
			server, err := proxy.Start(context.Background(), proxy.Options{
				RequestHooks: []proxy.RequestHook{handler.HandleRequest},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
			request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/simple/project/", nil)
			request.Header.Set("Accept-Encoding", encoding)
			metadata, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			forwarded, _ := io.ReadAll(metadata.Body)
			_ = metadata.Body.Close()
			if metadata.Header.Get("Content-Encoding") != encoding || !bytes.Equal(forwarded, compressed) {
				t.Fatalf("manager-visible metadata encoding=%q bytes changed=%v", metadata.Header.Get("Content-Encoding"), !bytes.Equal(forwarded, compressed))
			}
			artifact, err := client.Get(upstream.URL + "/objects/" + encoding + "?id=artifact-secret")
			if err != nil {
				t.Fatal(err)
			}
			_ = artifact.Body.Close()
			wantDate := time.Date(2025, 11, 12, 13, 14, 15, 0, time.UTC)
			if artifact.StatusCode != http.StatusForbidden || artifactHits.Load() != 0 || !reportedDate.Equal(wantDate) {
				t.Fatalf("compressed artifact status=%d hits=%d date=%v; want 403, 0, %v", artifact.StatusCode, artifactHits.Load(), reportedDate, wantDate)
			}
		})
	}
}

func compressPyPIMetadata(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	switch encoding {
	case "br":
		writer := brotli.NewWriter(&compressed)
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	case "zstd":
		writer, err := zstd.NewWriter(&compressed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test encoding %q", encoding)
	}
	return compressed.Bytes()
}
