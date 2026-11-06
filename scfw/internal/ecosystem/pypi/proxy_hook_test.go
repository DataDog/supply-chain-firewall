// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func testProxyHook(t *testing.T) *proxyHook {
	t.Helper()
	handler, err := newProxyHook(context.Background(), ProxyHookOptions{
		EvaluatePackage: func(context.Context, pm.Package, error) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func mustParseHookURL(t *testing.T, raw string) url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return *parsed
}

func TestPyPIControllerTracksOnlyMetadataRedirects(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusOK, http.StatusNotModified,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			handler := testProxyHook(t)
			source := mustParseHookURL(t, "https://index.example/simple/project/")
			target := mustParseHookURL(t, "https://index.example/catalog/opaque/")
			handler.ObserveMetadataHeaders(context.Background(), proxy.Response{
				Request: proxy.Request{Method: http.MethodGet, URL: source}, StatusCode: status,
				Header: http.Header{"Location": []string{"/catalog/opaque/"}},
			})
			_, _, found := handler.Metadata.ProjectForURL(&target)
			if want := status >= 300 && status != http.StatusNotModified; found != want {
				t.Fatalf("redirect registered = %t, want %t", found, want)
			}
		})
	}
	handler := testProxyHook(t)
	source := mustParseHookURL(t, "https://index.example/unrelated/")
	target := mustParseHookURL(t, "https://index.example/catalog/opaque/")
	handler.ObserveMetadataHeaders(context.Background(), proxy.Response{
		Request: proxy.Request{Method: http.MethodGet, URL: source}, StatusCode: http.StatusFound,
		Header: http.Header{"Location": []string{target.String()}},
	})
	if _, _, found := handler.Metadata.ProjectForURL(&target); found {
		t.Fatal("redirect from an unrelated endpoint registered a Simple project")
	}
}

func TestPyPIProxyStreamsHTMLWithoutWaitingForTheCompleteBody(t *testing.T) {
	streamingPrefixFixture := readPyPIFixture(t, "metadata/streaming-prefix.html")
	streamingTailFixture := readPyPIFixture(t, "metadata/streaming-tail.html")
	for _, contentType := range []string{"text/html", "application/vnd.pypi.simple.v1+html"} {
		t.Run(contentType, func(t *testing.T) {
			prefix := streamingPrefixFixture
			tail := streamingTailFixture
			// Exceed ordinary HTTP write buffers without completing the page.
			padding := strings.Repeat(" ", 64<<10)
			releaseTail := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(releaseTail) }) }
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				_, _ = io.WriteString(w, prefix+padding)
				w.(http.Flusher).Flush()
				select {
				case <-releaseTail:
					_, _ = io.WriteString(w, tail)
				case <-r.Context().Done():
				}
			}))
			defer upstream.Close()
			defer release()
			var evaluations atomic.Int32
			handler := testProxyHook(t)
			handler.EvaluateArtifact = func(context.Context, Artifact) error { evaluations.Add(1); return nil }
			server, err := proxy.Start(context.Background(), proxy.Options{RequestHooks: []proxy.RequestHook{handler.HandleRequest}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			proxyURL, _ := url.Parse(server.ClientConfig().URL)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			prefixRead := make(chan error, 1)
			result := make(chan error, 1)
			go func() {
				response, err := client.Get(upstream.URL + "/simple/project/")
				if err != nil {
					prefixRead <- err
					result <- err
					return
				}
				defer response.Body.Close()
				got := make([]byte, len(prefix))
				_, err = io.ReadFull(response.Body, got)
				if err == nil && string(got) != prefix {
					err = fmt.Errorf("HTML prefix changed: %q", got)
				}
				prefixRead <- err
				if err != nil {
					result <- err
					return
				}
				rest, err := io.ReadAll(response.Body)
				if err == nil && string(rest) != padding+tail {
					err = fmt.Errorf("HTML tail changed: %q", rest)
				}
				result <- err
			}()
			select {
			case err := <-prefixRead:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("HTML was buffered before forwarding")
			}
			target := mustParseHookURL(t, upstream.URL+"/files/project-1.0.tar.gz")
			if _, found := handler.Metadata.ArtifactForURL(&target); found || evaluations.Load() != 0 {
				t.Fatal("HTML links or dates were consumed as package metadata")
			}
			release()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("HTML stream did not finish")
			}
			if _, found := handler.Metadata.ArtifactForURL(&target); found || evaluations.Load() != 0 {
				t.Fatal("completed HTML response populated package metadata")
			}
		})
	}
}

func TestNewProxyHookResolvesPackageBeforePolicy(t *testing.T) {
	publicationErr := errors.New("registry unavailable")
	date := time.Date(2025, 3, 4, 5, 6, 7, 8, time.FixedZone("registry", 3600))
	for _, failure := range []error{nil, publicationErr, context.Canceled} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			runContext, cancelRun := context.WithCancel(context.Background())
			defer cancelRun()
			requestContext, cancelRequest := context.WithCancel(context.Background())
			cancelRequest()
			blocked := errors.New("blocked by policy")
			lookups, evaluations := 0, 0
			hook, err := NewProxyHook(runContext, ProxyHookOptions{
				ResolvePublishDate: func(ctx context.Context, name, version, source string) (time.Time, error) {
					lookups++
					if ctx != runContext || ctx.Err() != nil {
						t.Error("publication resolution did not use the live run context")
					}
					if name != "my-project" || version != "1.0" || source != "https://files.pythonhosted.org/packages/my_project-1.0-py3-none-any.whl" {
						t.Errorf("unexpected artifact identity: %s %s %s", name, version, source)
					}
					return date, failure
				},
				EvaluatePackage: func(ctx context.Context, pkg pm.Package, publishErr error) error {
					evaluations++
					if ctx != requestContext || !errors.Is(publishErr, failure) {
						t.Errorf("callback context/error = %v/%v, want request context/%v", ctx, publishErr, failure)
					}
					wantDate := date.UTC()
					if failure != nil {
						wantDate = time.Time{}
					}
					want := pm.Package{Ecosystem: common.PYPI, Name: "my-project", Version: "1.0", Source: "https://files.pythonhosted.org/packages/my_project-1.0-py3-none-any.whl", PublishDate: wantDate}
					if pkg != want {
						t.Errorf("package = %#v, want %#v", pkg, want)
					}
					return blocked
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := proxy.Request{Method: http.MethodGet, URL: mustParseHookURL(t, "https://user:password@files.pythonhosted.org/packages/my_project-1.0-py3-none-any.whl?token=secret#sha256=abc")}
			for range 2 {
				responseHook, err := hook(requestContext, request)
				if responseHook != nil || !errors.Is(err, blocked) {
					t.Fatalf("hook = %v, error = %v; want policy rejection", responseHook != nil, err)
				}
			}
			if lookups != 2 || evaluations != 2 {
				t.Fatalf("lookups/evaluations = %d/%d; each request must resolve before policy", lookups, evaluations)
			}
		})
	}
}

func TestNewProxyHookOwnsMetadataPerInvocation(t *testing.T) {
	var packages []pm.Package
	options := ProxyHookOptions{
		ClassifierOptions: RequestClassifierOptions{SimpleIndexURLs: []string{"https://index.example/python-packages/"}},
		EvaluatePackage: func(_ context.Context, pkg pm.Package, publicationErr error) error {
			if publicationErr != nil {
				t.Fatal(publicationErr)
			}
			packages = append(packages, pkg)
			return nil
		},
	}
	first, err := NewProxyHook(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProxyHook(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	// Later caller changes cannot change an existing invocation's classifier.
	options.ClassifierOptions.SimpleIndexURLs[0] = "https://other.example/simple/"
	request := proxy.Request{Method: http.MethodGet, URL: mustParseHookURL(t, "https://index.example/python-packages/project/")}
	responseHook, err := first(context.Background(), request)
	if err != nil || responseHook == nil {
		t.Fatalf("metadata hook=%v error=%v", responseHook != nil, err)
	}
	response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}}, Body: []byte(readPyPIJSONFixture(t, "metadata/primary-source"))}
	bodyHook, err := responseHook(context.Background(), response)
	if err != nil || bodyHook == nil {
		t.Fatalf("body hook=%v error=%v", bodyHook != nil, err)
	}
	if err := bodyHook.Handle(context.Background(), response); err != nil {
		t.Fatal(err)
	}
	artifact := proxy.Request{Method: http.MethodGet, URL: mustParseHookURL(t, "https://index.example/objects/primary?token=secret")}
	if _, err := first(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	want := pm.Package{Ecosystem: common.PYPI, Name: "project", Version: "1.0", Source: "https://index.example/objects/primary", PublishDate: time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)}
	if len(packages) != 1 || packages[0] != want {
		t.Fatalf("observed packages = %#v, want %#v", packages, want)
	}
	if _, err := second(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	if len(packages) != 1 {
		t.Fatal("metadata from the first invocation leaked into the second")
	}
}

func TestNewProxyHookUsesSuppliedClientForPublicationFallback(t *testing.T) {
	requests := 0
	date := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	client := &http.Client{Transport: hookTransportFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.String() != "https://pypi.org/pypi/project/json" {
			t.Errorf("unexpected registry request: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(readPyPIJSONFixture(t, "releases/sdist")))}, nil
	})}
	evaluations := 0
	hook, err := NewProxyHook(context.Background(), ProxyHookOptions{
		Client: client,
		EvaluatePackage: func(_ context.Context, pkg pm.Package, publicationErr error) error {
			evaluations++
			if publicationErr != nil || pkg.PublishDate != date {
				t.Errorf("date=%v error=%v, want %v, nil", pkg.PublishDate, publicationErr, date)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hook(context.Background(), proxy.Request{Method: http.MethodGet, URL: mustParseHookURL(t, "https://files.pythonhosted.org/project-1.0.tar.gz")}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || evaluations != 1 {
		t.Fatalf("registry requests/evaluations = %d/%d, want 1/1", requests, evaluations)
	}
}

type hookTransportFunc func(*http.Request) (*http.Response, error)

func (f hookTransportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestNewProxyHookRejectsInvalidConfiguration(t *testing.T) {
	for _, options := range []ProxyHookOptions{
		{},
		{EvaluatePackage: func(context.Context, pm.Package, error) error { return nil }, ClassifierOptions: RequestClassifierOptions{SimpleIndexURLs: []string{"relative-index"}}},
	} {
		if hook, err := NewProxyHook(context.Background(), options); err == nil || hook != nil {
			t.Fatal("invalid hook configuration was accepted")
		}
	}
}
