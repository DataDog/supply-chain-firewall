// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/common"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// fakePackumentClient answers every packument request with status and body,
// without network access, recording each request it receives.
type fakePackumentClient struct {
	status   int
	body     string
	hits     atomic.Int32
	mutex    sync.Mutex
	requests []*http.Request
}

func (registry *fakePackumentClient) client() *http.Client {
	return &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		// Like real transports, a canceled request never reaches the registry.
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
		registry.hits.Add(1)
		registry.mutex.Lock()
		registry.requests = append(registry.requests, request)
		registry.mutex.Unlock()
		status := registry.status
		if status == 0 {
			status = http.StatusOK
		}
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(registry.body)),
			Request:    request,
		}, nil
	})}
}

type packageCall struct {
	ctx        context.Context
	pkg        pm.Package
	publishErr error
}

func recordingHook(t *testing.T, runContext context.Context, client *http.Client, result error) (func(context.Context, string) error, func() []packageCall) {
	t.Helper()
	var mutex sync.Mutex
	var calls []packageCall
	hook, err := NewProxyHook(runContext, ProxyHookOptions{
		Client: client,
		EvaluatePackage: func(ctx context.Context, pkg pm.Package, publishErr error) error {
			mutex.Lock()
			defer mutex.Unlock()
			calls = append(calls, packageCall{ctx: ctx, pkg: pkg, publishErr: publishErr})
			return result
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := func(ctx context.Context, rawURL string) error {
		request := getRequest(t, rawURL)
		request.Header.Set("Authorization", "Bearer t0k3n")
		responseHook, err := hook(ctx, request)
		if responseHook != nil {
			t.Fatal("npm hook returned a response hook, want none")
		}
		return err
	}
	return handle, func() []packageCall {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]packageCall(nil), calls...)
	}
}

func TestNewProxyHookResolvesPackageBeforePolicy(t *testing.T) {
	registry := &fakePackumentClient{body: leftPadPackument(t)}
	blocked := errors.New("blocked by policy")
	handle, calls := recordingHook(t, context.Background(), registry.client(), blocked)
	// A canceled request context proves resolution follows the run context.
	requestContext, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()

	if err := handle(requestContext, "https://user:tok@registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz?token=x"); !errors.Is(err, blocked) {
		t.Fatalf("hook error = %v, want the policy's rejection", err)
	}
	got := calls()
	if len(got) != 1 || got[0].ctx != requestContext || got[0].publishErr != nil {
		t.Fatalf("calls = %+v, want one evaluation in the request context without a publication error", got)
	}
	want := pm.Package{Ecosystem: common.NPM, Name: "left-pad", Version: "1.3.0", Source: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", PublishDate: leftPad130Date}
	if got[0].pkg != want {
		t.Fatalf("package = %#v, want %#v", got[0].pkg, want)
	}
	if auth := registry.requests[0].Header.Get("Authorization"); auth != "Bearer t0k3n" {
		t.Fatalf("packument request Authorization = %q, want the tarball request's", auth)
	}
}

func TestNewProxyHookEvaluatesWhenPublicationLookupFails(t *testing.T) {
	registry := &fakePackumentClient{status: http.StatusNotFound}
	handle, calls := recordingHook(t, context.Background(), registry.client(), nil)

	if err := handle(context.Background(), "https://evil.example/left-pad/-/left-pad-1.3.0.tgz"); err != nil {
		t.Fatalf("hook error = %v, want the policy's nil", err)
	}
	got := calls()
	if len(got) != 1 || got[0].publishErr == nil || !got[0].pkg.PublishDate.IsZero() || got[0].pkg.Name != "left-pad" {
		t.Fatalf("calls = %+v, want one evaluation of left-pad carrying the publication failure and no date", got)
	}
}

func TestNewProxyHookPassesRunCancellationToPolicy(t *testing.T) {
	registry := &fakePackumentClient{body: leftPadPackument(t)}
	runContext, cancelRun := context.WithCancel(context.Background())
	cancelRun()
	handle, calls := recordingHook(t, runContext, registry.client(), nil)

	_ = handle(context.Background(), "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
	got := calls()
	if len(got) != 1 || !errors.Is(got[0].publishErr, context.Canceled) {
		t.Fatalf("calls = %+v, want the run cancellation passed to policy", got)
	}
}

func TestNewProxyHookOwnsPublicationsPerInvocation(t *testing.T) {
	registry := &fakePackumentClient{body: leftPadPackument(t)}
	for range 2 {
		handle, _ := recordingHook(t, context.Background(), registry.client(), nil)
		for range 2 {
			if err := handle(context.Background(), "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if hits := registry.hits.Load(); hits != 2 {
		t.Fatalf("packument fetches = %d, want one per hook invocation", hits)
	}
}

func TestNewProxyHookRejectsInvalidConfiguration(t *testing.T) {
	evaluate := func(context.Context, pm.Package, error) error { return nil }
	var noRunContext context.Context
	for name, run := range map[string]func() error{
		"no run context": func() error {
			_, err := NewProxyHook(noRunContext, ProxyHookOptions{EvaluatePackage: evaluate})
			return err
		},
		"no policy callback": func() error {
			_, err := NewProxyHook(context.Background(), ProxyHookOptions{})
			return err
		},
		"invalid registry URL": func() error {
			_, err := NewProxyHook(context.Background(), ProxyHookOptions{EvaluatePackage: evaluate, ClassifierOptions: ClassifierOptions{RegistryURLs: []string{"not a url"}}})
			return err
		},
	} {
		if err := run(); err == nil {
			t.Errorf("%s: NewProxyHook() returned nil error", name)
		}
	}
}

func TestNewProxyHookNeverLogsCredentials(t *testing.T) {
	var logs bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	var mutex sync.Mutex
	var seen []string
	hook, err := NewProxyHook(context.Background(), ProxyHookOptions{
		Client: http.DefaultClient,
		EvaluatePackage: func(_ context.Context, pkg pm.Package, publishErr error) error {
			mutex.Lock()
			defer mutex.Unlock()
			seen = append(seen, pkg.Source, publishErr.Error())
			return errors.New("blocked by policy")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := proxiedClient(t, hook)

	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/left-pad/-/left-pad-1.3.0.tgz?token=secret-query", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer secret-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || len(seen) != 2 {
		t.Fatalf("status = %d, evaluations = %d; want 403 and one evaluation", response.StatusCode, len(seen)/2)
	}
	for name, text := range map[string]string{"logs": logs.String(), "evaluation inputs": strings.Join(seen, " ")} {
		if strings.Contains(text, "secret") {
			t.Fatalf("%s expose credentials: %q", name, text)
		}
	}
}
