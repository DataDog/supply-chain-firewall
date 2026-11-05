// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileResponseInspectionLifecycle(t *testing.T) {
	payload := readProxyFixture(t, "package.json")
	for _, mode := range []string{"allow", "reject", "failure", "oversized", "chunked oversized", "truncated", "both handlers"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			limit, length := int64(len(payload)), int64(len(payload))
			switch mode {
			case "oversized", "chunked oversized":
				limit--
			case "truncated":
				length++
			}
			if mode == "chunked oversized" {
				length = -1
			}
			response := &http.Response{StatusCode: http.StatusOK, ContentLength: length,
				Header: http.Header{"X-Original": {"yes"}}, Body: io.NopCloser(strings.NewReader(payload))}
			defer response.Body.Close()
			requestURL, _ := url.Parse("https://user:credential-secret@registry.example/download?token=credential-secret")
			request := Request{Method: http.MethodGet, URL: *requestURL}
			calls := 0
			hook := &ResponseBodyHook{MaxBytes: limit, HandleFile: func(_ context.Context, snapshot Response, body *io.SectionReader) error {
				calls++
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 1 {
					t.Fatalf("temporary files=%v error=%v", entries, err)
				}
				info, err := os.Stat(filepath.Join(directory, entries[0].Name()))
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("temporary file mode: %v %v", info, err)
				}
				data, err := io.ReadAll(body)
				if err != nil || string(data) != payload || body.Size() != int64(len(payload)) || snapshot.Body != nil {
					t.Fatalf("file contents=%q error=%v", data, err)
				}
				snapshot.Header.Set("X-Original", "changed")
				if mode == "reject" {
					return errors.Join(ErrResponseRejected, errors.New("credential-secret"))
				}
				if mode == "failure" {
					return errors.New("credential-secret")
				}
				return nil
			}}
			if mode == "both handlers" {
				hook.Handle = func(context.Context, Response) error { return nil }
			}
			hooks := []ResponseHook{func(context.Context, Response) (*ResponseBodyHook, error) { return hook, nil }}
			// A memory observer must receive its own copy even when another hook
			// opts into a file, and it cannot alter the replayed upstream bytes.
			if mode == "allow" {
				hooks = append(hooks, func(context.Context, Response) (*ResponseBodyHook, error) {
					return &ResponseBodyHook{MaxBytes: limit, Handle: func(_ context.Context, snapshot Response) error {
						if string(snapshot.Body) != payload {
							t.Error("mixed body observers did not receive the complete response")
						}
						snapshot.Body[0] = '!'
						return nil
					}}, nil
				})
			}
			err := runResponseHooks(context.Background(), request, response, hooks, directory)
			if mode == "allow" {
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				if err != nil || string(data) != payload || response.Header.Get("X-Original") != "yes" {
					t.Fatalf("replay=%q headers=%v error=%v", data, response.Header, err)
				}
			} else if err == nil {
				t.Fatal("inspection failure was accepted")
			}
			if mode == "reject" && !errors.Is(err, ErrResponseRejected) {
				t.Fatalf("policy rejection lost: %v", err)
			}
			if mode != "allow" && mode != "reject" && mode != "failure" && calls != 0 {
				t.Fatal("incomplete or oversized response reached the callback")
			}
			_ = response.Body.Close()
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Fatalf("temporary files leaked: %v %v", entries, err)
			}
		})
	}
}

func TestFilePolicyDecisionPrecedesForwarding(t *testing.T) {
	payload := readProxyFixture(t, "package.json")
	for _, useTLS := range []bool{false, true} {
		t.Run(fmt.Sprint(useTLS), func(t *testing.T) {
			registryURL, options := newTestRegistry(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, payload)
			}), useTLS)
			started, release := make(chan struct{}), make(chan struct{})
			options.RequestHooks = []RequestHook{func(context.Context, Request) (ResponseHook, error) {
				return func(context.Context, Response) (*ResponseBodyHook, error) {
					return &ResponseBodyHook{MaxBytes: 1024, HandleFile: func(ctx context.Context, _ Response, _ *io.SectionReader) error {
						close(started)
						select {
						case <-release:
							return errors.Join(ErrResponseRejected, errors.New("credential-secret"))
						case <-ctx.Done():
							return ctx.Err()
						}
					}}, nil
				}, nil
			}}
			server := startTestProxy(t, options)
			client := newProxyClient(t, server)
			finished := make(chan *http.Response, 1)
			go func() {
				response, err := client.Get(registryURL)
				if err != nil {
					t.Error(err)
				}
				finished <- response
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("file inspection did not start")
			}
			select {
			case response := <-finished:
				if response != nil {
					_ = response.Body.Close()
				}
				t.Fatal("response was forwarded before the policy decision")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			response := <-finished
			if response == nil {
				t.Fatal("missing rejection response")
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != http.StatusForbidden || strings.Contains(string(body), "credential-secret") || strings.Contains(string(body), payload) {
				t.Fatalf("rejection=%d %q", response.StatusCode, body)
			}
		})
	}
}

func TestInspectReaderAlwaysRemovesTemporaryFiles(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	payload := readProxyFixture(t, "package.json")
	for _, mode := range []string{"allow", "failure", "limit", "canceled"} {
		ctx, cancel := context.WithCancel(context.Background())
		if mode == "canceled" {
			cancel()
		}
		limit := int64(len(payload))
		if mode == "limit" {
			limit--
		}
		err := InspectReader(ctx, strings.NewReader(payload), limit, func(body *io.SectionReader) error {
			data, err := io.ReadAll(body)
			if err != nil || string(data) != payload {
				t.Fatalf("inspection=%q error=%v", data, err)
			}
			if mode == "failure" {
				return errors.New("inspection failed")
			}
			return nil
		})
		cancel()
		if (err == nil) != (mode == "allow") {
			t.Fatalf("%s: %v", mode, err)
		}
		if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
			t.Fatalf("%s leaked files: %v %v", mode, entries, err)
		}
	}
}

func TestCancelDuringFileBufferingRemovesTemporaryFiles(t *testing.T) {
	started, upstreamCanceled := make(chan struct{}), make(chan struct{})
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		close(started)
		<-request.Context().Done()
		close(upstreamCanceled)
	}))
	defer registry.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, registry.URL, nil)
	response, err := registry.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	directory := t.TempDir()
	finished := make(chan error, 1)
	go func() {
		hook := func(context.Context, Response) (*ResponseBodyHook, error) {
			return &ResponseBodyHook{MaxBytes: 1024, HandleFile: func(context.Context, Response, *io.SectionReader) error {
				t.Error("incomplete response reached the callback")
				return nil
			}}, nil
		}
		finished <- runResponseHooks(ctx, Request{Method: http.MethodGet, URL: *request.URL}, response, []ResponseHook{hook}, directory)
	}()
	<-started
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled response inspection succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt file buffering")
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not canceled")
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("cancellation leaked temporary files: %v %v", entries, err)
	}
}
