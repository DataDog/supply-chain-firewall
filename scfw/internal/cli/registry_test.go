// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	npmregistry "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type classifierOptionsManager struct {
	fakePackageManager
	options pypi.RequestClassifierOptions
	command []string
	err     error
}

func (m *classifierOptionsManager) PyPIClassifierOptions(command []string) (pypi.RequestClassifierOptions, error) {
	m.command = slices.Clone(command)
	return m.options, m.err
}

type npmClassifierOptionsManager struct {
	fakePackageManager
	options npmregistry.ClassifierOptions
	command []string
	err     error
}

func (m *npmClassifierOptionsManager) NpmClassifierOptions(command []string) (npmregistry.ClassifierOptions, error) {
	m.command = slices.Clone(command)
	return m.options, m.err
}

func TestNpmRegistrationsBindClassifierOptionsToHook(t *testing.T) {
	factory, found := findPackageManagerFactory("npm")
	if !found || len(factory.ProxyHooks) != 1 {
		t.Fatal("npm registration must provide its ecosystem hook")
	}
	var packuments atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/npm/repo/lab-pkg" {
			http.NotFound(w, r)
			return
		}
		packuments.Add(1)
		_, _ = io.WriteString(w, readProxyJSONFixture(t, "npm/packument"))
	}))
	defer registry.Close()
	base := registry.URL + "/api/npm/repo/"
	manager := &npmClassifierOptionsManager{options: npmregistry.ClassifierOptions{RegistryURLs: []string{base}}}
	command := []string{"install", "lab-pkg"}
	tarball := base + "lab-pkg/-/lab-pkg-1.0.0.tgz"
	refusal := errors.New("blocked by policy")
	calls := 0
	hook, err := factory.ProxyHooks[0](context.Background(), manager, command, registry.Client(), func(_ context.Context, pkg pm.Package, publicationErr error) error {
		calls++
		if publicationErr != nil || pkg.Source != tarball || pkg.Name != "lab-pkg" || pkg.Version != "1.0.0" || pkg.PublishDate != time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) {
			t.Errorf("unexpected resolved package/error: %#v/%v", pkg, publicationErr)
		}
		return refusal
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(manager.command, command) {
		t.Fatalf("classifier command=%v, want %v", manager.command, command)
	}
	if _, err := hook(context.Background(), proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, tarball)}); !errors.Is(err, refusal) {
		t.Fatalf("hook error=%v, want the evaluation refusal", err)
	}
	if calls != 1 || packuments.Load() != 1 {
		t.Fatalf("evaluations=%d packuments=%d, want 1 each", calls, packuments.Load())
	}
	failure := errors.New("invalid npm settings")
	manager.err = failure
	if _, err := factory.ProxyHooks[0](context.Background(), manager, command, nil, func(context.Context, pm.Package, error) error { return nil }); !errors.Is(err, failure) {
		t.Fatalf("setup error=%v, want settings error", err)
	}
}

func TestYarnRegistrationsBindClassifierOptionsToHook(t *testing.T) {
	factory, found := findPackageManagerFactory("yarn")
	if !found || len(factory.ProxyHooks) != 1 {
		t.Fatal("yarn registration must provide its ecosystem hook")
	}
	var packuments atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/npm/repo/lab-pkg" {
			http.NotFound(w, r)
			return
		}
		packuments.Add(1)
		_, _ = io.WriteString(w, readProxyJSONFixture(t, "npm/packument"))
	}))
	defer registry.Close()
	base := registry.URL + "/api/npm/repo/"
	manager := &npmClassifierOptionsManager{options: npmregistry.ClassifierOptions{RegistryURLs: []string{base}}}
	command := []string{"add", "lab-pkg"}
	tarball := base + "lab-pkg/-/lab-pkg-1.0.0.tgz"
	refusal := errors.New("blocked by policy")
	calls := 0
	hook, err := factory.ProxyHooks[0](context.Background(), manager, command, registry.Client(), func(_ context.Context, pkg pm.Package, publicationErr error) error {
		calls++
		if publicationErr != nil || pkg.Source != tarball || pkg.Name != "lab-pkg" || pkg.Version != "1.0.0" || pkg.PublishDate != time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) {
			t.Errorf("unexpected resolved package/error: %#v/%v", pkg, publicationErr)
		}
		return refusal
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(manager.command, command) {
		t.Fatalf("classifier command=%v, want %v", manager.command, command)
	}
	if _, err := hook(context.Background(), proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, tarball)}); !errors.Is(err, refusal) {
		t.Fatalf("hook error=%v, want the evaluation refusal", err)
	}
	if calls != 1 || packuments.Load() != 1 {
		t.Fatalf("evaluations=%d packuments=%d, want 1 each", calls, packuments.Load())
	}
	failure := errors.New("invalid yarn settings")
	manager.err = failure
	if _, err := factory.ProxyHooks[0](context.Background(), manager, command, nil, func(context.Context, pm.Package, error) error { return nil }); !errors.Is(err, failure) {
		t.Fatalf("setup error=%v, want settings error", err)
	}
}

func TestPnpmRegistrationsBindClassifierOptionsToHook(t *testing.T) {
	for _, name := range []string{"pnpm", "pnpx", "pn", "pnx"} {
		t.Run(name, func(t *testing.T) {
			factory, found := findPackageManagerFactory(name)
			if !found || len(factory.ProxyHooks) != 1 {
				t.Fatalf("%s registration must provide its ecosystem hook", name)
			}
			var packuments atomic.Int32
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/npm/repo/lab-pkg" {
					http.NotFound(w, r)
					return
				}
				packuments.Add(1)
				_, _ = io.WriteString(w, readProxyJSONFixture(t, "npm/packument"))
			}))
			defer registry.Close()
			base := registry.URL + "/api/npm/repo/"
			manager := &npmClassifierOptionsManager{options: npmregistry.ClassifierOptions{RegistryURLs: []string{base}}}
			command := []string{"add", "lab-pkg"}
			tarball := base + "lab-pkg/-/lab-pkg-1.0.0.tgz"
			refusal := errors.New("blocked by policy")
			calls := 0
			hook, err := factory.ProxyHooks[0](context.Background(), manager, command, registry.Client(), func(_ context.Context, pkg pm.Package, publicationErr error) error {
				calls++
				if publicationErr != nil || pkg.Source != tarball || pkg.Name != "lab-pkg" || pkg.Version != "1.0.0" || pkg.PublishDate != time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) {
					t.Errorf("unexpected resolved package/error: %#v/%v", pkg, publicationErr)
				}
				return refusal
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(manager.command, command) {
				t.Fatalf("classifier command=%v, want %v", manager.command, command)
			}
			if _, err := hook(context.Background(), proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, tarball)}); !errors.Is(err, refusal) {
				t.Fatalf("hook error=%v, want the evaluation refusal", err)
			}
			if calls != 1 || packuments.Load() != 1 {
				t.Fatalf("evaluations=%d packuments=%d, want 1 each", calls, packuments.Load())
			}
			failure := errors.New("invalid pnpm settings")
			manager.err = failure
			if _, err := factory.ProxyHooks[0](context.Background(), manager, command, nil, func(context.Context, pm.Package, error) error { return nil }); !errors.Is(err, failure) {
				t.Fatalf("setup error=%v, want settings error", err)
			}
		})
	}
}

func TestPyPIRegistrationsBindClassifierOptionsToHook(t *testing.T) {
	for _, name := range []string{"pip", "pip3", "poetry"} {
		t.Run(name, func(t *testing.T) {
			factory, found := findPackageManagerFactory(name)
			if !found || len(factory.ProxyHooks) != 1 {
				t.Fatal("PyPI registration must provide its ecosystem hook")
			}
			manager := &classifierOptionsManager{options: pypi.RequestClassifierOptions{SimpleIndexURLs: []string{"https://index.example/python-packages/"}}}
			command := []string{"install", "project"}
			calls := 0
			hook, err := factory.ProxyHooks[0](context.Background(), manager, command, nil, func(_ context.Context, pkg pm.Package, publicationErr error) error {
				calls++
				if publicationErr != nil || pkg.Source != "https://index.example/objects/opaque" || pkg.Name != "project" || pkg.Version != "1.0" || pkg.PublishDate != time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC) {
					t.Errorf("unexpected resolved package/error: %#v/%v", pkg, publicationErr)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(manager.command, command) {
				t.Fatalf("classifier command=%v, want %v", manager.command, command)
			}
			request := proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, "https://index.example/python-packages/project/")}
			responseHook, err := hook(context.Background(), request)
			if err != nil || responseHook == nil {
				t.Fatalf("metadata hook=%v error=%v", responseHook != nil, err)
			}
			response := proxy.Response{Request: request, StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/vnd.pypi.simple.v1+json"}}, Body: []byte(readProxyJSONFixture(t, "pypi/opaque-sdist"))}
			bodyHook, err := responseHook(context.Background(), response)
			if err != nil || bodyHook == nil {
				t.Fatalf("body hook=%v error=%v", bodyHook != nil, err)
			}
			if err := bodyHook.Handle(context.Background(), response); err != nil {
				t.Fatal(err)
			}
			if _, err := hook(context.Background(), proxy.Request{Method: http.MethodGet, URL: mustParseURL(t, "https://index.example/objects/opaque")}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("evaluations=%d, want 1", calls)
			}
			failure := errors.New("invalid pip settings")
			manager.err = failure
			if _, err := factory.ProxyHooks[0](context.Background(), manager, command, nil, nil); !errors.Is(err, failure) {
				t.Fatalf("setup error=%v, want settings error", err)
			}
		})
	}
}
