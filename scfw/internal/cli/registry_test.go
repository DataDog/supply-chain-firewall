// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

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

func TestPipRegistrationsBindClassifierOptionsToHook(t *testing.T) {
	for _, name := range []string{"pip", "pip3"} {
		t.Run(name, func(t *testing.T) {
			factory, found := findPackageManagerFactory(name)
			if !found || len(factory.ProxyHooks) != 1 {
				t.Fatal("pip registration must provide its ecosystem hook")
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
