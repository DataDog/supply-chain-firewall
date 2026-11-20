// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyRoutesGitThroughGitClient(t *testing.T) {
	for _, version := range []string{"1.22.22", "4.18.1"} {
		t.Run(version, func(t *testing.T) {
			isolateYarnEnvironment(t)
			userProxy := "http://user-git-proxy.test:3128"
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_0", userProxy)
			t.Setenv("GIT_SSL_NO_VERIFY", "1")
			manager := fakeYarn(t, version)
			options, err := manager.ProxyOptions([]string{"install"})
			if err != nil {
				t.Fatal(err)
			}
			route := options.AdditionalClients["git"].RouteForRequest
			if route == nil {
				t.Fatal("yarn must route its Git traffic through a dedicated git client")
			}
			target, _ := url.Parse("https://git.test/repo.git")
			outbound, err := route(proxy.Request{Method: "GET", URL: *target})
			if err != nil {
				t.Fatal(err)
			}
			if outbound.ProxyURL == nil || outbound.ProxyURL.String() != userProxy {
				t.Fatalf("outbound proxy = %v, want the user's http.proxy", outbound.ProxyURL)
			}

			config := testClientConfig(t)
			gitCA := filepath.Join(t.TempDir(), "git-ca.pem")
			config.AdditionalClients = map[string]proxy.ClientConfig{"git": {URL: "http://127.0.0.1:7", CACertificatePath: gitCA}}
			spec, err := manager.ProxyCommand(context.Background(), []string{"install"}, config)
			if err != nil {
				t.Fatal(err)
			}
			var proxies []string
			for key, value := range spec.EnvOverrides {
				if strings.HasPrefix(key, "GIT_CONFIG_KEY_") && value == "http.proxy" {
					proxies = append(proxies, spec.EnvOverrides["GIT_CONFIG_VALUE_"+strings.TrimPrefix(key, "GIT_CONFIG_KEY_")])
				}
			}
			if !slices.Equal(proxies, []string{"http://127.0.0.1:7"}) {
				t.Fatalf("child http.proxy = %q, want only the git client", proxies)
			}
			if spec.EnvOverrides["GIT_SSL_CAINFO"] != gitCA {
				t.Fatalf("GIT_SSL_CAINFO = %q, want the git client CA", spec.EnvOverrides["GIT_SSL_CAINFO"])
			}
			if !slices.Contains(spec.EnvRemovals, "GIT_SSL_NO_VERIFY") {
				t.Fatalf("EnvRemovals = %v, want GIT_SSL_NO_VERIFY", spec.EnvRemovals)
			}
		})
	}
}
