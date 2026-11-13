// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPoetryProcessGitUsesCapturedRoutingWithoutFilePrecedence(t *testing.T) {
	for _, version := range []pm.Version{{Major: 2}, {Major: 2, Minor: 2}, {Major: 2, Minor: 5}} {
		for _, upstream := range []string{"", "http://environment-proxy.example:8080"} {
			t.Run(fmt.Sprintf("%s/upstream=%s", version, upstream), func(t *testing.T) {
				root := isolatedPoetryProject(t)
				path := os.Getenv("GIT_CONFIG_GLOBAL")
				before := poetrySettingsFixture(t, "git-proxy-settings.conf", path)
				t.Setenv("https_proxy", upstream)
				ssl := poetryInvocationConfig(t)
				pem, err := os.ReadFile(ssl.CACertificatePath)
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("SSL_CERT_FILE", ssl.CACertificatePath)
				manager := Poetry{version: version}
				options, err := manager.ProxyOptions([]string{"-C", root, "install"})
				if err != nil {
					t.Fatal(err)
				}
				target, _ := url.Parse("https://git.example/repo/info/refs?service=git-upload-pack")
				request := proxy.Request{URL: *target, Header: http.Header{"User-Agent": {"git/dulwich/0.22.8"}}}
				route, err := options.RouteForRequest(request)
				if err != nil {
					t.Fatal(err)
				}
				if (upstream == "" && route.ProxyURL != nil) || (upstream != "" && (route.ProxyURL == nil || route.ProxyURL.String() != upstream)) {
					t.Fatalf("process client used Git-file routing: %v", route.ProxyURL)
				}
				if route.TLS.InsecureSkipVerify || !route.TLS.RootCAs.Equal(configPool(t, pem)) {
					t.Fatal("Git-file verification overrode explicit SSL trust")
				}
				again, err := options.RouteForRequest(request)
				if err != nil || again != route {
					t.Fatalf("process route did not reuse its connection pool: %v", err)
				}
				preserved := false
				for name, client := range options.AdditionalClients {
					if name == poetryNativeGitClient {
						continue
					}
					native, err := client.RouteForRequest(request)
					if err != nil {
						t.Fatal(err)
					}
					if native.ProxyURL != nil && native.ProxyURL.Host == "file-proxy.example:8080" && native.TLS.InsecureSkipVerify {
						preserved = true
					}
				}
				if !preserved {
					t.Fatal("native Git lost its configured routing/TLS profile")
				}
				after, err := os.ReadFile(path)
				if err != nil || string(after) != string(before) {
					t.Fatal("Git configuration changed")
				}
			})
		}
	}
}
