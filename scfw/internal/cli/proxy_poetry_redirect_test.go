// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPoetryRedirectPreservesSourceTLS(t *testing.T) {
	manager := poetryForProxyTest(t)
	wheel := pypiWheel(t)
	for _, mutual := range []bool{false, true} {
		t.Run(fmt.Sprintf("mutual=%t", mutual), func(t *testing.T) {
			identity, ca, pem := proxyTLSIdentity(t)
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(ca)
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}}
			if mutual {
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				tlsConfig.ClientCAs = roots
			}
			var downloads atomic.Int32
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mutual && !bytes.Equal(r.TLS.PeerCertificates[0].Raw, identity.Certificate[0]) {
					t.Error("original client identity was replaced")
				}
				if r.Header.Get("Authorization") != "" {
					t.Error("credentials survived cross-origin redirect")
				}
				downloads.Add(1)
				_, _ = w.Write(wheel)
			}))
			target.TLS = tlsConfig.Clone()
			target.StartTLS()
			target.URL = strings.Replace(target.URL, "127.0.0.1", "localhost", 1)
			defer target.Close()
			var proxyHits atomic.Int32
			upstream := proxyTestUpstream(t, upstreamProxyOptions{credentials: "proxy:proxy-secret", hits: &proxyHits})
			t.Setenv("https_proxy", strings.Replace(upstream.URL, "://", "://proxy:proxy-secret@", 1))
			t.Setenv("no_proxy", strings.TrimPrefix(target.URL, "https://"))
			source := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
			}))
			source.TLS = tlsConfig.Clone()
			source.StartTLS()
			source.URL = strings.Replace(source.URL, "127.0.0.1", "localhost", 1)
			defer source.Close()
			verify, client := "false", `""`
			if mutual {
				verify = strconv.Quote(writeProxyTLSFile(t, ca))
				client = strconv.Quote(writeProxyTLSFile(t, pem))
			}
			configuration := fmt.Sprintf(readProxyFixture(t, "poetry/redirect-tls.toml.tmpl"), strconv.Quote(source.URL), verify, client)
			config := t.TempDir()
			path := filepath.Join(config, "config.toml")
			poetryTestFile(t, path, configuration)
			t.Setenv("POETRY_CONFIG_DIR", config)
			for _, proxied := range []bool{false, true} {
				root := t.TempDir()
				t.Setenv("POETRY_CACHE_DIR", filepath.Join(root, "cache"))
				poetryTestFile(t, filepath.Join(root, "pyproject.toml"), readProxyFixture(t, "poetry/git-pyproject.toml"))
				args := []string{"--directory", root, "--no-interaction", "add", "--lock", source.URL + "/project-1.0-py3-none-any.whl"}
				before := downloads.Load()
				beforeProxy := proxyHits.Load()
				if proxied {
					runner := &capturingPoetryRunner{Poetry: manager}
					commandErr, setupErr := runThroughProxy(context.Background(), runner, args, nil)
					if commandErr != nil || setupErr != nil {
						t.Fatalf("proxied Poetry: %v / %v", commandErr, setupErr)
					}
					assertProxyCleaned(t, runner.config)
				} else if err := manager.RunCommand(context.Background(), args); err != nil {
					t.Fatalf("direct Poetry: %v", err)
				}
				if downloads.Load() == before {
					t.Fatal("redirect test was served from cache")
				}
				if proxyHits.Load()-beforeProxy < 2 {
					t.Fatal("redirect did not retain the initiating proxy mapping")
				}
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != configuration {
				t.Fatal("redirect handling modified configuration")
			}
		})
	}
}
