// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestGitRemoteProxyMatchesNativeCommandContext(t *testing.T) {
	for _, test := range []struct {
		name, remote  string
		clone, direct bool
	}{
		{name: "raw fetch"}, {name: "raw ls-remote"}, {name: "clone origin", remote: "origin", clone: true},
		{name: "named fetch", remote: "origin"}, {name: "custom clone name", remote: "upstream", clone: true},
		{name: "quoted remote name", remote: "up'$(false)", clone: true}, {name: "explicit direct", remote: "origin", clone: true, direct: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := gitNetworkEnvironment(t)
			var originHits, httpHits atomic.Int32
			originProxy := countingGitProxy(t, &originHits)
			httpProxy := countingGitProxy(t, &httpHits)
			var destinationHits atomic.Int32
			destination := countingGitProxy(t, &destinationHits)
			remote := test.remote
			if remote == "" {
				remote = "origin"
			}
			value := originProxy.URL
			if test.direct {
				value = ""
			}
			t.Setenv("GIT_CONFIG_COUNT", "2")
			t.Setenv("GIT_CONFIG_KEY_0", "remote."+remote+".proxy")
			t.Setenv("GIT_CONFIG_VALUE_0", value)
			t.Setenv("GIT_CONFIG_KEY_1", "http.proxy")
			t.Setenv("GIT_CONFIG_VALUE_1", httpProxy.URL)
			repository := filepath.Join(directory, "cache")
			if err := runGitProcess(directory, nil, "init", "--bare", repository); err != nil {
				t.Fatal(err)
			}
			target := destination.URL + "/repo"
			args := []string{"fetch", target, "HEAD"}
			switch {
			case test.clone:
				args = []string{"clone", "--origin", remote, target, filepath.Join(directory, "native")}
			case test.remote != "":
				if err := runGitProcess(repository, nil, "config", "remote."+remote+".url", target); err != nil {
					t.Fatal(err)
				}
				args = []string{"fetch", remote, "HEAD"}
			case test.name == "raw ls-remote":
				args = []string{"ls-remote", target}
			}
			_ = runGitProcess(repository, nil, args...)
			counters := []*atomic.Int32{&originHits, &httpHits, &destinationHits}
			selected := 1
			if test.remote != "" {
				selected = 0
			}
			if test.direct {
				selected = 2
			}
			for index, counter := range counters {
				if (counter.Load() > 0) != (index == selected) {
					t.Fatalf("native selected proxy %d, expected %d", index, selected)
				}
			}
			before := counters[selected].Load()
			if test.clone {
				args[len(args)-1] = filepath.Join(directory, "proxied")
			}
			settings, err := Read(directory)
			if err != nil {
				t.Fatal(err)
			}
			gitThroughSCFW(t, repository, settings, args...)
			for index, counter := range counters {
				if index == selected {
					if counter.Load() <= before {
						t.Fatal("selected native route was not preserved")
					}
				} else if counter.Load() != 0 {
					t.Fatalf("SCFW selected incorrect route %d", index)
				}
			}
		})
	}
}

func TestGitNamedRemoteRetainsOriginalURLTLS(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	origin := gitTLSOrigin(t, &hits)
	ca := filepath.Join(directory, "git-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	target := origin.URL[:len("https://")] + "alice@" + origin.URL[len("https://"):] + "/repo"
	t.Setenv("GIT_CONFIG_COUNT", "3")
	keys := []string{"remote.origin.proxy", "http.proxy", "http." + target + ".sslCAInfo"}
	values := []string{"", "http://unused-proxy.invalid:8080", ca}
	for index, key := range keys {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), values[index])
	}
	_ = runGitProcess(directory, nil, "clone", target, filepath.Join(directory, "native"))
	before := hits.Load()
	if before == 0 {
		t.Fatal("native Git did not apply named remote proxy and username-scoped trust")
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "clone", target, filepath.Join(directory, "proxied"))
	if hits.Load() == before {
		t.Fatal("named remote lost original URL-specific TLS settings")
	}
}

func TestGitNamedRemoteRedirectKeepsOriginalTLS(t *testing.T) {
	directory := gitNetworkEnvironment(t)
	var hits atomic.Int32
	destination := gitTLSOrigin(t, &hits)
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))
	defer original.Close()
	t.Setenv("GIT_CONFIG_COUNT", "3")
	keys := []string{"remote.origin.proxy", "http." + original.URL + "/.sslVerify", "http." + destination.URL + "/.sslVerify"}
	values := []string{"", "false", "true"}
	for index, key := range keys {
		t.Setenv("GIT_CONFIG_KEY_"+strconv.Itoa(index), key)
		t.Setenv("GIT_CONFIG_VALUE_"+strconv.Itoa(index), values[index])
	}
	target := original.URL + "/repo"
	_ = runGitProcess(directory, nil, "clone", target, filepath.Join(directory, "native"))
	before := hits.Load()
	if before == 0 {
		t.Fatal("native clone did not retain original TLS setting")
	}
	settings, err := Read(directory)
	if err != nil {
		t.Fatal(err)
	}
	gitThroughSCFW(t, directory, settings, "clone", target, filepath.Join(directory, "proxied"))
	if hits.Load() == before {
		t.Fatal("named remote redirect reselected TLS against redirect URL")
	}
}
