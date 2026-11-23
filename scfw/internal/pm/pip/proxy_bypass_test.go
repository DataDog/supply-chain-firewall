// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestHTTPSBypassNativeRequestVectors(t *testing.T) {
	raw, err := os.ReadFile("../internal/pythonproxy/testdata/bypass_routes.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Target, Requests, Urllib string
		Loose, Ambiguous               bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			target, err := url.Parse(test.Target)
			if err != nil {
				t.Fatal(err)
			}
			hook := pipHTTPSBypassHook(pipDiscoveryResult{HTTPS: "http://gateway.example", RequestsNoProxy: test.Requests, NoProxy: test.Urllib, LooseNoProxy: test.Loose})
			_, err = hook(context.Background(), proxy.Request{URL: *target, Header: http.Header{"User-Agent": {"pip/26.2"}}})
			if errors.Is(err, pythonproxy.ErrAmbiguousHTTPSBypass) != test.Ambiguous {
				t.Fatalf("ambiguous=%v: %v", test.Ambiguous, err)
			}
		})
	}
}

func TestHTTPSBypassNativeGitRequests(t *testing.T) {
	for _, test := range []struct {
		name, path, agent string
		ambiguous         bool
	}{
		{"native-agent", "/repo.git/info/refs?service=git-upload-pack", "git/2.55.0", false},
		{"native-dumb-http", "/repo.git/HEAD", "git/2.55.0", false},
		{"configured-agent-refs", "/repo.git/info/refs?service=git-upload-pack", "custom-git", false},
		{"configured-agent-upload", "/repo.git/git-upload-pack", "custom-git", false},
		{"configured-agent-dumb-head", "/repo.git/HEAD", "custom-git", false},
		{"configured-agent-dumb-refs", "/repo.git/info/refs", "custom-git", false},
		{"pip-is-not-git", "/repo.git/info/refs?service=git-upload-pack", "pip/26.2", true},
		{"requests-is-not-git", "/repo.git/git-upload-pack", "python-requests/2.34.2", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse("https://files.example" + test.path)
			if err != nil {
				t.Fatal(err)
			}
			hook := pipHTTPSBypassHook(pipDiscoveryResult{HTTPS: "http://gateway.example", RequestsNoProxy: "files.example:443", NoProxy: "files.example:443"})
			_, err = hook(context.Background(), proxy.Request{URL: *target, Header: http.Header{"User-Agent": {test.agent}}})
			if test.ambiguous {
				if !errors.Is(err, pythonproxy.ErrAmbiguousHTTPSBypass) {
					t.Fatalf("Requests ambiguity lost: %v", err)
				}
			} else if err != nil {
				t.Fatalf("native Git request rejected: %v", err)
			}
		})
	}
}
