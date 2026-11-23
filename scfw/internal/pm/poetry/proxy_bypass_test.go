// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/pythonproxy"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
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
		if test.Loose {
			continue
		}
		t.Run(test.Name, func(t *testing.T) {
			target, err := url.Parse(test.Target)
			if err != nil {
				t.Fatal(err)
			}
			settings := poetryProxySettings{upstream: poetryProxyConfiguration{Config: httpproxy.Config{HTTPSProxy: "http://gateway.example"}, requestsNoProxy: test.Requests, urllibNoProxy: test.Urllib}}
			hook := settings.httpsBypassHook
			_, err = hook(context.Background(), proxy.Request{URL: *target})
			if errors.Is(err, pythonproxy.ErrAmbiguousHTTPSBypass) != test.Ambiguous {
				t.Fatalf("ambiguous=%v: %v", test.Ambiguous, err)
			}
		})
	}
}

func TestHTTPSBypassRetainsInitiatingSourceProxy(t *testing.T) {
	origin, _ := url.Parse("https://index.example/simple")
	target, _ := url.Parse("https://files.example/project.whl")
	settings := poetryProxySettings{
		upstream:     poetryProxyConfiguration{Config: httpproxy.Config{HTTPSProxy: "http://gateway.example"}, requestsNoProxy: "files.example:443", urllibNoProxy: "files.example:443"},
		certificates: []poetryCertificateRoute{{address: origin, err: errors.New("unused TLS configuration")}},
	}
	request := proxy.Request{URL: *target, ClientIdentity: "poetry-source-0"}
	if _, err := settings.httpsBypassHook(context.Background(), request); err != nil {
		t.Fatalf("retained source proxy rejected: %v", err)
	}
	selected, err := settings.requestsProxy(request)
	if err != nil || selected == nil || selected.String() != "http://gateway.example" {
		t.Fatalf("retained source proxy: %v %v", selected, err)
	}
	for _, identity := range []string{"client:git", "client:other"} {
		request.ClientIdentity = identity
		if _, err := settings.httpsBypassHook(context.Background(), request); err != nil {
			t.Fatalf("independent client rejected: %v", err)
		}
	}
	request.ClientIdentity = ""
	request.Header = map[string][]string{"User-Agent": {"git/2.55.0"}}
	if _, err := settings.httpsBypassHook(context.Background(), request); err != nil {
		t.Fatalf("native Git rejected: %v", err)
	}
}
