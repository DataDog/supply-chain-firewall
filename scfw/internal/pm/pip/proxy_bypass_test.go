// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"encoding/json"
	"errors"
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
			_, err = hook(context.Background(), proxy.Request{URL: *target})
			if errors.Is(err, pythonproxy.ErrAmbiguousHTTPSBypass) != test.Ambiguous {
				t.Fatalf("ambiguous=%v: %v", test.Ambiguous, err)
			}
		})
	}
}
