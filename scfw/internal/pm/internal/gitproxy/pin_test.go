// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestGitPublicKeyPinMatchesNativeVerification(t *testing.T) {
	for _, verify := range []bool{true, false} {
		for _, correct := range []bool{true, false} {
			t.Run("verify="+strconv.FormatBool(verify)+"/correct="+strconv.FormatBool(correct), func(t *testing.T) {
				directory := gitNetworkEnvironment(t)
				var hits atomic.Int32
				origin := gitTLSOrigin(t, &hits)
				ca := filepath.Join(directory, "ca.pem")
				if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
					t.Fatal(err)
				}
				digest := make([]byte, sha256.Size)
				if correct {
					sum := sha256.Sum256(origin.Certificate().RawSubjectPublicKeyInfo)
					copy(digest, sum[:])
				}
				t.Setenv("GIT_SSL_CAINFO", ca)
				t.Setenv("GIT_CONFIG_COUNT", "2")
				t.Setenv("GIT_CONFIG_KEY_0", "http.pinnedPubkey")
				t.Setenv("GIT_CONFIG_VALUE_0", "sha256//"+base64.StdEncoding.EncodeToString(digest))
				t.Setenv("GIT_CONFIG_KEY_1", "http.sslVerify")
				t.Setenv("GIT_CONFIG_VALUE_1", strconv.FormatBool(verify))
				target := origin.URL + "/repo"
				_ = runGitProcessForPin(directory, target)
				if (hits.Load() > 0) != correct {
					t.Fatal("native Git pin result differs from expected")
				}
				hits.Store(0)
				settings, err := Read(directory)
				if err != nil {
					t.Fatal(err)
				}
				transport := proxy.NewTransport(proxy.Options{RouteForRequest: settings.Route})
				defer transport.CloseIdleConnections()
				response, err := (&http.Client{Transport: transport}).Get(target)
				if response != nil {
					_ = response.Body.Close()
				}
				if (err == nil) != correct || (hits.Load() > 0) != correct {
					t.Fatal("outbound TLS did not preserve the native pin result")
				}
			})
		}
	}
}

func runGitProcessForPin(directory, target string) error {
	command := exec.Command("git", "ls-remote", target)
	command.Dir = directory
	return command.Run()
}
