// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/uv"
)

// Independent certificates are essential: httptest's default TLS certificate is
// shared by every server and cannot expose accidental unions of trust stores.
func uvTLSIdentity(t *testing.T) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SCFW TLS fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := *template
	leaf.SerialNumber = new(big.Int).Add(serial, big.NewInt(1))
	leaf.IsCA = false
	leaf.Subject.CommonName = "SCFW TLS endpoint"
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), certificate...)
	identity := append(bytes.Clone(chain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})...)
	parsed, err := tls.X509KeyPair(chain, identity)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, certificate, identity
}

func writeUVTLSFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUVTLSMatchesDirectUV(t *testing.T) {
	executable := uvTestEnvironment(t)
	wheel := pipWheel(t)
	trustTemplate := readProxyFixture(t, "uv/trust.toml.tmpl")
	identityA, certA, clientA := uvTLSIdentity(t)
	identityB, certB, _ := uvTLSIdentity(t)
	newRegistry := func(identity tls.Certificate, client bool) *httptest.Server {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/project-1.0-py3-none-any.whl" {
				http.NotFound(w, r)
				return
			}
			http.ServeContent(w, r, "project-1.0-py3-none-any.whl", time.Time{}, bytes.NewReader(wheel))
		}))
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}}
		if client {
			server.TLS.ClientAuth = tls.RequireAnyClientCert
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}
	registryA, registryB, mutual := newRegistry(identityA, false), newRegistry(identityB, false), newRegistry(identityA, true)
	fileA, fileB, clientFile := writeUVTLSFile(t, certA), writeUVTLSFile(t, certB), writeUVTLSFile(t, clientA)
	dirA, dirB := filepath.Dir(fileA), filepath.Dir(fileB)
	if err := os.Symlink(fileA, filepath.Join(dirA, "01234567.0")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dirA, "absent"), filepath.Join(dirA, "broken.0")); err != nil {
		t.Fatal(err)
	}
	hostA, _ := url.Parse(registryA.URL)
	portA, _ := strconv.Atoi(hostA.Port())
	for _, test := range []struct {
		name, origin string
		environment  map[string]string
		flags        []string
		config       string
		allowed      bool
	}{
		{name: "default trust rejects private CA", origin: registryA.URL},
		{name: "native TLS rejects private CA", origin: registryA.URL, flags: []string{"--native-tls"}},
		{name: "custom file", origin: registryA.URL, environment: map[string]string{"SSL_CERT_FILE": fileA}, allowed: true},
		{name: "custom directory", origin: registryA.URL, environment: map[string]string{"SSL_CERT_DIR": dirA}, allowed: true},
		{name: "union of environment file and directory", origin: registryB.URL, environment: map[string]string{"SSL_CERT_FILE": fileA, "SSL_CERT_DIR": dirB}, allowed: true},
		{name: "unrelated custom CA rejected", origin: registryB.URL, environment: map[string]string{"SSL_CERT_FILE": fileA}},
		{name: "explicit cert overrides bad environment", origin: registryA.URL, environment: map[string]string{"SSL_CERT_FILE": fileB, "SSL_CERT_DIR": dirB}, flags: []string{"--cert", fileA}, allowed: true},
		{name: "explicit cert excludes environment roots", origin: registryB.URL, environment: map[string]string{"SSL_CERT_FILE": fileB, "SSL_CERT_DIR": dirB}, flags: []string{"--cert", fileA}},
		{name: "missing environment source", origin: registryA.URL, environment: map[string]string{"SSL_CERT_FILE": filepath.Join(t.TempDir(), "absent")}},
		{name: "empty environment directory", origin: registryA.URL, environment: map[string]string{"SSL_CERT_DIR": t.TempDir()}},
		{name: "string trusted host", origin: registryA.URL, flags: []string{"--allow-insecure-host", hostA.Host}, allowed: true},
		{name: "structured trusted host", origin: registryA.URL, config: fmt.Sprintf(trustTemplate, hostA.Hostname(), "https", portA), allowed: true},
		{name: "structured wrong port", origin: registryA.URL, config: fmt.Sprintf(trustTemplate, hostA.Hostname(), "https", portA+1)},
		{name: "structured wrong scheme", origin: registryA.URL, config: fmt.Sprintf(trustTemplate, hostA.Hostname(), "http", portA)},
		{name: "environment trusted host", origin: registryA.URL, environment: map[string]string{"UV_INSECURE_HOST": hostA.Host}, allowed: true},
		{name: "CLI clears environment trusted host", origin: registryA.URL, environment: map[string]string{"UV_INSECURE_HOST": hostA.Host}, flags: []string{"--allow-insecure-host="}},
		{name: "Git CA does not widen uv roots", origin: registryA.URL, environment: map[string]string{"GIT_SSL_CAINFO": fileA}},
		{name: "unused invalid Git CA does not block registry", origin: registryA.URL, environment: map[string]string{"GIT_SSL_CAINFO": filepath.Join(t.TempDir(), "absent"), "SSL_CERT_FILE": fileA}, allowed: true},
		{name: "mutual TLS identity", origin: mutual.URL, environment: map[string]string{"SSL_CERT_FILE": fileA, "SSL_CLIENT_CERT": clientFile}, allowed: true},
		{name: "mutual TLS missing identity", origin: mutual.URL, environment: map[string]string{"SSL_CERT_FILE": fileA}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			for key, value := range test.environment {
				t.Setenv(key, value)
			}
			common := []string{"--no-config", "pip", "install", "--no-deps"}
			if test.config != "" {
				path := filepath.Join(t.TempDir(), "uv.toml")
				if err := os.WriteFile(path, []byte(test.config), 0600); err != nil {
					t.Fatal(err)
				}
				common = []string{"--config-file", path, "pip", "install", "--no-deps"}
			}
			common = append(common, test.flags...)
			args := func() []string {
				return append(append([]string{}, common...), "--target", t.TempDir(), test.origin+"/project-1.0-py3-none-any.whl")
			}
			t.Setenv("UV_CACHE_DIR", t.TempDir())
			direct := exec.Command(executable, args()...)
			output, directErr := direct.CombinedOutput()
			if (directErr == nil) != test.allowed {
				t.Fatalf("direct uv: %v %s", directErr, output)
			}
			t.Setenv("UV_CACHE_DIR", t.TempDir())
			manager, err := uv.NewUV(context.Background(), "uv", executable)
			if err != nil {
				t.Fatal(err)
			}
			runner := &capturingUVRunner{UV: manager}
			commandErr, setupErr := runThroughProxy(context.Background(), runner, args(), nil)
			if setupErr != nil || (commandErr == nil) != test.allowed {
				t.Fatalf("proxied uv: %v/%v (direct %v)", commandErr, setupErr, directErr)
			}
			assertUVProxyCleaned(t, runner)
		})
	}
}

func TestUVAuthenticatedHTTPSUpstreamTrust(t *testing.T) {
	executable := uvTestEnvironment(t)
	wheel := pipWheel(t)
	registryIdentity, registryCA, _ := uvTLSIdentity(t)
	proxyIdentity, proxyCA, _ := uvTLSIdentity(t)
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "project-1.0-py3-none-any.whl", time.Time{}, bytes.NewReader(wheel))
	}))
	registry.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{registryIdentity}}
	registry.StartTLS()
	defer registry.Close()
	var hits atomic.Int32
	upstream := goproxy.NewProxyHttpServer()
	upstream.ConnectDial = net.Dial
	upstream.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if ctx.Req.Header.Get("Proxy-Authorization") != "Basic cHJveHk6c2VjcmV0" {
			t.Error("proxy authentication lost")
		}
		hits.Add(1)
		return goproxy.OkConnect, host
	})
	server := httptest.NewUnstartedServer(upstream)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{proxyIdentity}}
	server.StartTLS()
	defer server.Close()
	t.Setenv("HTTPS_PROXY", strings.Replace(server.URL, "https://", "https://proxy:secret@", 1))
	t.Chdir(t.TempDir())
	for _, trusted := range []bool{true, false} {
		t.Run(fmt.Sprintf("proxy CA trusted=%v", trusted), func(t *testing.T) {
			bundle := bytes.Clone(registryCA)
			if trusted {
				bundle = append(bundle, proxyCA...)
			}
			t.Setenv("SSL_CERT_FILE", writeUVTLSFile(t, bundle))
			for _, proxied := range []bool{false, true} {
				t.Setenv("UV_CACHE_DIR", t.TempDir())
				args := []string{"--no-config", "pip", "install", "--no-deps", "--target", t.TempDir(), registry.URL + "/project-1.0-py3-none-any.whl"}
				var err error
				if proxied {
					manager, setup := uv.NewUV(context.Background(), "uv", executable)
					if setup != nil {
						t.Fatal(setup)
					}
					runner := &capturingUVRunner{UV: manager}
					var setupErr error
					err, setupErr = runThroughProxy(context.Background(), runner, args, nil)
					if setupErr != nil {
						t.Fatal(setupErr)
					}
					assertUVProxyCleaned(t, runner)
				} else {
					_, err = exec.Command(executable, args...).CombinedOutput()
				}
				if (err == nil) != trusted {
					t.Fatalf("proxied=%v err=%v", proxied, err)
				}
			}
		})
	}
	if hits.Load() < 2 {
		t.Fatal("HTTPS upstream was not traversed")
	}
}
