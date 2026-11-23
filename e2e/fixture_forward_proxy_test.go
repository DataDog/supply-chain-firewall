//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// forwardProxy keeps origins and TLS tunnels byte-transparent. It binds only to
// loopback, accepts an explicit destination allowlist, and never uses host proxy
// settings. Each case owns its listeners, connections, and route evidence.
type forwardProxy struct {
	server         *httptest.Server
	transport      *http.Transport
	allowed        []string
	authorization  string
	mu             sync.Mutex
	routes         []forwardRoute
	connections    map[net.Conn]bool
	closed         bool
	certificatePEM []byte
}
type forwardRoute struct {
	At         time.Time `json:"at"`
	Method     string    `json:"method"`
	Authority  string    `json:"authority"`
	Authorized bool      `json:"authorized"`
	Error      string    `json:"error,omitempty"`
}

func newForwardProxy(secure, authenticated bool, allowed []string) (*forwardProxy, error) {
	p := &forwardProxy{allowed: slices.Clone(allowed), connections: map[net.Conn]bool{}, transport: &http.Transport{Proxy: nil, DisableCompression: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}
	if authenticated {
		p.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password"))
	}
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.server.Config.ReadHeaderTimeout = 10 * time.Second
	if secure {
		config, root, err := forwardingTLS()
		if err != nil {
			p.server.Close()
			return nil, err
		}
		p.certificatePEM = root
		p.server.TLS = config
		p.server.StartTLS()
	} else {
		p.server.Start()
	}
	return p, nil
}
func (p *forwardProxy) URL() string {
	u, _ := url.Parse(p.server.URL)
	if p.authorization != "" {
		u.User = url.UserPassword("fixture-user", "fixture-password")
	}
	return u.String()
}
func (p *forwardProxy) certificate() []byte { return slices.Clone(p.certificatePEM) }

func forwardingTLS() (*tls.Config, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{Subject: pkix.Name{CommonName: "SCFW forwarding fixture CA"}, SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "SCFW forwarding fixture"}, SerialNumber: big.NewInt(2), NotBefore: root.NotBefore, NotAfter: root.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}}
	return config, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), nil
}
func (p *forwardProxy) snapshot() []forwardRoute {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.routes)
}
func (p *forwardProxy) close() {
	p.mu.Lock()
	p.closed = true
	for c := range p.connections {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	p.server.Close()
}
func (p *forwardProxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.connections[c] = true
	return true
}
func (p *forwardProxy) release(c net.Conn) {
	_ = c.Close()
	p.mu.Lock()
	delete(p.connections, c)
	p.mu.Unlock()
}
func (p *forwardProxy) serve(w http.ResponseWriter, r *http.Request) {
	route := forwardRoute{At: time.Now().UTC(), Method: r.Method, Authority: r.URL.Host, Authorized: p.authorization == "" || r.Header.Get("Proxy-Authorization") == p.authorization}
	if r.Method == http.MethodConnect {
		route.Authority = r.Host
	}
	defer func() { p.mu.Lock(); p.routes = append(p.routes, route); p.mu.Unlock() }()
	if !route.Authorized {
		w.Header().Set("Proxy-Authenticate", `Basic realm="scfw-e2e"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	host, _, err := net.SplitHostPort(route.Authority)
	if err != nil {
		host = route.Authority
	}
	if !slices.Contains(p.allowed, host) {
		route.Error = "destination not allowed"
		http.Error(w, route.Error, http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", route.Authority)
		if err != nil {
			route.Error = err.Error()
			http.Error(w, "origin connection failed", http.StatusBadGateway)
			return
		}
		if !p.track(upstream) {
			return
		}
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			p.release(upstream)
			route.Error = err.Error()
			return
		}
		if !p.track(downstream) {
			p.release(upstream)
			return
		}
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			p.release(upstream)
			p.release(downstream)
			return
		}
		if err := buffered.Flush(); err != nil {
			p.release(upstream)
			p.release(downstream)
			return
		}
		// Log CONNECT at establishment; its lifetime can extend beyond command exit.
		go func() {
			done := make(chan struct{})
			go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close(); close(done) }()
			_, _ = io.Copy(downstream, upstream)
			p.release(downstream)
			p.release(upstream)
			<-done
		}()
		return
	}
	outgoing := r.Clone(r.Context())
	outgoing.RequestURI = ""
	outgoing.Header = r.Header.Clone()
	outgoing.Header.Del("Proxy-Authorization")
	outgoing.Header.Del("Proxy-Connection")
	response, err := p.transport.RoundTrip(outgoing)
	if err != nil {
		route.Error = err.Error()
		http.Error(w, "origin request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		w.Header()[key] = slices.Clone(values)
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func TestHarnessForwardProxy(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, authenticated := range []bool{false, true} {
			t.Run(fmt.Sprintf("tls-%v-auth-%v", secure, authenticated), func(t *testing.T) {
				origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Proxy-Authorization") != "" {
						t.Error("proxy credentials reached origin")
					}
					w.Header().Set("Content-Encoding", "identity")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte("unaltered origin bytes"))
				}))
				defer origin.Close()
				p, err := newForwardProxy(secure, authenticated, []string{"127.0.0.1"})
				if err != nil {
					t.Fatal(err)
				}
				defer p.close()
				proxyURL, _ := url.Parse(p.URL())
				roots := x509.NewCertPool()
				roots.AddCert(origin.Certificate())
				if secure && !roots.AppendCertsFromPEM(p.certificate()) {
					t.Fatal("missing forwarding CA")
				}
				transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				response, err := client.Get(origin.URL)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(data) != "unaltered origin bytes" || response.StatusCode != http.StatusCreated || response.Header.Get("Content-Encoding") != "identity" {
					t.Fatalf("origin changed: %q %v", data, err)
				}
				if routes := p.snapshot(); len(routes) != 1 || !routes[0].Authorized || routes[0].Method != "CONNECT" {
					t.Fatalf("missing tunnel evidence: %+v", routes)
				}
				// Closing the fixture must terminate an idle CONNECT, not hang teardown.
				p.close()
			})
		}
	}
}
func TestHarnessForwardProxyHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credentials reached origin")
		}
		_, _ = io.WriteString(w, "raw origin response")
	}))
	defer origin.Close()
	p, err := newForwardProxy(false, true, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	for _, credentials := range []bool{false, true} {
		address := p.server.URL
		if credentials {
			address = p.URL()
		}
		u, _ := url.Parse(address)
		transport := &http.Transport{Proxy: http.ProxyURL(u)}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if credentials && string(data) != "raw origin response" {
			t.Fatal("HTTP forwarding changed bytes")
		}
		if !credentials && response.StatusCode != http.StatusProxyAuthRequired {
			t.Fatal("missing authentication accepted")
		}
		response, err = client.Get("http://forbidden.invalid/")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if credentials && response.StatusCode != http.StatusForbidden {
			t.Fatal("unlisted destination accepted")
		}
	}
	if routes := p.snapshot(); len(routes) != 4 || !strings.Contains(routes[3].Error, "not allowed") {
		t.Fatalf("lost rejection evidence: %+v", routes)
	}
}
