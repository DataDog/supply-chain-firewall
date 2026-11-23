//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"text/template"
	"time"
)

const policyEvaluatePath = "/api/v2/static-analysis-sca/scfw/policy/evaluate"
const policyReportPath = "/api/v2/static-analysis-sca/scfw/report"
const policyDummyAPIKey = "scfw-e2e-dummy-api-key"
const policyDummyAppKey = "scfw-e2e-dummy-app-key"

type policyAPIExchange struct {
	Path          string          `json:"path"`
	Method        string          `json:"method"`
	Host          string          `json:"host"`
	ContentType   string          `json:"content_type"`
	Authenticated bool            `json:"authenticated"`
	TLS           bool            `json:"tls"`
	At            time.Time       `json:"at"`
	Request       json.RawMessage `json:"request"`
	Response      json.RawMessage `json:"response"`
	Error         string          `json:"error,omitempty"`
}

type policyFixture struct {
	mutex     sync.Mutex
	exchanges []policyAPIExchange
	response  json.RawMessage
	server    *httptest.Server
}

func policyResponse(c candidate, outcome string) (json.RawMessage, error) {
	t, err := template.ParseFiles("testdata/policy_api/responses.json.tmpl")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	ecosystem := c.Ecosystem
	if ecosystem == "pypi" {
		ecosystem = "PyPI"
	}
	if err := t.Execute(&b, map[string]string{"Ecosystem": ecosystem, "Project": c.Project, "Version": c.Version}); err != nil {
		return nil, err
	}
	var responses map[string]json.RawMessage
	if err := json.Unmarshal(b.Bytes(), &responses); err != nil {
		return nil, err
	}
	response, ok := responses[outcome]
	if !ok {
		return nil, fmt.Errorf("unknown policy fixture outcome %q", outcome)
	}
	return response, nil
}

func (f *policyFixture) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/health" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	event := policyAPIExchange{Path: request.URL.Path, Method: request.Method, Host: request.Host, ContentType: request.Header.Get("Content-Type"), Authenticated: request.Header.Get("dd-api-key") == policyDummyAPIKey && request.Header.Get("dd-application-key") == policyDummyAppKey, TLS: request.TLS != nil, At: time.Now().UTC()}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 || !json.Valid(body) {
		event.Error = "invalid or oversized JSON request"
	} else {
		event.Request = body
	}
	if event.Method != http.MethodPost || event.Host != "api.scfw.test" || event.ContentType != "application/json" || !event.Authenticated || !event.TLS {
		event.Error = "incorrect policy transport or authentication"
	}
	response := json.RawMessage(`{}`)
	switch event.Path {
	case policyEvaluatePath:
		response = f.response
	case policyReportPath:
	default:
		event.Error = "unexpected API path"
	}
	if event.Error != "" {
		response = json.RawMessage(`{"error":"invalid fixture request"}`)
	}
	event.Response = response
	f.mutex.Lock()
	f.exchanges = append(f.exchanges, event)
	f.mutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if event.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	_, _ = w.Write(response)
}

func startPolicyFixture(r *caseRun, outcome string) (*policyFixture, error) {
	if os.Getenv("SCFW_E2E_POLICY_WORKER") != "disposable" || !slices.Contains(r.Cell.Capabilities, "controlled-policy-api") {
		return nil, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("policy-api requires a provisioned disposable worker capability"))
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(r.Context, "api.scfw.test")
	if err != nil || len(addresses) == 0 {
		return nil, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("fixture DNS unavailable: %v", err))
	}
	for _, address := range addresses {
		if !address.IP.IsLoopback() {
			return nil, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("fixture DNS must resolve exclusively to loopback"))
		}
	}
	directory := os.Getenv("SCFW_E2E_POLICY_TLS")
	if err := requireAbsolute(directory); err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key"))
	if err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	pem, err := os.ReadFile(filepath.Join(directory, "ca.crt"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("invalid fixture root")
	}
	response, err := policyResponse(r.Candidate, outcome)
	if err != nil {
		return nil, err
	}
	f := &policyFixture{response: response}
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		return nil, classified("INFRASTRUCTURE_FAILURE", err)
	}
	f.server = httptest.NewUnstartedServer(f)
	f.server.Listener.Close()
	f.server.Listener = listener
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request, err := http.NewRequestWithContext(r.Context, http.MethodGet, "https://api.scfw.test/health", nil)
	if err != nil {
		f.server.Close()
		return nil, err
	}
	health, err := client.Do(request)
	if err != nil {
		f.server.Close()
		return nil, classified("INFRASTRUCTURE_FAILURE", fmt.Errorf("fixture TLS preflight: %w", err))
	}
	health.Body.Close()
	if health.StatusCode != http.StatusNoContent {
		f.server.Close()
		return nil, fmt.Errorf("fixture health status %d", health.StatusCode)
	}
	r.Env["SCFW_MODE"], r.Env["DD_SITE"] = "datadog", "scfw.test"
	r.Env["DD_API_KEY"], r.Env["DD_APP_KEY"] = policyDummyAPIKey, policyDummyAppKey
	r.Env["SSL_CERT_FILE"] = filepath.Join(directory, "ca-bundle.crt")
	r.Result.Observations["controlled_policy_exception"] = map[string]any{"reason": "deterministic Datadog evaluate/report decisions; package registries remain public", "host": "api.scfw.test", "addresses": addresses, "tls_verified": true}
	if err := r.Keep("fixture-public-ca", filepath.Join(directory, "ca.crt")); err != nil {
		f.server.Close()
		return nil, err
	}
	return f, nil
}

func (f *policyFixture) closeAndKeep(r *caseRun) error {
	f.server.Close()
	f.mutex.Lock()
	events := slices.Clone(f.exchanges)
	f.mutex.Unlock()
	path := filepath.Join(r.Root, "policy-http.json")
	if err := writeJSON(path, events); err != nil {
		return err
	}
	if err := r.Keep("policy-http", path); err != nil {
		return err
	}
	connection, err := net.DialTimeout("tcp", "127.0.0.1:443", time.Second)
	if err == nil {
		connection.Close()
		return fmt.Errorf("policy fixture listener remained open")
	}
	r.Result.Observations["policy_fixture_closed"] = true
	return nil
}

func TestHarnessPolicyFixtureTransport(t *testing.T) {
	response, err := policyResponse(candidate{Ecosystem: "pypi", Project: "idna", Version: "1.0"}, "BLOCK")
	if err != nil {
		t.Fatal(err)
	}
	f := &policyFixture{response: response}
	for _, path := range []string{policyEvaluatePath, policyReportPath, "/unexpected"} {
		request := httptest.NewRequest(http.MethodPost, "https://api.scfw.test"+path, bytes.NewBufferString(`{"data":{}}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("dd-api-key", policyDummyAPIKey)
		request.Header.Set("dd-application-key", policyDummyAppKey)
		recorder := httptest.NewRecorder()
		f.ServeHTTP(recorder, request)
		want := http.StatusOK
		if path == "/unexpected" {
			want = http.StatusBadRequest
		}
		if recorder.Code != want {
			t.Fatalf("%s status %d", path, recorder.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "http://api.scfw.test"+policyEvaluatePath, bytes.NewBufferString(`{}`))
	recorder := httptest.NewRecorder()
	f.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || f.exchanges[3].Error == "" {
		t.Fatal("accepted unauthenticated plaintext request")
	}
	if len(f.exchanges) != 4 || !bytes.Equal(f.exchanges[0].Response, response) {
		t.Fatal("fixture did not retain exact HTTP exchanges")
	}
}
