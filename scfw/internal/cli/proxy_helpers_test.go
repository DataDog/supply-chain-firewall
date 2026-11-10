// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"github.com/klauspost/compress/zstd"
)

type upstreamProxyOptions struct {
	credentials    string
	tls            *tls.Config
	connectAddress string
	hits           *atomic.Int32
}

func pypiWheel(t *testing.T) []byte {
	t.Helper()
	return pypiWheelNamed(t, "project")
}

func pypiWheelNamed(t *testing.T, packageName string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range []string{"project/__init__.py", "project-1.0.dist-info/METADATA", "project-1.0.dist-info/WHEEL", "project-1.0.dist-info/RECORD"} {
		body := readProxyFixture(t, filepath.Join("pip", "wheel", name))
		body = strings.ReplaceAll(body, "project", packageName)
		file, err := writer.Create(strings.ReplaceAll(name, "project", packageName))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func pypiSdist(t *testing.T, files ...string) []byte {
	t.Helper()
	return pypiSdistArchive(t, "gzip", files...)
}

func pypiSdistArchive(t *testing.T, format string, files ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var compressed io.WriteCloser
	switch format {
	case "gzip":
		compressed = gzip.NewWriter(&buffer)
	case "zstd":
		var err error
		compressed, err = zstd.NewWriter(&buffer, zstd.WithEncoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported test archive format %q", format)
	}
	writer := tar.NewWriter(compressed)
	// A stdlib-only PEP 517 backend avoids network access to install build tools.
	if len(files) == 0 {
		files = []string{"pyproject.toml", "backend.py", "PKG-INFO"}
	}
	for _, name := range files {
		body := readProxyFixture(t, filepath.Join("pip", "sdist", name))
		if err := writer.WriteHeader(&tar.Header{Name: "project-1.0/" + name, Mode: 0600, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func proxyTLSIdentity(t *testing.T) (tls.Certificate, []byte, []byte) {
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

func writeProxyTLSFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func proxyTestUpstream(t *testing.T, options upstreamProxyOptions) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(options.credentials)) {
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
		options.hits.Add(1)
		if r.Method == http.MethodConnect {
			address := r.Host
			if options.connectAddress != "" {
				address = options.connectAddress
			}
			upstream, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				http.Error(w, "connect failed", http.StatusBadGateway)
				return
			}
			client, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				_ = upstream.Close()
				return
			}
			defer func() { _ = client.Close(); _ = upstream.Close() }()
			_, _ = buffer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
			if err := buffer.Flush(); err != nil {
				return
			}
			done := make(chan struct{})
			go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			<-done
			return
		}
		request := r.Clone(r.Context())
		request.RequestURI = ""
		request.Header.Del("Proxy-Authorization")
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		response, err := transport.RoundTrip(request)
		if err != nil {
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = response.Body.Close() }()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	server := httptest.NewUnstartedServer(handler)
	if options.tls != nil {
		server.TLS = options.tls
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func assertProxyCleaned(t *testing.T, config proxy.ClientConfig) {
	t.Helper()
	for _, client := range config.AdditionalClients {
		assertProxyCleaned(t, client)
	}
	if config.URL == "" {
		t.Fatal("command was not configured for interception")
	}
	if _, err := os.Stat(filepath.Dir(config.CACertificatePath)); !os.IsNotExist(err) {
		t.Fatal("invocation directory was not removed")
	}
	connection, err := net.DialTimeout("tcp", strings.TrimPrefix(config.URL, "http://"), time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("invocation proxy is still listening")
	}
}

// The source fixtures remain shared; construct adversarial containers in memory.
func pypiZstandardZIP(t *testing.T) []byte {
	t.Helper()
	compressed, err := gzip.NewReader(bytes.NewReader(pypiSdist(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = compressed.Close() }()
	source := tar.NewReader(compressed)
	var inner bytes.Buffer
	zipWriter := zip.NewWriter(&inner)
	for {
		header, err := source.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		file, err := zipWriter.Create(header.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(file, source); err != nil {
			t.Fatal(err)
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	metadata := strings.ReplaceAll(readProxyFixture(t, "pip/sdist/PKG-INFO"), "Name: project", "Name: allowed")
	var outer bytes.Buffer
	tarWriter := tar.NewWriter(&outer)
	for _, entry := range []struct {
		name string
		body []byte
	}{{"allowed-1.0/PKG-INFO", []byte(metadata)}, {"allowed-1.0/payload.zip", inner.Bytes()}} {
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if outer.Len() > 128<<10 {
		t.Fatal("test Zstandard raw block exceeds its format limit")
	}
	payload := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0}
	payload = binary.LittleEndian.AppendUint32(payload, uint32(outer.Len()))
	block := uint32(outer.Len())<<3 | 1
	payload = append(payload, byte(block), byte(block>>8), byte(block>>16))
	return append(payload, outer.Bytes()...)
}

func pypiGzipWithZIPTail(t *testing.T) []byte {
	t.Helper()
	var tail bytes.Buffer
	writer := zip.NewWriter(&tail)
	file, err := writer.Create("data.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, "unrelated"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return append(pypiSdist(t), tail.Bytes()...)
}
