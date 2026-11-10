// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package gitproxy snapshots Git network settings and configures intercepted Git clients.
package gitproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

const maxConfigurationBytes = 4 << 20

// Settings is an invocation-scoped snapshot of Git configuration and environment.
type Settings struct {
	executable                string
	directory                 string
	home                      string
	environment               []string
	configuration             string
	entries                   []gitConfigurationEntry
	fileEntries               []gitConfigurationEntry
	commandEntries            []gitConfigurationEntry
	profiles                  []routeProfile
	remoteProfiles            []remoteProfile
	unscopedConfiguration     string
	nativeRootsOnce           sync.Once
	nativeRoots               *x509.CertPool
	nativeRootsErr            error
	caInfo, caPath, cert, key string
	noVerify                  bool
	discoveryErr              error
	sslPaths                  []string
	mutex                     sync.Mutex
	routes                    map[string]*proxy.OutboundRoute
}

type gitConfigurationEntry struct {
	key, value string
	implicit   bool
}

type boundedGitOutput struct{ bytes.Buffer }

func (b *boundedGitOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxConfigurationBytes {
		return 0, errors.New("git configuration exceeds discovery limit")
	}
	return b.Buffer.Write(data)
}

func runGitConfiguration(executable, directory string, environment []string, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	command.Env = environment
	command.Stdin = strings.NewReader(input)
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	var output boundedGitOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && output.Len() == 0 {
			return nil, nil
		}
		return nil, errors.New("could not read Git network configuration")
	}
	return output.Bytes(), nil
}

// Read discovers Git configuration through bounded read-only queries.
// Discovery errors are deferred until Git traffic actually needs the settings.
func Read(directory string) (*Settings, error) {
	s := &Settings{directory: directory, environment: os.Environ(), routes: map[string]*proxy.OutboundRoute{}}
	if info, err := os.Stat(s.directory); err != nil || !info.IsDir() {
		s.directory, _ = os.Getwd()
	}
	s.directory, _ = filepath.Abs(s.directory)
	s.home, _ = os.UserHomeDir()
	s.caInfo, s.caPath, s.cert, s.key = os.Getenv("GIT_SSL_CAINFO"), os.Getenv("GIT_SSL_CAPATH"), os.Getenv("GIT_SSL_CERT"), os.Getenv("GIT_SSL_KEY")
	_, s.noVerify = os.LookupEnv("GIT_SSL_NO_VERIFY")
	executable, err := exec.LookPath("git")
	if err != nil {
		return s, nil
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		s.discoveryErr = errors.New("could not locate Git executable")
		return s, nil
	}
	s.executable = executable
	// Dependency clones do not inherit the caller repository's local settings or
	// gitdir/onbranch conditional includes. Discover the system/global/command
	// configuration with an empty Git directory, including when GIT_DIR is
	// inherited. Retain the process directory for relative global/include paths.
	directory, err = os.MkdirTemp("", "scfw-git-discovery-*")
	if err != nil {
		s.discoveryErr = errors.New("could not prepare Git configuration discovery")
		return s, nil
	}
	defer func() { _ = os.RemoveAll(directory) }()
	var environment []string
	for _, entry := range s.environment {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GIT_DIR" && key != "GIT_WORK_TREE" && key != "GIT_COMMON_DIR" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "GIT_DIR="+directory)
	data, err := runGitConfiguration(executable, s.directory, environment, "", "config", "--includes", "--null", "--show-scope", "--list")
	if err != nil {
		s.discoveryErr = err
		return s, nil
	}
	records := bytes.Split(data, []byte{0})
	for i := 0; i+1 < len(records); i += 2 {
		parsed := parseGitConfiguration(append(slices.Clone(records[i+1]), 0))
		scope := string(records[i])
		if scope != "system" && scope != "global" && scope != "command" {
			continue
		}
		s.entries = append(s.entries, parsed...)
		if scope == "command" {
			s.commandEntries = append(s.commandEntries, parsed...)
		}
		if string(records[i]) == "global" || string(records[i]) == "system" {
			s.fileEntries = append(s.fileEntries, parsed...)
		}
	}
	s.configuration = renderGitConfiguration(s.entries)
	var unscoped []gitConfigurationEntry
	for _, entry := range s.entries {
		if !strings.HasPrefix(entry.key, "http.") || strings.LastIndexByte(entry.key, '.') == len("http") {
			unscoped = append(unscoped, entry)
		}
	}
	s.unscopedConfiguration = renderGitConfiguration(unscoped)
	s.discoverProfiles()
	s.discoverRemoteProfiles()

	s.sslPaths = append([]string{os.Getenv("SSL_CERT_FILE")}, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)

	return s, nil
}

func parseGitConfiguration(data []byte) []gitConfigurationEntry {
	var entries []gitConfigurationEntry
	for _, record := range bytes.Split(data, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		key, value, present := strings.Cut(string(record), "\n")
		entries = append(entries, gitConfigurationEntry{key: key, value: value, implicit: !present})
	}
	return entries
}
func gitQuoted(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`, "\b", `\b`).Replace(value) + `"`
}

// IsRequest recognizes Git HTTP requests, including configured user agents.
func (s *Settings) IsRequest(request proxy.Request) bool {
	agent := request.Header.Get("User-Agent")
	if custom := environmentValue(s.environment, "GIT_HTTP_USER_AGENT"); custom != "" && custom == agent {
		return true
	}
	if strings.HasPrefix(agent, "git/") || strings.HasPrefix(agent, "git-dulwich/") {
		return true
	}
	for _, entry := range s.entries {
		if strings.HasSuffix(entry.key, ".useragent") && entry.value != "" && entry.value == agent {
			return true
		}
	}
	return request.URL.Query().Get("service") == "git-upload-pack" || strings.HasSuffix(request.URL.Path, "/git-upload-pack")
}

// Available reports whether Git was found during discovery.
func (s *Settings) Available() bool { return s.executable != "" }

// Values returns URL-matched system/global and inherited command configuration.
func (s *Settings) Values(target *url.URL) (map[string]string, error) {
	return s.values(target, s.configuration)
}

// FileValues returns URL-matched system/global configuration for clients that
// do not consume repository or command-scoped Git configuration.
func (s *Settings) FileValues(target *url.URL) (map[string]string, error) {
	return s.values(target, renderGitConfiguration(s.fileEntries))
}

func (s *Settings) values(target *url.URL, configuration string) (map[string]string, error) {
	values := map[string]string{}
	if s.executable == "" {
		return values, nil
	}
	// The flattened snapshot already contains inherited command-scope overrides.
	// Strip those environment controls before asking Git to URL-match the snapshot.
	var environment []string
	for _, entry := range s.environment {
		key, _, _ := strings.Cut(entry, "=")
		if key == "GIT_CONFIG_COUNT" || key == "GIT_CONFIG_PARAMETERS" || strings.HasPrefix(key, "GIT_CONFIG_KEY_") || strings.HasPrefix(key, "GIT_CONFIG_VALUE_") {
			continue
		}
		environment = append(environment, entry)
	}
	data, err := runGitConfiguration(s.executable, s.directory, environment, configuration, "config", "--file", "-", "--null", "--get-urlmatch", "http", target.String())
	if err != nil {
		return nil, err
	}
	for _, entry := range parseGitConfiguration(data) {
		value := entry.value
		if entry.implicit {
			value = "true"
		}
		values[strings.TrimPrefix(entry.key, "http.")] = value
	}

	// Git accepts nonzero integers as true and rejects malformed booleans.
	// Query the same flattened snapshot with Git's own type conversion so URL
	// scopes and file-only clients retain those semantics.
	for _, key := range []string{"sslverify", "proxysslverify"} {
		if _, configured := values[key]; !configured {
			continue
		}
		normalized, err := runGitConfiguration(s.executable, s.directory, environment, configuration,
			"config", "--file", "-", "--null", "--type=bool", "--get-urlmatch", "http."+key, target.String())
		if err != nil {
			return nil, err
		}
		value := strings.TrimSuffix(string(normalized), "\x00")
		if value != "true" && value != "false" {
			return nil, errors.New("invalid Git TLS verification setting")
		}
		values[key] = value
	}

	return values, nil
}

// Route resolves native Git routing and trust for one HTTP request.
func (s *Settings) Route(request proxy.Request) (*proxy.OutboundRoute, error) {
	if s.discoveryErr != nil {
		return nil, s.discoveryErr
	}
	return s.route(request, &request.URL, "default", s.unscopedConfiguration, nil)
}

func (s *Settings) route(request proxy.Request, original *url.URL, profile, configuration string, remoteProxy *string) (*proxy.OutboundRoute, error) {
	if s.discoveryErr != nil {
		return nil, s.discoveryErr
	}
	key := profile + "\x00" + request.URL.Scheme + "://" + request.URL.Host
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if existing := s.routes[key]; existing != nil {
		return existing, nil
	}
	if len(s.routes) >= 4096 {
		return nil, errors.New("too many Git network destinations")
	}
	values, err := s.values(original, configuration)
	if err != nil {
		return nil, err
	}
	originalProxy, present := values["proxy"]
	if remoteProxy != nil {
		originalProxy, present = *remoteProxy, true
	}
	if !present {
		originalProxy = s.EnvironmentValue("http_proxy")
		if request.URL.Scheme == "https" {
			originalProxy = firstNonempty(s.EnvironmentValue("https_proxy"), s.EnvironmentValue("HTTPS_PROXY"))
		}
		if originalProxy == "" {
			originalProxy = firstNonempty(s.EnvironmentValue("all_proxy"), s.EnvironmentValue("ALL_PROXY"))
		}
	}
	if bypassesProxy(&request.URL, firstNonempty(s.EnvironmentValue("no_proxy"), s.EnvironmentValue("NO_PROXY"))) {
		originalProxy = ""
	}
	values["proxy"] = originalProxy
	for _, entry := range []struct{ key, value string }{{"sslcainfo", s.caInfo}, {"sslcapath", s.caPath}, {"sslcert", s.cert}, {"sslkey", s.key}} {
		if entry.value != "" {
			values[entry.key] = entry.value
		}
	}
	if s.noVerify {
		values["sslverify"] = "false"
	}
	route, err := s.routeValues(&request.URL, values, true)
	if err != nil {
		return nil, err
	}
	s.routes[key] = route
	return route, nil
}

// RouteValues builds an outbound route from effective Git network values.
// Adapters for other Git clients can supply their own precedence rules. Boolean
// values must be normalized by Values or FileValues before calling this method.
func (s *Settings) RouteValues(target *url.URL, values map[string]string) (*proxy.OutboundRoute, error) {
	return s.routeValues(target, values, false)
}

func (s *Settings) routeValues(target *url.URL, values map[string]string, native bool) (*proxy.OutboundRoute, error) {
	if s.discoveryErr != nil {
		return nil, s.discoveryErr
	}
	upstream, err := proxy.ParseUpstreamProxyURL(values["proxy"])
	if err != nil {
		return nil, err
	}
	route := &proxy.OutboundRoute{ProxyURL: upstream}
	// Do not read certificates for a connection that will never use TLS.
	if target.Scheme == "https" {
		route.TLS, err = s.destinationTLS(values, native)
		if err != nil {
			return nil, err
		}
	}
	if upstream != nil && upstream.Scheme == "https" {
		route.ProxyTLS, err = s.upstreamProxyTLS(values, native)
		if err != nil {
			return nil, err
		}
	}
	return route, nil
}

func (s *Settings) destinationTLS(values map[string]string, native bool) (*tls.Config, error) {
	ca, caPath := values["sslcainfo"], values["sslcapath"]
	paths := []string{gitConfigurationPath(ca, s.directory, s.home), gitConfigurationPath(caPath, s.directory, s.home)}
	roots, paths, err := s.trustMaterial(values, "sslverify", ca != "" || caPath != "", paths, native)
	if err != nil {
		return nil, err
	}
	config, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths: paths, RootCAs: roots,
		ClientCertificatePath: gitConfigurationPath(values["sslcert"], s.directory, s.home),
		ClientKeyPath:         gitConfigurationPath(values["sslkey"], s.directory, s.home),
	})
	if err != nil {
		return nil, err
	}
	enabled, err := verificationEnabled(values, "sslverify")
	if err != nil {
		return nil, err
	}
	config.InsecureSkipVerify = !enabled // Explicit, normalized Git verification setting.
	if native {
		if err := s.pinPublicKey(config, values["pinnedpubkey"]); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func (s *Settings) upstreamProxyTLS(values map[string]string, native bool) (*tls.Config, error) {
	// HTTPS proxy trust and identities are independent of destination TLS.
	// Explicit proxy settings replace the default SSL paths for this connection.
	effective := map[string]string{}
	for _, entry := range []struct{ key, environment string }{{"proxysslcainfo", "GIT_PROXY_SSL_CAINFO"}, {"proxysslcert", "GIT_PROXY_SSL_CERT"}, {"proxysslkey", "GIT_PROXY_SSL_KEY"}} {
		effective[entry.key] = values[entry.key]
		if value := s.EnvironmentValue(entry.environment); value != "" {
			effective[entry.key] = value
		}
	}
	ca := effective["proxysslcainfo"]
	paths := []string{gitConfigurationPath(ca, s.directory, s.home)}
	roots, paths, err := s.trustMaterial(values, "proxysslverify", ca != "", paths, native)
	if err != nil {
		return nil, err
	}
	config, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths: paths, RootCAs: roots,
		ClientCertificatePath: gitConfigurationPath(effective["proxysslcert"], s.directory, s.home),
		ClientKeyPath:         gitConfigurationPath(effective["proxysslkey"], s.directory, s.home),
	})
	if err != nil {
		return nil, err
	}
	enabled, err := verificationEnabled(values, "proxysslverify")
	if err != nil {
		return nil, err
	}
	config.InsecureSkipVerify = !enabled // Explicit, normalized HTTPS-proxy verification setting.
	return config, nil
}

func verificationEnabled(values map[string]string, key string) (bool, error) {
	value, configured := values[key]
	if !configured {
		return true, nil
	}
	// Values and FileValues normalize Git's full boolean syntax. Reject raw
	// or malformed input from other callers rather than disabling verification.
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errors.New("invalid Git TLS verification setting")
	}
}

func gitConfigurationPath(value, directory, home string) string {
	if value == "" {
		return ""
	}
	if home != "" {
		if value == "~" {
			value = home
		} else if strings.HasPrefix(value, "~/") {
			value = filepath.Join(home, value[2:])
		}
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(directory, value)
	}
	return value
}
func environmentValue(environment []string, name string) string {
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		if key == name {
			return value
		}
	}
	return ""
}

func renderGitConfiguration(entries []gitConfigurationEntry) string {
	var snapshot strings.Builder
	for _, entry := range entries {
		if strings.HasPrefix(entry.key, "include.") || strings.HasPrefix(entry.key, "includeif.") {
			continue
		}
		first, last := strings.IndexByte(entry.key, '.'), strings.LastIndexByte(entry.key, '.')
		if first < 0 {
			continue
		}
		section, name := entry.key[:first], entry.key[last+1:]
		snapshot.WriteString("[" + section)
		if first != last {
			snapshot.WriteString(" " + gitQuoted(entry.key[first+1:last]))
		}
		snapshot.WriteString("]\n" + name)
		if !entry.implicit {
			snapshot.WriteString(" = " + gitQuoted(entry.value))
		}
		snapshot.WriteString("\n")
	}
	return snapshot.String()
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// EnvironmentValue returns a value captured before child overrides were applied.
func (s *Settings) EnvironmentValue(name string) string { return environmentValue(s.environment, name) }
