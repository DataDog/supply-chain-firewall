// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type poetryGitSettings struct {
	executable                     string
	directory                      string
	home                           string
	environment                    []string
	configuration                  string
	entries                        []gitConfigurationEntry
	fileEntries                    []gitConfigurationEntry
	native                         bool
	envProxy                       string
	httpProxy, httpsProxy, noProxy string
	caInfo, caPath, cert, key      string
	noVerify                       bool
	proxyTLS                       *tls.Config
	discoveryErr                   error
	sslPaths                       []string
	mutex                          sync.Mutex
	routes                         map[string]*proxy.OutboundRoute
}

type gitConfigurationEntry struct {
	key, value string
	implicit   bool
}

type boundedGitOutput struct{ bytes.Buffer }

func (b *boundedGitOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxPoetryConfigurationBytes {
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

func readPoetryGitSettings(settings poetrySettings) (*poetryGitSettings, error) {
	s := &poetryGitSettings{directory: settings.workingDirectory, environment: os.Environ(), routes: map[string]*proxy.OutboundRoute{}}
	if info, err := os.Stat(s.directory); err != nil || !info.IsDir() {
		s.directory, _ = os.Getwd()
	}
	s.home, _ = os.UserHomeDir()
	s.native = poetryBoolean(settings.get("system-git-client"), poetryBoolean(settings.get("experimental", "system-git-client"), false))
	s.httpProxy = os.Getenv("http_proxy")
	s.httpsProxy = firstNonempty(os.Getenv("https_proxy"), os.Getenv("HTTPS_PROXY"))
	s.noProxy = os.Getenv("no_proxy")
	if s.native {
		s.noProxy = firstNonempty(s.noProxy, os.Getenv("NO_PROXY"))
	}
	// Dulwich's urllib3 manager prefers lowercase HTTPS_PROXY for every scheme.
	for _, name := range []string{"https_proxy", "http_proxy", "all_proxy"} {
		if value := os.Getenv(name); value != "" {
			s.envProxy = value
			break
		}
	}
	s.caInfo, s.caPath, s.cert, s.key = os.Getenv("GIT_SSL_CAINFO"), os.Getenv("GIT_SSL_CAPATH"), os.Getenv("GIT_SSL_CERT"), os.Getenv("GIT_SSL_KEY")
	_, s.noVerify = os.LookupEnv("GIT_SSL_NO_VERIFY")
	executable, err := exec.LookPath("git")
	if err != nil {
		return s, nil
	}
	s.executable = executable
	data, err := runGitConfiguration(executable, s.directory, s.environment, "", "config", "--includes", "--null", "--show-scope", "--list")
	if err != nil {
		s.discoveryErr = err
		return s, nil
	}
	records := bytes.Split(data, []byte{0})
	for i := 0; i+1 < len(records); i += 2 {
		parsed := parseGitConfiguration(append(slices.Clone(records[i+1]), 0))
		s.entries = append(s.entries, parsed...)
		if string(records[i]) == "global" || string(records[i]) == "system" {
			s.fileEntries = append(s.fileEntries, parsed...)
		}
	}
	selected := s.entries
	if !s.native {
		selected = s.fileEntries
	}
	s.configuration = renderGitConfiguration(selected)

	paths := []string{s.caInfo, s.caPath, os.Getenv("SSL_CERT_FILE")}
	paths = append(paths, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)
	s.sslPaths = append([]string{os.Getenv("SSL_CERT_FILE")}, filepath.SplitList(os.Getenv("SSL_CERT_DIR"))...)
	s.proxyTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{CABundlePaths: paths})
	if err != nil {
		s.discoveryErr = err
		s.proxyTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
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

func (s *poetryGitSettings) isRequest(request proxy.Request) bool {
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

func (s *poetryGitSettings) values(target *url.URL) (map[string]string, error) {
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
	data, err := runGitConfiguration(s.executable, s.directory, environment, s.configuration, "config", "--file", "-", "--null", "--get-urlmatch", "http", target.String())
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
	return values, nil
}

func (s *poetryGitSettings) route(request proxy.Request) (*proxy.OutboundRoute, error) {
	if s.discoveryErr != nil {
		return nil, s.discoveryErr
	}
	key := request.URL.Scheme + "://" + request.URL.Host + request.URL.Path
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if existing := s.routes[key]; existing != nil {
		return existing, nil
	}
	if len(s.routes) >= 4096 {
		return nil, errors.New("too many Git network destinations")
	}
	values, err := s.values(&request.URL)
	if err != nil {
		return nil, err
	}
	originalProxy, present := values["proxy"]
	if s.native {
		for _, entry := range s.entries {
			if entry.key == "remote.origin.proxy" {
				originalProxy, present = entry.value, true
			}
		}
		if !present {
			originalProxy = s.httpProxy
			if request.URL.Scheme == "https" {
				originalProxy = s.httpsProxy
			}
			if originalProxy == "" {
				originalProxy = environmentValue(s.environment, "all_proxy")
				if originalProxy == "" {
					originalProxy = environmentValue(s.environment, "ALL_PROXY")
				}
			}
		}
		// NO_PROXY is honored by libcurl even for an explicitly configured proxy.
		if poetryBypassesProxy(&request.URL, s.noProxy) {
			originalProxy = ""
		}
	} else if s.envProxy != "" && !poetryBypassesProxy(&request.URL, s.noProxy) {
		originalProxy = s.envProxy
	}
	var upstream *url.URL
	if originalProxy != "" {
		upstream, err = url.Parse(poetryProxyURL(originalProxy))
		if err != nil || upstream.Hostname() == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
			return nil, errors.New("unsupported Git proxy URL")
		}
	}
	ca, caPath, certificate, privateKey := values["sslcainfo"], values["sslcapath"], values["sslcert"], values["sslkey"]
	if s.caInfo != "" && (s.native || ca == "") {
		ca = s.caInfo
	}
	if s.caPath != "" {
		caPath = s.caPath
	}
	if s.cert != "" {
		certificate = s.cert
	}
	if s.key != "" {
		privateKey = s.key
	}
	paths := []string{gitConfigurationPath(ca, s.directory, s.home), gitConfigurationPath(caPath, s.directory, s.home)}
	if ca == "" && caPath == "" {
		paths = append(paths, s.sslPaths...)
	}
	tlsConfig, err := proxy.NewTLSConfig(proxy.TLSConfigOptions{
		CABundlePaths: paths, ReplaceSystemRoots: ca != "" || caPath != "",
		ClientCertificatePath: gitConfigurationPath(certificate, s.directory, s.home), ClientKeyPath: gitConfigurationPath(privateKey, s.directory, s.home),
	})
	if err != nil {
		return nil, err
	}
	verification, configured := values["sslverify"]
	tlsConfig.InsecureSkipVerify = configured && !poetryBoolean(verification, true) // Explicit URL-scoped Git verification setting.
	if s.native && s.noVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	for _, entry := range []struct{ key, environment string }{{"proxysslcainfo", "GIT_PROXY_SSL_CAINFO"}, {"proxysslcert", "GIT_PROXY_SSL_CERT"}, {"proxysslkey", "GIT_PROXY_SSL_KEY"}} {
		if value := environmentValue(s.environment, entry.environment); value != "" {
			values[entry.key] = value
		}
	}
	proxyTLS := s.proxyTLS
	if values["proxysslcainfo"] != "" || values["proxysslcert"] != "" {
		proxyTLS, err = proxy.NewTLSConfig(proxy.TLSConfigOptions{CABundlePaths: []string{gitConfigurationPath(values["proxysslcainfo"], s.directory, s.home)}, ReplaceSystemRoots: values["proxysslcainfo"] != "", ClientCertificatePath: gitConfigurationPath(values["proxysslcert"], s.directory, s.home), ClientKeyPath: gitConfigurationPath(values["proxysslkey"], s.directory, s.home)})
		if err != nil {
			return nil, err
		}
	}
	if value, present := values["proxysslverify"]; present && !poetryBoolean(value, true) {
		proxyTLS = proxyTLS.Clone()
		proxyTLS.InsecureSkipVerify = true
	}
	route := &proxy.OutboundRoute{ProxyURL: upstream, TLS: tlsConfig, ProxyTLS: proxyTLS}
	s.routes[key] = route
	return route, nil
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

func (s *poetryGitSettings) childOverrides(overrides map[string]string, config proxy.ClientConfig) error {
	count := 0
	if value := environmentValue(s.environment, "GIT_CONFIG_COUNT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 || parsed > 4096 {
			return errors.New("invalid inherited Git configuration count")
		}
		count = parsed
	}
	for index := 0; index < count; index++ {
		for _, prefix := range []string{"GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"} {
			key := prefix + strconv.Itoa(index)
			overrides[key] = environmentValue(s.environment, key)
		}
	}
	forced := map[string]string{"http.proxy": config.URL, "http.sslcainfo": config.CACertificatePath, "http.sslcapath": "", "http.sslverify": "true"}
	for _, entry := range s.entries {
		if strings.HasPrefix(entry.key, "http.") {
			prefix := entry.key[:strings.LastIndexByte(entry.key, '.')+1]
			if value, ok := forced["http."+entry.key[strings.LastIndexByte(entry.key, '.')+1:]]; ok {
				forced[prefix+entry.key[strings.LastIndexByte(entry.key, '.')+1:]] = value
			}
		}
		if strings.HasPrefix(entry.key, "remote.") && strings.HasSuffix(entry.key, ".proxy") {
			forced[entry.key] = config.URL
		}
	}
	// Append rather than replacing caller-provided Git command-scope settings.
	parameters := environmentValue(s.environment, "GIT_CONFIG_PARAMETERS")
	keys := make([]string, 0, len(forced))
	for key := range forced {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		value := forced[key]
		overrides["GIT_CONFIG_KEY_"+strconv.Itoa(count)] = key
		overrides["GIT_CONFIG_VALUE_"+strconv.Itoa(count)] = value
		count++
		parameters += " '" + strings.ReplaceAll(key+"="+value, "'", "'\\''") + "'"
	}
	// Modern Dulwich reads GIT_CONFIG_GLOBAL but does not apply command-scope
	// Git overrides. An ephemeral flattened file covers both clients without
	// changing HOME, the user's files, includes, or credential helper settings.
	snapshot := slices.Clone(s.fileEntries)
	for _, key := range keys {
		snapshot = append(snapshot, gitConfigurationEntry{key: key, value: forced[key]})
	}
	path := filepath.Join(filepath.Dir(config.CACertificatePath), "gitconfig")
	if err := os.WriteFile(path, []byte(renderGitConfiguration(snapshot)), 0600); err != nil {
		return errors.New("could not prepare invocation Git settings")
	}
	overrides["GIT_CONFIG_GLOBAL"] = path
	overrides["GIT_CONFIG_SYSTEM"] = os.DevNull
	overrides["GIT_CONFIG_NOSYSTEM"] = "1"
	overrides["GIT_CONFIG_COUNT"] = strconv.Itoa(count)
	overrides["GIT_CONFIG_PARAMETERS"] = strings.TrimSpace(parameters)
	overrides["GIT_SSL_CAPATH"] = ""
	return nil
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
