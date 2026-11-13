// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	"golang.org/x/net/http/httpproxy"
)

type npmVerificationSettings map[string]string

func configKey(s string) string {
	if strings.HasPrefix(s, "//") || strings.HasPrefix(s, "@") {
		return s
	}
	return strings.ToLower(strings.ReplaceAll(s, "_", "-"))
}
func npmCLIConfig(command []string) npmVerificationSettings {
	out := npmVerificationSettings{}
	for i := 0; i < len(command); i++ {
		a := command[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		key, boolean, e := npmOption(a)
		if e != nil {
			continue
		}
		_, value, eq := strings.Cut(a, "=")
		if !eq {
			value = "true"
			if !boolean && i+1 < len(command) {
				i++
				value = command[i]
			} else if boolean && i+1 < len(command) && npmBooleanValue(key, command[i+1]) {
				i++
				value = command[i]
			}
		}
		if strings.HasPrefix(a, "--no-") {
			value = "false"
		}
		out[configKey(key)] = value
	}
	return out
}

// verificationSettings reads network settings for SCFW's HTTP requests only.
// npm retains ownership of command execution and preflight configuration.
func (n Npm) verificationSettings(command []string) (npmVerificationSettings, error) {
	if e := npmCommandError(command); e != nil {
		return nil, e
	}
	cli := npmCLIConfig(command)
	if cli["prefix"] != "" {
		return nil, errors.New("npm --prefix overrides are unsupported by artifact verification")
	}
	env := npmVerificationSettings{}
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if ok && strings.HasPrefix(strings.ToLower(k), "npm_config_") {
			env[configKey(k[len("npm_config_"):])] = v
		}
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	user := filepath.Join(home, ".npmrc")
	prefix := filepath.Dir(filepath.Dir(n.executable))
	if node, e := exec.LookPath("node"); e == nil {
		if physical, e := filepath.EvalSymlinks(node); e == nil {
			prefix = filepath.Dir(filepath.Dir(physical))
		}
	}
	builtin := npmVerificationSettings{}
	if physical, e := filepath.EvalSymlinks(n.executable); e == nil {
		_ = readNpmConfig(filepath.Join(filepath.Dir(filepath.Dir(physical)), "npmrc"), builtin)
	}
	root, e := n.verificationProjectRoot()
	if e != nil {
		return nil, e
	}
	project := npmVerificationSettings{}
	globalMode := env["global"] == "true" || env["location"] == "global"
	if v, ok := cli["global"]; ok {
		globalMode = v == "true"
	}
	if cli["location"] == "global" {
		globalMode = true
	}
	if !globalMode && root != "" {
		if e := readNpmConfig(filepath.Join(root, ".npmrc"), project); e != nil {
			return nil, e
		}
	}
	for _, layer := range []npmVerificationSettings{builtin, project, env, cli} {
		if v := layer["userconfig"]; v != "" {
			user = v
		}
		if v := layer["prefix"]; v != "" {
			prefix = v
		}
	}
	userSettings := npmVerificationSettings{}
	if e := readNpmConfig(user, userSettings); e != nil {
		return nil, e
	}
	for _, layer := range []npmVerificationSettings{userSettings, project, env, cli} {
		if value := layer["prefix"]; value != "" {
			prefix = value
		}
	}
	global := filepath.Join(prefix, "etc", "npmrc")
	for _, layer := range []npmVerificationSettings{builtin, userSettings, project, env, cli} {
		if v := layer["globalconfig"]; v != "" {
			global = v
		}
	}
	globalSettings := npmVerificationSettings{}
	if e := readNpmConfig(global, globalSettings); e != nil {
		return nil, e
	}
	settings := npmVerificationSettings{"registry": "https://registry.npmjs.org/"}
	for _, layer := range []npmVerificationSettings{builtin, globalSettings, userSettings, project, env, cli} {
		for k, v := range layer {
			settings[k] = v
		}
	}
	if globalMode {
		settings["global"] = "true"
	}

	for key, value := range settings {
		if key == "cafile" || key == "userconfig" || key == "globalconfig" || strings.HasSuffix(key, ":certfile") || strings.HasSuffix(key, ":keyfile") {
			settings[key] = npmAbsolutePath(value)
		}
	}
	return settings, nil
}
func readNpmConfig(file string, out npmVerificationSettings) error {
	f, e := os.Open(file)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return errors.New("cannot read npm configuration")
	}
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "\"'")
		v = os.Expand(v, func(k string) string { return os.Getenv(k) })
		key := configKey(strings.TrimSpace(k))
		if strings.HasSuffix(key, "[]") {
			key = strings.TrimSuffix(key, "[]")
			if previous, ok := out[key]; ok {
				v = previous + "\n" + v
			}
		}
		out[key] = v
	}
	if scanner.Err() != nil {
		return errors.New("invalid npm configuration")
	}
	return nil
}
func (s npmVerificationSettings) registry(name string) string {
	value := s["registry"]
	if strings.HasPrefix(name, "@") {
		scope, _, _ := strings.Cut(name, "/")
		if scoped := s[scope+":registry"]; scoped != "" {
			value = scoped
		}
	}
	if normalized, e := canonicalNpmURL(value); e == nil {
		return normalized
	}
	return value
}

func (s npmVerificationSettings) authorization(u *url.URL) string {
	best := ""
	for key := range s {
		if !strings.HasPrefix(key, "//") {
			continue
		}
		index := strings.LastIndex(key, ":")
		if index < 2 {
			continue
		}
		scope := key[:index]
		if s[scope+":_authToken"] == "" && s[scope+":_auth"] == "" && (s[scope+":username"] == "" || s[scope+":_password"] == "") {
			continue
		}
		parsed, e := url.Parse(u.Scheme + ":" + scope)
		if e != nil || !strings.EqualFold(parsed.Host, u.Host) {
			continue
		}
		prefix := strings.TrimRight(parsed.EscapedPath(), "/")
		if u.EscapedPath() != prefix && !strings.HasPrefix(u.EscapedPath(), prefix+"/") {
			continue
		}
		if len(scope) > len(best) {
			best = scope
		}
	}
	if best == "" {
		return ""
	}
	if v := s[best+":_authToken"]; v != "" {
		return "Bearer " + v
	}
	if v := s[best+":_auth"]; v != "" {
		return "Basic " + v
	}
	if username := s[best+":username"]; username != "" {
		password, e := base64.StdEncoding.DecodeString(s[best+":_password"])
		if e == nil {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+string(password)))
		}
	}
	return ""
}
func (s npmVerificationSettings) transportOptions() (proxy.Options, error) {
	cfg := httpproxy.FromEnvironment()
	if v, ok := s["proxy"]; ok {
		if v == "false" {
			v = ""
		}
		cfg.HTTPProxy = v
		cfg.HTTPSProxy = v
	}
	if v, ok := s["https-proxy"]; ok {
		if v == "false" {
			v = ""
		}
		cfg.HTTPSProxy = v
	}
	if v, ok := s["noproxy"]; ok {
		cfg.NoProxy = v
	}
	for _, v := range []string{cfg.HTTPProxy, cfg.HTTPSProxy} {
		if _, e := proxy.ParseUpstreamProxyURL(v); e != nil {
			return proxy.Options{}, e
		}
	}

	var roots *x509.CertPool
	_, explicitCA := s["ca"]
	if s["cafile"] != "" || explicitCA {
		roots = x509.NewCertPool()
	}
	tlsConfig, e := proxy.NewTLSConfig(proxy.TLSConfigOptions{RootCAs: roots, CABundlePaths: []string{s["cafile"]}})
	if e != nil {
		return proxy.Options{}, e
	}
	if s["strict-ssl"] == "false" {
		tlsConfig.InsecureSkipVerify = true
	}
	if s["ca"] != "" && !tlsConfig.RootCAs.AppendCertsFromPEM([]byte(strings.ReplaceAll(s["ca"], "\\n", "\n"))) {
		return proxy.Options{}, errors.New("invalid npm inline CA")
	}
	if s["cert"] != "" || s["key"] != "" {
		certificate, e := tls.X509KeyPair([]byte(strings.ReplaceAll(s["cert"], "\\n", "\n")), []byte(strings.ReplaceAll(s["key"], "\\n", "\n")))
		if e != nil {
			return proxy.Options{}, errors.New("invalid npm client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	options := proxy.Options{Upstream: *cfg, UpstreamTLS: tlsConfig}

	profiles := map[string]*tls.Config{}
	for k, certfile := range s {
		if !strings.HasPrefix(k, "//") || !strings.HasSuffix(k, ":certfile") {
			continue
		}
		scope := strings.TrimSuffix(k, ":certfile")
		profile := tlsConfig.Clone()
		keyfile := s[scope+":keyfile"]
		if keyfile == "" {
			keyfile = certfile
		}
		certificate, e := tls.LoadX509KeyPair(certfile, keyfile)
		if e != nil {
			return proxy.Options{}, errors.New("cannot load scoped npm client certificate")
		}
		profile.Certificates = []tls.Certificate{certificate}
		profiles[scope] = profile
	}
	for k := range s {
		if strings.HasSuffix(k, ":keyfile") {
			scope := strings.TrimSuffix(k, ":keyfile")
			if profiles[scope] == nil {
				return proxy.Options{}, errors.New("scoped npm client certificate missing")
			}
		}
	}
	if len(profiles) > 0 {
		var mu sync.Mutex
		routes := map[string]*proxy.OutboundRoute{}
		options.RouteForRequest = func(request proxy.Request) (*proxy.OutboundRoute, error) {
			best := ""
			selected := tlsConfig
			for scope, profile := range profiles {
				u, e := url.Parse(request.URL.Scheme + ":" + scope)
				prefix := ""
				if e == nil {
					prefix = strings.TrimRight(u.EscapedPath(), "/")
				}
				if e == nil && strings.EqualFold(u.Host, request.URL.Host) && (request.URL.EscapedPath() == prefix || strings.HasPrefix(request.URL.EscapedPath(), prefix+"/")) && len(scope) > len(best) {
					best = scope
					selected = profile
				}
			}
			upstream, e := cfg.ProxyFunc()(&request.URL)
			if e != nil {
				return nil, e
			}
			key := best + "|"
			if upstream != nil {
				key += upstream.String()
			}
			mu.Lock()
			defer mu.Unlock()
			if route := routes[key]; route != nil {
				return route, nil
			}
			proxyTLS := tlsConfig.Clone()
			proxyTLS.Certificates = nil
			route := &proxy.OutboundRoute{ProxyURL: upstream, TLS: selected, ProxyTLS: proxyTLS}
			routes[key] = route
			return route, nil
		}
	}
	return options, nil
}

func npmAbsolutePath(value string) string {
	if value == "" || value == "false" {
		return value
	}
	if strings.HasPrefix(value, "~/") {
		if home, e := os.UserHomeDir(); e == nil {
			value = filepath.Join(home, value[2:])
		}
	}
	if absolute, e := filepath.Abs(value); e == nil {
		return absolute
	}
	return value
}

func (n Npm) verificationProjectRoot() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Request configuration also applies before the first package.json exists.
	// Keep this separate from the original temporary-project manifest check.
	output, err := exec.CommandContext(ctx, n.Executable(), "prefix").Output()
	if err != nil {
		return "", errors.New("cannot determine npm verification configuration directory")
	}
	prefix := strings.TrimSpace(string(output))
	if prefix == "" {
		return "", errors.New("npm verification configuration directory unavailable")
	}
	if physical, err := filepath.EvalSymlinks(prefix); err == nil {
		prefix = physical
	}
	return prefix, nil
}
