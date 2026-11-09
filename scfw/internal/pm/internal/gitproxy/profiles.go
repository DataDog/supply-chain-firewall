// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type routeProfile struct {
	name          string
	scope, target url.URL
}

func (s *Settings) discoverProfiles() {
	scopes := map[string]url.URL{}
	for _, entry := range s.entries {
		if !strings.HasPrefix(entry.key, "http.") {
			continue
		}
		last := strings.LastIndexByte(entry.key, '.')
		if last <= len("http.") || !networkSetting(entry.key[last+1:]) {
			continue
		}
		scope, err := url.Parse(entry.key[len("http."):last])
		if err != nil || (scope.Scheme != "http" && scope.Scheme != "https") || scope.Host == "" {
			continue
		}
		if !normalizeScope(scope) {
			continue
		}
		scope.Scheme = strings.ToLower(scope.Scheme)
		port := scope.Port()
		if port == "" {
			port = "80"
			if scope.Scheme == "https" {
				port = "443"
			}
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			continue
		}
		port = strconv.Itoa(number)
		scope.Host = net.JoinHostPort(strings.ToLower(scope.Hostname()), port)
		if scope.Path == "" {
			scope.Path = "/"
		}
		if scope.User != nil {
			scope.User = url.User(scope.User.Username())
		}
		scopes[scope.String()] = *scope
	}
	// Intersections let Git's own proxy selection preserve per-key combinations
	// of host wildcards, paths, and usernames. Each selected listener then binds
	// the original configuration; generated paths and redirects cannot reselect it.
	var addresses []string
	for address := range scopes {
		addresses = append(addresses, address)
	}
	slices.Sort(addresses)
	for index := 0; index < len(addresses); index++ {
		if len(addresses) > 128 {
			s.discoveryErr = errors.New("too many Git configuration profiles")
			return
		}
		for other := 0; other < index; other++ {
			scope, ok := intersectScopes(scopes[addresses[index]], scopes[addresses[other]])
			if !ok {
				continue
			}
			address := scope.String()
			if _, exists := scopes[address]; !exists {
				scopes[address] = scope
				addresses = append(addresses, address)
			}
		}
	}
	slices.Sort(addresses)
	// A representative wildcard label must not accidentally select another
	// configured literal hostname. All actual overlaps have their own profile.
	label := "scfw-profile"
	for {
		present := false
		for _, scope := range scopes {
			if strings.Contains(scope.Host, label) {
				present = true
				break
			}
		}
		if !present {
			break
		}
		label += "x"
	}
	for index, address := range addresses {
		scope := scopes[address]
		target := scope
		target.Host = strings.ReplaceAll(target.Host, "*", label)
		s.profiles = append(s.profiles, routeProfile{name: "git-scope-" + strconv.Itoa(index), scope: scope, target: target})
	}
}

// Git normalizes escapes and dot segments before testing path prefixes. Keep
// encoded delimiters distinct, and retain repeated and trailing slashes.
func normalizeScope(scope *url.URL) bool {
	escaped := scope.EscapedPath()
	var normalized strings.Builder
	for index := 0; index < len(escaped); index++ {
		if escaped[index] != '%' {
			normalized.WriteByte(escaped[index])
			continue
		}
		if index+2 >= len(escaped) {
			return false
		}
		value, err := strconv.ParseUint(escaped[index+1:index+3], 16, 8)
		if err != nil {
			return false
		}
		character := byte(value)
		if character <= 0x20 || character >= 0x7f || strings.ContainsRune(":/?#[]@!$&'()*+,;=\"%{}|\\^`", rune(character)) {
			normalized.WriteByte('%')
			normalized.WriteString(strings.ToUpper(escaped[index+1 : index+3]))
		} else {
			normalized.WriteByte(character)
		}
		index += 2
	}
	var segments []string
	parts := strings.Split(normalized.String(), "/")
	for index, part := range parts {
		switch part {
		case ".":
			if index == len(parts)-1 {
				segments = append(segments, "")
			}
		case "..":
			if len(segments) <= 1 {
				return false
			}
			segments = segments[:len(segments)-1]
			if index == len(parts)-1 {
				segments = append(segments, "")
			}
		default:
			segments = append(segments, part)
		}
	}
	scope.RawPath = strings.Join(segments, "/")
	var err error
	scope.Path, err = url.PathUnescape(scope.RawPath)
	return err == nil
}

func networkSetting(key string) bool {
	switch key {
	case "proxy", "sslcainfo", "sslcapath", "sslcert", "sslkey", "sslverify", "pinnedpubkey", "proxysslcainfo", "proxysslcert", "proxysslkey", "proxysslverify":
		return true
	default:
		return false
	}
}

func intersectScopes(a, b url.URL) (url.URL, bool) {
	if a.Scheme != b.Scheme || a.Port() != b.Port() {
		return url.URL{}, false
	}
	left, right := strings.Split(a.Hostname(), "."), strings.Split(b.Hostname(), ".")
	if len(left) != len(right) {
		return url.URL{}, false
	}
	for index := range left {
		if left[index] == "*" {
			left[index] = right[index]
		} else if right[index] != "*" && left[index] != right[index] {
			return url.URL{}, false
		}
	}
	scope := a
	scope.Host = net.JoinHostPort(strings.Join(left, "."), a.Port())
	if a.User != nil && b.User != nil && a.User.Username() != b.User.Username() {
		return url.URL{}, false
	}
	if b.User != nil {
		scope.User = b.User
	}
	first, second := a.EscapedPath(), b.EscapedPath()
	if first != second {
		if strings.HasPrefix(second, strings.TrimSuffix(first, "/")+"/") {
			scope.Path, scope.RawPath = b.Path, b.RawPath
		} else if !strings.HasPrefix(first, strings.TrimSuffix(second, "/")+"/") {
			return url.URL{}, false
		}
	}
	return scope, true
}

// AdditionalClients supplies invocation listeners for native Git URL scopes.
// Git selects a listener against the command's original URL, then the listener
// retains that configuration across generated requests and redirects. Adapters
// flatten these clients into the invocation's additional clients.
func (s *Settings) AdditionalClients() map[string]proxy.Options {
	clients := map[string]proxy.Options{}
	for _, profile := range s.profiles {
		clients[profile.name] = proxy.Options{RouteForRequest: func(request proxy.Request) (*proxy.OutboundRoute, error) {
			return s.route(request, &profile.target, profile.name, s.configuration, nil)
		}}
	}
	for _, profile := range s.remoteProfiles {
		clients[profile.name] = proxy.Options{RouteForRequest: func(request proxy.Request) (*proxy.OutboundRoute, error) {
			original, configuration := &request.URL, s.unscopedConfiguration
			if profile.scope != nil {
				original, configuration = &profile.scope.target, s.configuration
			}
			return s.route(request, original, profile.name, configuration, &profile.upstream)
		}}
	}
	return clients
}

func (s *Settings) interceptionCA(config proxy.ClientConfig) (string, error) {
	names := make([]string, 0, len(s.profiles)+len(s.remoteProfiles))
	for _, profile := range s.profiles {
		names = append(names, profile.name)
	}
	for _, profile := range s.remoteProfiles {
		names = append(names, profile.name)
	}
	if len(names) == 0 {
		return config.CACertificatePath, nil
	}
	bundle, err := os.ReadFile(config.CACertificatePath)
	if err != nil {
		return "", errors.New("could not read invocation Git CA")
	}
	for _, name := range names {
		client, ok := config.AdditionalClients[name]
		if !ok {
			return "", errors.New("missing Git configuration proxy")
		}
		ca, err := os.ReadFile(client.CACertificatePath)
		if err != nil {
			return "", errors.New("could not read invocation Git identity CA")
		}
		bundle = append(append(bundle, '\n'), ca...)
	}
	path := filepath.Join(filepath.Dir(config.CACertificatePath), "git-identity-ca.pem")
	if err := os.WriteFile(path, bundle, 0600); err != nil {
		return "", errors.New("could not prepare invocation Git identity CAs")
	}
	return path, nil
}

func isRemoteProxy(key string) bool {
	return strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".proxy")
}
func isOutboundOnly(key string) bool {
	return isRemoteProxy(key) || (strings.HasPrefix(key, "http.") && (strings.HasSuffix(key, ".pinnedpubkey") || strings.HasSuffix(key, ".proxy")))
}
func isInclude(key string) bool { return key == "include.path" || strings.HasPrefix(key, "includeif.") }
func gitParameter(key, value string) string {
	return " '" + strings.ReplaceAll(key+"="+value, "'", "'\\''") + "'"
}
