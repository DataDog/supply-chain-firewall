// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"errors"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// artifactURLMapperForSettings preserves npm's effective resolved source for
// independent verification requests, including native registry-host substitution.
func (n Npm) artifactURLMapperForSettings(s npmVerificationSettings) func(string) (string, error) {
	legacy := n.version.Major == 7
	known := n.version.Major == 7 || n.version.Major >= 9
	if n.version.Major == 8 {
		if physical, e := filepath.EvalSymlinks(n.executable); e == nil {
			file, e := os.Open(filepath.Join(filepath.Dir(filepath.Dir(physical)), "node_modules", "pacote", "lib", "remote.js"))
			if e == nil {
				body, err := io.ReadAll(io.LimitReader(file, 128<<10))
				_ = file.Close()
				if err == nil {
					if strings.Contains(string(body), "this.replaceRegistryHost") {
						legacy = false
						known = true
					} else if strings.Contains(string(body), "const magic") {
						legacy = true
						known = true
					}
				}
			}
		}
	}
	registry := strings.TrimRight(s["registry"], "/")
	replace := s["replace-registry-host"]
	if replace == "" || replace == "npmjs" {
		replace = "registry.npmjs.org"
	}
	magic := func(value string) bool {
		return strings.HasPrefix(value, "https://registry.npmjs.org/") || strings.HasPrefix(value, "http://registry.npmjs.org/")
	}

	return func(source string) (string, error) {
		original, e := url.Parse(source)
		if e != nil || original.Host == "" || (original.Scheme != "http" && original.Scheme != "https") {
			return source, nil
		}
		canonical, e := canonicalNpmURL(source)
		if e != nil {
			return "", e
		}
		u, _ := url.Parse(canonical)
		legacyMap := func() (string, error) {
			if !magic(source) || magic(registry+"/") {
				return canonical, nil
			}
			parts := strings.SplitN(source, "://registry.npmjs.org/", 2)
			if len(parts) != 2 {
				return canonical, nil
			}
			return canonicalNpmURL(registry + "/" + parts[1])
		}
		modernMap := func() (string, error) {
			if replace == "never" || (replace != "always" && replace != u.Host) {
				return canonical, nil
			}
			base, e := url.Parse(registry)
			if e != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
				return "", errors.New("invalid npm artifact registry")
			}
			if strings.HasPrefix(u.EscapedPath(), "//") {
				return "", errors.New("unsupported npm network-path artifact reference")
			}
			base.Path = u.Path
			base.RawPath = u.RawPath
			base.RawQuery = ""
			base.ForceQuery = false
			base.Fragment = ""
			base.RawFragment = ""
			return canonicalNpmURL(base.String())
		}
		if !known {
			old, oldErr := legacyMap()
			current, currentErr := modernMap()
			if oldErr == nil && currentErr == nil && old == current {
				return current, nil
			}
			return "", errors.New("npm registry-host substitution cannot be established for this launcher")
		}
		if legacy {
			return legacyMap()
		}
		return modernMap()
	}
}

// canonicalNpmURL models the HTTP URL form used by Node's WHATWG URL loader:
// host case/default ports, dot segments (including encoded dots), and fragments.
// It preserves escaped non-dot path bytes, query order, and signed parameters.
func canonicalNpmURL(source string) (string, error) {
	u, e := url.Parse(source)
	if e != nil {
		return "", errors.New("invalid npm HTTP URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("unsupported npm HTTP URL")
	}
	if strings.ContainsRune(source, 92) {
		return "", errors.New("ambiguous npm HTTP URL")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("invalid npm HTTP host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") && ip.To4() != nil {
			return "", errors.New("unsupported mapped npm HTTP host")
		}
		host = ip.String()
	} else {
		ascii := true
		for _, c := range host {
			if c > 127 {
				ascii = false
				break
			}
		}
		if !ascii {
			host, e = idna.Lookup.ToASCII(host)
			if e != nil {
				return "", errors.New("invalid npm HTTP host")
			}
		}
		host = strings.ToLower(host)
		last := strings.TrimSuffix(host, ".")
		if i := strings.LastIndexByte(last, '.'); i >= 0 {
			last = last[i+1:]
		}
		numeric := last != ""
		for _, c := range last {
			if c < '0' || c > '9' {
				numeric = false
			}
		}
		if numeric || strings.HasPrefix(last, "0x") {
			return "", errors.New("unsupported numeric npm HTTP host")
		}
	}
	port := u.Port()
	if port != "" {
		number, e := strconv.Atoi(port)
		if e != nil || number < 0 || number > 65535 {
			return "", errors.New("invalid npm HTTP port")
		}
		port = strconv.Itoa(number)
	}

	if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	raw := u.EscapedPath()
	if raw == "" {
		raw = "/"
	}
	segments := strings.Split(raw, "/")
	out := []string{}
	for i, segment := range segments {
		dot := strings.ReplaceAll(strings.ToLower(segment), "%2e", ".")
		switch dot {
		case ".":
			if i == len(segments)-1 {
				out = append(out, "")
			}
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if i == len(segments)-1 {
				out = append(out, "")
			}
		default:
			out = append(out, segment)
		}
	}
	raw = strings.Join(out, "/")
	if raw == "" {
		raw = "/"
	}
	decoded, e := url.PathUnescape(raw)
	if e != nil {
		return "", errors.New("invalid npm HTTP path")
	}
	u.Path = decoded
	u.RawPath = raw
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), nil
}
