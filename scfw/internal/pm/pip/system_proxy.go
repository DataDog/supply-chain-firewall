// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type systemProxySettings struct {
	proxies       map[string]string
	exceptions    []string
	excludeSimple bool
}

// urllib uses macOS SystemConfiguration only when its environment proxy map
// is empty. Even NO_PROXY alone suppresses the native fallback.
func pipProxies(readSystem func() (systemProxySettings, error)) (systemProxySettings, error) {
	if proxies := pipEnvironmentProxies(); len(proxies) != 0 {
		return systemProxySettings{proxies: proxies}, nil
	}
	return readSystem()
}

func readSystemProxies() (systemProxySettings, error) {
	if runtime.GOOS != "darwin" {
		return systemProxySettings{}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// scutil reads the same SCDynamicStoreCopyProxies dictionary as _scproxy,
	// without requiring cgo or a Python interpreter. Ignore scutil's optional
	// BYPASS_GLOBAL_PROXY switch, which urllib does not consult.
	command := exec.CommandContext(ctx, "/usr/sbin/scutil", "--proxy")
	command.Env = []string{}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "BYPASS_GLOBAL_PROXY=") {
			command.Env = append(command.Env, item)
		}
	}
	command.WaitDelay = time.Second
	output, err := command.Output()
	if err != nil {
		return systemProxySettings{}, errors.New("could not read macOS system proxy settings")
	}
	return parseSystemProxies(string(output))
}

func parseSystemProxies(output string) (systemProxySettings, error) {
	settings := systemProxySettings{proxies: map[string]string{}}
	output = strings.TrimSpace(output)
	if output == "No proxy configuration available" {
		return settings, nil
	}
	if !strings.HasPrefix(output, "<dictionary> {\n") {
		return settings, errors.New("invalid macOS system proxy settings")
	}
	values := map[string]string{}
	depth, exceptions := 0, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "}" {
			depth--
			if depth < 2 {
				exceptions = false
			}
			continue
		}
		key, value, _ := strings.Cut(line, " : ")
		if depth == 1 {
			values[key] = value
			exceptions = key == "ExceptionsList" && value == "<array> {"
		} else if depth == 2 && exceptions {
			settings.exceptions = append(settings.exceptions, value)
		}
		if strings.HasSuffix(line, " {") {
			depth++
		}
	}
	if depth != 0 || !strings.HasSuffix(output, "\n}") {
		return settings, errors.New("invalid macOS system proxy settings")
	}
	for _, scheme := range []string{"http", "https"} {
		prefix := strings.ToUpper(scheme)
		if !pipBoolean(values[prefix+"Enable"]) || values[prefix+"Proxy"] == "" {
			continue
		}
		host := values[prefix+"Proxy"]
		if port := values[prefix+"Port"]; port != "" {
			if net.ParseIP(strings.Trim(host, "[]")) != nil {
				host = net.JoinHostPort(strings.Trim(host, "[]"), port)
			} else {
				host += ":" + port
			}
		}
		// HTTPS destinations also use an HTTP CONNECT proxy in _scproxy.
		settings.proxies[scheme] = "http://" + host
	}
	settings.excludeSimple = pipBoolean(values["ExcludeSimpleHostnames"])
	return settings, nil
}

func (settings systemProxySettings) bypasses(target *url.URL) bool {
	host := strings.ToLower(target.Hostname())
	if settings.excludeSimple && !strings.Contains(host, ".") {
		return true
	}
	for _, exception := range settings.exceptions {
		// urllib accepts abbreviated IPv4 networks such as 10.1 or 169.254/16.
		address, mask, hasMask := strings.Cut(exception, "/")
		parts := strings.Split(address, ".")
		if len(parts) <= 4 {
			bits := 8 * len(parts)
			if hasMask {
				var err error
				bits, err = strconv.Atoi(mask)
				if err != nil {
					continue
				}
			}
			for len(parts) < 4 {
				parts = append(parts, "0")
			}
			if ip, err := netip.ParseAddr(strings.Join(parts, ".")); err == nil {
				if prefix, err := ip.Prefix(bits); err == nil {
					if targetIP, err := netip.ParseAddr(host); err == nil && prefix.Contains(targetIP) {
						return true
					}
				}
				continue
			}
		}
		if match, _ := path.Match(strings.ReplaceAll(exception, "[!", "[^"), host); match {
			return true
		}
	}
	return false
}
