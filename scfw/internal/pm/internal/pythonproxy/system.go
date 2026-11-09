// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package pythonproxy reads native proxy settings shared by Python adapters.
package pythonproxy

import (
	"bytes"
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

// Settings contains native proxy URLs and Python-compatible bypass rules.
type Settings struct {
	Proxies       map[string]string
	Exceptions    []string
	ExcludeSimple bool
}

// ReadSystem reads macOS native settings with bounded output and execution.
func ReadSystem() (Settings, error) {
	if runtime.GOOS != "darwin" {
		return Settings{}, nil
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
	var output systemOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return Settings{}, errors.New("could not read macOS system proxy settings")
	}
	return ParseSystem(output.String())
}

// ParseSystem decodes the read-only scutil proxy dictionary.
func ParseSystem(output string) (Settings, error) {
	settings := Settings{Proxies: map[string]string{}}
	output = strings.TrimSpace(output)
	if output == "No proxy configuration available" {
		return settings, nil
	}
	if !strings.HasPrefix(output, "<dictionary> {\n") {
		return settings, errors.New("invalid macOS system proxy settings")
	}
	values := map[string]string{}
	depth, Exceptions := 0, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "}" {
			depth--
			if depth < 2 {
				Exceptions = false
			}
			continue
		}
		key, value, _ := strings.Cut(line, " : ")
		if depth == 1 {
			values[key] = value
			Exceptions = key == "ExceptionsList" && value == "<array> {"
		} else if depth == 2 && Exceptions {
			settings.Exceptions = append(settings.Exceptions, value)
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
		if !enabled(values[prefix+"Enable"]) || values[prefix+"Proxy"] == "" {
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
		settings.Proxies[scheme] = "http://" + host
	}
	settings.ExcludeSimple = enabled(values["ExcludeSimpleHostnames"])
	return settings, nil
}

// Bypasses applies native exceptions without bypassing SCFW inspection.
func (settings Settings) Bypasses(target *url.URL) bool {
	host := strings.ToLower(target.Hostname())
	if settings.ExcludeSimple && !strings.Contains(host, ".") {
		return true
	}
	for _, exception := range settings.Exceptions {
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

func enabled(value string) bool {
	return value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
}

type systemOutput struct{ bytes.Buffer }

func (b *systemOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1<<20 {
		return 0, errors.New("system proxy settings exceed discovery limit")
	}
	return b.Buffer.Write(data)
}
