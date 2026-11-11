// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package uv

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const maxScriptBytes = 16 << 20

// Directory packages and zipapps influence uv's configuration discovery but do
// not carry PEP 723 metadata. Keep that decision separate from script inspection.
func (options commandOptions) runConfigurationDirectory(working string) (string, error) {
	script, err := options.scriptPath(working)
	if err != nil {
		return "", err
	}
	if script != "" {
		return physicalParent(script)
	}
	if options.runTarget == "" || strings.EqualFold(options.runTarget, "python") || options.moduleMode() {
		return "", nil
	}
	target := resolvePath(working, options.runTarget)
	info, err := os.Stat(target)
	if err != nil {
		return "", nil
	}
	if info.IsDir() {
		if entry, err := os.Stat(filepath.Join(target, "__main__.py")); err == nil && entry.Mode().IsRegular() {
			return physicalParent(target)
		}
	} else if info.Mode().IsRegular() {
		archive, err := zip.OpenReader(target)
		if err == nil {
			defer func() { _ = archive.Close() }()
			for _, entry := range archive.File {
				if entry.Name == "__main__.py" {
					return physicalParent(target)
				}
			}
		}
	}
	return "", nil
}

func (options commandOptions) moduleMode() bool {
	for _, option := range options.options {
		if option.name == "module" || option.name == "-m" {
			return true
		}
	}
	return false
}

// Identify only targets whose metadata uv itself reads. Arguments to external
// commands and Python modules remain opaque. stdin and remote scripts cannot be
// inspected without consuming input or changing uv's download/execution behavior.
func (options commandOptions) scriptPath(working string) (string, error) {
	var target string
	if options.command == "run" {
		target = options.runTarget
		if target == "-" || strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			return "", errors.New("uv proxy mode does not support stdin or remote scripts; use a local script")
		}
		if options.moduleMode() {
			return "", nil
		}
		forced := false
		for _, option := range options.options {
			switch option.name {
			case "script", "gui-script":
				forced = true
			}
		}
		if !forced {
			switch strings.ToLower(filepath.Ext(target)) {
			case ".py", ".pyc", ".pyw":
			default:
				return "", nil
			}
			info, err := os.Stat(resolvePath(working, target))
			if err != nil || !info.Mode().IsRegular() {
				return "", nil // uv treats this as an external command, not a script.
			}
		}
	} else {
		for _, option := range options.options {
			if option.name == "script" {
				target = option.value
			}
		}
	}
	if target == "" {
		return "", nil
	}
	return resolvePath(working, target), nil
}

// Inline settings take precedence even with --no-config or --config-file. An
// inline proxy cannot be replaced by environment variables or a uv.toml file;
// reject it without rewriting the script, its arguments, or its cache identity.
func scriptSettings(path string) (map[string]any, error) {
	parsed, err := readScriptMetadata(path)
	if err != nil || parsed == nil {
		return nil, err
	}
	tool, _ := parsed["tool"].(map[string]any)
	settings, _ := tool["uv"].(map[string]any)
	for _, key := range []string{"http-proxy", "https-proxy"} {
		if _, configured := settings[key]; configured {
			return nil, errors.New("uv proxy mode does not support inline script proxy settings; configure the upstream proxy in the environment or uv.toml")
		}
	}
	directory, err := physicalParent(path)
	if err != nil {
		return nil, errors.New("could not inspect uv script metadata")
	}
	return standaloneSettings(settings, directory), nil
}

func readScriptMetadata(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}
	invalid := errors.New("could not inspect uv script metadata")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxScriptBytes {
		return nil, invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, maxScriptBytes+1))
	if err != nil || len(content) > maxScriptBytes {
		return nil, invalid
	}
	start := bytes.Index(content, []byte("# /// script"))
	if start < 0 || (start > 0 && content[start-1] != '\n' && content[start-1] != '\r') {
		return nil, nil
	}
	lines := strings.Split(strings.ReplaceAll(string(content[start:]), "\r\n", "\n"), "\n")
	if lines[0] != "# /// script" {
		return nil, nil
	}
	var metadata []string
	closing := -1
	for _, line := range lines[1:] {
		if line == "#" {
			metadata = append(metadata, "")
			continue
		}
		line, comment := strings.CutPrefix(line, "# ")
		if !comment {
			break
		}
		if line == "///" {
			closing = len(metadata)
		}
		metadata = append(metadata, line)
	}
	if closing < 0 {
		return nil, invalid
	}
	var parsed map[string]any
	if toml.Unmarshal([]byte(strings.Join(metadata[:closing], "\n")), &parsed) != nil {
		return nil, invalid
	}
	return parsed, nil
}
