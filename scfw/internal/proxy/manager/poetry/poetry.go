// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package poetry owns Poetry package-source discovery and overrides.
package poetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
	pypiecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem/pypi"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/manager/shared"
)

var pythonShebang = regexp.MustCompile(`^#!([^\s]+/python[^\s]*)`)

type Manager struct{}

func (Manager) Name() string { return "poetry" }

type poetryFile struct {
	Tool struct {
		Poetry struct {
			Source []poetrySource `toml:"source"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

type poetrySource struct {
	Name     string `toml:"name"`
	URL      string `toml:"url"`
	Priority string `toml:"priority"`
}

func (manager *Manager) Registries(ctx context.Context, executable string, args []string) (proxy.RegistryConfiguration, error) {
	project := poetryProjectDirectory(args)
	operation := shared.Operation(args, map[string]bool{"--directory": true, "--project": true, "-c": true, "-p": true})
	if operation == "install" || operation == "sync" {
		if _, err := os.Stat(filepath.Join(project, "poetry.lock")); err != nil {
			if os.IsNotExist(err) {
				return proxy.RegistryConfiguration{}, errors.New("poetry proxy mode requires an existing poetry.lock so ephemeral registry URLs cannot be persisted")
			}
			return proxy.RegistryConfiguration{}, err
		}
		if _, err := shared.CommandOutput(ctx, executable, "check", "--lock", "--directory", project); err != nil {
			return proxy.RegistryConfiguration{}, fmt.Errorf("verify poetry.lock is current: %w", err)
		}
	}
	contents, err := os.ReadFile(filepath.Join(project, "pyproject.toml"))
	if err != nil && !os.IsNotExist(err) {
		return proxy.RegistryConfiguration{}, err
	}
	var file poetryFile
	if len(contents) > 0 {
		if err := toml.Unmarshal(contents, &file); err != nil {
			return proxy.RegistryConfiguration{}, err
		}
	}
	// Poetry's built-in PyPI repository is constructed from the service root
	// and appends /simple itself.
	defaultRegistry, err := shared.ParseURL("Poetry PyPI source", "https://pypi.org/")
	if err != nil {
		return proxy.RegistryConfiguration{}, err
	}
	named := make(map[string]*url.URL)
	for _, source := range file.Tool.Poetry.Source {
		if source.URL == "" {
			continue
		}
		parsed, parseErr := shared.ParseURL("Poetry source "+source.Name, source.URL)
		if parseErr != nil {
			return proxy.RegistryConfiguration{}, parseErr
		}
		named[source.Name] = parsed
	}
	caFile := os.Getenv("REQUESTS_CA_BUNDLE")
	if caFile == "" {
		caFile = os.Getenv("SSL_CERT_FILE")
	}
	return proxy.RegistryConfiguration{Default: defaultRegistry, Named: named, Handler: pypiecosystem.Handler{}, UseNetrc: true, CAFile: caFile}, nil
}

func poetryProjectDirectory(args []string) string {
	directory, _ := os.Getwd()
	for index := 0; index < len(args); index++ {
		if (args[index] == "--directory" || args[index] == "-C") && index+1 < len(args) {
			return args[index+1]
		}
		if value, found := strings.CutPrefix(args[index], "--directory="); found {
			return value
		}
	}
	return directory
}

func (manager *Manager) Prepare(executable string, args []string, registryURL string, named map[string]string) (proxy.PreparedCommand, error) {
	contents, err := os.ReadFile(executable)
	if err != nil {
		return proxy.PreparedCommand{}, fmt.Errorf("read Poetry launcher: %w", err)
	}
	firstLine, _, _ := strings.Cut(string(contents), "\n")
	match := pythonShebang.FindStringSubmatch(firstLine)
	if len(match) != 2 {
		return proxy.PreparedCommand{}, errors.New("poetry proxy mode requires a Python Poetry launcher")
	}
	sources, err := json.Marshal(named)
	if err != nil {
		return proxy.PreparedCommand{}, fmt.Errorf("encode Poetry sources: %w", err)
	}
	file, err := os.CreateTemp("", "scfw-poetry-proxy-*.py")
	if err != nil {
		return proxy.PreparedCommand{}, fmt.Errorf("create Poetry proxy bootstrap: %w", err)
	}
	bootstrap := `import json
import os
from poetry.factory import Factory
from poetry.repositories.pypi_repository import PyPiRepository

_pypi_url = os.environ.pop("SCFW_POETRY_PYPI_URL")
_sources = json.loads(os.environ.pop("SCFW_POETRY_SOURCE_URLS"))
_original = Factory.create_package_source.__func__

@classmethod
def _create_package_source(cls, source, config, disable_cache=False):
    source = dict(source)
    name = source.get("name", "")
    if name.lower() == "pypi":
        repository = PyPiRepository(url=_pypi_url, config=config, disable_cache=disable_cache)
        # Poetry uses two different bases for Simple API and JSON fallback
        # calls. Assign both explicitly because its internal URL concatenation
        # assumes the service root has no path component.
        repository._url = _pypi_url.rstrip("/") + "/simple"
        repository._base_url = _pypi_url.rstrip("/") + "/"
        return repository
    if name in _sources:
        source["url"] = _sources[name]
    return _original(cls, source, config, disable_cache=disable_cache)

Factory.create_package_source = _create_package_source
from poetry.console.application import main
raise SystemExit(main())
`
	if _, err := file.WriteString(bootstrap); err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, file.Close(), os.Remove(file.Name()))
	}
	if err := file.Close(); err != nil {
		return proxy.PreparedCommand{}, errors.Join(err, os.Remove(file.Name()))
	}
	return proxy.PreparedCommand{
		Executable: match[1],
		Args:       append([]string{file.Name()}, args...),
		Env: shared.OverrideEnvironment(map[string]string{
			"SCFW_POETRY_PYPI_URL":    strings.TrimSuffix(registryURL, "/"),
			"SCFW_POETRY_SOURCE_URLS": string(sources),
		}),
		Cleanup: func() error { return os.Remove(file.Name()) },
	}, nil
}
