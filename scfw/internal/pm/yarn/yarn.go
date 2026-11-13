// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

var ExecutableNames = []string{"yarn"}

type generation uint8

const (
	classic generation = iota
	berry
)

type Yarn struct {
	executable string
	version    pm.Version
	versionErr error
}

// NewYarn records the version that will actually run here: a global Classic
// yarn hands off to a project's yarnPath bundle, and `yarn --version` reports
// that bundle's version. A version failure only fails commands that need it.
func NewYarn(ctx context.Context, name, executable string) (Yarn, error) {
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return Yarn{}, err
		}
	}
	yarn := Yarn{executable: executable}
	output, err := exec.CommandContext(ctx, executable, "--version").Output()
	if err == nil {
		yarn.version, err = pm.ParseVersion(strings.TrimSpace(string(output)))
	}
	yarn.versionErr = err
	return yarn, nil
}

func (yarn Yarn) generation() (generation, error) {
	if yarn.versionErr != nil {
		return 0, fmt.Errorf("%w: could not determine yarn version: %v", pm.ErrUnsupportedVersion, yarn.versionErr)
	}
	switch {
	case yarn.version.Major == 1 && yarn.version.Minor >= 22:
		return classic, nil
	case yarn.version.Major == 4:
		return berry, nil
	}
	return 0, fmt.Errorf("%w: yarn %s is not supported (supported: 1.22+ and 4.x)", pm.ErrUnsupportedVersion, yarn.version)
}

func (yarn Yarn) Executable() string {
	return yarn.executable
}

func (yarn Yarn) ProjectDirectory(_ []string) (string, error) {
	return os.Getwd()
}

func (yarn Yarn) RunCommand(ctx context.Context, command []string) error {
	child := exec.CommandContext(ctx, yarn.executable, command...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	return child.Run()
}

func (yarn Yarn) ResolveInstallTargets(_ context.Context, command []string) (*pm.Set[pm.Package], error) {
	if yarn.ProxyCommandSupported(command) {
		return nil, errors.New("yarn package operations require proxy mode (set SCFW_PROXY_ENABLED=1)")
	}
	return pm.NewSet[pm.Package](), nil
}
