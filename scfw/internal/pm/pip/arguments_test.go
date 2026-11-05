// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pip

import (
	"context"
	"slices"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestProxyOptionsIgnoreCommandAndPosition(t *testing.T) {
	want := []pipOption{
		{name: "proxy", value: "http://original.example"},
		{name: "cert", value: "/registry.pem"},
	}
	for _, command := range []string{"install", "download", "wheel", "unrecognized-command"} {
		for _, args := range [][]string{
			{"--proxy", "http://original.example", "--cert=/registry.pem", command, "project"},
			{command, "--proxy=http://original.example", "project", "--cert", "/registry.pem"},
			{command, "project", "--proxy", "http://original.example", "--cert=/registry.pem"},
		} {
			options, targets := parsePipOptions(args)
			if !slices.Equal(options, want) || !slices.Equal(targets, []string{command, "project"}) {
				t.Fatalf("%q: options=%+v targets=%q", args, options, targets)
			}
		}
	}
}

func TestProxyOptionsExtractOnlyUsedSettings(t *testing.T) {
	options, targets := parsePipOptions([]string{
		"--timeout=2", "download", "--future-flag", "--no-dependencies",
		"-vrrequirements.txt", "--trusted-host", "first.example", "--trusted-host=second.example",
		"--index-url=https://index.example/simple", "--", "--proxy", "http://positional.example",
	})
	want := []pipOption{
		{name: "trusted-host", value: "first.example"},
		{name: "trusted-host", value: "second.example"},
		{name: "index-url", value: "https://index.example/simple"},
	}
	if !slices.Equal(options, want) || !slices.Equal(targets, []string{"download", "--proxy", "http://positional.example"}) {
		t.Fatalf("options=%+v targets=%q", options, targets)
	}
}

func TestProxyOptionsLeaveUnrelatedArgumentsToPip(t *testing.T) {
	options, targets := parsePipOptions([]string{"download", "--log", "build.log", "--dest", "out", "-Cother=1", "project"})
	if len(options) != 0 || !slices.Equal(targets, []string{"download", "build.log", "out", "project"}) {
		t.Fatalf("interpreted unrelated arguments: options=%+v targets=%q", options, targets)
	}
}

func TestProxyOptionsExplicitShortAliases(t *testing.T) {
	options, targets := parsePipOptions([]string{
		"-ihttps://index.example/simple", "-f", "wheelhouse", "-cconstraints.txt",
		"-e", "https://files.example/project-1.0.tar.gz", "-vrrequirements.txt",
	})
	want := []pipOption{
		{name: "index-url", value: "https://index.example/simple"},
		{name: "find-links", value: "wheelhouse"},
	}
	if !slices.Equal(options, want) || !slices.Equal(targets, []string{"https://files.example/project-1.0.tar.gz"}) {
		t.Fatalf("short aliases: options=%+v", options)
	}
}

func TestProxyOptionsDoNotExpandLongAbbreviations(t *testing.T) {
	options, _ := parsePipOptions([]string{
		"--prox=http://ignored.example", "--cer=/ignored.pem",
		"--trusted-h=ignored.example", "--in=https://ignored.example/simple",
	})
	if len(options) != 0 {
		t.Fatalf("expanded unsupported long abbreviations: %+v", options)
	}
}

func TestProxyOptionsEmptyAndMissingValues(t *testing.T) {
	options, _ := parsePipOptions([]string{"--proxy="})
	if !slices.Equal(options, []pipOption{{name: "proxy", value: ""}}) {
		t.Fatalf("explicit empty proxy lost: options=%+v", options)
	}
	for _, tail := range [][]string{{"--cert"}, {"-r"}, {"--isolated=false"}} {
		args := append([]string{"--proxy", "http://original.example"}, tail...)
		options, _ := parsePipOptions(args)
		if !slices.Equal(options, []pipOption{{name: "proxy", value: "http://original.example"}}) {
			t.Fatalf("%q discarded the original proxy: %+v", args, options)
		}
	}
}

func TestProxyOptionsIndexAliasPreservesDiscovery(t *testing.T) {
	manager := goDiscoveryPip(t)
	index := "https://private.example/packages"
	settings, err := manager.settings([]string{"download", "--pypi-url=" + index, "project"})
	if err != nil || !slices.Contains(settings.Indexes, index) {
		t.Fatalf("index alias lost discovery: %+v %v", settings, err)
	}
}

func TestProxyOptionsPreserveRouting(t *testing.T) {
	manager := goDiscoveryPip(t)
	config := proxy.ClientConfig{URL: "http://127.0.0.1:1234", CACertificatePath: "/run/ca.pem"}
	const original = "http://original.example"
	const environment = "http://environment.example"
	t.Setenv("PIP_PROXY", environment)
	for _, test := range []struct {
		args []string
		want string
	}{
		{nil, environment},
		{[]string{"help"}, environment},
		{[]string{"help", "install"}, environment},
		{[]string{"--help"}, environment},
		{[]string{"--version"}, environment},
		{[]string{"freeze", "--all"}, environment},
		{[]string{"uninstall", "-r", "https://private.example/requirements.txt"}, environment},
		{[]string{"not-a-command"}, environment},
		{[]string{"--log", "--help", "install"}, environment},
		{[]string{"--proxy", original, "--future-global-flag", "install", "--future-command-flag", "project"}, original},
		{[]string{"--log", "help", "install", "--proxy", original, "project"}, original},
		{[]string{"--log", "help", "download", "--proxy", original, "project"}, original},
		{[]string{"--log", "help", "wheel", "--proxy", original, "project"}, original},
		{[]string{"install", "--proxy", original, "--cert", "--help", "project"}, original},
		{[]string{"install", "--proxy", original, "--cert", "-h", "project"}, original},
		{[]string{"install", "--proxy", original, "--cert", "--version", "project"}, original},
		{[]string{"install", "--proxy", original, "--cert", "-V", "project"}, original},
		{[]string{"--proxy", original, "install", "--no-dependencies", "https://private.example/project-1.0.tar.gz"}, original},
		{[]string{"--proxy", original, "install", "--all-releases=:all:", "project"}, original},
		{[]string{"--proxy", original, "install", "--for", "project"}, original},
		{[]string{"--proxy", original, "download", "--no-dependencies", "project"}, original},
		{[]string{"--proxy", original, "wheel", "--only-final=:all:", "project"}, original},
		{[]string{"--proxy", original, "install", "-vrrequirements.txt", "project"}, original},
		{[]string{"--proxy", original, "--no-p", "download", "--only=:all:", "https://private.example/project-1.0.tar.gz"}, original},
		{[]string{"--proxy", original, "install", "--break-system-packages", "https://private.example/project-1.0.tar.gz"}, original},
	} {
		settings, err := manager.settings(test.args)
		if err != nil || settings.HTTPS != test.want {
			t.Fatalf("%q lost upstream settings: %+v %v", test.args, settings, err)
		}
		spec, err := manager.ProxyCommand(context.Background(), test.args, config)
		if err != nil {
			t.Fatal(err)
		}
		want := append(slices.Clone(test.args), "--proxy", config.URL, "--cert", config.CACertificatePath)
		if !slices.Equal(spec.Args, want) {
			t.Fatalf("%q changed arguments or routing: %q", test.args, spec.Args)
		}
	}
}
