// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

func TestPoetryCanonicalPyPICertificates(t *testing.T) {
	root := isolatedPoetryProject(t)
	if err := os.Chmod(filepath.Join(root, "pyproject.toml"), 0600); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "canonical-pypi.toml", filepath.Join(root, "pyproject.toml"))
	poetrySettingsFixture(t, "canonical-pypi-certificates.toml", filepath.Join(root, "poetry.toml"))
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"https://pypi.org/simple/project/", "https://pypi.org/pypi/project/json"} {
		target, _ := url.Parse(address)
		route, err := options.RouteForRequest(proxy.Request{URL: *target})
		if err != nil || !route.TLS.InsecureSkipVerify {
			t.Fatalf("canonical PyPI TLS policy lost: %v", err)
		}
	}
}

func TestPoetryTLSIdentityKeepsRedirectPolicyScoped(t *testing.T) {
	root := isolatedPoetryProject(t)
	poetrySettingsFixture(t, "redirect-certificates.toml", filepath.Join(root, "poetry.toml"))
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	config := poetryInvocationConfig(t)
	spec, err := manager.ProxyCommand(context.Background(), []string{"-C", root, "install"}, config)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvOverrides["POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT"] == "" {
		t.Fatal("source identity was not configured")
	}
	target, _ := url.Parse("https://cdn.example/project.whl")
	for _, identity := range []string{"", "poetry-source-0", ""} {
		route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: identity})
		if err != nil || route.TLS.InsecureSkipVerify != (identity != "") {
			t.Fatalf("redirect policy escaped its client identity: %s / %v", identity, err)
		}
	}
}

func TestPoetryDefaultIdentityDoesNotAdoptRepositoryTLS(t *testing.T) {
	root := isolatedPoetryProject(t)
	poetrySettingsFixture(t, "redirect-certificates.toml", filepath.Join(root, "poetry.toml"))
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://index.example/simple/project.whl")
	for _, identity := range []string{"poetry-default", "poetry-source-0", "poetry-default"} {
		route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: identity})
		if err != nil || route.TLS.InsecureSkipVerify != (identity == "poetry-source-0") || len(route.TLS.Certificates) != 0 {
			t.Fatalf("default policy changed at configured redirect target: %s / %v", identity, err)
		}
	}
}

func TestPoetrySourceIdentityRetainsExistingProxyMapping(t *testing.T) {
	root := isolatedPoetryProject(t)
	t.Setenv("https_proxy", "http://user:secret@gateway.example:8080")
	t.Setenv("no_proxy", "cdn.example")
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://cdn.example/project.whl")
	route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: "poetry-source-0"})
	if err != nil || route.ProxyURL == nil || route.ProxyURL.Host != "gateway.example:8080" {
		t.Fatalf("redirect dropped initiating gateway: %v / %v", route, err)
	}
	route, err = options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: "poetry-default"})
	if err != nil || route.ProxyURL != nil {
		t.Fatalf("source proxy escaped to unrelated requests: %v / %v", route, err)
	}
	origin, _ := url.Parse("https://unconfigured.example/project.whl")
	request := proxy.Request{URL: *origin, ClientIdentity: "poetry-default"}
	hook, err := options.RequestHooks[0](context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hook(context.Background(), proxy.Response{Request: request, StatusCode: 302, Header: map[string][]string{"Location": {target.String()}}})
	if err == nil || !strings.Contains(err.Error(), "NO_PROXY") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unrepresentable redirect was silent or unsafe: %v", err)
	}
}

func TestPoetryProjectRepositoriesRetainGlobalContexts(t *testing.T) {
	root := isolatedPoetryProject(t)
	poetrySettingsFixture(t, "repositories-overridden.toml", filepath.Join(root, "config.toml"))
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	options, err := manager.ProxyOptions([]string{"-C", root, "install"})
	if err != nil {
		t.Fatal(err)
	}
	for address, insecure := range map[string]bool{
		"https://superseded.example/project.whl":  true,
		"https://index.example/simple/project/":   true,
		"https://custom-pypi.example/project.whl": true,
	} {
		target, _ := url.Parse(address)
		route, err := options.RouteForRequest(proxy.Request{URL: *target})
		if err != nil || route.TLS.InsecureSkipVerify != insecure {
			t.Fatalf("repository registration differs at %s: %v", address, err)
		}
	}
}

func TestPoetryOwnArgumentBoundary(t *testing.T) {
	for _, test := range []struct{ command, own []string }{
		{[]string{"run", "python", "-Cchild", "--project", "child"}, []string{"run"}},
		{[]string{"-C", "run", "install"}, []string{"-C", "run", "install"}},
		{[]string{"--project", "run", "run", "--directory=project", "python", "-Pchild"}, []string{"--project", "run", "run", "--directory=project"}},
		{[]string{"run", "-C", "project", "--", "python", "-Cchild"}, []string{"run", "-C", "project"}},
		{[]string{"add", "--", "git+https://git.example/repo"}, []string{"add", "--", "git+https://git.example/repo"}},
	} {
		before := slices.Clone(test.command)
		if own := poetryOwnArguments(test.command); !slices.Equal(own, test.own) {
			t.Errorf("%v: own=%v, want %v", test.command, own, test.own)
		}
		if !slices.Equal(before, test.command) {
			t.Fatal("discovery mutated command")
		}
	}
}

func TestPoetryProxyCommandSelection(t *testing.T) {
	for _, test := range []struct {
		args  []string
		proxy bool
	}{
		{nil, false},
		{[]string{"--no-plugins"}, false},
		{[]string{"--version"}, false},
		{[]string{"-V"}, false},
		{[]string{"--help"}, false},
		{[]string{"-h"}, false},
		{[]string{"-vvh"}, false},
		{[]string{"-qV"}, false},
		{[]string{"help", "install"}, false},
		{[]string{"list"}, false},
		{[]string{"about"}, false},
		{[]string{"install", "--help"}, false},
		{[]string{"--directory", "project", "install", "--help"}, false},
		{[]string{"--project", "project", "--version"}, false},
		{[]string{"install"}, true},
		{[]string{"add", "help"}, true},
		{[]string{"add", "run"}, true},
		{[]string{"--directory", "run", "install"}, true},
		{[]string{"--project=run", "lock"}, true},
		{[]string{"-Crun", "update"}, true},
		{[]string{"-vC", "run", "install"}, true},
		{[]string{"-nP", "run", "add", "project"}, true},
		{[]string{"--dir", "run", "install"}, true},
		{[]string{"--p", "run", "lock"}, true},
		{[]string{"--directory", "help", "install"}, true},
		{[]string{"--project", "--help", "install"}, true},
		{[]string{"-C--help", "install"}, true},
		{[]string{"add", "--", "--help"}, true},
		{[]string{"--", "install", "--help"}, true},
		{[]string{"run", "--help"}, false},
		{[]string{"run"}, false},
		{[]string{"run", "app", "--help"}, false},
		{[]string{"run", "app", "--version"}, false},
		{[]string{"run", "--", "app", "--help"}, false},
		{[]string{"--project", "run", "run", "app", "--help"}, false},
		{[]string{"--directory", "project with spaces", "run", "python", "app.py"}, false},
		{[]string{"-Cproject", "run", "python", "app.py"}, false},
		{[]string{"-vC", "project", "run", "python", "app.py"}, false},
		{[]string{"--dir", "project", "run", "python", "app.py"}, false},
		{[]string{"--proj", "run", "run", "app"}, false},
		{[]string{"run", "--directory", "project", "python", "app.py"}, false},
		{[]string{"--", "run", "python", "app.py"}, false},
		{[]string{"--directory", "project", "--", "run", "python", "app.py"}, false},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			if got := (Poetry{}).ProxyCommandSupported(test.args); got != test.proxy {
				t.Fatalf("proxy selection=%t, want %t", got, test.proxy)
			}
		})
	}
}

func TestPoetryDiscoveryIgnoresRunChildOptions(t *testing.T) {
	root := isolatedPoetryProject(t)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	poetrySettingsFixture(t, "invalid.lock", filepath.Join(child, "pyproject.toml"))
	t.Chdir(root)
	command := []string{"run", "python", "child-options.py", "-P", "child", "--project=child", "-Cchild", "--directory", "child"}
	manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
	directory, err := manager.ProjectDirectory(command)
	if err != nil || directory != root {
		t.Fatalf("child selected working directory: %q / %v", directory, err)
	}
	settings, err := readPoetrySettings(command)
	if err != nil || settings.projectDirectory != root {
		t.Fatalf("child selected project: %q / %v", settings.projectDirectory, err)
	}
	if _, err := manager.ProxyOptions(command); err != nil {
		t.Fatal(err)
	}
	options, err := manager.PyPIClassifierOptions(command)
	if err != nil || !slices.Equal(options.SimpleIndexURLs, []string{"https://index.example/simple/"}) {
		t.Fatalf("child altered source hints: %v / %v", options, err)
	}
	spec, err := manager.ProxyCommand(context.Background(), command, poetryInvocationConfig(t))
	if err != nil || !slices.Equal(spec.Args, command) {
		t.Fatalf("child arguments changed: %v / %v", spec.Args, err)
	}
}

func TestPoetryConfiguredRepositoryOrderAndScopes(t *testing.T) {
	for _, fixture := range []string{"repositories.toml", "repositories-inline.toml", "repositories-dotted.toml"} {
		t.Run(fixture, func(t *testing.T) {
			root := isolatedPoetryProject(t)
			poetrySettingsFixture(t, fixture, filepath.Join(root, "config.toml"))
			args := []string{"--directory", root, "install"}
			settings, err := readPoetrySettings(args)
			if err != nil {
				t.Fatal(err)
			}
			want := []poetrySource{{Name: "Zulu", URL: "https://global.example/zulu/"}, {Name: "Alpha", URL: "https://global.example/alpha/"}}
			if !reflect.DeepEqual(settings.configuredRepositories(), want) {
				t.Fatalf("repository order/case changed: %v", settings.configuredRepositories())
			}
			manager := Poetry{version: pm.Version{Major: 2, Minor: 5}}
			hints, err := manager.PyPIClassifierOptions(args)
			if err != nil || !slices.Equal(hints.SimpleIndexURLs, []string{"https://index.example/simple/"}) {
				t.Fatalf("repositories changed package sources: %v / %v", hints, err)
			}
			if fixture != "repositories.toml" {
				return
			}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			// Neither path contains the target; equal matches retain declaration order.
			target, _ := url.Parse("https://global.example/download/project.whl")
			route, err := options.RouteForRequest(proxy.Request{URL: *target})
			if err != nil || !route.TLS.InsecureSkipVerify || !route.ProxyTLS.InsecureSkipVerify {
				t.Fatalf("first repository lost its effective verification policy: %v", err)
			}
			target, _ = url.Parse("https://global.example/alpha/project.whl")
			route, err = options.RouteForRequest(proxy.Request{URL: *target})
			if err != nil || route.TLS.InsecureSkipVerify || route.ProxyTLS.InsecureSkipVerify {
				t.Fatalf("verification exception escaped its repository: %v", err)
			}
			config := poetryInvocationConfig(t)
			spec, err := manager.ProxyCommand(context.Background(), args, config)
			if err != nil || spec.EnvOverrides["POETRY_CERTIFICATES_ZULU_VERIFY"] != config.CACertificatePath {
				t.Fatalf("configured repository did not trust interception: %v", err)
			}
			t.Setenv("POETRY_REPOSITORIES_ENV_REPO_URL", "https://environment.example/simple/")
			if got := settings.configuredRepositories(); !reflect.DeepEqual(got, []poetrySource{{Name: "env-repo", URL: "https://environment.example/simple/"}}) {
				t.Fatalf("environment map did not replace file repositories: %v", got)
			}
		})
	}
}

func TestPoetryIgnoredLockDoesNotPreventProxySetup(t *testing.T) {
	for _, version := range []pm.Version{{Major: 2}, {Major: 2, Minor: 1}, {Major: 2, Minor: 2}, {Major: 2, Minor: 5}} {
		for _, oversized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/oversized=%t", version, oversized), func(t *testing.T) {
				root := isolatedPoetryProject(t)
				before, err := readPoetryFixture("invalid.lock")
				if err != nil {
					t.Fatal(err)
				}
				if oversized {
					before = bytes.Repeat([]byte("# ignored lock\n"), maxPoetryConfigurationBytes/14+1)
				}
				path := filepath.Join(root, "poetry.lock")
				if err := os.WriteFile(path, before, 0600); err != nil {
					t.Fatal(err)
				}
				manager := Poetry{version: version}
				args := []string{"--directory", root, "lock", "--regenerate"}
				if _, err := manager.ProxyOptions(args); err != nil {
					t.Fatalf("ignored lock blocked regeneration: %v", err)
				}
				if _, err := manager.PyPIClassifierOptions(args); err != nil {
					t.Fatalf("classifier parsed ignored lock: %v", err)
				}
				args = []string{"--directory", root, "install"}
				if _, err := manager.PyPIClassifierOptions(args); err != nil {
					t.Fatalf("source hints parsed lockfile: %v", err)
				}
				if _, err := manager.ProxyOptions(args); err != nil {
					t.Fatalf("proxy setup parsed the lockfile: %v", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("discovery changed lockfile")
				}
			})
		}
	}
}

func TestPoetryCollidingSourceIdentitiesCannotWeakenTLS(t *testing.T) {
	for _, test := range []struct{ equivalent, bypass bool }{{}, {equivalent: true}, {equivalent: true, bypass: true}} {
		t.Run(fmt.Sprintf("equivalent=%t/bypass=%t", test.equivalent, test.bypass), func(t *testing.T) {
			root := isolatedPoetryProject(t)
			if test.bypass {
				t.Setenv("https_proxy", "http://gateway.example:8080")
				t.Setenv("no_proxy", "other.example")
			}
			if err := os.Chmod(filepath.Join(root, "pyproject.toml"), 0600); err != nil {
				t.Fatal(err)
			}
			poetrySettingsFixture(t, "colliding-sources.toml", filepath.Join(root, "pyproject.toml"))
			template, err := os.ReadFile("testdata/colliding-certificates.toml.tmpl")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "poetry.toml"), []byte(fmt.Sprintf(string(template), test.equivalent)), 0400); err != nil {
				t.Fatal(err)
			}
			manager := Poetry{version: pm.Version{Major: 2, Minor: 5}, proxyState: &poetryProxyState{}}
			args := []string{"-C", root, "install"}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatal(err)
			}
			config := poetryInvocationConfig(t)
			issue := config.IdentityCertificate
			identities := map[string]string{}
			config.IdentityCertificate = func(identity string) (string, error) {
				path, err := issue(identity)
				identities[path] = identity
				return path, err
			}
			spec, err := manager.ProxyCommand(context.Background(), args, config)
			if err != nil {
				t.Fatal(err)
			}
			identity := identities[spec.EnvOverrides["POETRY_CERTIFICATES_FOO_BAR_CLIENT_CERT"]]
			for _, address := range []string{"https://strict.example/simple/project/", "https://other.example/simple/project/"} {
				target, _ := url.Parse(address)
				route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: identity})
				if !test.equivalent || test.bypass {
					if err == nil || !strings.Contains(err.Error(), "names") || !strings.Contains(err.Error(), "TLS") {
						t.Fatalf("ambiguous alias silently selected a TLS policy: %v / %v", route, err)
					}
				} else if err != nil || route.TLS.InsecureSkipVerify {
					t.Fatalf("equivalent TLS alias was rejected or weakened: %v", err)
				}
			}
			// HTTP-only traffic does not present a TLS identity and must retain
			// its normal route even when unused TLS settings are ambiguous.
			target, _ := url.Parse("http://strict.example/simple/project/")
			if _, err := options.RouteForRequest(proxy.Request{URL: *target}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPoetryCertificateEnvironmentNamesUseFullUppercase(t *testing.T) {
	for name, expected := range map[string]string{"foo-bar": "FOO_BAR", "straße": "STRASSE", "ﬀ": "FF"} {
		if prefix := poetryCertificatePrefix(name); prefix != "POETRY_CERTIFICATES_"+expected+"_" {
			t.Fatalf("Python environment name changed: %q", prefix)
		}
		t.Setenv("POETRY_CERTIFICATES_"+expected+"_CERT", "custom.pem")
		if value := (poetrySettings{}).get("certificates", name, "cert"); value != "custom.pem" {
			t.Fatalf("certificate override was lost for %q: %v", name, value)
		}
	}
}

func TestPoetryUnusedRepositoryURLsDeferValidation(t *testing.T) {
	for _, environment := range []bool{false, true} {
		t.Run(fmt.Sprintf("environment=%t", environment), func(t *testing.T) {
			root := isolatedPoetryProject(t)
			path := filepath.Join(root, "config.toml")
			before := poetrySettingsFixture(t, "unused-repositories.toml", path)
			if environment {
				for name, address := range map[string]string{"EMPTY": "", "RELATIVE": "upload/packages", "HOSTLESS": "https:///upload", "UNPARSEABLE": "https://user:secret@unused.example/%zz", "PRIVATE": ""} {
					t.Setenv("POETRY_REPOSITORIES_"+name+"_URL", address)
				}
			}
			manager := Poetry{version: pm.Version{Major: 2}, proxyState: &poetryProxyState{}}
			args := []string{"-C", root, "install"}
			options, err := manager.ProxyOptions(args)
			if err != nil {
				t.Fatalf("unused repository blocked setup: %v", err)
			}
			settings, err := manager.prepareProxy(args)
			if err != nil {
				t.Fatal(err)
			}
			repositories := settings.settings.configuredRepositories()
			retainedEmpty := false
			for _, repository := range repositories {
				if repository.Name == "empty" && repository.URL == "" {
					retainedEmpty = true
				}
			}
			if !retainedEmpty {
				t.Fatal("empty configured repository was discarded")
			}
			invalid := -1
			for index, repository := range settings.certificates {
				if repository.source.Name == "unparseable" {
					invalid = index
					break
				}
			}
			if invalid < 0 || !errors.Is(settings.certificates[invalid].err, errPoetrySourceURL) {
				t.Fatal("invalid URL was not retained as a deferred error")
			}
			config := poetryInvocationConfig(t)
			config.IdentityCertificate = func(identity string) (string, error) { return identity, nil }
			spec, err := manager.ProxyCommand(context.Background(), args, config)
			if err != nil {
				t.Fatalf("unused repository blocked child setup: %v", err)
			}
			for _, name := range []string{"EMPTY", "RELATIVE", "HOSTLESS", "UNPARSEABLE"} {
				if _, exists := spec.EnvOverrides["POETRY_CERTIFICATES_"+name+"_CERT"]; exists {
					t.Fatalf("unmatchable repository %s received a TLS identity", name)
				}
			}
			target, _ := url.Parse("https://index.example/simple/project.whl")
			identity := spec.EnvOverrides["POETRY_CERTIFICATES_PRIVATE_CLIENT_CERT"]
			for _, selected := range []string{"", identity} {
				route, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: selected})
				if err != nil || route.TLS.InsecureSkipVerify {
					t.Fatalf("unused alias changed valid source trust: %v", err)
				}
			}
			identity = "poetry-source-" + strconv.Itoa(invalid)
			if _, err := options.RouteForRequest(proxy.Request{URL: *target, ClientIdentity: identity}); !errors.Is(err, errPoetrySourceURL) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("selected invalid URL did not produce a safe deferred error: %v", err)
			}
			t.Setenv("POETRY_CERTIFICATES_PRIVATE_CERT", "/missing/selected-secret.pem")
			manager.proxyState = &poetryProxyState{}
			options, err = manager.ProxyOptions(args)
			if err != nil {
				t.Fatalf("selected certificate error was raised during setup: %v", err)
			}
			if _, err := options.RouteForRequest(proxy.Request{URL: *target}); err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("selected source certificate error was lost or leaked: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("repository configuration changed")
			}
		})
	}
}
