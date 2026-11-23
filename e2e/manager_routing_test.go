//go:build e2e

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package e2e_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

type managerRouteCase struct {
	name  string
	block bool
}

func init() {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		names := []string{"domain-suffix", "domain-boundary", "port-match", "port-miss", "ip-exact", "ip-cidr", "ip-port", "ip-miss", "port-nondefault-match", "port-nondefault-miss", "all-fallback"}
		switch manager {
		case "npm":
			names = append(names, "npmrc-proxy", "npm-env-proxy", "npm-flag-proxy", "npm-flag-bypass")
		case "pip":
			names = append(names, "pip-global-proxy", "pip-command-proxy", "pip-env-proxy", "pip-flag-proxy", "pip-explicit-fallback", "pip-no-proxy-env-config", "pip-no-proxy-env-flag")
		case "poetry":
			names = append(names, "empty-lowercase-fallback")
		case "uv":
			names = append(names, "uv-file-https", "uv-file-http", "uv-file-bypass", "uv-explicit-file")
		}
		if manager == "pip" || manager == "poetry" {
			names = slices.DeleteFunc(names, func(name string) bool { return name == "port-match" })
			names = append(names, "port-default-explicit", "port-default-implicit")
		}
		names = append(names, "malformed-proxy")
		for _, name := range names {
			for _, block := range []bool{false, true} {
				if (name == "malformed-proxy" || strings.HasPrefix(name, "port-default-")) && block {
					continue
				}
				options := managerRouteCase{name, block}
				id, key, profile := "NET-10", "pypi-old", "public-pypi"
				if manager == "npm" {
					key, profile = "npm-old", "public-npm"
				}
				if strings.HasPrefix(name, "domain-") || strings.HasPrefix(name, "port-") || strings.HasPrefix(name, "ip-") {
					id = "NET-09"
				}
				if strings.HasPrefix(name, "ip-") || strings.HasPrefix(name, "port-nondefault-") {
					profile = "controlled-address-index-public-artifacts"
				}
				var capabilities []string
				if strings.HasPrefix(name, "uv-") {
					id = "UV-07"
					capabilities = []string{"uv-file-proxy"}
				}
				if name == "pip-no-proxy-env-flag" {
					capabilities = []string{"pip-no-proxy-env"}
				}
				action := "allow"
				if block {
					action = "block"
				}
				if name == "malformed-proxy" || strings.HasPrefix(name, "port-default-") {
					action = "reject"
				}
				spec := scenario{
					Scenario: id, Variant: manager + "-" + name + "-" + action, Manager: manager, Mode: "proxy", Backend: "local", RegistryProfile: profile, DiscoveryKey: key, Capabilities: capabilities, Timeout: 5 * time.Minute,
					Run: func(r *caseRun) error { return runManagerRouting(r, options) },
				}
				suites["manager-routing"] = append(suites["manager-routing"], spec)
				if (manager == "pip" || manager == "poetry") && (strings.HasPrefix(name, "port-default-") || strings.HasPrefix(name, "port-nondefault-")) {
					suites["python-port-bypass"] = append(suites["python-port-bypass"], spec)
				}
				if manager == "pip" && (name == "pip-global-proxy" || name == "pip-explicit-fallback") {
					suites["pip-proxy-boundary"] = append(suites["pip-proxy-boundary"], spec)
				}
			}
		}
	}
}

func runManagerRouting(r *caseRun, options managerRouteCase) error {
	native := *r
	native.Root = filepath.Join(r.Root, "native")
	native.WorkDir = filepath.Join(native.Root, "work")
	env, err := isolatedEnvironment(native.Root)
	if err != nil {
		return err
	}
	native.Env = env
	native.Result = &result{Evidence: map[string]fileEvidence{}, Observations: map[string]any{}}
	defer func() {
		r.Result.Commands = append(r.Result.Commands, native.Result.Commands...)
		r.Result.Observations["native"] = native.Result.Observations
		for key, value := range native.Result.Evidence {
			r.Result.Evidence["native-"+key] = value
		}
	}()
	if err := managerRoutingPhase(&native, options, false); err != nil {
		return fmt.Errorf("native control: %w", err)
	}
	return managerRoutingPhase(r, options, true)
}

type managerRoutingRecipe struct {
	args           []string
	python, target string
	originals      map[string][]byte
	routeHost      string
	expected       int // -1 direct; 0 selected; 1 competing upstream.
	merged         bool
	cleanup        func() error
}

func managerRoutingPhase(r *caseRun, options managerRouteCase, protected bool) (returnErr error) {
	allowed := []string{"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "api.osv.dev", "raw.githubusercontent.com", "127.0.0.1", "localhost"}
	selected, err := newForwardProxy(false, false, allowed)
	if err != nil {
		return err
	}
	defer selected.close()
	competing, err := newForwardProxy(false, false, allowed)
	if err != nil {
		return err
	}
	defer competing.close()
	defer func() {
		path := filepath.Join(r.Root, "routing.json")
		err := writeJSON(path, map[string]any{"selected": selected.snapshot(), "competing": competing.snapshot()})
		if err == nil {
			err = r.Keep("routing", path)
		}
		returnErr = errors.Join(returnErr, err)
	}()
	recipe, err := prepareManagerRouting(r, options, selected.URL(), competing.URL())
	if recipe.cleanup != nil {
		defer func() { returnErr = errors.Join(returnErr, recipe.cleanup()) }()
	}
	if err != nil {
		return err
	}
	r.Result.Observations["expected_upstream"] = recipe.expected
	r.Result.Observations["route_host"] = recipe.routeHost
	commandArgs := append([]string{r.Cell.Executable}, recipe.args...)
	if protected {
		r.Env["SCFW_PROXY_ENABLED"] = "1"
		if options.block {
			if err := writeFinding(r, r.Candidate.Ecosystem, r.Candidate.Project, r.Candidate.Version, "CRITICAL"); err != nil {
				return err
			}
		}
		commandArgs = append([]string{r.Binary, "run", "--executable", r.Cell.Executable, "--", r.Cell.Manager}, recipe.args...)
	}
	command, commandErr := managerRoutingCommand(r, recipe, protected, commandArgs)
	if command.TimedOut {
		return commandErr
	}
	stderr, err := os.ReadFile(command.Stderr.Path)
	if err != nil {
		return err
	}
	for path, want := range recipe.originals {
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("original routing configuration changed: %s", path)
		}
		if err := r.Keep("config-after-"+filepath.Base(path), path); err != nil {
			return err
		}
	}
	if options.name == "malformed-proxy" {
		if command.ExitCode <= 0 {
			return fmt.Errorf("malformed proxy unexpectedly succeeded: %v", commandErr)
		}
		if protected {
			if !strings.Contains(string(stderr), "proxy") || (!strings.Contains(string(stderr), "invalid") && !strings.Contains(string(stderr), "port")) {
				return fmt.Errorf("missing proxy setup diagnostic: %s", stderr)
			}
			if err := assertUVNoPolicy(r); err != nil {
				return err
			}
			r.Result.ResolvedAction = "REJECTED"
			return assertUVNoProxy(r, string(stderr))
		}
		return nil
	}
	if protected && strings.HasPrefix(options.name, "port-default-") {
		if command.ExitCode <= 0 || !strings.Contains(string(stderr), "explicit HTTPS port 443") {
			return fmt.Errorf("missing default-port compatibility diagnostic: exit=%d: %s", command.ExitCode, stderr)
		}
		if err := assertManagerRoutingInstall(r, recipe, true); err != nil {
			return err
		}
		if err := assertUVNoPolicy(r); err != nil {
			return err
		}
		if err := assertUVNoProxy(r, string(stderr)); err != nil {
			return err
		}
		if err := assertForwardRoute(selected.snapshot(), command, recipe.routeHost, false); err != nil {
			return err
		}
		if err := assertForwardRoute(competing.snapshot(), command, recipe.routeHost, false); err != nil {
			return err
		}
		r.Result.ResolvedAction = "REJECTED"
		return nil
	}
	blocked := protected && options.block
	if (command.ExitCode != 0) != blocked || command.ExitCode < 0 {
		return fmt.Errorf("exit %d, blocked=%v: %w", command.ExitCode, blocked, commandErr)
	}
	if err := assertManagerRoutingInstall(r, recipe, blocked); err != nil {
		return err
	}
	if protected {
		outcome := "ALLOW"
		if blocked {
			outcome = "BLOCK"
		}
		records, err := readPolicy(r.Env["SCFW_LOG_FILE"])
		if err != nil {
			return err
		}
		if err := assertPolicy(records, r.Candidate, r.Cell.Manager, r.Cell.Executable, outcome); err != nil {
			return err
		}
		r.Result.PolicyOutcome, r.Result.ResolvedAction = outcome, outcome
		if err := r.Keep("policy", r.Env["SCFW_LOG_FILE"]); err != nil {
			return err
		}
		if err := assertCleanup(r, string(stderr)); err != nil {
			return err
		}
	}
	// Public artifact requests distinguish manager routing from independent policy
	// metadata lookups. BLOCK withholds that request; IP cases observe index traffic.
	if !blocked || strings.HasPrefix(options.name, "ip-") || strings.HasPrefix(options.name, "port-nondefault-") {
		if err := assertForwardRoute(selected.snapshot(), command, recipe.routeHost, recipe.expected == 0); err != nil {
			return fmt.Errorf("selected route: %w", err)
		}
		if err := assertForwardRoute(competing.snapshot(), command, recipe.routeHost, recipe.expected == 1); err != nil {
			return fmt.Errorf("competing route: %w", err)
		}
	}
	return nil
}

func managerRoutingCommand(r *caseRun, recipe managerRoutingRecipe, protected bool, args []string) (commandEvidence, error) {
	if !protected || !recipe.merged {
		return r.Command("install", args...)
	}
	observer, err := filepath.Abs("testdata/uv_config_scripts/observe.py")
	if err != nil {
		return commandEvidence{}, err
	}
	input, statePath := filepath.Join(r.Root, "stdin"), filepath.Join(r.Root, "merged.json")
	if err := os.WriteFile(input, nil, 0600); err != nil {
		return commandEvidence{}, err
	}
	command, commandErr := r.Command("observed-install", append([]string{r.Cell.Runtime, observer, input, statePath, r.Env["TMPDIR"]}, args...)...)
	var state uvConfigState
	if err := readJSON(statePath, &state); err != nil {
		return command, err
	}
	if err := recordUVObservation(r, state, statePath, args, command); err != nil {
		return command, err
	}
	if len(state.Merged) == 0 {
		return command, fmt.Errorf("no temporary merged uv configuration observed")
	}
	for path, content := range state.Merged {
		var config map[string]any
		if err := toml.Unmarshal([]byte(content), &config); err != nil {
			return command, err
		}
		proxy, ok := config["https-proxy"].(string)
		if !ok || !strings.HasPrefix(proxy, "http://127.0.0.1:") || config["http-proxy"] != proxy || config["index-url"] != "https://pypi.org/simple" {
			return command, fmt.Errorf("merged configuration did not preserve index and replace routing")
		}
		bypass, ok := config["no-proxy"].([]any)
		if !ok || len(bypass) != 0 {
			return command, fmt.Errorf("merged config retained proxy bypass")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			return command, fmt.Errorf("temporary merged config remains: %s", path)
		}
	}
	return command, commandErr
}

func prepareManagerRouting(r *caseRun, options managerRouteCase, selected, competing string) (managerRoutingRecipe, error) {
	recipe := managerRoutingRecipe{originals: map[string][]byte{}}
	r.Env["PATH"] = filepath.Dir(r.Cell.Executable) + string(os.PathListSeparator) + filepath.Dir(r.Cell.Runtime) + string(os.PathListSeparator) + r.Env["PATH"]
	switch r.Cell.Manager {
	case "npm":
		if _, err := prepareNPMProject(r); err != nil {
			return recipe, err
		}
	case "poetry":
		python, err := preparePoetry(r, "direct")
		if err != nil {
			return recipe, err
		}
		recipe.python = python
	case "uv":
		if _, _, err := prepareUV(r, uvOptions{}); err != nil {
			return recipe, err
		}
		delete(r.Env, "UV_DEFAULT_INDEX")
		venv := filepath.Join(r.Root, "venv")
		if _, err := r.Command("venv", r.Cell.Runtime, "-m", "venv", "--without-pip", venv); err != nil {
			return recipe, classified("INFRASTRUCTURE_FAILURE", err)
		}
		recipe.python = filepath.Join(venv, "bin", "python")
	}
	artifactURL, err := url.Parse(r.Candidate.Artifacts[0].URL)
	if err != nil {
		return recipe, err
	}
	recipe.routeHost = artifactURL.Hostname()
	index := "https://pypi.org/simple"
	if r.Cell.Manager == "npm" {
		index = "https://registry.npmjs.org/"
	}
	r.Env["HTTPS_PROXY"], r.Env["HTTP_PROXY"] = selected, selected
	controlled := strings.HasPrefix(options.name, "ip-") || strings.HasPrefix(options.name, "port-nondefault-")
	if controlled {
		index, recipe.cleanup, err = managerIPIndex(r, strings.HasPrefix(options.name, "port-nondefault-"))
		if err != nil {
			return recipe, err
		}
		u, _ := url.Parse(index)
		recipe.routeHost = u.Hostname()
	}
	target := r.Candidate.Project + "==" + r.Candidate.Version
	if r.Cell.Manager == "npm" {
		target = r.Candidate.Project + "@" + r.Candidate.Version
	}
	directPort := strings.HasPrefix(options.name, "port-") && !strings.HasPrefix(options.name, "port-nondefault-")
	if directPort {
		if options.name != "port-default-implicit" {
			artifactURL.Host = artifactURL.Hostname() + ":443"
		}
		target = artifactURL.String()
	}
	switch r.Cell.Manager {
	case "npm":
		r.Env["npm_config_registry"] = index
		if controlled {
			// Keep discovered public tarball URLs when npm uses the loopback index.
			r.Env["npm_config_replace_registry_host"] = "never"
		}
		recipe.args = []string{"install", target, "--ignore-scripts", "--no-audit", "--no-fund"}
	case "pip":
		r.Env["PIP_INDEX_URL"] = index
		recipe.target = filepath.Join(r.Root, "installed")
		recipe.args = []string{"install", "--no-deps", "--only-binary=:all:", "--target", recipe.target, target}
	case "poetry":
		values := map[string]string{"Python": r.Cell.RuntimeVersion, "Name": r.Candidate.Project, "Version": r.Candidate.Version, "Index": "", "URL": ""}
		if controlled {
			values["Index"] = index
		}
		if directPort {
			values["URL"] = target
		}
		if err := managerRoutingFixture("project.toml.tmpl", filepath.Join(r.WorkDir, "pyproject.toml"), values, nil); err != nil {
			return recipe, err
		}
		recipe.args = []string{"--no-interaction", "install"}
	case "uv":
		recipe.args = []string{"pip", "install", "--python", recipe.python, "--index-url", index, target}
	}
	name := options.name
	switch {
	case name == "domain-suffix":
		r.Env["NO_PROXY"], recipe.expected = ".org", -1
	case name == "domain-boundary":
		r.Env["NO_PROXY"] = "ythonhosted.org"
		if r.Cell.Manager == "npm" {
			r.Env["NO_PROXY"] = "pmjs.org"
		}
		if r.Cell.Manager == "pip" && uvVersionCompare(r.Cell.ManagerVersion, "26.2") < 0 {
			recipe.expected = -1
		}
	case name == "port-match" || name == "port-miss" || strings.HasPrefix(name, "port-default-"):
		port := "443"
		if name == "port-miss" {
			port = "444"
		}
		r.Env["NO_PROXY"] = recipe.routeHost + ":" + port
		if (name == "port-match" || name == "port-default-explicit") && (r.Cell.Manager == "pip" || r.Cell.Manager == "poetry") {
			recipe.expected = -1
		}
	case strings.HasPrefix(name, "port-nondefault-"):
		u, _ := url.Parse(index)
		r.Env["NO_PROXY"] = u.Host
		if name == "port-nondefault-miss" {
			r.Env["NO_PROXY"] = "localhost:1"
		} else if r.Cell.Manager == "pip" || r.Cell.Manager == "poetry" {
			recipe.expected = -1
		}
	case strings.HasPrefix(name, "ip-"):
		pattern := "127.0.0.2"
		switch name {
		case "ip-exact":
			pattern, recipe.expected = "127.0.0.1", -1
		case "ip-cidr":
			pattern = "127.0.0.0/8"
			if r.Cell.Manager != "npm" {
				recipe.expected = -1
			}
		case "ip-port":
			u, _ := url.Parse(index)
			pattern = u.Host
		}
		r.Env["NO_PROXY"] = pattern
	case name == "all-fallback":
		delete(r.Env, "HTTP_PROXY")
		delete(r.Env, "HTTPS_PROXY")
		r.Env["ALL_PROXY"] = selected
		if r.Cell.Manager == "npm" {
			recipe.expected = -1
		}
	case name == "empty-lowercase-fallback":
		r.Env["HTTPS_PROXY"], r.Env["https_proxy"], r.Env["ALL_PROXY"] = competing, "", selected
	case strings.HasPrefix(name, "npm-") || name == "npmrc-proxy":
		fileProxy := competing
		if name == "npmrc-proxy" {
			fileProxy = selected
		}
		if name != "npm-flag-bypass" {
			if err := managerRoutingFixture("npmrc.tmpl", r.Env["npm_config_userconfig"], map[string]string{"Proxy": fileProxy}, recipe.originals); err != nil {
				return recipe, err
			}
			r.Env["HTTPS_PROXY"] = competing
		}
		switch name {
		case "npm-env-proxy":
			r.Env["npm_config_https_proxy"] = selected
		case "npm-flag-proxy":
			r.Env["npm_config_https_proxy"] = competing
			recipe.args = append(recipe.args, "--https-proxy="+selected)
		case "npm-flag-bypass":
			recipe.args = append(recipe.args, "--noproxy="+recipe.routeHost)
			recipe.expected = -1
		}
	case strings.HasPrefix(name, "pip-"):
		values := map[string]string{"Global": "", "Install": "", "NoProxy": ""}
		delete(r.Env, "HTTPS_PROXY")
		delete(r.Env, "HTTP_PROXY")
		switch name {
		case "pip-global-proxy":
			values["Global"], r.Env["HTTPS_PROXY"] = selected, competing
			if uvVersionCompare(r.Cell.ManagerVersion, "22.1") < 0 {
				recipe.expected = 1
			}

		case "pip-command-proxy":
			values["Global"], values["Install"] = competing, selected
		case "pip-env-proxy":
			values["Global"], r.Env["PIP_PROXY"] = competing, selected
		case "pip-flag-proxy":
			values["Global"], r.Env["PIP_PROXY"] = competing, competing
			recipe.args = append(recipe.args, "--proxy", selected)
		case "pip-explicit-fallback":
			r.Env["PIP_PROXY"], r.Env["HTTPS_PROXY"], r.Env["NO_PROXY"] = selected, competing, "*"
		case "pip-no-proxy-env-config":
			values["NoProxy"], r.Env["HTTPS_PROXY"] = "true", selected
			if uvVersionCompare(r.Cell.ManagerVersion, "26.2") >= 0 {
				recipe.expected = -1
			}
		case "pip-no-proxy-env-flag":
			r.Env["HTTPS_PROXY"] = selected
			recipe.args = append(recipe.args, "--no-proxy-env")
			recipe.expected = -1
		}
		path := filepath.Join(r.Root, "pip.conf")
		if err := managerRoutingFixture("pip.conf.tmpl", path, values, recipe.originals); err != nil {
			return recipe, err
		}
		r.Env["PIP_CONFIG_FILE"] = path
	case strings.HasPrefix(name, "uv-"):
		recipe.merged = true
		delete(r.Env, "UV_NO_CONFIG")
		r.Env["UV_NO_SYSTEM_CONFIG"] = "1"
		r.Env["HTTPS_PROXY"] = competing
		fixture := "https"
		if name == "uv-file-http" {
			fixture, recipe.expected = "http", -1
		}
		if name == "uv-file-bypass" {
			fixture, recipe.expected = "bypass", -1
			r.Env["NO_PROXY"] = "does-not-match.invalid"
		}
		path := filepath.Join(r.WorkDir, "uv.toml")
		if name == "uv-explicit-file" {
			if err := managerUVRoutingFixture("https", path, competing, recipe.originals); err != nil {
				return recipe, err
			}
			path = filepath.Join(r.WorkDir, "explicit.toml")
			recipe.args = append(recipe.args, "--config-file", path)
		}
		if err := managerUVRoutingFixture(fixture, path, selected, recipe.originals); err != nil {
			return recipe, err
		}
	case name == "malformed-proxy":
		r.Env["HTTPS_PROXY"] = "http://127.0.0.1:not-a-port"
	}
	for path := range recipe.originals {
		if err := r.Keep("config-before-"+filepath.Base(path), path); err != nil {
			return recipe, err
		}
	}
	settings := map[string]string{}
	for key, value := range r.Env {
		if strings.Contains(strings.ToLower(key), "proxy") {
			settings[key] = value
		}
	}
	r.Result.Observations["routing_environment"] = settings
	return recipe, nil
}

func managerRoutingFixture(name, path string, values map[string]string, original map[string][]byte) error {
	raw, err := os.ReadFile(filepath.Join("testdata/manager_routing", name))
	if err != nil {
		return err
	}
	content, err := uvRender(string(raw), values)
	if err != nil {
		return err
	}
	if original != nil {
		return uvWriteSnapshot(path, content, original)
	}
	return os.WriteFile(path, content, 0600)
}
func managerUVRoutingFixture(name, path, proxy string, original map[string][]byte) error {
	raw, err := os.ReadFile("testdata/manager_routing/configurations.toml.tmpl")
	if err != nil {
		return err
	}
	var configs map[string]map[string]any
	if err := toml.Unmarshal(raw, &configs); err != nil {
		return err
	}
	content, err := toml.Marshal(configs[name])
	if err != nil {
		return err
	}
	content, err = uvRender(string(content), map[string]string{"Proxy": proxy})
	if err != nil {
		return err
	}
	return uvWriteSnapshot(path, content, original)
}

func assertManagerRoutingInstall(r *caseRun, recipe managerRoutingRecipe, blocked bool) error {
	if r.Cell.Manager == "npm" {
		return assertNPMInstall(r, blocked)
	}
	expected := r.Candidate.Version
	if blocked {
		expected = ""
	}
	if r.Cell.Manager != "pip" {
		return assertUVInstalled(r, recipe.python, expected, "installed")
	}
	script, err := filepath.Abs("testdata/pip_baseline/inspect_install.py")
	if err != nil {
		return err
	}
	command, err := r.Command("installed-state", r.Cell.Runtime, "-I", script, recipe.target, r.Candidate.Project, r.Candidate.Module)
	if err != nil {
		return err
	}
	var installed struct {
		Present  bool
		Version  string
		Imported bool
	}
	if err := readJSON(command.Stdout.Path, &installed); err != nil {
		return err
	}
	r.Result.Observations["installed"] = installed
	if installed.Present == blocked || installed.Version != expected || (!blocked && !installed.Imported) {
		return fmt.Errorf("unexpected installed state: %+v", installed)
	}
	return nil
}

func managerIPIndex(r *caseRun, domain bool) (string, func() error, error) {
	var body []byte
	contentType := "text/html"
	if r.Cell.Manager == "npm" {
		var err error
		body, err = os.ReadFile(r.Candidate.Metadata[0].Body.Path)
		if err != nil {
			return "", nil, err
		}
		contentType = "application/json"
	} else {
		raw, err := os.ReadFile("testdata/manager_routing/simple.html.tmpl")
		if err != nil {
			return "", nil, err
		}
		a := r.Candidate.Artifacts[0]
		body, err = uvRender(string(raw), map[string]string{"URL": a.URL, "Name": a.Name, "SHA256": a.SHA256})
		if err != nil {
			return "", nil, err
		}
	}
	path := filepath.Join(r.Root, "address-index-body")
	if err := os.WriteFile(path, body, 0600); err != nil {
		return "", nil, err
	}
	if err := r.Keep("controlled-index", path); err != nil {
		return "", nil, err
	}
	var mutex sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		requests = append(requests, request.URL.Path)
		mutex.Unlock()
		if strings.HasSuffix(request.URL.Path, ".tgz") || strings.HasSuffix(request.URL.Path, ".whl") {
			http.Error(w, "artifacts must use the discovered public origin", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
	cleanup := func() error {
		server.Close()
		mutex.Lock()
		observed := slices.Clone(requests)
		mutex.Unlock()
		path := filepath.Join(r.Root, "address-index-requests.json")
		if err := writeJSON(path, observed); err != nil {
			return err
		}
		if err := r.Keep("controlled-index-requests", path); err != nil {
			return err
		}
		if len(observed) == 0 {
			return fmt.Errorf("controlled address index was never requested")
		}
		return nil
	}
	r.Result.Observations["controlled_origin_reason"] = "Literal IP and nondefault domain-port bypass require a loopback index; package artifacts retain their discovered public URLs and bytes."
	address := server.URL
	if domain {
		address = strings.Replace(address, "127.0.0.1", "localhost", 1)
	}
	r.Result.Observations["controlled_index"] = address
	return address + "/simple", cleanup, nil
}

func TestHarnessManagerRoutingInventory(t *testing.T) {
	for _, manager := range []string{"npm", "pip", "poetry", "uv"} {
		cases, err := selectCases(cell{ID: "routing", Manager: manager, Modes: []string{"proxy"}, Suites: []string{"manager-routing"}, Capabilities: []string{"uv-file-proxy", "pip-no-proxy-env"}}, []string{"manager-routing"})
		if err != nil {
			t.Fatal(err)
		}
		applicable := slices.DeleteFunc(cases, func(p plannedCase) bool { return p.NotApplicable != "" })
		expected := map[string]int{"npm": 31, "pip": 37, "poetry": 25, "uv": 31}[manager]
		if len(applicable) != expected {
			t.Fatalf("%s has %d cases, want %d", manager, len(applicable), expected)
		}
		if !slices.ContainsFunc(applicable, func(p plannedCase) bool { return strings.Contains(p.Variant, "ip-exact-block") }) {
			t.Fatal("missing IP inspection case")
		}
	}
}
