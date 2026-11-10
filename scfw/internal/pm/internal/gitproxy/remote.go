// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type remoteProfile struct {
	name, remote, base, upstream string
	scope                        *routeProfile
}

func (s *Settings) discoverRemoteProfiles() {
	remotes := map[string]string{}
	for _, entry := range s.entries {
		if !isRemoteProxy(entry.key) {
			continue
		}
		if entry.implicit {
			s.discoveryErr = errors.New("missing Git remote proxy value")
			return
		}
		remote := strings.TrimSuffix(strings.TrimPrefix(entry.key, "remote."), ".proxy")
		remotes[remote] = entry.value
	}
	if len(s.profiles)+(len(s.profiles)+1)*len(remotes) > 128 {
		s.discoveryErr = errors.New("too many Git configuration profiles")
		return
	}
	names := make([]string, 0, len(remotes))
	for remote := range remotes {
		names = append(names, remote)
	}
	slices.Sort(names)
	for index, remote := range names {
		prefix := "git-remote-" + strconv.Itoa(index) + "-"
		s.remoteProfiles = append(s.remoteProfiles, remoteProfile{name: prefix + "default", remote: remote, upstream: remotes[remote]})
		for _, scope := range s.profiles {
			s.remoteProfiles = append(s.remoteProfiles, remoteProfile{name: prefix + scope.name, remote: remote, base: scope.name, upstream: remotes[remote], scope: &scope})
		}
	}
}

//go:embed remote_helper.sh.tmpl
var remoteHelperSource string

func shellQuoted(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

// Git passes each HTTP helper the remote name and original URL. Only the
// invocation's private helper directory is changed; native helpers are linked
// through so submodules and other Git commands retain their original behavior.
func (s *Settings) prepareRemoteHelpers(overrides map[string]string, config proxy.ClientConfig) error {
	if len(s.remoteProfiles) == 0 {
		return nil
	}
	data, err := runGitConfiguration(s.executable, s.directory, s.environment, "", "--exec-path")
	if err != nil {
		return err
	}
	source := strings.TrimSuffix(string(data), "\n")
	if source == "" {
		return errors.New("could not discover native Git HTTP helpers")
	}
	if !filepath.IsAbs(source) {
		source = filepath.Join(s.directory, source)
	}
	entries, err := os.ReadDir(source)
	if err != nil || len(entries) > 4096 {
		return errors.New("could not read native Git helper directory")
	}
	directory, err := os.MkdirTemp(filepath.Dir(config.CACertificatePath), "git-exec-")
	if err != nil {
		return errors.New("could not prepare invocation Git helpers")
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "git-remote-http" || name == "git-remote-https" {
			continue
		}
		if err := os.Symlink(filepath.Join(source, name), filepath.Join(directory, name)); err != nil {
			return errors.New("could not prepare invocation Git helpers")
		}
	}
	allowed, remotes, err := s.remoteHelperCases(config)
	if err != nil {
		return err
	}
	parsed, err := template.New("git-http-helper").Parse(remoteHelperSource)
	if err != nil {
		return errors.New("could not prepare invocation Git HTTP helpers")
	}
	for _, name := range []string{"git-remote-http", "git-remote-https"} {
		helper := filepath.Join(source, name)
		info, err := os.Stat(helper)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return errors.New("native Git HTTP helper is unavailable")
		}
		var script bytes.Buffer
		err = parsed.Execute(&script, struct{ Git, Helper, Allowed, Remotes string }{shellQuoted(s.executable), shellQuoted(helper), allowed, remotes})
		if err != nil {
			return errors.New("could not prepare invocation Git HTTP helpers")
		}
		if err := os.WriteFile(filepath.Join(directory, name), script.Bytes(), 0700); err != nil {
			return errors.New("could not write invocation Git HTTP helpers")
		}
	}
	overrides["GIT_EXEC_PATH"] = directory
	return nil
}

func (s *Settings) remoteHelperCases(config proxy.ClientConfig) (string, string, error) {
	base := map[string]string{"": config.URL}
	var allowed, remotes strings.Builder
	fmt.Fprintf(&allowed, "    %s) ;;\n", shellQuoted(config.URL))
	for _, profile := range s.profiles {
		client, ok := config.AdditionalClients[profile.name]
		if !ok {
			return "", "", errors.New("missing Git configuration proxy")
		}
		base[profile.name] = client.URL
		fmt.Fprintf(&allowed, "    %s) ;;\n", shellQuoted(client.URL))
	}
	previous := ""
	for index, profile := range s.remoteProfiles {
		if index == 0 || profile.remote != previous {
			if index != 0 {
				remotes.WriteString("        *) scfw_fail ;;\n        esac\n        ;;\n")
			}
			fmt.Fprintf(&remotes, "    %s)\n        case \"$scfw_profile\" in\n", shellQuoted(profile.remote))
		}
		client, ok := config.AdditionalClients[profile.name]
		if !ok {
			return "", "", errors.New("missing Git remote proxy configuration")
		}
		fmt.Fprintf(&remotes, "        %s) scfw_remote_proxy=%s; scfw_remote_parameter=%s ;;\n", shellQuoted(base[profile.base]), shellQuoted(client.URL), shellQuoted(gitParameter("remote."+profile.remote+".proxy", client.URL)))
		previous = profile.remote
	}
	if len(s.remoteProfiles) > 0 {
		remotes.WriteString("        *) scfw_fail ;;\n        esac\n        ;;\n")
	}
	return allowed.String(), remotes.String(), nil
}
