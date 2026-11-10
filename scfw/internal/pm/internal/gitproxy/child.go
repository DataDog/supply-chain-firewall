// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package gitproxy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ChildOverrides redirects Git network settings without changing inherited files.
func (s *Settings) ChildOverrides(overrides map[string]string, config proxy.ClientConfig) error {
	// Rebuild inherited command settings from the flattened snapshot. Original
	// proxies and pins belong on the outbound side. The HTTP helper preserves
	// Git's distinction between named remotes and raw URLs.
	var inherited []gitConfigurationEntry
	for _, entry := range s.commandEntries {
		if !isOutboundOnly(entry.key) && !isInclude(entry.key) {
			inherited = append(inherited, entry)
		}
	}
	count := len(inherited)
	if count > 4096 {
		return errors.New("invalid inherited Git configuration count")
	}
	for index, entry := range inherited {
		value := entry.value
		if entry.implicit {
			value = "true"
		}
		overrides["GIT_CONFIG_KEY_"+strconv.Itoa(index)] = entry.key
		overrides["GIT_CONFIG_VALUE_"+strconv.Itoa(index)] = value
	}
	ca, err := s.interceptionCA(config)
	if err != nil {
		return err
	}
	forced := map[string]string{"http.proxy": config.URL, "http.sslcainfo": ca, "http.sslcapath": "", "http.sslverify": "true"}
	for _, entry := range s.entries {
		if strings.HasPrefix(entry.key, "http.") && !strings.HasSuffix(entry.key, ".proxy") {
			prefix := entry.key[:strings.LastIndexByte(entry.key, '.')+1]
			if value, ok := forced["http."+entry.key[strings.LastIndexByte(entry.key, '.')+1:]]; ok {
				forced[prefix+entry.key[strings.LastIndexByte(entry.key, '.')+1:]] = value
			}
		}
	}
	for _, profile := range s.profiles {
		client, ok := config.AdditionalClients[profile.name]
		if !ok {
			return errors.New("missing Git configuration proxy")
		}
		forced["http."+profile.scope.String()+".proxy"] = client.URL
	}
	keys := make([]string, 0, len(forced))
	for key := range forced {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		value := forced[key]
		overrides["GIT_CONFIG_KEY_"+strconv.Itoa(count)] = key
		overrides["GIT_CONFIG_VALUE_"+strconv.Itoa(count)] = value
		count++
	}
	// Some Git clients only read GIT_CONFIG_GLOBAL. A flattened snapshot covers
	// those clients and native Git without
	// changing HOME, the user's files, includes, or credential helper settings.
	var snapshot []gitConfigurationEntry
	for _, entry := range s.fileEntries {
		if !isOutboundOnly(entry.key) {
			snapshot = append(snapshot, entry)
		}
	}
	for _, key := range keys {
		snapshot = append(snapshot, gitConfigurationEntry{key: key, value: forced[key]})
	}
	path := filepath.Join(filepath.Dir(config.CACertificatePath), "gitconfig")
	if err := os.WriteFile(path, []byte(renderGitConfiguration(snapshot)), 0600); err != nil {
		return errors.New("could not prepare invocation Git settings")
	}
	overrides["GIT_CONFIG_GLOBAL"] = path
	overrides["GIT_CONFIG_SYSTEM"] = os.DevNull
	overrides["GIT_CONFIG_NOSYSTEM"] = "1"
	overrides["GIT_CONFIG_COUNT"] = strconv.Itoa(count)
	// Both command-configuration mechanisms are already captured in the
	// snapshot. Replay only through COUNT so multivalued entries occur once.
	overrides["GIT_CONFIG_PARAMETERS"] = ""
	overrides["GIT_SSL_CAINFO"] = ca
	overrides["GIT_SSL_CAPATH"] = ""
	return s.prepareRemoteHelpers(overrides, config)
}
