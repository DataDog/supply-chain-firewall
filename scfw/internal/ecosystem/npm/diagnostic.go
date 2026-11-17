// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"encoding/json"
	"net/url"
	"strings"
)

// DiagnosticMetadata validates an already-read packument without changing
// enforcement classification. RequestRegistryAPI does not recognize packuments.
func (classifier *Classifier) DiagnosticMetadata(requestURL url.URL, body []byte, publication bool) bool {
	if len(body) > 64<<10 {
		return false
	}
	if kind, _ := classifier.Classify(&requestURL); kind == RequestTarball {
		return false
	}
	var document struct {
		Name     string                     `json:"name"`
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
		Tags     map[string]string          `json:"dist-tags"`
	}
	if json.Unmarshal(body, &document) != nil {
		return false
	}
	if publication {
		return len(document.Time) > 0
	}
	registries := classifier.registries
	if len(registries) == 0 {
		registries = []url.URL{{Scheme: "https", Host: "registry.npmjs.org", Path: "/"}}
	}
	for _, registry := range registries {
		if !strings.EqualFold(registry.Host, requestURL.Host) || !strings.EqualFold(registry.Scheme, requestURL.Scheme) {
			continue
		}
		base := strings.TrimSuffix(registry.Path, "/") + "/"
		if !strings.HasPrefix(requestURL.Path, base) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(requestURL.Path, base), "/")
		if name == "" || strings.HasPrefix(name, "-") {
			continue
		}
		if name == document.Name && (document.Versions != nil || document.Time != nil || document.Tags != nil) {
			return true
		}
	}
	return false
}
