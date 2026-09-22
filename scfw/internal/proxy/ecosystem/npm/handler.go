// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package npm handles npm registry metadata and package download URLs.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	baseecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	proxyecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem"
)

const maxRewriteSize = 64 << 20

type requestContextKey struct{}

// Handler rewrites redirects, registry URLs, and npm dist.tarball URLs.
type Handler struct{}

// RewriteRequest asks npm registries for the full packument, whose time map is
// omitted from the abbreviated install document requested by npm clients.
func (Handler) RewriteRequest(request *http.Request, registries []*url.URL) {
	if request.Method != http.MethodGet || !isPackumentURL(request.URL, registries) {
		return
	}
	*request = *request.WithContext(context.WithValue(request.Context(), requestContextKey{}, true))
	accept, changed := fullPackumentAccept(request.Header.Values("Accept"))
	if !changed {
		return
	}
	request.Header.Set("Accept", accept)
	request.Header.Del("If-Modified-Since")
	request.Header.Del("If-None-Match")
}

// Package identifies standard npm registry tarball paths.
func (Handler) Package(destination *url.URL) (pm.Package, bool) {
	marker := "/-/"
	index := strings.LastIndex(destination.Path, marker)
	if index < 1 {
		return pm.Package{}, false
	}
	name := strings.Trim(destination.Path[:index], "/")
	filename := strings.TrimSuffix(path.Base(destination.Path), ".tgz")
	packageBase := path.Base(name)
	version, found := strings.CutPrefix(filename, packageBase+"-")
	if !found || version == "" {
		return pm.Package{}, false
	}
	source := *destination
	source.User, source.RawQuery, source.Fragment = nil, "", ""
	return pm.Package{Ecosystem: baseecosystem.NPM, Name: name, Version: version, Source: source.String()}, true
}

func (Handler) RewriteResponse(response *http.Response, rewrite proxyecosystem.RewriteURL, registries []*url.URL) error {
	rewriteLocation(response, rewrite)
	packumentResponse := response.Request != nil && response.Request.Context().Value(requestContextKey{}) == true && response.StatusCode >= 200 && response.StatusCode < 300
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if !packumentResponse && (err != nil || !isJSON(mediaType)) {
		return nil
	}
	if response.ContentLength > maxRewriteSize {
		if packumentResponse {
			return fmt.Errorf("rewrite npm packument: response exceeds %d bytes", maxRewriteSize)
		}
		return nil
	}
	body, complete, err := readBody(response, maxRewriteSize)
	if err != nil {
		return err
	}
	if !complete {
		if packumentResponse {
			return fmt.Errorf("rewrite npm packument: response exceeds %d bytes", maxRewriteSize)
		}
		return nil
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		response.Body = io.NopCloser(bytes.NewReader(body))
		if packumentResponse {
			return fmt.Errorf("decode npm packument: %w", err)
		}
		return nil
	}
	if !rewriteJSON(document, "", rewrite, registries, nil) {
		response.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	rewritten, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode npm registry response: %w", err)
	}
	replaceBody(response, rewritten)
	return nil
}

func fullPackumentAccept(values []string) (string, bool) {
	const abbreviated = "application/vnd.npm.install-v1+json"
	var alternatives []string
	foundAbbreviated := false
	foundFull := false
	for _, value := range values {
		for _, alternative := range strings.Split(value, ",") {
			alternative = strings.TrimSpace(alternative)
			mediaType, _, err := mime.ParseMediaType(alternative)
			if err == nil && strings.EqualFold(mediaType, abbreviated) {
				foundAbbreviated = true
				continue
			}
			if err == nil && strings.EqualFold(mediaType, "application/json") {
				if foundFull {
					continue
				}
				foundFull = true
				alternatives = append(alternatives, "application/json")
				continue
			}
			if alternative != "" {
				alternatives = append(alternatives, alternative)
			}
		}
	}
	if !foundAbbreviated {
		return "", false
	}
	if !foundFull {
		alternatives = append([]string{"application/json"}, alternatives...)
	}
	return strings.Join(alternatives, ", "), true
}

func isPackumentURL(destination *url.URL, registries []*url.URL) bool {
	for _, registry := range registries {
		if !strings.EqualFold(destination.Scheme, registry.Scheme) || !strings.EqualFold(destination.Host, registry.Host) {
			continue
		}
		basePath := strings.TrimSuffix(registry.Path, "/")
		if basePath != "" && destination.Path != basePath && !strings.HasPrefix(destination.Path, basePath+"/") {
			continue
		}
		relative := strings.Trim(strings.TrimPrefix(destination.Path, basePath), "/")
		parts := strings.Split(relative, "/")
		if len(parts) == 1 && parts[0] != "" && !strings.HasPrefix(parts[0], "-") {
			return true
		}
		if len(parts) == 2 && strings.HasPrefix(parts[0], "@") && parts[1] != "" {
			return true
		}
	}
	return false
}

func rewriteJSON(value any, key string, rewrite proxyecosystem.RewriteURL, registries []*url.URL, pkg *pm.Package) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			if childKey == "versions" {
				name, _ := typed["name"].(string)
				if versions, ok := child.(map[string]any); ok && name != "" {
					publishDates := parsePublishDates(typed["time"])
					for version, metadata := range versions {
						identified := &pm.Package{Ecosystem: baseecosystem.NPM, Name: name, Version: version, PublishDate: publishDates[version]}
						changed = rewriteJSON(metadata, childKey, rewrite, registries, identified) || changed
					}
					continue
				}
			}
			if value, ok := child.(string); ok && shouldRewrite(childKey, value, registries) {
				parsed, _ := url.Parse(value)
				var identified *pm.Package
				if childKey == "tarball" && pkg != nil {
					copy := *pkg
					source := *parsed
					source.User, source.RawQuery, source.Fragment = nil, "", ""
					copy.Source = source.String()
					identified = &copy
				}
				typed[childKey] = rewrite(parsed, identified)
				changed = true
				continue
			}
			changed = rewriteJSON(child, childKey, rewrite, registries, pkg) || changed
		}
	case []any:
		for _, child := range typed {
			changed = rewriteJSON(child, key, rewrite, registries, pkg) || changed
		}
	}
	return changed
}

func parsePublishDates(value any) map[string]time.Time {
	publishDates := make(map[string]time.Time)
	values, ok := value.(map[string]any)
	if !ok {
		return publishDates
	}
	for version, value := range values {
		timestamp, ok := value.(string)
		if !ok {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			publishDates[version] = parsed
		}
	}
	return publishDates
}

func shouldRewrite(key, value string, registries []*url.URL) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return false
	}
	if key == "tarball" {
		return true
	}
	for _, registry := range registries {
		if strings.EqualFold(parsed.Scheme, registry.Scheme) && strings.EqualFold(parsed.Host, registry.Host) {
			return true
		}
	}
	return false
}

func rewriteLocation(response *http.Response, rewrite proxyecosystem.RewriteURL) {
	if location := response.Header.Get("Location"); location != "" {
		if resolved, err := response.Request.URL.Parse(location); err == nil && (resolved.Scheme == "http" || resolved.Scheme == "https") {
			response.Header.Set("Location", rewrite(resolved, nil))
		}
	}
}

func readBody(response *http.Response, limit int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, false, fmt.Errorf("read npm registry response: %w", err)
	}
	if int64(len(body)) > limit {
		response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), response.Body))
		return nil, false, nil
	}
	if err := response.Body.Close(); err != nil {
		return nil, false, fmt.Errorf("close npm registry response: %w", err)
	}
	return body, true, nil
}

func replaceBody(response *http.Response, body []byte) {
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	response.Header.Del("ETag")
	response.Header.Del("Content-MD5")
}

func isJSON(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}
