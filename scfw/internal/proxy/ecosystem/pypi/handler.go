// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package pypi handles Python simple-index metadata and distribution downloads.
package pypi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	baseecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	proxyecosystem "github.com/DataDog/supply-chain-firewall/scfw/internal/proxy/ecosystem"
)

const maxRewriteSize = 64 << 20

// Handler rewrites PEP 503 HTML, PEP 691 JSON, and redirects.
type Handler struct{}

// Package identifies wheel and source-distribution filenames.
func (Handler) Package(destination *url.URL) (pm.Package, bool) {
	return packageFromFilename(path.Base(destination.Path), destination)
}

func packageFromFilename(filename string, destination *url.URL) (pm.Package, bool) {
	var name, version string
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.Split(strings.TrimSuffix(filename, ".whl"), "-")
		if len(parts) < 5 {
			return pm.Package{}, false
		}
		name, version = parts[0], parts[1]
	} else {
		stem := filename
		matched := false
		for _, extension := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"} {
			if strings.HasSuffix(stem, extension) {
				stem = strings.TrimSuffix(stem, extension)
				matched = true
				break
			}
		}
		if !matched {
			return pm.Package{}, false
		}
		separator := strings.LastIndex(stem, "-")
		if separator < 1 || separator == len(stem)-1 {
			return pm.Package{}, false
		}
		name, version = stem[:separator], stem[separator+1:]
	}
	name = strings.ReplaceAll(name, "_", "-")
	source := *destination
	source.User, source.RawQuery, source.Fragment = nil, "", ""
	return pm.Package{Ecosystem: baseecosystem.PYPI, Name: name, Version: version, Source: source.String()}, true
}

func (Handler) RewriteResponse(response *http.Response, rewrite proxyecosystem.RewriteURL, _ []*url.URL) error {
	if location := response.Header.Get("Location"); location != "" {
		if resolved, err := response.Request.URL.Parse(location); err == nil && isHTTP(resolved) {
			response.Header.Set("Location", rewrite(resolved, nil))
		}
	}
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType != "text/html" && mediaType != "application/vnd.pypi.simple.v1+json" && mediaType != "application/json" {
		return nil
	}
	if response.ContentLength > maxRewriteSize {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRewriteSize+1))
	if err != nil {
		return fmt.Errorf("read Python index response: %w", err)
	}
	if len(body) > maxRewriteSize {
		response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), response.Body))
		return nil
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("close Python index response: %w", err)
	}
	var rewritten []byte
	if mediaType == "text/html" {
		rewritten = rewriteHTML(body, response.Request.URL, rewrite)
	} else {
		rewritten = rewriteJSON(body, response.Request.URL, rewrite)
	}
	response.Body = io.NopCloser(bytes.NewReader(rewritten))
	response.ContentLength = int64(len(rewritten))
	response.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	response.Header.Del("ETag")
	response.Header.Del("Content-MD5")
	return nil
}

func rewriteHTML(body []byte, base *url.URL, rewrite proxyecosystem.RewriteURL) []byte {
	document, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return body
	}
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "a") {
			for index := range node.Attr {
				if !strings.EqualFold(node.Attr[index].Key, "href") {
					continue
				}
				resolved, parseErr := base.Parse(node.Attr[index].Val)
				if parseErr != nil || !isHTTP(resolved) {
					continue
				}
				pkg, ok := (Handler{}).Package(resolved)
				if !ok {
					pkg, ok = packageFromFilename(strings.TrimSpace(nodeText(node)), resolved)
				}
				if ok {
					node.Attr[index].Val = rewrite(resolved, &pkg)
				} else {
					node.Attr[index].Val = rewrite(resolved, nil)
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	var rewritten bytes.Buffer
	if html.Render(&rewritten, document) != nil {
		return body
	}
	return rewritten.Bytes()
}

func nodeText(node *html.Node) string {
	var text strings.Builder
	var visit func(*html.Node)
	visit = func(current *html.Node) {
		if current.Type == html.TextNode {
			text.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(node)
	return text.String()
}

func rewriteJSON(body []byte, base *url.URL, rewrite proxyecosystem.RewriteURL) []byte {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil || !walk(document, "", base, rewrite) {
		return body
	}
	rewritten, err := json.Marshal(document)
	if err != nil {
		return body
	}
	return rewritten
}

func walk(value any, key string, base *url.URL, rewrite proxyecosystem.RewriteURL) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for childKey, child := range typed {
			if text, ok := child.(string); ok && (childKey == "url" || childKey == "download_url") {
				resolved, err := base.Parse(text)
				if err == nil && isHTTP(resolved) {
					pkg, ok := (Handler{}).Package(resolved)
					if !ok {
						if filename, exists := typed["filename"].(string); exists {
							filenameURL := &url.URL{Scheme: resolved.Scheme, Host: resolved.Host, Path: "/" + filename}
							pkg, ok = (Handler{}).Package(filenameURL)
							if ok {
								source := *resolved
								source.User, source.RawQuery, source.Fragment = nil, "", ""
								pkg.Source = source.String()
							}
						}
					}
					if ok {
						typed[childKey] = rewrite(resolved, &pkg)
					} else {
						typed[childKey] = rewrite(resolved, nil)
					}
					changed = true
					continue
				}
			}
			changed = walk(child, childKey, base, rewrite) || changed
		}
	case []any:
		for _, child := range typed {
			changed = walk(child, key, base, rewrite) || changed
		}
	}
	return changed
}

func isHTTP(value *url.URL) bool {
	return value != nil && (strings.EqualFold(value.Scheme, "http") || strings.EqualFold(value.Scheme, "https")) && value.Host != ""
}
