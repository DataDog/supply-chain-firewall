// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"golang.org/x/net/html"
)

// DiagnosticMetadata validates a bounded candidate independently of enforcement.
// Binary downloads are not metadata merely because their MIME type says JSON.
func (classifier *RequestClassifier) DiagnosticMetadata(requestURL url.URL, header http.Header, body []byte) bool {
	if len(body) > 64<<10 {
		return false
	}
	kind, _ := classifier.ClassifyResponse(http.MethodGet, &requestURL, header)
	if kind == RequestArtifact || kind == RequestCoreMetadata {
		return false
	}
	var document struct {
		Info *struct {
			Name string `json:"name"`
		} `json:"info"`
		Meta     map[string]json.RawMessage `json:"meta"`
		Files    []json.RawMessage          `json:"files"`
		Projects []json.RawMessage          `json:"projects"`
		Releases map[string]json.RawMessage `json:"releases"`
		URLs     []json.RawMessage          `json:"urls"`
	}
	if json.Unmarshal(body, &document) == nil {
		return (document.Info != nil && document.Info.Name != "" && (document.Releases != nil || document.URLs != nil)) ||
			((document.Meta != nil || kind == RequestSimpleAPI) && (document.Files != nil || document.Projects != nil))
	}
	if kind != RequestSimpleAPI {
		return false
	}
	tokens := html.NewTokenizer(bytes.NewReader(body))
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			return false
		case html.StartTagToken:
			token := tokens.Token()
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						return true
					}
				}
			}
		}
	}
}
