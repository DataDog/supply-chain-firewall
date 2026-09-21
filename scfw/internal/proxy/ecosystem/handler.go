// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package ecosystem defines the registry-protocol boundary used by the proxy.
// Implementations understand ecosystem-specific index documents and make every
// package download traverse the local proxy.
package ecosystem

import (
	"net/http"
	"net/url"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
)

// RewriteURL converts an upstream URL into a URL served by the local proxy.
// Package is non-nil when registry metadata identifies the download exactly.
type RewriteURL func(*url.URL, *pm.Package) string

// Handler rewrites one registry response without depending on a package manager.
type Handler interface {
	RewriteResponse(response *http.Response, rewrite RewriteURL, registries []*url.URL) error
	Package(*url.URL) (pm.Package, bool)
}
