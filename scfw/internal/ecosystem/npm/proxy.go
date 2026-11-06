// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"net/http"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ProxyHandler gates npm tarball downloads during one package-manager run.
// Classifier and EvaluateArtifact must be non-nil; the callback may run
// concurrently.
type ProxyHandler struct {
	Classifier       *Classifier
	EvaluateArtifact func(context.Context, Artifact) error
}

// HandleRequest invokes the artifact callback before a tarball download is
// forwarded upstream. Every other request passes untouched: response bodies
// are never inspected, so large packuments cannot fail the client's install.
func (h ProxyHandler) HandleRequest(requestContext context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if request.Method != http.MethodGet {
		return nil, nil
	}
	kind, artifact := h.Classifier.Classify(&request.URL)
	if kind != RequestTarball {
		return nil, nil
	}
	artifact.authorization = request.Header.Get("Authorization")
	return nil, h.EvaluateArtifact(requestContext, artifact)
}
