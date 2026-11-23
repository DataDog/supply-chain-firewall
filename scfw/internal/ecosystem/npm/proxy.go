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
// concurrently. Client re-fetches cached or partial opaque tarballs.
type ProxyHandler struct {
	Classifier       *Classifier
	EvaluateArtifact func(context.Context, Artifact) error
	Client           *http.Client
}

// HandleRequest invokes the artifact callback before a registry tarball is
// forwarded upstream; tarballs from unknown hosts are also held until their
// package.json declares the evaluated package. Opaque tarballs get a response
// hook that identifies them from their package.json, as does any other GET
// whose response looks like a download. Packument bodies are JSON and never
// inspected, so large packuments cannot fail the install.
func (h ProxyHandler) HandleRequest(requestContext context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if request.Method != http.MethodGet {
		return nil, nil
	}
	kind, artifact := h.Classifier.Classify(&request.URL)
	if expected, verified := h.Classifier.verifiedTargets.LoadAndDelete(redactURL(&request.URL)); verified && kind != RequestTarball {
		return h.verifyTarball(expected.(Artifact)), nil
	}
	switch kind {
	case RequestTarball:
		artifact.authorization = request.Header.Get("Authorization")
		if err := h.EvaluateArtifact(requestContext, artifact); err != nil || h.Classifier.isKnownRegistry(&request.URL) {
			return nil, err
		}
		// An unknown host could serve another package under this name.
		return h.verifyTarball(artifact), nil
	case RequestOpaqueTarball:
		return h.observeOpaqueTarball, nil
	case RequestRegistryAPI:
		return nil, nil
	}
	return h.observeDownload, nil
}
