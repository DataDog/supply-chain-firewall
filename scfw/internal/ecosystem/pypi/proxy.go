// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pypi

import (
	"context"
	"errors"
	"net/http"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ProxyHandler observes PyPI registry traffic during one package-manager run.
// The caller supplies a shared metadata cache and classifier, an independent
// registry client, and the policy callback to invoke for artifact requests.
// RunContext, Metadata, Classifier, and EvaluateArtifact must be non-nil.
// Configure the handler before use; the callback may run concurrently.
type ProxyHandler struct {
	RunContext       context.Context
	Client           *http.Client
	Metadata         *MetadataCache
	Classifier       *RequestClassifier
	EvaluateArtifact func(context.Context, Artifact) error
}

// HandleRequest invokes the artifact callback before forwarding upstream.
// Response hooks inspect JSON metadata and identify opaque downloads from
// archive metadata. HTML and already-identified artifact bodies keep streaming.
func (e ProxyHandler) HandleRequest(requestContext context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if request.Method != http.MethodGet {
		return nil, nil
	}
	if e.Metadata.IsCoreMetadataURL(&request.URL) {
		return nil, nil
	}
	artifact, advertised := e.Metadata.ArtifactForURL(&request.URL)
	if !advertised {
		kind, classified := e.Classifier.ClassifyRequest(request.Method, &request.URL)
		// Redirect context supplements metadata classification; it cannot
		// exempt recognizable distributions or their core-metadata sidecars.
		if project, tentative, registered := e.Metadata.ProjectForURL(&request.URL); registered && kind != RequestArtifact && kind != RequestCoreMetadata {
			if tentative {
				e.Metadata.RegisterProjectCandidate(request.URL, project, request.Header)
			} else {
				e.Metadata.RegisterProject(request.URL, project, request.Header)
			}
			return e.ObserveResponseHeaders, nil
		}
		if kind == RequestJSONAPI || kind == RequestSimpleAPI {
			// Redirect context identifies the requested project more reliably
			// than a destination path. Capture its own request credentials
			// without replacing that context with the destination's name.
			project, tentative, registered := e.Metadata.ProjectForURL(&request.URL)
			if !registered {
				project, _ = e.Classifier.SimpleProject(&request.URL, nil)
			}
			if tentative {
				e.Metadata.RegisterProjectCandidate(request.URL, project, request.Header)
			} else if project != "" {
				e.Metadata.RegisterProject(request.URL, project, request.Header)
			} else {
				e.Metadata.Register(request.URL, request.Header)
			}
			return e.ObserveResponseHeaders, nil
		}
		if kind == RequestCoreMetadata {
			return nil, nil
		}
		if kind != RequestArtifact {
			project, endpoints, discoverable := e.Classifier.MetadataDiscovery(&request.URL)
			if discoverable && e.Client != nil {
				if err := e.Metadata.Discover(
					e.RunContext, e.Client, project, endpoints, &request.URL, request.Header,
				); isContextError(err) {
					return nil, err
				}
				artifact, advertised = e.Metadata.ArtifactForURL(&request.URL)
			}
			if !advertised {
				return e.ObserveResponseHeaders, nil
			}
		} else {
			artifact = classified
		}
	}

	return nil, e.EvaluateArtifact(requestContext, artifact)
}

// ObserveMetadataHeaders records metadata endpoints and resolves an uncached
// 304 through an independent request before the package manager can issue a
// download from metadata held only in its own cache.
func (e ProxyHandler) ObserveMetadataHeaders(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	if isHTMLMetadataContentType(response.Header) {
		// Retain only HTTP redirect context, so an HTML index redirected to
		// an archive-shaped path is still forwarded as metadata.
		if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != http.StatusNotModified {
			e.Metadata.RegisterRedirect(response.Request.URL, response.Header.Get("Location"))
		}
		return nil, nil
	}
	kind, project, tentative := e.classifyMetadataResponse(response)
	if kind != RequestJSONAPI && kind != RequestSimpleAPI {
		return nil, nil
	}
	if tentative {
		e.Metadata.RegisterProjectCandidate(response.Request.URL, project, response.Request.Header)
	} else if project != "" {
		e.Metadata.RegisterProject(response.Request.URL, project, response.Request.Header)
	} else {
		e.Metadata.Register(response.Request.URL, response.Request.Header)
	}
	switch response.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		e.Metadata.RegisterRedirect(response.Request.URL, response.Header.Get("Location"))
	case http.StatusNotModified:
		if !e.Metadata.HasObserved(response.Request.URL) && e.Client != nil {
			if err := e.Metadata.Refresh(ctx, e.Client, response.Request.URL); err != nil {
				return nil, err
			}
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, nil
	}
	if response.Header.Get("Content-Type") != "" && !IsMetadataContentType(response.Header) {
		return nil, nil
	}
	return &proxy.ResponseBodyHook{
		MaxBytes: MaxMetadataBytes,
		Handle: func(_ context.Context, response proxy.Response) error {
			return e.Metadata.Observe(response.Request.URL, response.Header, response.Body)
		},
	}, nil
}

func (e ProxyHandler) classifyMetadataResponse(response proxy.Response) (RequestKind, string, bool) {
	kind, _ := e.Classifier.ClassifyResponse(response.Request.Method, &response.Request.URL, response.Header)
	if response.Request.Method == http.MethodGet && (kind == RequestUnrelated || kind == RequestSimpleAPI) {
		if project, tentative, found := e.Metadata.ProjectForURL(&response.Request.URL); found {
			if !tentative || (response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
				IsMetadataContentType(response.Header)) {
				return RequestSimpleAPI, project, false
			}
			if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
				return RequestSimpleAPI, project, true
			}
		}
		// An archive-shaped Simple path is ambiguous until response headers
		// arrive. Bodyless redirects/304s can still establish project context;
		// successful responses must supply metadata media-type evidence first.
		if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
			if project, found := e.Classifier.SimpleProject(&response.Request.URL, nil); found {
				return RequestSimpleAPI, project, true
			}
		}
	}
	project, _ := e.Classifier.SimpleProject(&response.Request.URL, response.Header)
	return kind, project, false
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
