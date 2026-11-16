// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// urlKey identifies a URL as clients request it: without credentials or a
// fragment, which a redirect Location may carry but a request never does.
func urlKey(value *url.URL) string {
	key := *value
	key.User = nil
	key.Fragment, key.RawFragment = "", ""
	return key.String()
}

func (h ProxyHandler) observeOpaqueTarball(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	switch status := response.StatusCode; {
	case status == http.StatusPartialContent || status == http.StatusNotModified:
		// The client may hold the rest in its cache, so inspect a full copy
		// before forwarding the original response.
		return nil, h.inspectFullTarball(ctx, response)
	case status < 200 || status == http.StatusNoContent || status >= 400:
		// No body, or one npm rejects.
		return nil, nil
	}
	if location := response.Header.Get("Location"); location != "" && response.StatusCode >= 300 {
		if target, err := response.Request.URL.Parse(location); err == nil && (target.Scheme == "http" || target.Scheme == "https") {
			h.Classifier.opaqueRedirects.Store(urlKey(target), struct{}{})
		}
	}
	// npm unpacks the body of any other status it does not follow, including
	// 205 and 300; a followed redirect's body is not an archive and passes.
	return &proxy.ResponseBodyHook{
		MaxBytes: archive.MaxArtifactBytes,
		HandleFile: func(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
			return h.evaluateTarball(ctx, response, body)
		},
	}, nil
}

func (h ProxyHandler) inspectFullTarball(ctx context.Context, original proxy.Response) error {
	if h.Client == nil {
		return errors.New("cannot identify partial or cached npm tarball")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, original.Request.URL.String(), nil)
	if err != nil {
		return err
	}
	request.Header = archive.FullDownloadHeaders(original.Request.Header)
	response, err := sameOriginAuthorizationClient(h.Client, &original.Request.URL).Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return errors.New("could not inspect complete npm tarball")
	}
	if response.ContentLength > archive.MaxArtifactBytes {
		return archive.ErrLimit
	}
	original.Header = response.Header
	return proxy.InspectReader(ctx, response.Body, archive.MaxArtifactBytes, func(body *io.SectionReader) error {
		return h.evaluateTarball(ctx, original, body)
	})
}

func (h ProxyHandler) evaluateTarball(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
	// Node clients remove the HTTP content encoding before unpacking.
	return archive.InspectDecoded(ctx, body, response.Header.Get("Content-Encoding"), func(body *io.SectionReader) error {
		artifact, found, err := inspectTarball(ctx, body)
		if err != nil || !found {
			return err
		}
		artifact.Source = redactURL(&response.Request.URL)
		if err := h.EvaluateArtifact(ctx, artifact); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.Join(proxy.ErrResponseRejected, err)
		}
		return nil
	})
}
