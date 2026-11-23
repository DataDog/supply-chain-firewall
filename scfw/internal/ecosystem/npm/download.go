// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/internal/archive"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// observeDownload inspects responses whose URL no tarball pattern matches,
// such as redirect targets (GitHub's api.github.com tarball redirects to a
// codeload legacy.tar.gz), when the response alone looks like a download.
// The archive signature and root package.json then confirm the package.
func (h ProxyHandler) observeDownload(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	switch response.StatusCode {
	case http.StatusOK, http.StatusPartialContent, http.StatusNotModified:
		if archive.IsDownload(response.Header) {
			return h.observeOpaqueTarball(ctx, response)
		}
	}
	return nil, nil
}

func (h ProxyHandler) observeOpaqueTarball(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
	switch status := response.StatusCode; {
	case status == http.StatusPartialContent || status == http.StatusNotModified:
		// The client may hold the rest in its cache, so inspect a full copy
		// before forwarding the original response.
		return nil, h.inspectFullTarball(ctx, response, nil)
	case status < 200 || status == http.StatusNoContent || status >= 400:
		// No body, or one npm rejects.
		return nil, nil
	}
	// npm unpacks the body of any other status it does not follow, including
	// 205 and 300; a followed redirect's body is not an archive and passes.
	return &proxy.ResponseBodyHook{
		MaxBytes: archive.MaxArtifactBytes,
		HandleFile: func(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
			return h.evaluateTarball(ctx, response, body, nil)
		},
	}, nil
}

// verifyTarball returns a response hook that forwards a tarball only when its
// package.json declares the expected, already evaluated, package.
func (h ProxyHandler) verifyTarball(expected Artifact) proxy.ResponseHook {
	return func(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		switch status := response.StatusCode; {
		case status == http.StatusPartialContent || status == http.StatusNotModified:
			return nil, h.inspectFullTarball(ctx, response, &expected)
		case status < 200 || status == http.StatusNoContent || status >= 400:
			return nil, nil
		case (status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther ||
			status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect) && response.Header.Get("Location") != "":
			// The full fetch follows the redirect the client is about to follow.
			return nil, h.inspectFullTarball(ctx, response, &expected)
		}
		return &proxy.ResponseBodyHook{
			MaxBytes: archive.MaxArtifactBytes,
			HandleFile: func(ctx context.Context, response proxy.Response, body *io.SectionReader) error {
				return h.evaluateTarball(ctx, response, body, &expected)
			},
		}, nil
	}
}

func (h ProxyHandler) inspectFullTarball(ctx context.Context, original proxy.Response, expected *Artifact) error {
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
		return h.evaluateTarball(ctx, original, body, expected)
	})
}

// evaluateTarball evaluates the package a tarball declares or, given expected,
// requires the tarball to declare that package instead.
func (h ProxyHandler) evaluateTarball(ctx context.Context, response proxy.Response, body *io.SectionReader, expected *Artifact) error {
	// Node clients remove the HTTP content encoding before unpacking.
	return archive.InspectDecoded(ctx, body, response.Header.Get("Content-Encoding"), func(body *io.SectionReader) error {
		artifact, found, err := inspectTarball(ctx, body)
		if err != nil || (!found && expected == nil) {
			return err
		}
		artifact.Source = redactURL(&response.Request.URL)
		if expected != nil {
			if !found {
				return errors.New("npm tarball does not declare its package")
			}
			if artifact.Name != expected.Name || artifact.Version != expected.Version {
				// The 403 body hides the reason.
				slog.Warn("npm tarball declares a different package than its URL", "url", artifact.Source,
					"expected", expected.Name+"@"+expected.Version, "declared", artifact.Name+"@"+artifact.Version)
				return errors.Join(proxy.ErrResponseRejected, fmt.Errorf("npm tarball declares %s@%s, not %s@%s",
					artifact.Name, artifact.Version, expected.Name, expected.Version))
			}
			return nil
		}
		if err := h.EvaluateArtifact(ctx, artifact); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return errors.Join(proxy.ErrResponseRejected, err)
		}
		return nil
	})
}
