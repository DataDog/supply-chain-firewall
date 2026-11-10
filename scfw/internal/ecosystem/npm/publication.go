// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	// maxPackumentBytes bounds a decoded packument; the largest public ones
	// (e.g. next) are about 30 MB.
	maxPackumentBytes int64 = 64 << 20
	// packumentFetchTimeout bounds how long a tarball request is held while
	// its publication data is fetched.
	packumentFetchTimeout = time.Minute
)

// PublicationCache resolves tarball publication data from the registry's full
// packument, fetching each packument at most once per package-manager run.
// Clients' own metadata cannot be relied on: many request the abbreviated
// packument, which omits publish times, and lockfile installs request none.
// The zero value is ready to use.
type PublicationCache struct {
	mutex   sync.Mutex
	entries map[string]*packumentEntry
}

type packumentEntry struct {
	done chan struct{}
	// incomplete marks a fetch abandoned by its caller's cancellation, which
	// must not decide the outcome for other requests.
	incomplete bool
	packument  packument
	err        error
}

// transientError marks a fetch failure worth retrying, so it is not cached.
type transientError struct{ error }

func (e transientError) Unwrap() error { return e.error }

type packument struct {
	Time map[string]string `json:"time"`
}

// Resolve returns the publish time of artifact's version. The tarball
// request's Authorization is reused only toward the tarball's origin.
func (cache *PublicationCache) Resolve(ctx context.Context, client *http.Client, artifact Artifact) (time.Time, error) {
	entry, err := cache.packument(ctx, client, artifact.PackumentURL, artifact.authorization)
	if err != nil {
		return time.Time{}, fmt.Errorf("resolve publication data for npm %s: %w", artifact.Name, err)
	}
	raw := entry.Time[artifact.Version]
	if raw == "" {
		return time.Time{}, fmt.Errorf("publication date unavailable for npm %s@%s", artifact.Name, artifact.Version)
	}
	date, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid publication date for npm %s@%s", artifact.Name, artifact.Version)
	}
	return date, nil
}

func (cache *PublicationCache) packument(ctx context.Context, client *http.Client, packumentURL url.URL, authorization string) (packument, error) {
	key := packumentURL.String()
	for {
		cache.mutex.Lock()
		if cache.entries == nil {
			cache.entries = make(map[string]*packumentEntry)
		}
		entry, exists := cache.entries[key]
		if !exists {
			entry = &packumentEntry{done: make(chan struct{})}
			cache.entries[key] = entry
		}
		cache.mutex.Unlock()

		if exists {
			select {
			case <-entry.done:
				if entry.incomplete {
					continue
				}
				return entry.packument, entry.err
			case <-ctx.Done():
				return packument{}, ctx.Err()
			}
		}

		entry.packument, entry.err = fetchPackument(ctx, client, packumentURL, authorization)
		cache.mutex.Lock()
		// Waiters already in flight share a transient error; only later
		// requests fetch again.
		canceled := entry.err != nil && ctx.Err() != nil
		var transient transientError
		if canceled || errors.As(entry.err, &transient) {
			entry.incomplete = canceled
			delete(cache.entries, key)
		}
		close(entry.done)
		cache.mutex.Unlock()
		return entry.packument, entry.err
	}
}

// fetchPackument requests the full packument. Errors never include the URL or
// headers, which can carry registry credentials.
func fetchPackument(ctx context.Context, client *http.Client, packumentURL url.URL, authorization string) (packument, error) {
	fetchContext, cancel := context.WithTimeout(ctx, packumentFetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(fetchContext, http.MethodGet, packumentURL.String(), nil)
	if err != nil {
		return packument{}, errors.New("build npm packument request")
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	response, err := sameOriginAuthorizationClient(client, &packumentURL).Do(request)
	if err != nil {
		if fetchErr := fetchContextErr(ctx, fetchContext); fetchErr != nil {
			return packument{}, fetchErr
		}
		return packument{}, transientError{errors.New("npm packument request failed")}
	}
	defer response.Body.Close() //nolint:errcheck

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		statusErr := fmt.Errorf("npm packument request returned status %d", response.StatusCode)
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError {
			return packument{}, transientError{statusErr}
		}
		return packument{}, statusErr
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPackumentBytes+1))
	if err != nil {
		if fetchErr := fetchContextErr(ctx, fetchContext); fetchErr != nil {
			return packument{}, fetchErr
		}
		return packument{}, transientError{errors.New("read npm packument failed")}
	}
	if int64(len(body)) > maxPackumentBytes {
		return packument{}, fmt.Errorf("npm packument exceeds %d bytes", maxPackumentBytes)
	}
	var decoded packument
	if err := json.Unmarshal(body, &decoded); err != nil {
		return packument{}, fmt.Errorf("decode npm packument: %w", err)
	}
	return decoded, nil
}

// fetchContextErr reports why a packument fetch stopped early: the run's own
// cancellation is returned as is, while the fetch timeout becomes a plain
// publication error, so callers never mistake a slow registry for cancellation.
func fetchContextErr(runContext, fetchContext context.Context) error {
	if err := runContext.Err(); err != nil {
		return err
	}
	if fetchContext.Err() != nil {
		return transientError{errors.New("npm packument request timed out")}
	}
	return nil
}

// sameOriginAuthorizationClient copies client so redirects keep Authorization
// only within origin's scheme, host and port. net/http alone forwards it to
// subdomains as well.
func sameOriginAuthorizationClient(client *http.Client, origin *url.URL) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	scoped := *client
	checkRedirect := client.CheckRedirect
	scoped.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if !strings.EqualFold(request.URL.Scheme, origin.Scheme) || !strings.EqualFold(request.URL.Host, origin.Host) {
			request.Header.Del("Authorization")
		}
		if checkRedirect != nil {
			return checkRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &scoped
}
