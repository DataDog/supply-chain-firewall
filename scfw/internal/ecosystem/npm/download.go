// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

var artifactTimeout = 2 * time.Minute

// Checker owns invocation-only metadata and inspection concurrency. Results are
// never cached by name or URL: every response is hashed and inspected anew.
type Checker struct {
	MapArtifactURL func(string) (string, error)
	Client         *http.Client
	Publications   PublicationCache
	Authorization  func(*url.URL) string
	slots          chan struct{}
}

func NewChecker(client *http.Client, authorization func(*url.URL) string) *Checker {
	if client == nil {
		client = http.DefaultClient
	}
	scoped := *client
	previous := client.CheckRedirect
	scoped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		req.Header.Del("Authorization")
		if authorization != nil {
			req.Header.Set("Authorization", authorization(req.URL))
		}
		if previous != nil {
			return previous(req, via)
		}
		if len(via) >= 10 {
			return errors.New("npm redirect limit")
		}
		return nil
	}
	return &Checker{Client: &scoped, Authorization: authorization, slots: make(chan struct{}, 4)}
}
func (c *Checker) auth(u *url.URL) string {
	if c.Authorization != nil {
		return c.Authorization(u)
	}
	return ""
}
func (c *Checker) Manifest(ctx context.Context, a Artifact) ([]byte, error) {
	p, e := c.Publications.packument(ctx, c.Client, a.PackumentURL, c.auth(&a.PackumentURL))
	if e != nil {
		return nil, e
	}
	if p.Name != a.Name {
		return nil, errors.New("registry packument identity mismatch")
	}
	raw, ok := p.Versions[a.Version]
	if !ok {
		return nil, errors.New("registry version unavailable")
	}
	return append([]byte(nil), raw...), nil
}
func resultFor(a Artifact) pm.ArtifactResult {
	return pm.ArtifactResult{Package: pm.Package{Ecosystem: "npm", Name: a.Name, Version: a.Version, Source: a.Source}, Status: pm.ArtifactUnverifiable, Reason: "artifact-verification", Detail: "unable to verify npm artifact"}
}

// Verify checks already-buffered actual artifact bytes. source is the original
// advertised URL, even if the completed response followed a CDN redirect.
func (c *Checker) Verify(ctx context.Context, a Artifact, source string, reader io.ReadSeeker, lockIntegrity string) pm.ArtifactResult {
	result := resultFor(a)
	raw, e := c.Manifest(ctx, a)
	if e != nil {
		result.Detail = "full registry manifest unavailable"
		return result
	}
	m, e := parseObject(raw, maxManifestBytes)
	if e != nil {
		result.Detail = "invalid registry manifest"
		return result
	}
	dist, ok := m["dist"].(map[string]any)
	if !ok {
		result.Detail = "registry distribution metadata unavailable"
		return result
	}
	tarball, _ := dist["tarball"].(string)
	mappedTarball, mapErr := c.mapURL(tarball)
	if mapErr != nil {
		result.Detail = "artifact URL mapping unavailable"
		return result
	}
	if tarball == "" || mappedTarball != source {
		result.Detail = "artifact is not associated with the selected registry version"
		return result
	}
	sri, _ := dist["integrity"].(string)
	shasum, _ := dist["shasum"].(string)
	for _, k := range []string{"integrity", "shasum"} {
		if v, ok := dist[k]; ok {
			if _, ok := v.(string); !ok {
				result.Detail = "invalid advertised integrity"
				return result
			}
		}
	}
	legacyDigest := ""
	if value, present := m["_shasum"]; present {
		var valid bool
		legacyDigest, valid = value.(string)
		if !valid || legacyDigest == "" {
			result.Detail = "invalid publisher digest metadata"
			return result
		}
	}
	for _, digest := range []struct{ sri, sha string }{{sri, shasum}, {lockIntegrity, ""}, {"", legacyDigest}} {
		available, err := checkIntegrity(artifactContextReadSeeker{artifactContextReader: artifactContextReader{ctx: ctx, reader: reader}, Seeker: reader}, digest.sri, digest.sha)
		result.IntegrityAvailable = result.IntegrityAvailable || available
		if err != nil {
			result.Detail = err.Error()
			if result.Detail == "artifact integrity mismatch" {
				result.Status = pm.ArtifactMismatched
				result.Reason = "integrity"
			}
			return result
		}
	}
	if _, e = reader.Seek(0, io.SeekStart); e != nil {
		return result
	}
	manifest, facts, e := inspectArchive(ctx, reader)
	if e != nil {
		result.Status = pm.ArtifactMismatched
		result.Reason = "invalid-artifact"
		if errors.Is(e, errInspectionLimit) || ctx.Err() != nil {
			result.Status = pm.ArtifactUnverifiable
			result.Reason = "artifact-verification"
		}
		result.Detail = e.Error()
		return result
	}
	differences, e := CompareManifests(a.Name, a.Version, raw, manifest, facts)
	if e != nil {
		result.Status = pm.ArtifactMismatched
		result.Reason = "invalid-artifact"
		if errors.Is(e, errInspectionLimit) {
			result.Status = pm.ArtifactUnverifiable
			result.Reason = "artifact-verification"
		}
		result.Detail = "invalid package manifest JSON"
		return result
	}
	result.Status = pm.ArtifactMatched
	result.Detail = "registry and artifact manifests match"
	if len(differences) > 0 {
		result.Status = pm.ArtifactMismatched
		result.Reason = "manifest-confusion"
		result.Detail = DifferenceSummary(differences)
	}
	return result
}

// Fetch verifies the exact preflight-selected URL, retaining its private query.
func (c *Checker) Fetch(ctx context.Context, a Artifact, source, lockIntegrity string) pm.ArtifactResult {
	result := resultFor(a)
	ctx, cancel := context.WithTimeout(ctx, artifactTimeout)
	defer cancel()
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return result
	}
	source, e := c.mapURL(source)
	if e != nil {
		result.Detail = "artifact URL mapping unavailable"
		return result
	}
	u, e := url.Parse(source)
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return result
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if e != nil {
		return result
	}
	req.Header.Set("Authorization", c.auth(u))
	response, e := sameOriginAuthorizationClient(c.Client, u).Do(req)
	if e != nil {
		return result
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		result.Detail = "artifact response is not a complete successful download"
		return result
	}
	e = proxy.InspectReader(ctx, response.Body, maxArtifactBytes, func(r *io.SectionReader) error {
		return inspectHTTPArtifact(ctx, response.Header.Get("Content-Encoding"), r, func(decoded *io.SectionReader) error {
			result = c.Verify(ctx, a, source, decoded, lockIntegrity)
			return nil
		})
	})
	if e != nil {
		result.Status = pm.ArtifactUnverifiable
		result.Detail = "artifact download or inspection incomplete"
	}
	return result
}

// MetadataArtifact retains exact registry identity separately from the CDN URL.
func MetadataArtifact(registry, name, version, source string) (Artifact, error) {
	u, e := url.Parse(strings.TrimRight(registry, "/") + "/" + url.PathEscape(name))
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return Artifact{}, errors.New("invalid npm registry")
	}
	display, e := url.Parse(source)
	if e != nil {
		return Artifact{}, errors.New("invalid npm source")
	}
	return Artifact{Name: name, Version: version, Source: redactURL(display), PackumentURL: *u}, nil
}
func encodeManifest(m map[string]any) []byte { b, _ := json.Marshal(m); return b }

func (c *Checker) Publication(ctx context.Context, a Artifact) (time.Time, error) {
	a.authorization = c.auth(&a.PackumentURL)
	return c.Publications.Resolve(ctx, c.Client, a)
}

func (c *Checker) mapURL(source string) (string, error) {
	if c.MapArtifactURL == nil {
		return source, nil
	}
	return c.MapArtifactURL(source)
}
