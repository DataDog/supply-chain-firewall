// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

// ExpectedArtifact retains private lock-selected source and integrity.
type ExpectedArtifact struct {
	Artifact       Artifact
	URL, Integrity string
}

// NonRegistrySource records manager-established Git provenance.
type NonRegistrySource struct {
	Name, Source string
	Reference    string
	ArchiveURLs  []string
}

type artifactProxyHook struct {
	nonRegistry []NonRegistrySource
	base        *proxyHook
	options     ProxyHookOptions
	checker     *Checker
	mu          sync.Mutex
	artifacts   map[string]Artifact
	observed    map[string][][]byte
	origins     map[string]proxy.Request
	redirects   map[string]int
}

func newArtifactProxyHook(_ context.Context, base *proxyHook, options ProxyHookOptions) proxy.RequestHook {
	h := &artifactProxyHook{base: base, options: options, checker: NewChecker(options.Client, options.Authorization), artifacts: map[string]Artifact{}, observed: map[string][][]byte{}, origins: map[string]proxy.Request{}, redirects: map[string]int{}}
	h.nonRegistry = append([]NonRegistrySource(nil), options.NonRegistrySources...)
	h.checker.MapArtifactURL = options.MapArtifactURL
	for _, expected := range options.ExpectedArtifacts {
		a := expected.Artifact
		a.downloadURL = expected.URL
		a.lockIntegrity = expected.Integrity
		h.artifacts[expected.URL] = a
	}
	return h.handle
}
func (h *artifactProxyHook) handle(ctx context.Context, request proxy.Request) (proxy.ResponseHook, error) {
	if request.Method != http.MethodGet {
		return nil, nil
	}
	source := request.URL.String()
	h.mu.Lock()
	a, known := h.artifacts[source]
	original := request
	if origin, ok := h.origins[source]; ok {
		original = origin
	}
	h.mu.Unlock()
	if h.options.ValidateArtifactRequest != nil {
		validation := original
		if known && a.downloadURL != "" {
			if u, e := url.Parse(a.downloadURL); e == nil {
				validation.URL = *u
			}
		}
		if e := h.options.ValidateArtifactRequest(validation); e != nil {
			return nil, h.reject(ctx, pm.Package{Ecosystem: "npm", Source: redactURL(&original.URL)}, "npm artifact request source could not be established")
		}
	}
	if !known {
		var proof NonRegistrySource
		hasProof := false
		if h.options.ResolveNonRegistryRequest != nil {
			proof, hasProof = h.options.ResolveNonRegistryRequest(original)
		}
		if hasProof {
			for _, uri := range proof.ArchiveURLs {
				if source == uri {
					return h.gitArchiveHook(request, proof), nil
				}
			}
		}
		h.mu.Lock()
		var gitSource *NonRegistrySource
		for _, candidate := range h.nonRegistry {
			if h.options.ResolveNonRegistryRequest != nil && (!hasProof || candidate.Source != proof.Source || candidate.Reference != proof.Reference) {
				continue
			}
			for _, uri := range candidate.ArchiveURLs {
				if source == uri {
					copy := candidate
					if hasProof {
						copy.Name = proof.Name
					}
					gitSource = &copy
					break
				}
			}
			if gitSource != nil {
				break
			}
		}
		h.mu.Unlock()
		if gitSource != nil {
			return h.gitArchiveHook(request, *gitSource), nil
		}
		if hasProof {
			return nil, h.reject(ctx, pm.Package{Ecosystem: "npm", Name: proof.Name, Version: proof.Reference, Source: proof.Source}, "Git archive request source could not be established")
		}
	}

	if !known {
		kind, guess := h.base.Classifier.Classify(&original.URL)
		if kind == RequestTarball {
			if h.options.RegistryRequestName != nil {
				if name, ok := h.options.RegistryRequestName(original); ok {
					guess.Name = name
				}
			}
			a = guess
			known = true
			if h.options.RegistryArtifact != nil {
				var e error
				a, e = h.options.RegistryArtifact(guess.Name, guess.Version, original.URL.String())
				if e != nil {
					return nil, errors.New("cannot associate npm artifact with registry")
				}
			}
		}
	}
	if !known {
		return h.unknownHook(request, original), nil
	}
	if a.downloadURL == "" {
		a.downloadURL = original.URL.String()
	}
	if h.options.RegistryRequestName != nil {
		if name, ok := h.options.RegistryRequestName(original); ok && name != a.Name {
			return nil, h.options.EvaluateResult(ctx, pm.ArtifactResult{Package: pm.Package{Ecosystem: "npm", Name: name, Version: a.Version, Source: a.Source}, Status: pm.ArtifactMismatched, Reason: "manifest-confusion", Detail: "requested package identity contradicts registry artifact association"})
		}
	}
	pkg := pm.Package{Ecosystem: "npm", Name: a.Name, Version: a.Version, Source: a.Source}
	date, publishErr := h.checker.Publication(ctx, a)
	pkg.PublishDate = date.UTC()
	if e := h.options.EvaluatePackage(ctx, pkg, publishErr); e != nil {
		return nil, e
	}
	return func(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != 304 {
			location, e := url.Parse(response.Header.Get("Location"))
			if e != nil || location.String() == "" {
				return nil, h.reject(ctx, pkg, "invalid artifact redirect")
			}
			next := request.URL.ResolveReference(location)
			if next.Scheme != "http" && next.Scheme != "https" {
				return nil, h.reject(ctx, pkg, "unsupported artifact redirect")
			}
			h.mu.Lock()
			if previous, ok := h.artifacts[next.String()]; ok && (previous.Name != a.Name || previous.Version != a.Version || previous.lockIntegrity != a.lockIntegrity || previous.downloadURL != a.downloadURL) {
				h.mu.Unlock()
				return nil, h.reject(ctx, pkg, "artifact redirect conflicts with another artifact expectation")
			}
			h.artifacts[next.String()] = a
			h.mu.Unlock()
			return nil, nil
		}
		if response.StatusCode != http.StatusOK {
			return nil, h.reject(ctx, pkg, "artifact response is not a complete successful download")
		}
		if response.Header.Get("Content-Range") != "" {
			return nil, h.reject(ctx, pkg, "partial artifact response")
		}
		if response.Header.Get("Content-Length") != "" && response.Header.Get("Content-Encoding") == "" {
			if response.Header.Get("Content-Length") == "0" {
				return nil, h.reject(ctx, pkg, "empty artifact response")
			}
		}
		return &proxy.ResponseBodyHook{MaxBytes: maxArtifactBytes, HandleFile: func(ctx context.Context, response proxy.Response, r *io.SectionReader) error {
			inspectionContext, cancel := context.WithTimeout(ctx, artifactTimeout)
			defer cancel()
			select {
			case h.checker.slots <- struct{}{}:
			case <-inspectionContext.Done():
				return h.reject(ctx, pkg, "npm inspection timed out")
			}
			defer func() { <-h.checker.slots }()
			ctx = inspectionContext
			var result pm.ArtifactResult
			check := func(r *io.SectionReader) error {
				result = h.checker.Verify(ctx, a, a.downloadURL, r, a.lockIntegrity)
				result.Package = pkg
				result = h.compareObserved(ctx, a, result, r)
				return nil
			}
			switch strings.ToLower(response.Header.Get("Content-Encoding")) {
			case "", "identity":
				_ = check(r)
			case "gzip":
				gz, e := gzip.NewReader(artifactContextReader{ctx: ctx, reader: r})
				if e != nil {
					return h.reject(ctx, pkg, "invalid HTTP artifact encoding")
				}
				defer gz.Close() //nolint:errcheck
				if e = proxy.InspectReader(ctx, gz, maxArtifactBytes, check); e != nil {
					return h.reject(ctx, pkg, "incomplete HTTP artifact encoding")
				}
			default:
				return h.reject(ctx, pkg, "unsupported HTTP artifact encoding")
			}
			result.Package = pkg

			return h.options.EvaluateResult(ctx, result)
		}}, nil
	}, nil
}
func (h *artifactProxyHook) reject(ctx context.Context, pkg pm.Package, detail string) error {
	return h.options.EvaluateResult(ctx, pm.ArtifactResult{Package: pkg, Status: pm.ArtifactUnverifiable, Reason: "artifact-verification", Detail: detail})
}
func (h *artifactProxyHook) metadataHook(request proxy.Request) proxy.ResponseHook {
	trusted := false
	for _, base := range h.options.ClassifierOptions.RegistryURLs {
		u, e := url.Parse(base)
		if e == nil && u.Scheme == request.URL.Scheme && u.Host == request.URL.Host && strings.HasPrefix(request.URL.Path, strings.TrimRight(u.Path, "/")+"/") {
			trusted = true
		}
	}
	if !trusted {
		return nil
	}
	return func(_ context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		if response.StatusCode != 200 {
			return nil, nil
		}
		return &proxy.ResponseBodyHook{MaxBytes: maxPackumentBytes, Handle: func(_ context.Context, response proxy.Response) error {
			data := response.Body
			if response.Header.Get("Content-Encoding") == "gzip" {
				gz, e := gzip.NewReader(strings.NewReader(string(data)))
				if e != nil {
					return errors.New("invalid npm metadata encoding")
				}
				defer gz.Close() //nolint:errcheck
				data, e = io.ReadAll(io.LimitReader(gz, maxPackumentBytes+1))
				if e != nil {
					return errors.New("invalid npm metadata encoding")
				}
			}
			m, e := parseObject(data, maxPackumentBytes)
			if e != nil {
				return errors.New("invalid observed npm metadata")
			}
			versions, ok := m["versions"].(map[string]any)
			if !ok {
				return nil
			}
			name, _ := m["name"].(string)
			if name == "" || !h.requestNames(request, name) {
				return errors.New("observed npm metadata has no identity")
			}
			for version, v := range versions {
				if len(version) > 256 || !semverPattern.MatchString(version) {
					continue
				}
				manifest, ok := v.(map[string]any)
				if !ok {
					return errors.New("invalid observed npm version")
				}
				if manifest["name"] != name || manifest["version"] != version {
					return errors.New("observed registry identity mismatch")
				}
				dist, _ := manifest["dist"].(map[string]any)
				source, _ := dist["tarball"].(string)
				if source == "" {
					continue
				}
				var a Artifact
				if h.options.RegistryArtifact != nil {
					a, e = h.options.RegistryArtifact(name, version, source)
				} else {
					a = Artifact{Name: name, Version: version, PackumentURL: request.URL}
					u, err := url.Parse(source)
					if err != nil {
						return errors.New("invalid advertised artifact URL")
					}
					a.Source = redactURL(u)
				}
				if e != nil {
					return errors.New("invalid observed npm association")
				}
				h.mu.Lock()
				mapped, e := h.checker.mapURL(source)
				if e != nil {
					h.mu.Unlock()
					return errors.New("npm artifact URL mapping unavailable")
				}
				source = mapped
				if u, e := url.Parse(source); e == nil {
					a.Source = redactURL(u)
				}
				a.downloadURL = source
				if previous, ok := h.artifacts[source]; ok {
					if previous.Name != a.Name || previous.Version != a.Version {
						h.mu.Unlock()
						return errors.New("observed metadata contradicts locked identity")
					}
					a.lockIntegrity = previous.lockIntegrity
				}
				key := name + "@" + version
				if len(h.observed[key]) >= 16 {
					h.mu.Unlock()
					return errors.New("too many npm metadata observations")
				}
				h.artifacts[source] = a
				h.observed[key] = append(h.observed[key], encodeManifest(manifest))
				h.mu.Unlock()
			}
			return nil
		}}, nil
	}
}

// Abbreviated metadata may omit selected fields. Enforce the same field list
// as the artifact comparator, plus registry identity and distribution integrity.
func metadataAgrees(full, observed []byte) bool {
	a, e := parseObject(full, maxManifestBytes)
	if e != nil {
		return false
	}
	b, e := parseObject(observed, maxManifestBytes)
	if e != nil {
		return false
	}
	selectedA, selectedB := comparisonManifest(a), comparisonManifest(b)
	for _, key := range []string{"dist", "_id", "_shasum"} {
		if value, present := a[key]; present {
			selectedA[key] = value
		}
		if value, present := b[key]; present {
			selectedB[key] = value
		}
	}
	a, b = selectedA, selectedB
	for k, v := range b {
		if _, ok := a[k]; !ok {
			switch k {
			case "_hasShrinkwrap", "hasInstallScript":
				continue
			default:
				return false
			}
		}
		if av, ok := a[k]; ok {
			d := []Difference{}
			if k == "dist" {
				fullDist, ok := av.(map[string]any)
				observedDist, valid := v.(map[string]any)
				if !ok || !valid {
					return false
				}
				for field, value := range observedDist {
					if field == "tarball" || field == "integrity" || field == "shasum" {
						if actual, ok := fullDist[field]; ok {
							diffJSON("/dist/"+field, actual, value, &d)
						} else {
							return false
						}
					}
				}
			} else {
				diffJSON("/"+k, av, v, &d)
			}
			if len(d) > 0 {
				return false
			}
		}
	}
	return true
}

func (h *artifactProxyHook) requestNames(request proxy.Request, name string) bool {
	for _, base := range h.options.ClassifierOptions.RegistryURLs {
		u, e := url.Parse(base)
		if e != nil || u.Scheme != request.URL.Scheme || u.Host != request.URL.Host {
			continue
		}
		prefix := strings.TrimRight(u.Path, "/") + "/"
		if strings.TrimPrefix(request.URL.Path, prefix) == name {
			return true
		}
	}
	return false
}
func (h *artifactProxyHook) unknownHook(actualRequest, request proxy.Request) proxy.ResponseHook {
	metadata := h.metadataHook(request)
	return func(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != 304 {
			location, e := url.Parse(response.Header.Get("Location"))
			if e != nil || location.String() == "" {
				return nil, errors.New("invalid unidentified npm redirect")
			}
			next := actualRequest.URL.ResolveReference(location)
			if next.Scheme != "https" && next.Scheme != "http" {
				return nil, errors.New("unsupported npm redirect")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if previous, ok := h.origins[next.String()]; ok && previous.URL.String() != request.URL.String() {
				return nil, errors.New("ambiguous npm redirect provenance")
			}
			depth := h.redirects[actualRequest.URL.String()] + 1
			if depth > 10 {
				return nil, errors.New("npm redirect limit")
			}
			h.origins[next.String()] = request
			h.redirects[next.String()] = depth
			return nil, nil
		}
		if response.StatusCode == http.StatusPartialContent || response.StatusCode == http.StatusNotModified || response.Header.Get("Content-Range") != "" {
			return nil, h.reject(ctx, pm.Package{Ecosystem: "npm", Source: redactURL(&request.URL)}, "unidentified npm download is not a complete response")
		}
		if response.StatusCode != 200 {
			return nil, nil
		}
		return &proxy.ResponseBodyHook{MaxBytes: maxArtifactBytes, HandleFile: func(ctx context.Context, response proxy.Response, r *io.SectionReader) (resultErr error) {
			requestContext := ctx
			defer func() {
				if resultErr != nil && !errors.Is(resultErr, proxy.ErrResponseRejected) && requestContext.Err() == nil {
					_ = h.reject(requestContext, pm.Package{Ecosystem: "npm", Source: redactURL(&request.URL)}, "unidentified npm response could not be verified")
				}
			}()
			ctx, cancel := context.WithTimeout(ctx, artifactTimeout)
			defer cancel()
			select {
			case h.checker.slots <- struct{}{}:
			case <-ctx.Done():
				return errors.New("npm inspection timed out")
			}
			defer func() { <-h.checker.slots }()
			return inspectHTTPArtifact(ctx, response.Header.Get("Content-Encoding"), r, func(r *io.SectionReader) error {
				prefix := make([]byte, 1)
				if _, e := r.ReadAt(prefix, 0); e != nil {
					return errors.New("empty npm response")
				}
				if prefix[0] != 0x1f {
					if request.URL.Query().Get("service") == "git-upload-pack" || strings.HasSuffix(request.URL.Path, "/info/refs") {
						if validGitDiscovery(r) {
							return nil
						}
						return errors.New("invalid Git discovery response")
					}

					if metadata == nil {
						return errors.New("unassociated npm response")
					}
					body, e := io.ReadAll(io.LimitReader(r, maxPackumentBytes+1))
					if e != nil {
						return errors.New("incomplete npm metadata")
					}
					response.Header = response.Header.Clone()
					response.Header.Del("Content-Encoding")
					response.Body = body
					hook, e := metadata(ctx, response)
					if e != nil {
						return e
					}
					if hook == nil {
						return errors.New("unrecognized npm response")
					}
					return hook.Handle(ctx, response)
				}
				manifest, _, e := inspectArchive(ctx, r)
				if e != nil {
					return errors.New("unidentified npm artifact cannot be inspected")
				}
				m, e := parseObject(manifest, maxManifestBytes)
				if e != nil {
					return errors.New("invalid npm root manifest")
				}
				name, _ := m["name"].(string)
				version, _ := m["version"].(string)
				if name == "" || version == "" || h.options.RegistryArtifact == nil {
					return errors.New("unidentified npm artifact has no registry identity")
				}
				registryProven := false
				if h.options.RegistryRequestName != nil {
					if expected, ok := h.options.RegistryRequestName(request); ok {
						name = expected
						registryProven = true
					}
				}
				if hostedGitArchive(&request.URL) && !registryProven {
					return errors.New("hosted archive source provenance is unavailable")
				}
				a, e := h.options.RegistryArtifact(name, version, request.URL.String())
				if e != nil {
					return errors.New("npm registry association unavailable")
				}
				pkg := pm.Package{Ecosystem: "npm", Name: name, Version: version, Source: a.Source}
				date, publishErr := h.checker.Publication(ctx, a)
				pkg.PublishDate = date.UTC()
				if e = h.options.EvaluatePackage(ctx, pkg, publishErr); e != nil {
					return e
				}
				result := h.checker.Verify(ctx, a, request.URL.String(), r, "")
				result.Package = pkg
				result = h.compareObserved(ctx, a, result, r)
				return h.options.EvaluateResult(ctx, result)
			})
		}}, nil
	}
}
func inspectHTTPArtifact(ctx context.Context, encoding string, r *io.SectionReader, check func(*io.SectionReader) error) error {
	switch strings.ToLower(encoding) {
	case "", "identity":
		return check(r)
	case "gzip":
		gz, e := gzip.NewReader(artifactContextReader{ctx: ctx, reader: r})
		if e != nil {
			return errors.New("invalid HTTP artifact encoding")
		}
		defer gz.Close() //nolint:errcheck
		return proxy.InspectReader(ctx, gz, maxArtifactBytes, check)
	default:
		return errors.New("unsupported HTTP artifact encoding")
	}
}

func (h *artifactProxyHook) compareObserved(ctx context.Context, a Artifact, result pm.ArtifactResult, r io.ReadSeeker) pm.ArtifactResult {
	if result.Status != pm.ArtifactMatched {
		return result
	}
	h.mu.Lock()
	observations := append([][]byte(nil), h.observed[a.Name+"@"+a.Version]...)
	h.mu.Unlock()
	if len(observations) == 0 {
		return result
	}
	raw, e := h.checker.Manifest(ctx, a)
	if e != nil {
		result.Status = pm.ArtifactUnverifiable
		result.Detail = "observed registry metadata cannot be verified"
		return result
	}
	if _, e = r.Seek(0, io.SeekStart); e != nil {
		return result
	}
	_, facts, e := inspectArchive(ctx, r)
	if e != nil {
		result.Status = pm.ArtifactUnverifiable
		result.Detail = "archive facts unavailable"
		return result
	}
	full, e := parseObject(raw, maxManifestBytes)
	if e != nil {
		return result
	}
	normalizeManifest(full, facts)
	for _, observed := range observations {
		m, e := parseObject(observed, maxManifestBytes)
		if e != nil {
			result.Status = pm.ArtifactUnverifiable
			return result
		}
		diff := []Difference{}
		for key, value := range m {
			if key == "hasInstallScript" || key == "_hasShrinkwrap" {
				if full[key] != value {
					diff = append(diff, Difference{Path: "/" + key, Kind: "observed indicator mismatch"})
				}
			}
		}
		if len(diff) > 0 || !h.metadataAgrees(raw, observed) {
			result.Status = pm.ArtifactMismatched
			result.Reason = "manifest-confusion"
			result.Detail = "metadata observed by npm disagrees with the registry manifest or archive facts"
			return result
		}
	}
	return result
}

func validGitDiscovery(r *io.SectionReader) bool {
	if r.Size() > maxPackumentBytes {
		return false
	}
	reader := io.NewSectionReader(r, 0, r.Size())
	first := true
	for {
		header := make([]byte, 4)
		n, e := io.ReadFull(reader, header)
		if e == io.EOF && n == 0 {
			return !first
		}
		if e != nil {
			return false
		}
		size, e := strconv.ParseUint(string(header), 16, 16)
		if e != nil {
			return false
		}
		if size == 0 || size == 1 || size == 2 {
			if first {
				return false
			}
			continue
		}
		if size < 4 || size > 65520 {
			return false
		}
		payload := make([]byte, int(size)-4)
		if _, e = io.ReadFull(reader, payload); e != nil {
			return false
		}
		if first {
			if string(payload) != "# service=git-upload-pack\n" {
				return false
			}
			first = false
			continue
		}
		if len(payload) == 0 || payload[len(payload)-1] != '\n' {
			return false
		}
		nul := 0
		for i, c := range payload {
			if c == 0 {
				nul++
				if nul > 1 {
					return false
				}
				continue
			}
			if c == '\n' && i == len(payload)-1 {
				continue
			}
			if c < 0x20 || c > 0x7e {
				return false
			}
		}
	}
}

func (h *artifactProxyHook) gitArchiveHook(request proxy.Request, source NonRegistrySource) proxy.ResponseHook {
	return func(ctx context.Context, response proxy.Response) (*proxy.ResponseBodyHook, error) {
		if response.StatusCode >= 300 && response.StatusCode < 400 && response.StatusCode != 304 {
			location, e := url.Parse(response.Header.Get("Location"))
			if e != nil {
				return nil, errors.New("invalid Git archive redirect")
			}
			next := request.URL.ResolveReference(location)
			if next.Scheme != "https" && next.Scheme != "http" {
				return nil, errors.New("unsupported Git archive redirect")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if _, known := h.artifacts[next.String()]; known {
				return nil, errors.New("git archive redirect conflicts with registry evidence")
			}
			copy := source
			copy.ArchiveURLs = []string{next.String()}
			h.nonRegistry = append(h.nonRegistry, copy)
			return nil, nil
		}
		if response.StatusCode == 200 {
			result := pm.ArtifactResult{Package: pm.Package{Ecosystem: "npm", Name: source.Name, Version: source.Reference, Source: source.Source}, Status: pm.ArtifactNotApplicable, Detail: "Git source has no authoritative registry counterpart"}
			return nil, h.options.EvaluateResult(ctx, result)
		}
		return nil, nil
	}
}

func hostedGitArchive(u *url.URL) bool {
	switch strings.ToLower(u.Hostname()) {
	case "codeload.github.com":
		return true
	case "github.com":
		return strings.Contains(u.Path, "/archive/")
	case "api.github.com":
		return strings.Contains(u.Path, "/tarball/")
	case "gitlab.com":
		return strings.Contains(u.Path, "/-/archive/") || strings.Contains(u.Path, "/repository/archive")
	case "bitbucket.org":
		return strings.Contains(u.Path, "/get/")
	}
	return false
}

func (h *artifactProxyHook) metadataAgrees(full, observed []byte) bool {
	if h.checker.MapArtifactURL == nil {
		return metadataAgrees(full, observed)
	}
	mapped := [][]byte{}
	for _, raw := range [][]byte{full, observed} {
		m, e := parseObject(raw, maxManifestBytes)
		if e != nil {
			return false
		}
		if dist, ok := m["dist"].(map[string]any); ok {
			if source, ok := dist["tarball"].(string); ok {
				value, e := h.checker.mapURL(source)
				if e != nil {
					return false
				}
				dist["tarball"] = value
			}
		}
		mapped = append(mapped, encodeManifest(m))
	}
	return metadataAgrees(mapped[0], mapped[1])
}
