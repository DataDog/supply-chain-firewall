// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"context"
	"errors"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ecosystemnpm "github.com/DataDog/supply-chain-firewall/scfw/internal/ecosystem/npm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm"
	"github.com/DataDog/supply-chain-firewall/scfw/internal/proxy"
)

type npmArtifact struct {
	source, integrity string
	notApplicable     bool
	failure           string
}

func (n Npm) ResolveVerifiedInstallTargets(ctx context.Context, command []string) (*pm.Set[pm.Package], []pm.ArtifactResult, error) {
	if !npmInstallCommandSupported(command) {
		return pm.NewSet[pm.Package](), nil, nil
	}
	settings, e := n.verificationSettings(command)
	if e != nil {
		return nil, nil, e
	}
	if settings["offline"] == "true" || settings["prefer-offline"] == "true" {
		return nil, nil, errors.New("npm offline/cache-dependent preflight cannot use an isolated empty cache")
	}
	options, e := settings.transportOptions()
	if e != nil {
		return nil, nil, e
	}
	client := &http.Client{Transport: proxy.NewTransport(options)}
	defer client.CloseIdleConnections()
	checker := ecosystemnpm.NewChecker(client, settings.authorization)
	n.mapArtifactURL = n.artifactURLMapperForSettings(settings)
	checker.MapArtifactURL = n.mapArtifactURL
	n.artifacts = map[pm.Package][]npmArtifact{}
	// Publication data uses the same configured registry/auth context as checking.
	n.resolvePublishDate = func(ctx context.Context, _ ecosystem.Ecosystem, name, version, source string) (time.Time, error) {
		a, e := ecosystemnpm.MetadataArtifact(settings.registry(name), name, version, source)
		if e != nil {
			return time.Time{}, e
		}
		return checker.Publication(ctx, a)
	}
	targets, e := n.ResolveInstallTargets(ctx, command)
	if e != nil {
		return nil, nil, e
	}
	results := make([]pm.ArtifactResult, targets.Len())
	var wg sync.WaitGroup
	i := 0
	for pkg := range targets.Items() {
		idx := i
		i++
		evidences := n.artifacts[pkg]
		wg.Go(func() {
			result := pm.ArtifactResult{Package: pkg, Status: pm.ArtifactNotApplicable}
			for _, evidence := range evidences {
				if evidence.notApplicable {
					result.Detail = "not a separately selected registry artifact"
					continue
				}
				if evidence.failure != "" {
					result = pm.ArtifactResult{Package: pkg, Status: pm.ArtifactUnverifiable, Reason: "artifact-verification", Detail: evidence.failure}
					break
				}
				if !evidence.notApplicable && !npmHTTPSource(evidence.source) {
					result = pm.ArtifactResult{Package: pkg, Status: pm.ArtifactUnverifiable, Reason: "artifact-verification", Detail: "selected registry artifact URL unavailable"}
					break
				}
				if npmHTTPSource(evidence.source) {
					a, e := ecosystemnpm.MetadataArtifact(settings.registry(pkg.Name), pkg.Name, pkg.Version, evidence.source)
					if e != nil {
						result.Status = pm.ArtifactUnverifiable
						result.Detail = "registry association unavailable"
					} else {
						result = checker.Fetch(ctx, a, evidence.source, evidence.integrity)
						result.Package = pkg
					}
				}
				if result.Status == pm.ArtifactMismatched || result.Status == pm.ArtifactUnverifiable {
					break
				}
			}
			results[idx] = result
		})
	}
	wg.Wait()
	if e := ctx.Err(); e != nil {
		return nil, nil, e
	}
	return targets, results, nil
}
func publicNpmSource(source string) string {
	u, e := url.Parse(source)
	if e != nil {
		return ""
	}
	if u.Host == "" {
		return source
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func npmHTTPSource(source string) bool {
	u, e := url.Parse(source)
	return e == nil && u.Host != "" && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https"))
}
