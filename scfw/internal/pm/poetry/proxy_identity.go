// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/url"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const poetryIdentityDiagnostic = "Poetry repository names map to the same certificate environment variable but use different proxy/TLS settings; use names that remain distinct after uppercasing and replacing '-' with '_' or configure equivalent proxy/TLS settings"

func poetryCertificatePrefix(name string) string {
	return "POETRY_CERTIFICATES_" + poetryEnvironmentName(name) + "_"
}

func poetryEnvironmentName(name string) string {
	// Config uses Python's full Unicode uppercasing, including expansions.
	return cases.Upper(language.Und).String(strings.ReplaceAll(name, "-", "_"))
}

func (s *poetryProxySettings) prepareIdentities() {
	s.identityIndices = make([]int, len(s.certificates))
	s.ambiguousIdentities = map[int]bool{}
	groups := map[string]int{}
	for index, certificate := range s.certificates {
		s.identityIndices[index] = index
		if !certificate.hasHost() {
			continue
		}
		prefix := poetryCertificatePrefix(certificate.source.Name)
		first, present := groups[prefix]
		if !present {
			first = index
			groups[prefix] = first
		}
		s.identityIndices[index] = first
		sameFailure := certificate.err != nil && s.certificates[first].err != nil && certificate.err.Error() == s.certificates[first].err.Error()
		if first != index && !sameFailure && (certificate.err != nil || s.certificates[first].err != nil || !samePoetryTLS(certificate.tls, s.certificates[first].tls)) {
			s.ambiguousIdentities[first] = true
		}
		if first != index {
			for _, scheme := range []string{"http", "https"} {
				a, aErr := s.sourceProxy(first, scheme)
				b, bErr := s.sourceProxy(index, scheme)
				if aErr != nil || bErr != nil || !samePoetryProxy(a, b) {
					s.ambiguousIdentities[first] = true
				}
			}
		}
	}
}

func (s *poetryProxySettings) sourceProxy(index int, scheme string) (*url.URL, error) {
	if !s.certificates[index].hasHost() {
		return nil, errPoetrySourceURL
	}
	origin := *s.certificates[index].address
	origin.Scheme = scheme
	if s.system.Bypasses(&origin) {
		return nil, nil
	}
	return poetryProxyForURL(s.upstream)(&origin)
}

func (s *poetryProxySettings) identityCompatibilityError() error {
	s.identityWarning.Do(func() { slog.Error(poetryIdentityDiagnostic) })
	return errors.New(poetryIdentityDiagnostic)
}

func samePoetryProxy(a, b *url.URL) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.String() == b.String()
}

func samePoetryTLS(a, b *tls.Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.InsecureSkipVerify != b.InsecureSkipVerify {
		return false
	}
	if len(a.Certificates) != len(b.Certificates) {
		return false
	}
	for index, certificate := range a.Certificates {
		other := b.Certificates[index]
		if len(certificate.Certificate) != len(other.Certificate) {
			return false
		}
		for part, der := range certificate.Certificate {
			if !bytes.Equal(der, other.Certificate[part]) {
				return false
			}
		}
	}
	if a.RootCAs == nil || b.RootCAs == nil {
		return a.RootCAs == b.RootCAs
	}
	return a.RootCAs.Equal(b.RootCAs)
}
