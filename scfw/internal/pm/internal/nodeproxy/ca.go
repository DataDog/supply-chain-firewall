// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package nodeproxy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// NodeExtraCACerts returns the NODE_EXTRA_CA_CERTS value for a proxied child.
// Lifecycle scripts may still connect directly, so the user's own extra CAs
// are kept beside the SCFW CA in the invocation's private directory.
func NodeExtraCACerts(caCertificatePath string, caPEM []byte) (string, error) {
	userCAs, err := os.ReadFile(os.Getenv("NODE_EXTRA_CA_CERTS"))
	if err != nil {
		return caCertificatePath, nil
	}
	bundle := filepath.Join(filepath.Dir(caCertificatePath), "node-extra-ca.pem")
	if err := os.WriteFile(bundle, slices.Concat(userCAs, []byte("\n"), caPEM), 0600); err != nil {
		return "", errors.New("write Node CA bundle")
	}
	return bundle, nil
}
