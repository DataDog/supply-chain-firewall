// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import (
	"golang.org/x/net/http/httpproxy"
)

func (yarn Yarn) UpstreamProxy(_ []string) (httpproxy.Config, error) {
	if _, err := yarn.generation(); err != nil {
		return httpproxy.Config{}, err
	}
	return httpproxy.Config{}, nil
}
