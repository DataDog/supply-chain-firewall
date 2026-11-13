// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package yarn

import "net/url"

// yarnTrustURL mirrors Yarn's strict-ssl=false, which disables certificate
// verification for every registry request of the invocation.
func yarnTrustURL(strictSSL bool) func(*url.URL) bool {
	return func(target *url.URL) bool {
		return !strictSSL && target != nil && (target.Scheme == "http" || target.Scheme == "https")
	}
}
