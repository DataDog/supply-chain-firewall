// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package git discovers metadata about the Git repository containing a path.
package git

import (
	"errors"
	"fmt"

	gogit "github.com/go-git/go-git/v5"
)

// Metadata describes the Git repository containing a path.
type Metadata struct {
	RepositoryURL string
}

// Discover returns metadata about the Git repository containing path. A path that is
// not in a repository, or a repository without an origin URL, produces empty metadata.
func Discover(path string) (Metadata, error) {
	repository, err := gogit.PlainOpenWithOptions(path, &gogit.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if errors.Is(err, gogit.ErrRepositoryNotExists) {
		return Metadata{}, nil
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to open Git repository: %w", err)
	}

	origin, err := repository.Remote(gogit.DefaultRemoteName)
	if errors.Is(err, gogit.ErrRemoteNotFound) {
		return Metadata{}, nil
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("failed to read Git origin: %w", err)
	}

	urls := origin.Config().URLs
	if len(urls) == 0 || urls[0] == "" {
		return Metadata{}, nil
	}

	// Preserve the configured value exactly, matching
	// `git config --get remote.origin.url`. The API is responsible for resolving
	// this raw value to a normalized SCM repository identifier.
	return Metadata{RepositoryURL: urls[0]}, nil
}
