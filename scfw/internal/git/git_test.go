// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package git

import (
	"os"
	"path/filepath"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

func TestDiscoverFromNestedDirectory(t *testing.T) {
	repositoryDir := t.TempDir()
	repository, err := gogit.PlainInit(repositoryDir, false)
	if err != nil {
		t.Fatalf("PlainInit() returned unexpected error: %v", err)
	}
	_, err = repository.CreateRemote(&config.RemoteConfig{
		Name: gogit.DefaultRemoteName,
		URLs: []string{"git@github.com:DataDog/supply-chain-firewall.git"},
	})
	if err != nil {
		t.Fatalf("CreateRemote() returned unexpected error: %v", err)
	}

	nestedDir := filepath.Join(repositoryDir, "some", "nested", "directory")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() returned unexpected error: %v", err)
	}

	metadata, err := Discover(nestedDir)
	if err != nil {
		t.Fatalf("Discover() returned unexpected error: %v", err)
	}
	if want := "git@github.com:DataDog/supply-chain-firewall.git"; metadata.RepositoryURL != want {
		t.Fatalf("Discover().RepositoryURL = %q, want %q", metadata.RepositoryURL, want)
	}
}

func TestDiscoverWithoutRepositoryOrOrigin(t *testing.T) {
	t.Run("not a repository", func(t *testing.T) {
		metadata, err := Discover(t.TempDir())
		if err != nil {
			t.Fatalf("Discover() returned unexpected error: %v", err)
		}
		if metadata != (Metadata{}) {
			t.Fatalf("Discover() = %+v, want empty metadata", metadata)
		}
	})

	t.Run("no origin", func(t *testing.T) {
		repositoryDir := t.TempDir()
		if _, err := gogit.PlainInit(repositoryDir, false); err != nil {
			t.Fatalf("PlainInit() returned unexpected error: %v", err)
		}

		metadata, err := Discover(repositoryDir)
		if err != nil {
			t.Fatalf("Discover() returned unexpected error: %v", err)
		}
		if metadata != (Metadata{}) {
			t.Fatalf("Discover() = %+v, want empty metadata", metadata)
		}
	})
}

func TestDiscoverFromLinkedWorktree(t *testing.T) {
	repositoryDir := t.TempDir()
	repository, err := gogit.PlainInit(repositoryDir, false)
	if err != nil {
		t.Fatalf("PlainInit() returned unexpected error: %v", err)
	}
	_, err = repository.CreateRemote(&config.RemoteConfig{
		Name: gogit.DefaultRemoteName,
		URLs: []string{"https://example.com/acme/project.git"},
	})
	if err != nil {
		t.Fatalf("CreateRemote() returned unexpected error: %v", err)
	}

	worktreeGitDir := filepath.Join(repositoryDir, ".git", "worktrees", "linked")
	if err := os.MkdirAll(worktreeGitDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() returned unexpected error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatalf("writing commondir returned unexpected error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktreeGitDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0o644); err != nil {
		t.Fatalf("writing HEAD returned unexpected error: %v", err)
	}

	worktreeDir := t.TempDir()
	gitFile := []byte("gitdir: " + worktreeGitDir + "\n")
	if err := os.WriteFile(filepath.Join(worktreeDir, ".git"), gitFile, 0o644); err != nil {
		t.Fatalf("writing .git file returned unexpected error: %v", err)
	}

	metadata, err := Discover(worktreeDir)
	if err != nil {
		t.Fatalf("Discover() returned unexpected error: %v", err)
	}
	if want := "https://example.com/acme/project.git"; metadata.RepositoryURL != want {
		t.Fatalf("Discover().RepositoryURL = %q, want %q", metadata.RepositoryURL, want)
	}
}

func TestDiscoverPreservesConfiguredOriginURL(t *testing.T) {
	tests := []struct {
		name      string
		originURL string
	}{
		{
			name:      "HTTPS URL",
			originURL: "https://user:secret@example.com/acme/project.git?token=secret#main",
		},
		{
			name:      "file URL",
			originURL: "file:///private/project.git",
		},
		{
			name:      "local path",
			originURL: "../project.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repositoryDir := t.TempDir()
			repository, err := gogit.PlainInit(repositoryDir, false)
			if err != nil {
				t.Fatalf("PlainInit() returned unexpected error: %v", err)
			}
			_, err = repository.CreateRemote(&config.RemoteConfig{
				Name: gogit.DefaultRemoteName,
				URLs: []string{tt.originURL},
			})
			if err != nil {
				t.Fatalf("CreateRemote() returned unexpected error: %v", err)
			}

			metadata, err := Discover(repositoryDir)
			if err != nil {
				t.Fatalf("Discover() returned unexpected error: %v", err)
			}
			if metadata.RepositoryURL != tt.originURL {
				t.Fatalf("Discover().RepositoryURL = %q, want %q", metadata.RepositoryURL, tt.originURL)
			}
		})
	}
}
