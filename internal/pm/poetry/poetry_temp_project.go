// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package poetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const pypiProjectBaseURL = "https://pypi.org/project"

// findPoetryDirectoryFlag finds poetry's --directory/-C flag in command, in
// any of its accepted forms (--directory path, --directory=path, -C path,
// -Cpath, -C=path).
//
// Returns the token span [start, end) occupied by the flag and its argument
// and the argument's value; ok is false if the flag is not present or has no
// argument.
func findPoetryDirectoryFlag(command []string) (start, end int, value string, ok bool) {
	for i, token := range command {
		switch {
		case token == "--directory" || token == "-C":
			if i+1 >= len(command) {
				return 0, 0, "", false
			}
			return i, i + 2, command[i+1], true
		case strings.HasPrefix(token, "--directory="):
			return i, i + 1, strings.TrimPrefix(token, "--directory="), true
		case strings.HasPrefix(token, "-C") && token != "-C":
			return i, i + 1, strings.TrimPrefix(strings.TrimPrefix(token, "-C"), "="), true
		}
	}
	return 0, 0, "", false
}

// resolvePoetryProjectDir locates the project directory referenced by a
// poetry command, via its --directory/-C flag if present, falling back to
// the current working directory.
func resolvePoetryProjectDir(command []string) (string, error) {
	if _, _, value, ok := findPoetryDirectoryFlag(command); ok {
		return value, nil
	}
	return os.Getwd()
}

// stripPoetryDirectoryFlag removes any --directory/-C flag and its argument
// from command, so it can be safely re-run in a different project directory
// via exec.Cmd.Dir.
func stripPoetryDirectoryFlag(command []string) []string {
	start, end, _, ok := findPoetryDirectoryFlag(command)
	if !ok {
		return slices.Clone(command)
	}
	stripped := make([]string, 0, len(command)-(end-start))
	stripped = append(stripped, command[:start]...)
	stripped = append(stripped, command[end:]...)
	return stripped
}

// poetryTempProject prepares a temporary copy of a Poetry project's
// pyproject.toml (and poetry.toml + poetry.lock, if present), allowing
// poetry commands that write the lock file to run against the copy without
// affecting the original project.
type poetryTempProject struct {
	dir string
}

// newPoetryTempProject copies projectDir's pyproject.toml (and poetry.toml +
// poetry.lock, if present) into a fresh temporary directory placed as a
// sibling of projectDir (not the system temp root), so that relative local
// path dependencies still resolve. The caller must call cleanup when done.
func newPoetryTempProject(projectDir string) (*poetryTempProject, error) {
	dir, err := os.MkdirTemp(filepath.Dir(projectDir), ".scfw-poetry-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary poetry project directory: %w", err)
	}

	if err := copyPoetryFile(filepath.Join(projectDir, "pyproject.toml"), filepath.Join(dir, "pyproject.toml")); err != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("failed to remove temporary poetry project directory", "dir", dir, "error", rmErr)
		}
		return nil, fmt.Errorf("failed to set up temporary poetry project directory: %w", err)
	}
	for _, optional := range []string{"poetry.toml", "poetry.lock"} {
		src := filepath.Join(projectDir, optional)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyPoetryFile(src, filepath.Join(dir, optional)); err != nil {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				slog.Warn("failed to remove temporary poetry project directory", "dir", dir, "error", rmErr)
			}
			return nil, fmt.Errorf("failed to set up temporary poetry project directory: %w", err)
		}
	}

	return &poetryTempProject{dir: dir}, nil
}

// cleanup removes p's temporary directory, first asking poetry to remove the
// virtualenv it auto-created there so repeated runs don't leak cache entries.
func (p *poetryTempProject) cleanup(ctx context.Context, executable string) {
	envRemoveCmd := exec.CommandContext(ctx, executable, "env", "remove", "--all")
	envRemoveCmd.Dir = p.dir
	if output, err := envRemoveCmd.CombinedOutput(); err != nil {
		slog.Warn("failed to remove temporary poetry virtualenv", "error", err, "output", string(output))
	}

	if err := os.RemoveAll(p.dir); err != nil {
		slog.Warn("failed to remove temporary poetry project directory", "dir", p.dir, "error", err)
	}
}

func copyPoetryFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

type poetryLockFile struct {
	Package []poetryLockPackage `toml:"package"`
}

type poetryLockPackage struct {
	Name    string            `toml:"name"`
	Version string            `toml:"version"`
	Source  *poetryLockSource `toml:"source"`
}

type poetryLockSource struct {
	Type string `toml:"type"`
	URL  string `toml:"url"`
}

// parsePoetryLockFile parses a poetry.lock file and returns a mapping from
// (name, version) to the package's source.
//
// Packages with a source of type "directory" or "file" are mapped to an
// absolute local path, resolved relative to lockPath's directory (matching
// poetry's own semantics for relative local path dependencies). Packages
// with any other source type are mapped to the source URL. Packages with no
// source entry are assumed to come from PyPI and mapped to their canonical
// project page URL.
func parsePoetryLockFile(lockPath string) (map[poetryPackageKey]string, error) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	var lock poetryLockFile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", lockPath, err)
	}

	sourceMap := make(map[poetryPackageKey]string, len(lock.Package))
	for _, pkg := range lock.Package {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		key := poetryPackageKey{name: pkg.Name, version: pkg.Version}

		switch {
		case pkg.Source == nil:
			sourceMap[key] = fmt.Sprintf("%s/%s/%s/", pypiProjectBaseURL, pkg.Name, pkg.Version)
		case pkg.Source.URL == "":
			// No URL to report a source for.
		case pkg.Source.Type == "directory" || pkg.Source.Type == "file":
			path := pkg.Source.URL
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(lockPath), path)
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil, err
			}
			sourceMap[key] = abs
		default:
			sourceMap[key] = pkg.Source.URL
		}
	}
	return sourceMap, nil
}

// getPoetrySourceMap returns a (name, version) source mapping for the
// project referenced by command, run via executable.
//
// Locates the project directory via the --directory/-C flag in command,
// falling back to the current working directory. If a poetry.lock already
// exists there, it is parsed directly; otherwise one is generated from
// scratch in a temporary copy of the project, which is never itself
// modified.
//
// Returns a nil map (and logs a warning) on any failure, so callers can
// degrade gracefully to returning packages without source information.
func getPoetrySourceMap(ctx context.Context, executable string, command []string) map[poetryPackageKey]string {
	projectDir, err := resolvePoetryProjectDir(command)
	if err != nil {
		slog.Warn("could not determine package sources from poetry.lock", "error", err)
		return nil
	}

	lockPath := filepath.Join(projectDir, "poetry.lock")
	if _, err := os.Stat(lockPath); err == nil {
		sourceMap, err := parsePoetryLockFile(lockPath)
		if err != nil {
			slog.Warn("could not determine package sources from poetry.lock", "error", err)
			return nil
		}
		return sourceMap
	}

	temp, err := newPoetryTempProject(projectDir)
	if err != nil {
		slog.Warn("could not determine package sources from poetry.lock", "error", err)
		return nil
	}
	defer temp.cleanup(ctx, executable)

	slog.Warn("no poetry.lock found; generating one in a temporary directory (this may be slow)")
	lockCmd := exec.CommandContext(ctx, executable, "lock")
	lockCmd.Dir = temp.dir
	if output, err := lockCmd.CombinedOutput(); err != nil {
		slog.Warn("failed to generate poetry.lock in temporary directory", "error", err, "output", string(output))
	}

	tempLockPath := filepath.Join(temp.dir, "poetry.lock")
	if _, err := os.Stat(tempLockPath); err != nil {
		return nil
	}
	sourceMap, err := parsePoetryLockFile(tempLockPath)
	if err != nil {
		slog.Warn("could not determine package sources from poetry.lock", "error", err)
		return nil
	}
	return sourceMap
}

// regenerateLock returns the (name, version) -> source mappings of a
// project's poetry.lock before and after running command with --lock,
// performed in a temporary copy of the project so the real project is never
// modified. A project with no existing lock has nothing to diff against, so
// old is empty.
func (poetry Poetry) regenerateLock(ctx context.Context, command []string) (old, updated map[poetryPackageKey]string, err error) {
	projectDir, err := resolvePoetryProjectDir(command)
	if err != nil {
		return nil, nil, err
	}

	temp, err := newPoetryTempProject(projectDir)
	if err != nil {
		return nil, nil, err
	}
	defer temp.cleanup(ctx, poetry.Executable())

	lockPath := filepath.Join(temp.dir, "poetry.lock")

	old = map[poetryPackageKey]string{}
	if _, statErr := os.Stat(lockPath); statErr == nil {
		if old, err = parsePoetryLockFile(lockPath); err != nil {
			return nil, nil, err
		}
	}

	lockArgs := append(stripPoetryDirectoryFlag(command), "--lock")
	lockCmd := exec.CommandContext(ctx, poetry.Executable(), lockArgs...)
	lockCmd.Dir = temp.dir
	if _, err := lockCmd.CombinedOutput(); err != nil {
		return nil, nil, err
	}

	updated = map[poetryPackageKey]string{}
	if _, statErr := os.Stat(lockPath); statErr == nil {
		if updated, err = parsePoetryLockFile(lockPath); err != nil {
			return nil, nil, err
		}
	}

	return old, updated, nil
}
