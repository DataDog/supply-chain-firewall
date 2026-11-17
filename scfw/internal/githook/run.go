// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package githook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Run is the hook process: args are the socket, the hook name, and Git's hook
// arguments. It returns the hook's exit status.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(stderr, "supply chain firewall git hook: missing arguments")
		return 1
	}
	socket, name, gitArgs := args[0], args[1], args[2:]
	// Flag 1 marks a branch checkout, which covers clones and "checkout <sha>".
	if name == "post-checkout" && len(gitArgs) == 3 && gitArgs[2] == "1" && !inSubmodule(ctx) {
		if status := ask(ctx, socket, gitArgs[1], stderr); status != 0 {
			return status
		}
	}
	return chain(ctx, filepath.Join(filepath.Dir(socket), "hooks"), name, gitArgs, stdin, stdout, stderr)
}

// ask fails closed: a checkout the parent cannot rule on is blocked.
func ask(ctx context.Context, socket, sha string, stderr io.Writer) int {
	dir, err := os.Getwd()
	if err != nil {
		return unreachable(stderr, err)
	}
	origin, _ := gitOutput(ctx, "config", "--get", "remote.origin.url")
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return unreachable(stderr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(request{Dir: dir, Origin: origin, SHA: sha}); err != nil {
		return unreachable(stderr, err)
	}
	var answer response
	if err := json.NewDecoder(conn).Decode(&answer); err != nil {
		return unreachable(stderr, err)
	}
	if answer.Blocked {
		_, _ = fmt.Fprintln(stderr, answer.Message)
		return 1
	}
	return 0
}

func unreachable(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "supply chain firewall could not evaluate git checkout: %v\n", err)
	return 1
}

// chain runs the hook Git would have run without SCFW's hooks: the effective
// core.hooksPath other than ours, else the repository's hooks directory.
func chain(ctx context.Context, ours, name string, gitArgs []string, stdin io.Reader, stdout, stderr io.Writer) int {
	dir := ""
	// Values are listed from lowest to highest precedence; ours comes last.
	values, _ := gitOutput(ctx, "config", "--type=path", "--get-all", "core.hooksPath")
	for _, value := range strings.Split(values, "\n") {
		if value != "" && filepath.Clean(value) != filepath.Clean(ours) {
			dir = value
		}
	}
	if dir == "" {
		common, err := gitOutput(ctx, "rev-parse", "--git-common-dir")
		if err != nil {
			return 0
		}
		dir = filepath.Join(common, "hooks")
	} else if !filepath.IsAbs(dir) {
		// Git resolves a relative core.hooksPath against the working tree root.
		top, err := gitOutput(ctx, "rev-parse", "--show-toplevel")
		if err != nil {
			return 0
		}
		dir = filepath.Join(top, dir)
	}
	hook := filepath.Join(dir, name)
	if info, err := os.Stat(hook); err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return 0
	}
	child := exec.CommandContext(ctx, hook, gitArgs...)
	child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
	if err := child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		_, _ = fmt.Fprintf(stderr, "supply chain firewall could not run git hook %s: %v\n", name, err)
		return 1
	}
	return 0
}

// A submodule belongs to the package its superproject is checked out for.
func inSubmodule(ctx context.Context) bool {
	superproject, err := gitOutput(ctx, "rev-parse", "--show-superproject-working-tree")
	return err == nil && superproject != ""
}

func gitOutput(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "git", args...).Output()
	return strings.TrimSpace(string(output)), err
}
