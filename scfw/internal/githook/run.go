// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package githook

import (
	"context"
	"encoding/json"
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
	if name == "post-checkout" && len(gitArgs) == 3 && gitArgs[2] == "1" {
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

// chain runs the hook Git would have run without SCFW's hooks.
func chain(_ context.Context, _, _ string, _ []string, _ io.Reader, _, _ io.Writer) int {
	return 0
}

func gitOutput(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "git", args...).Output()
	return strings.TrimSpace(string(output)), err
}
