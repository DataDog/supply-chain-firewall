// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
)

var configureCmd = &cobra.Command{
	Use:     "configure",
	Short:   "Configure the environment for using Supply Chain Firewall.",
	Args:    cobra.NoArgs,
	PreRunE: func(cmd *cobra.Command, args []string) error { return rejectFlagLikeValues(cmd) },
	RunE:    runConfigure,
}

var (
	aliasNpm    bool
	aliasPip    bool
	aliasPoetry bool
	ddAPIKey    string
	ddAppKey    string
	ddSite      string
	scfwHome    string
	remove      bool
)

// configureArgType is the set of flag value types registerConfigureArg
// supports.
type configureArgType interface {
	~string | ~bool
}

// configureArgNames collects the name of every flag registered via
// registerConfigureArg, plus "remove" (registered separately since it isn't
// itself a configureArgType value), so that init can mark the full set as a
// one-required group in a single place.
var configureArgNames = []string{"remove"}

// registerConfigureArg registers a configureCmd flag named name, of type T,
// with the given default value and help message, writing into ptr, marks it
// mutually exclusive with --remove, and records it in configureArgNames.
func registerConfigureArg[T configureArgType](name string, defaultValue T, help string, ptr *T) {
	switch p := any(ptr).(type) {
	case *string:
		configureCmd.Flags().StringVar(p, name, any(defaultValue).(string), help)
	case *bool:
		configureCmd.Flags().BoolVar(p, name, any(defaultValue).(bool), help)
	}
	configureCmd.MarkFlagsMutuallyExclusive(name, "remove")
	configureArgNames = append(configureArgNames, name)
}

func init() {
	configureCmd.Flags().BoolVar(&remove, "remove", false, "Remove all Supply Chain Firewall managed configuration.")
	registerConfigureArg("alias-npm", false, "Add a shell wrapper to run all npm commands through Supply Chain Firewall.", &aliasNpm)
	registerConfigureArg("alias-pip", false, "Add shell wrappers to run all pip commands through Supply Chain Firewall.", &aliasPip)
	registerConfigureArg("alias-poetry", false, "Add a shell wrapper to run all poetry commands through Supply Chain Firewall.", &aliasPoetry)
	registerConfigureArg("dd-api-key", "", "Datadog API key used for policy evaluation and reporting.", &ddAPIKey)
	registerConfigureArg("dd-app-key", "", "Datadog application key used for policy evaluation and reporting.", &ddAppKey)
	registerConfigureArg("dd-site", "", "Datadog site parameter used for policy evaluation and reporting.", &ddSite)
	registerConfigureArg("scfw-home", "", "Directory that Supply Chain Firewall can use as a local cache.", &scfwHome)
	configureCmd.MarkFlagsOneRequired(configureArgNames...)
}

// configFile describes a shell rc file, relative to the user's home directory,
// and, when non-empty, the shell whose completion script should be installed in it.
type configFile struct {
	name            string
	completionShell string
}

// configFiles lists the shell rc files that SCFW's managed block is written to.
// A file is skipped entirely if it does not already exist.
var configFiles = []configFile{
	{name: ".bashrc", completionShell: "bash"},
	{name: ".bash_profile", completionShell: "bash"},
	{name: ".zshrc", completionShell: "zsh"},
	// .zprofile is also read by non-interactive login shells and runs before
	// .zshrc. Keep wrappers and exports there, but initialize completion only
	// after interactive-shell plugins have configured fpath in .zshrc.
	{name: ".zprofile"},
}

func runConfigure(cmd *cobra.Command, args []string) error {
	var errs []error

	if remove {
		if err := ddapi.RemoveDatadogAPIKey(); err != nil {
			errs = append(errs, err)
		}
		if err := ddapi.RemoveDatadogAppKey(); err != nil {
			errs = append(errs, err)
		}
	} else {
		if ddAPIKey != "" {
			if err := ddapi.StoreDatadogAPIKey(ddAPIKey); err != nil {
				errs = append(errs, err)
			}
		}
		if ddAppKey != "" {
			if err := ddapi.StoreDatadogAppKey(ddAppKey); err != nil {
				errs = append(errs, err)
			}
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		errs = append(errs, fmt.Errorf("scfw configure: %w", err))
		return errors.Join(errs...)
	}

	for _, file := range configFiles {
		var content string
		if !remove {
			content = buildManagedBlock(file.completionShell)
		}
		if err := updateConfigFile(filepath.Join(home, file.name), content); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// buildManagedBlock formats shell completion and the currently selected
// configuration options into the content of SCFW's managed block.
func buildManagedBlock(shell string) string {
	var b strings.Builder
	switch shell {
	case "bash":
		b.WriteString("if type _get_comp_words_by_ref >/dev/null 2>&1; then\n")
		b.WriteString("\teval \"$(scfw completion bash)\"\n")
		b.WriteString("else\n")
		b.WriteString("\tprintf '%s\\n' 'SCFW: bash completion is unavailable; install and initialize bash-completion to enable it.' >&2\n")
		b.WriteString("fi\n")
	case "zsh":
		b.WriteString("if ! type compdef >/dev/null 2>&1; then\n\tautoload -Uz compinit && compinit\nfi\n")
		b.WriteString("source <(scfw completion zsh)\n")
	}
	if aliasNpm {
		writePackageManagerFunction(&b, "npm")
	}
	if aliasPip {
		writePackageManagerFunction(&b, "pip")
		writePackageManagerFunction(&b, "pip3")
	}
	if aliasPoetry {
		writePackageManagerFunction(&b, "poetry")
	}
	if scfwHome != "" {
		fmt.Fprintf(&b, "export SCFW_HOME=%q\n", scfwHome)
	}
	if ddSite != "" {
		fmt.Fprintf(&b, "export DD_SITE=%q\n", ddSite)
	}
	return b.String()
}

// writePackageManagerFunction adds a transparent package-manager wrapper. Shell
// functions keep completion definitions registered for the original command name
// working, unlike aliases that can be expanded before completion (notably in zsh).
func writePackageManagerFunction(b *strings.Builder, name string) {
	fmt.Fprintf(b, "unalias %s 2>/dev/null || true\n%s() {\n\tscfw run -- %s \"$@\"\n}\n", name, name, name)
}

// updateConfigFile merges content into path's managed block and writes the
// result back, if path already exists and the merge actually changes it.
func updateConfigFile(path, content string) error {
	original, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s: %w", path, err)
	}

	updated, err := mergeManagedBlock(string(original), content)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if updated == string(original) {
		return nil
	}

	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

const (
	// Markers delimiting the block of shell configuration that SCFW manages
	// within a user's rc file. Content outside the block is left untouched.
	blockStart = "# BEGIN SCFW MANAGED BLOCK"
	blockEnd   = "# END SCFW MANAGED BLOCK"
)

// mergeManagedBlock returns the contents of a shell rc file with SCFW's
// managed block set to content. An empty content removes the block
// entirely. original is left untouched outside the managed block.
func mergeManagedBlock(original, content string) (string, error) {
	if content != "" {
		// Ensure the end marker always lands on its own line, regardless of
		// whether content already ends in a newline.
		content = strings.TrimRight(content, "\n") + "\n"
	}

	start := strings.Index(original, blockStart)
	if start == -1 {
		if strings.Contains(original, blockEnd) {
			return "", fmt.Errorf("malformed SCFW managed block: end marker without a start marker")
		}
		if content == "" {
			return original, nil
		}
		// No existing block to replace; append a new one to the end.
		return joinNonEmpty(original, blockStart+"\n"+content+blockEnd), nil
	}

	afterStart := start + len(blockStart)
	endRel := strings.Index(original[afterStart:], blockEnd)
	if endRel == -1 {
		return "", fmt.Errorf("malformed SCFW managed block: missing end marker")
	}
	end := afterStart + endRel + len(blockEnd)

	if strings.Contains(original[end:], blockStart) {
		return "", fmt.Errorf("multiple SCFW managed blocks found")
	}

	before, after := original[:start], original[end:]

	if content == "" {
		return joinNonEmpty(before, after), nil
	}
	return joinNonEmpty(before, blockStart+"\n"+content+blockEnd, after), nil
}

// joinNonEmpty joins the non-empty parts with a blank line between each,
// normalizing surrounding newlines so repeated merges stay byte-identical.
func joinNonEmpty(parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p := strings.Trim(p, "\n"); p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) == 0 {
		return ""
	}
	return strings.Join(nonEmpty, "\n\n") + "\n"
}
