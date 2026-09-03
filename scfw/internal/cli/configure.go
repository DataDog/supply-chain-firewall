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
	"strconv"
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
	aliasNpm          bool
	aliasPip          bool
	aliasPoetry       bool
	removeAliasNpm    bool
	removeAliasPip    bool
	removeAliasPoetry bool
	ddAPIKey          string
	ddAppKey          string
	ddSite            string
	scfwHome          string
	remove            bool
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
	registerConfigureArg("alias-npm", false, "Add shell aliases to run all npm commands through Supply Chain Firewall.", &aliasNpm)
	registerConfigureArg("remove-alias-npm", false, "Remove Supply Chain Firewall's npm shell alias.", &removeAliasNpm)
	registerConfigureArg("alias-pip", false, "Add shell aliases to run all pip commands through Supply Chain Firewall.", &aliasPip)
	registerConfigureArg("remove-alias-pip", false, "Remove Supply Chain Firewall's pip shell aliases.", &removeAliasPip)
	registerConfigureArg("alias-poetry", false, "Add shell aliases to run all poetry commands through Supply Chain Firewall.", &aliasPoetry)
	registerConfigureArg("remove-alias-poetry", false, "Remove Supply Chain Firewall's poetry shell alias.", &removeAliasPoetry)
	registerConfigureArg("dd-api-key", "", "Datadog API key used for policy evaluation and reporting.", &ddAPIKey)
	registerConfigureArg("dd-app-key", "", "Datadog application key used for policy evaluation and reporting.", &ddAppKey)
	registerConfigureArg("dd-site", "", "Datadog site parameter used for policy evaluation and reporting.", &ddSite)
	registerConfigureArg("scfw-home", "", "Directory that Supply Chain Firewall can use as a local cache.", &scfwHome)
	configureCmd.MarkFlagsMutuallyExclusive("alias-npm", "remove-alias-npm")
	configureCmd.MarkFlagsMutuallyExclusive("alias-pip", "remove-alias-pip")
	configureCmd.MarkFlagsMutuallyExclusive("alias-poetry", "remove-alias-poetry")
	configureCmd.MarkFlagsOneRequired(configureArgNames...)
}

// configFiles lists the shell rc files, relative to the user's home
// directory, that SCFW's managed block is written to. A file is skipped
// entirely if it does not already exist.
var configFiles = []string{".bashrc", ".bash_profile", ".zshrc", ".zprofile"}

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
	completionFiles := shellCompletionFiles(home)

	for _, name := range configFiles {
		path := filepath.Join(home, name)
		var content string
		if !remove {
			existingConfig, err := readManagedConfiguration(path)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			content = buildManagedBlock(
				existingConfig,
				cmd.Flags().Changed("scfw-home"),
				cmd.Flags().Changed("dd-site"),
			)
			if completionFiles[name] {
				content += shellCompletionConfig(name)
			}
		}
		if err := updateConfigFile(path, content); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Configuration updated. Restart your terminal for the changes to take effect."); err != nil {
		return fmt.Errorf("scfw configure: write restart notice: %w", err)
	}
	return nil
}

// shellCompletionFiles selects every Bash startup file because interactive
// login shells may not source .bashrc. Zsh sources .zshrc for every interactive
// shell, so .zprofile is only needed as a fallback for profile-only setups.
func shellCompletionFiles(home string) map[string]bool {
	selected := map[string]bool{".bashrc": true, ".bash_profile": true}
	zshFile := ".zshrc"
	if _, err := os.Stat(filepath.Join(home, zshFile)); os.IsNotExist(err) {
		zshFile = ".zprofile"
	}
	selected[zshFile] = true
	return selected
}

// shellCompletionConfig enables Cobra completion for the shell that sources
// the configuration file. Package-manager aliases keep their own command names,
// so their existing npm, pip, and Poetry completion definitions remain active.
func shellCompletionConfig(configFile string) string {
	switch configFile {
	case ".bashrc", ".bash_profile":
		return `if [[ $- == *i* ]] && ! complete -p scfw >/dev/null 2>&1; then
  source <(scfw completion bash)
fi
`
	case ".zshrc", ".zprofile":
		return `if [[ -o interactive ]]; then
  if (( ! $+functions[compdef] )); then
    autoload -U compinit && compinit
  fi
  if [[ -z ${_comps[scfw]-} ]]; then
    source <(scfw completion zsh)
  fi
fi
`
	default:
		return ""
	}
}

// buildManagedBlock formats the currently selected configuration options
// into the content of SCFW's managed block. Previously configured aliases
// remain enabled when their corresponding flags are omitted.
func buildManagedBlock(existingConfig managedConfiguration, scfwHomeChanged, ddSiteChanged bool) string {
	var b strings.Builder
	if !removeAliasNpm && (aliasNpm || hasConfiguredAlias(existingConfig.aliases, "npm")) {
		b.WriteString(`alias npm="scfw run -- npm"` + "\n")
	}
	if !removeAliasPip && (aliasPip || hasConfiguredAlias(existingConfig.aliases, "pip", "pip3")) {
		b.WriteString(`alias pip="scfw run -- pip"` + "\n")
		b.WriteString(`alias pip3="scfw run -- pip3"` + "\n")
	}
	if !removeAliasPoetry && (aliasPoetry || hasConfiguredAlias(existingConfig.aliases, "poetry")) {
		b.WriteString(`alias poetry="scfw run -- poetry"` + "\n")
	}
	configuredScfwHome := existingConfig.scfwHome
	if scfwHomeChanged || scfwHome != "" {
		configuredScfwHome = scfwHome
	}
	if configuredScfwHome != "" {
		fmt.Fprintf(&b, "export SCFW_HOME=%q\n", configuredScfwHome)
	}
	configuredDdSite := existingConfig.ddSite
	if ddSiteChanged || ddSite != "" {
		configuredDdSite = ddSite
	}
	if configuredDdSite != "" {
		fmt.Fprintf(&b, "export DD_SITE=%q\n", configuredDdSite)
	}
	return b.String()
}

func hasConfiguredAlias(existingAliases map[string]string, names ...string) bool {
	for _, name := range names {
		if existingAliases[name] == expectedAliasTarget(name) {
			return true
		}
	}
	return false
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

type managedConfiguration struct {
	aliases  map[string]string
	scfwHome string
	ddSite   string
}

// readManagedConfiguration returns the aliases and exports defined in SCFW's managed
// block in path. Files without a managed block (including missing files)
// contain no managed configuration.
func readManagedConfiguration(path string) (managedConfiguration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return managedConfiguration{}, nil
		}
		return managedConfiguration{}, fmt.Errorf("%s: %w", path, err)
	}

	content := string(data)
	block, err := parseManagedBlock(content)
	if err != nil {
		return managedConfiguration{}, fmt.Errorf("%s: %w", path, err)
	}
	if !block.found {
		return managedConfiguration{}, nil
	}

	config := managedConfiguration{aliases: make(map[string]string)}
	for line := range strings.Lines(content[block.contentStart:block.contentEnd]) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "alias ") {
			name, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "alias ")), "=")
			if name = strings.TrimSpace(name); ok && name != "" {
				config.aliases[name] = unquoteConfigValue(value)
			}
			continue
		}
		if strings.HasPrefix(line, "export ") {
			name, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "export ")), "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(name) {
			case "SCFW_HOME":
				config.scfwHome = unquoteConfigValue(value)
			case "DD_SITE":
				config.ddSite = unquoteConfigValue(value)
			}
		}
	}
	return config, nil
}

// readManagedBlock returns the aliases defined in SCFW's managed block in path.
func readManagedBlock(path string) (map[string]string, error) {
	config, err := readManagedConfiguration(path)
	return config.aliases, err
}

func unquoteConfigValue(value string) string {
	value = strings.TrimSpace(value)
	if unquoted, err := strconv.Unquote(value); err == nil {
		return unquoted
	}
	return value
}

const (
	// Markers delimiting the block of shell configuration that SCFW manages
	// within a user's rc file. Content outside the block is left untouched.
	blockStart = "# BEGIN SCFW MANAGED BLOCK"
	blockEnd   = "# END SCFW MANAGED BLOCK"
)

type managedBlock struct {
	found                    bool
	start, end               int
	contentStart, contentEnd int
}

// parseManagedBlock validates marker ordering and returns the byte boundaries
// of the single managed block, if present. Markers must occupy their own line.
func parseManagedBlock(content string) (managedBlock, error) {
	var block managedBlock
	inside := false

	for offset := 0; offset < len(content); {
		lineStart := offset
		lineEnd := len(content)
		if newline := strings.IndexByte(content[offset:], '\n'); newline >= 0 {
			lineEnd = offset + newline
			offset = lineEnd + 1
		} else {
			offset = len(content)
		}

		marker := strings.TrimSpace(content[lineStart:lineEnd])
		switch marker {
		case blockStart:
			if inside {
				return managedBlock{}, fmt.Errorf("malformed SCFW managed block: nested start marker")
			}
			if block.found {
				return managedBlock{}, fmt.Errorf("multiple SCFW managed blocks found")
			}
			block.found = true
			block.start = lineStart
			block.contentStart = offset
			inside = true
		case blockEnd:
			if !inside {
				return managedBlock{}, fmt.Errorf("malformed SCFW managed block: end marker without a start marker")
			}
			block.contentEnd = lineStart
			block.end = offset
			inside = false
		}
	}

	if inside {
		return managedBlock{}, fmt.Errorf("malformed SCFW managed block: missing end marker")
	}
	return block, nil
}

// mergeManagedBlock returns the contents of a shell rc file with SCFW's
// managed block set to content. An empty content removes the block
// entirely. original is left untouched outside the managed block.
func mergeManagedBlock(original, content string) (string, error) {
	if content != "" {
		// Ensure the end marker always lands on its own line, regardless of
		// whether content already ends in a newline.
		content = strings.TrimRight(content, "\n") + "\n"
	}

	block, err := parseManagedBlock(original)
	if err != nil {
		return "", err
	}
	if !block.found {
		if content == "" {
			return original, nil
		}
		// No existing block to replace; append a new one to the end.
		return joinNonEmpty(original, blockStart+"\n"+content+blockEnd), nil
	}

	before, after := original[:block.start], original[block.end:]

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
