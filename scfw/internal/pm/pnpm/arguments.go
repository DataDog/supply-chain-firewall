// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pnpm

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/pm/internal/nodeproxy"
)

// noptOptions describes pnpm 10/11's command-selecting nopt parse.
type noptOptions struct {
	// values always consume the next argument; strings consume it unless it
	// looks like an option; flags and unknown options consume only true or
	// false; enums are flags that also consume one of their literals.
	values, strings, flags []string
	enums                  map[string][]string
	shorthands, aliases    map[string]string
}

type parsedCommand struct {
	name, sub string
	// typed is the command name as typed, which pnpm's script overrides and
	// the script fallback look scripts up under.
	typed string
	// forced is a `pnpm pm <command>` prefix, which forces the built-in.
	forced bool
	// passthroughNpm is a pnpm 10 command pnpm hands to npm as the whole
	// command line, so no option may precede the name.
	passthroughNpm bool
	// help is set by help or version flags, which stop pnpm from running the
	// command.
	help   bool
	dir    string
	global bool
	// network holds the user's proxy, trust, and registry settings from the
	// command line, keyed by setting name.
	network nodeproxy.Config
	// args is the command without the user's proxy and trust options, which
	// SCFW replaces. Arguments pnpm passes to another program are kept.
	args []string
	// passthrough counts the leading args pnpm itself parses.
	passthrough int
	// withCurrent is `pnpm with current`, which runs the installed pnpm.
	withCurrent bool
}

// strippedSettings are the command-line settings SCFW overrides. Registries are
// recorded but left in place, because pnpm must still use them.
var strippedSettings = []string{
	"https-proxy", "proxy", "http-proxy", "noproxy", "no-proxy", "ca", "cafile", "strict-ssl", "cert", "key", "local-address",
	"pnpr-server",
}

// configLocationOptions choose the user .npmrc. pnpm 10 and 11 read their
// value only in the command's own parse, so the command-selecting tables do
// not list them; SCFW still takes their value to read the same file.
var configLocationOptions = []string{"userconfig", "npmrc-auth-file"}

var registryTLSKey = regexp.MustCompile(`^//.*:(ca|cafile|cert|certfile|key|keyfile)$`)

func networkSetting(key string) (recorded, stripped bool) {
	switch {
	case slices.Contains(strippedSettings, key), registryTLSKey.MatchString(key):
		return true, true
	case key == "registry", strings.HasPrefix(key, "@") && strings.HasSuffix(key, ":registry"),
		key == "pm-on-fail", key == "manage-package-manager-versions", slices.Contains(configLocationOptions, key),
		// Recorded for the settings the script-install gate reads but pnpm
		// keeps: verifyDepsBeforeRun and the layouts SCFW cannot decide.
		key == "verify-deps-before-run", key == "lockfile-dir", key == "modules-dir",
		key == "shared-workspace-lockfile", key == "git-branch-lockfile", key == "merge-git-branch-lockfiles":
		return true, false
	}
	return false, false
}

// parseCommand finds the command pnpm will run. pnpx and pnx run `pnpm dlx`.
func parseCommand(major int, dlx bool, command []string) parsedCommand {
	tokens := command
	if dlx {
		tokens = append([]string{"dlx"}, command...)
	}
	switch major {
	case 10:
		return parseNopt(major, nopt10, tokens, dlx)
	case 11:
		return parseNopt(major, nopt11, tokens, dlx)
	}
	return parseStrict(tokens, dlx)
}

func parseNopt(major int, table noptOptions, tokens []string, dlx bool) parsedCommand {
	parsed := parsedCommand{network: nodeproxy.Config{}}
	// A pass-through command is handed to npm with the whole command line, so
	// SCFW keeps parsing it, to strip the user's own proxy and trust options
	// from what npm receives.
	pnpmPassthrough := !dlx && major == 10 && len(tokens) > 0 && slices.Contains(npmPassthrough10, tokens[0])
	parsed.passthroughNpm = pnpmPassthrough
	var positionals []string
	stripped := make([]bool, len(tokens))
	dir, prefix := "", ""
	boundary := len(tokens)
	for index := 0; index < len(tokens); index++ {
		token := tokens[index]
		if token == "--" {
			positionals = append(positionals, tokens[index+1:]...)
			boundary = index
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			positionals = append(positionals, token)
			if !pnpmPassthrough && escapes(major, table.aliases, positionals) {
				boundary = index + 1
				break
			}
			continue
		}
		next := ""
		if index+1 < len(tokens) {
			next = tokens[index+1]
		}
		option := table.option(token, next)
		if option.consumed {
			index++
		}
		switch option.name {
		case "dir":
			dir = option.value
		case "prefix":
			prefix = option.value
		case "global":
			parsed.global = option.value != "false"
		case "help", "version":
			parsed.help = parsed.help || option.value != "false"
		}
		if recorded, strip := networkSetting(option.name); recorded {
			parsed.network[option.name] = append(parsed.network[option.name], option.value)
			if strip {
				stripped[index] = true
				if option.consumed {
					stripped[index-1] = true
				}
			}
		}
	}
	parsed.name, parsed.sub, parsed.withCurrent = resolveCommand(major, table.aliases, positionals)
	parsed.typed, parsed.forced = typedCommand(major, table.aliases, positionals)
	parsed.dir = dir
	if parsed.dir == "" {
		parsed.dir = prefix
	}
	parsed.args, parsed.passthrough = keptArguments(tokens, stripped, boundary, dlx)
	return parsed
}

// keptArguments drops the stripped options before boundary, and the dlx that
// pnpx and pnx imply.
func keptArguments(tokens []string, stripped []bool, boundary int, dlx bool) (args []string, passthrough int) {
	for index, token := range tokens {
		if (index >= boundary || !stripped[index]) && (!dlx || index != 0) {
			args = append(args, token)
			if index < boundary {
				passthrough++
			}
		}
	}
	return args, passthrough
}

type noptOption struct {
	name, value string
	consumed    bool
}

var optionLike = regexp.MustCompile(`^-{1,2}[^-]`)

// option resolves one option like nopt: any number of dashes, shorthands and
// single-letter clusters, unambiguous abbreviations, and no- negation.
// pnpm-specific --config.<key>, --@scope:registry and --//host/:key options
// take their value only with "=".
func (table noptOptions) option(token, next string) noptOption {
	body, value, assigned := strings.Cut(strings.TrimLeft(token, "-"), "=")
	if key, found := strings.CutPrefix(body, "config."); found && assigned {
		return noptOption{name: key, value: value}
	}
	if (strings.HasPrefix(body, "@") || strings.HasPrefix(body, "//")) && assigned {
		return noptOption{name: body, value: value}
	}
	names := table.expand(body)
	name := names[len(names)-1]
	result := noptOption{name: name}
	// Earlier letters of a cluster are flags without values.
	for _, earlier := range names[:len(names)-1] {
		if earlier == "help" || earlier == "version" {
			return noptOption{name: earlier, value: "true"}
		}
	}
	if expanded, shorthandValue, found := strings.Cut(name, "="); found {
		return noptOption{name: expanded, value: shorthandValue}
	}
	negated := false
	for strings.HasPrefix(name, "no-") {
		negated, name = !negated, table.long(strings.TrimPrefix(name, "no-"))
	}
	result.name = name
	switch {
	case assigned:
		result.value = value
	case negated:
		result.value = "false"
		result.consumed = next == "true" || next == "false"
	case slices.Contains(table.values, name), slices.Contains(configLocationOptions, name):
		result.consumed = next != "" && next != "--"
	case slices.Contains(table.strings, name):
		result.consumed = next != "" && next != "--" && !optionLike.MatchString(next)
	case next == "true" || next == "false" || slices.Contains(table.enums[name], next):
		result.consumed = true
	default:
		result.value = "true"
	}
	if result.consumed && !negated {
		result.value = next
	}
	return result
}

// expand resolves a dash-less option body to long option names, in order.
func (table noptOptions) expand(body string) []string {
	if table.known(body) {
		return []string{body}
	}
	if expansion, found := table.shorthands[body]; found {
		return []string{table.long(strings.TrimLeft(expansion, "-"))}
	}
	if len(body) > 1 {
		var names []string
		for _, letter := range body {
			expansion, found := table.shorthands[string(letter)]
			if !found {
				names = nil
				break
			}
			names = append(names, table.long(strings.TrimLeft(expansion, "-")))
		}
		if names != nil {
			return names
		}
	}
	return []string{table.long(body)}
}

// long expands an unambiguous abbreviation; anything else is returned as is.
func (table noptOptions) long(name string) string {
	if base, _, found := strings.Cut(name, "="); found && table.known(base) {
		return name
	}
	if table.known(name) || strings.HasPrefix(name, "no-") {
		return name
	}
	match := ""
	for _, candidate := range slices.Concat(table.values, table.strings, table.flags, slices.Collect(maps.Keys(table.enums))) {
		if strings.HasPrefix(candidate, name) {
			if match != "" {
				return name
			}
			match = candidate
		}
	}
	if match == "" {
		return name
	}
	return match
}

func (table noptOptions) known(name string) bool {
	_, enum := table.enums[name]
	return enum || slices.Contains(table.values, name) || slices.Contains(table.strings, name) || slices.Contains(table.flags, name)
}

// commandStart returns the index of the command among positionals, skipping
// the recursive prefixes, and `pm` and `with current` from pnpm 11.
func commandStart(major int, aliases map[string]string, positionals []string) int {
	index := 0
	if major >= 11 && len(positionals) > 0 && positionals[0] == "pm" {
		index++
	}
	for index < len(positionals) {
		name := canonical(aliases, positionals[index])
		switch {
		case name == "recursive":
			index++
		case name == "with" && index+1 < len(positionals) && positionals[index+1] == "current" && major >= 11:
			index += 2
		default:
			return index
		}
	}
	return index
}

func canonical(aliases map[string]string, name string) string {
	if alias, found := aliases[name]; found {
		return alias
	}
	return name
}

func resolveCommand(major int, aliases map[string]string, positionals []string) (name, sub string, withCurrent bool) {
	index := commandStart(major, aliases, positionals)
	withCurrent = major >= 11 && index >= 2 && index <= len(positionals) &&
		canonical(aliases, positionals[index-2]) == "with" && positionals[index-1] == "current"
	if index >= len(positionals) {
		return "", "", withCurrent
	}
	name = canonical(aliases, positionals[index])
	if index+1 < len(positionals) {
		sub = positionals[index+1]
	}
	return name, sub, withCurrent
}

// typedCommand returns the name pnpm's script override looks a script up
// under, which is the first positional as typed (argv.remain[0]), or the
// command after a `pm` prefix, and whether that prefix forces the built-in.
// The prefixes pnpm itself skips, like `recursive` and `with current`, do
// not move the lookup: pnpm would run their own name as a script, not the
// built-in they precede.
func typedCommand(major int, aliases map[string]string, positionals []string) (typed string, forced bool) {
	if major >= 11 && len(positionals) > 0 && positionals[0] == "pm" {
		if len(positionals) > 1 {
			typed = positionals[1]
		}
		return typed, true
	}
	if len(positionals) > 0 {
		typed = positionals[0]
	}
	return typed, false
}

// escapes reports whether the remaining arguments belong to another program:
// after create, exec, test, start, stop, and a script name, and after the
// script of run and the package of dlx and the version of with. Built-ins keep
// being parsed, so their proxy and trust options are still recorded and
// stripped.
func escapes(major int, aliases map[string]string, positionals []string) bool {
	index := commandStart(major, aliases, positionals)
	if index >= len(positionals) {
		return false
	}
	switch name := canonical(aliases, positionals[index]); name {
	case "create", "exec", "restart", "test", "start", "stop":
		return true
	case "dlx", "run", "with":
		return len(positionals) > index+1
	case "store", "env", "runtime", "pipeline":
		return false
	default:
		return !isBuiltin(major, name)
	}
}

func isBuiltin(major int, name string) bool {
	return slices.Contains(builtinCommands[major], name)
}

// fetchCommands resolve, fetch, or install packages in every supported version.
var fetchCommands = []string{
	"install", "add", "update", "remove", "link", "unlink", "import", "fetch", "dedupe", "rebuild", "prune",
	"install-test", "patch", "patch-commit", "patch-remove", "deploy", "dlx", "create", "self-update", "env",
	"approve-builds", "ci",
}

// commandKind describes what a command does with packages.
type commandKind int

const (
	// kindScript runs a package script or hands its arguments to another
	// program.
	kindScript commandKind = iota
	// kindFetch resolves, fetches, or installs packages.
	kindFetch
	// kindOther is a built-in command that does not fetch packages.
	kindOther
)

// scriptCommand reports whether pnpm runs a package script or another program:
// run, exec, and restart; a name that is not a built-in of its major, which
// pnpm falls back to `pnpm run <name>` for; and a built-in a same-named
// script in the command's package.json replaces, unless `pnpm pm` forces
// the built-in (pnpm 11 also keeps it under --global). Help and version flags
// stop pnpm, so nothing runs either way.
func scriptCommand(major int, parsed parsedCommand, scriptExists func(string) bool) bool {
	if parsed.help {
		return true
	}
	if parsed.passthroughNpm {
		return false
	}
	switch parsed.name {
	case "run", "exec", "restart", "test", "start", "stop":
		return true
	}
	if !isBuiltin(major, parsed.name) {
		return true
	}
	return !parsed.forced && (major != 11 || !parsed.global) &&
		slices.Contains(overridableScripts[major], parsed.typed) &&
		scriptExists != nil && scriptExists(parsed.typed)
}

// commandKind classifies a parsed command: scripts run directly and every
// other command, fetching or not, runs through the proxy. pack-app downloads
// the single-executable-application builder and a Node runtime; with,
// runtime, and pipeline download package-manager or runtime releases.
func classifyCommand(major int, parsed parsedCommand, scriptExists func(string) bool) commandKind {
	if scriptCommand(major, parsed, scriptExists) {
		return kindScript
	}
	switch parsed.name {
	case "store":
		if parsed.sub == "add" {
			return kindFetch
		}
	case "with", "runtime", "pipeline", "pack-app":
		return kindFetch
	}
	if slices.Contains(fetchCommands, parsed.name) {
		return kindFetch
	}
	return kindOther
}

// ProxyCommandSupported selects the commands pnpm runs through the SCFW
// proxy: every command except scripts. A script pnpm 11 or 12 would install
// dependencies before (verify_deps.go) is proxied too, so that install is
// evaluated. An unknown version is proxied so that the proxy path reports
// the version error.
func (p Pnpm) ProxyCommandSupported(command []string) bool {
	major, err := p.major(command)
	if err != nil {
		return true
	}
	parsed := parseCommand(major, p.dlx, command)
	if classifyCommand(major, parsed, p.scriptsAt(parsed)) == kindScript {
		return p.scriptInstalls(major, parsed)
	}
	return true
}

// pnpm 12 parses its command line with clap: long options are exact, and an
// option written before the subcommand takes a value when any subcommand's
// version of it does.
var (
	strictValueOptions = []string{
		"access", "allow-build", "audit-level", "base", "branch", "bump", "changed-files-ignore-pattern", "cidr", "cpu",
		"depth", "dir", "edit-dir", "entry", "env-file", "fetch-min-speed-ki-bps", "fetch-timeout", "fetch-warn-timeout-ms",
		"filter", "filter-prod", "find-by", "format", "http-proxy", "https-proxy", "ignore", "init-type", "interval", "libc",
		"location", "lockfile-dir", "loglevel", "merge-git-branch-lockfiles-branch-pattern", "message", "network-concurrency",
		"no-proxy", "node-linker", "npmrc-auth-file", "os", "otp", "out", "output-dir", "output-name", "pack-destination",
		"pack-gzip-level", "package", "patches-dir", "pnpr-server", "preid", "prefix", "publication-name", "publish-branch",
		"publish-wait-timeout", "registry", "release-notes", "repo", "report-to", "reporter", "runtime", "save-catalog-name",
		"save-prefix", "sbom-authors", "sbom-format", "sbom-spec-version", "sbom-supplier", "sbom-type", "scope",
		"search-limit", "sort-by", "state-dir", "store-dir", "summary", "tag", "tag-version-prefix", "target", "test-pattern",
		"upload-variant", "user-agent", "userconfig", "variant", "variant-integrity", "workspace-concurrency",
		"workspace-packages",
	}
	// Bare setting flags outside clap's table consume a value that does not
	// look like an option, a value that parses, or a boolean.
	strictTextSettings = []string{
		"cache-dir", "global-dir", "hoist-pattern", "lockfile-dir", "local-address", "modules-dir", "public-hoist-pattern",
		"trust-policy-exclude", "virtual-store-dir",
	}
	strictParsedSettings = map[string][]string{
		"node-linker":           {"hoisted", "isolated", "pnp"},
		"package-import-method": {"auto", "hardlink", "copy", "clone", "clone-or-copy"},
		"pm-on-fail":            {"download", "error", "warn", "ignore"},
		"runtime-on-fail":       {"download", "error", "warn", "ignore"},
		"trust-policy":          {"no-downgrade", "off"},
	}
	strictNumberSettings = []string{"child-concurrency", "trust-policy-ignore-after"}
	// strictSettingFlags are the network settings pnpm 12 extracts as bare
	// setting flags wherever they appear.
	strictSettingFlags = []string{"local-address", "strict-ssl"}
	strictShorts       = map[rune]string{'C': "dir", 'F': "filter", 'm': "message", 't': "tag", 'g': "global", 'h': "help", 'v': "version"}
	strictAliases      = func() map[string]string {
		aliases := maps.Clone(nopt11.aliases)
		maps.Copy(aliases, map[string]string{"licences": "licenses", "t": "test", "tst": "test"})
		return aliases
	}()
)

var number = regexp.MustCompile(`^[0-9]+$`)

func parseStrict(tokens []string, dlx bool) parsedCommand {
	parsed := parsedCommand{network: nodeproxy.Config{}}
	var positionals []string
	stripped := make([]bool, len(tokens))
	boundary := len(tokens)
	record := func(name, value string, indexes ...int) {
		recorded, strip := networkSetting(name)
		if !recorded {
			return
		}
		parsed.network[name] = append(parsed.network[name], value)
		for _, index := range indexes {
			stripped[index] = strip
		}
	}
	// pnpm 12 extracts configuration options anywhere after create, whose other
	// arguments belong to the create-* package.
	createTail := false
	for index := 0; index < len(tokens) && boundary == len(tokens); index++ {
		token := tokens[index]
		next := ""
		if index+1 < len(tokens) {
			next = tokens[index+1]
		}
		if createTail {
			name, value, assigned := strings.Cut(strings.TrimPrefix(token, "--"), "=")
			key, configured := strings.CutPrefix(name, "config.")
			switch {
			case !strings.HasPrefix(token, "--"):
			case configured && assigned:
				record(key, value, index)
			case (strings.HasPrefix(name, "@") || strings.HasPrefix(name, "//")) && assigned:
				record(name, value, index)
			case slices.Contains(strictSettingFlags, name) && assigned:
				record(name, value, index)
			case slices.Contains(strictSettingFlags, name):
				if value, consumed := strictValue(name, next); consumed {
					record(name, value, index, index+1)
					index++
				} else {
					record(name, value, index)
				}
			}
			continue
		}
		switch {
		case token == "--":
			// A leading "--" makes the next argument a script name, which
			// pnpm runs like `pnpm run <script>`; the install gate
			// applies to it as to any script.
			if len(positionals) == 0 {
				return parsedCommand{network: parsed.network, name: "run", typed: "run", args: tokens}
			}
			positionals = append(positionals, tokens[index+1:]...)
			boundary = index
		case !strings.HasPrefix(token, "-") || token == "-":
			positionals = append(positionals, token)
			if name, _, _ := resolveCommand(12, strictAliases, positionals); name == "create" {
				createTail = true
			} else if escapes(12, strictAliases, positionals) {
				boundary = index + 1
			}
		case !strings.HasPrefix(token, "--"):
			name, value, consumed := strictShort(token[1:], next)
			parsed.apply(name, value)
			if consumed {
				index++
			}
		default:
			name, value, assigned := strings.Cut(token[2:], "=")
			key, configured := strings.CutPrefix(name, "config.")
			if configured || strings.HasPrefix(name, "@") || strings.HasPrefix(name, "//") {
				if !configured {
					key = name
				}
				if assigned {
					record(key, value, index)
				}
				continue
			}
			consumed := false
			if !assigned {
				value, consumed = strictValue(name, next)
			}
			parsed.apply(name, value)
			if consumed {
				record(name, value, index, index+1)
				index++
			} else {
				record(name, value, index)
			}
		}
	}
	parsed.name, parsed.sub, parsed.withCurrent = resolveCommand(12, strictAliases, positionals)
	parsed.typed, parsed.forced = typedCommand(12, strictAliases, positionals)
	parsed.args, parsed.passthrough = keptArguments(tokens, stripped, boundary, dlx)
	return parsed
}

// strictValue reports the value an unassigned long option takes.
func strictValue(name, next string) (string, bool) {
	var takes bool
	switch {
	case slices.Contains(strictValueOptions, name), slices.Contains(strictTextSettings, name):
		takes = next != "" && !strings.HasPrefix(next, "-")
	case slices.Contains(strictNumberSettings, name):
		takes = number.MatchString(next)
	case strictParsedSettings[name] != nil:
		takes = slices.Contains(strictParsedSettings[name], next)
	case slices.Contains([]string{"true", "false", "1", "0"}, next):
		return next, true
	default:
		return "true", false
	}
	if !takes {
		return "", false
	}
	return next, true
}

// strictShort resolves a short-option cluster: a value-taking letter takes the
// rest of the cluster, or the next argument when it is last.
func strictShort(cluster, next string) (name, value string, consumed bool) {
	for offset, letter := range cluster {
		switch long := strictShorts[letter]; long {
		case "dir", "filter", "message", "tag":
			if rest := strings.TrimPrefix(cluster[offset+1:], "="); rest != "" {
				return long, rest, false
			}
			return long, next, next != ""
		case "help", "version", "global":
			name, value = long, "true"
		}
	}
	return name, value, false
}

func (parsed *parsedCommand) apply(name, value string) {
	switch name {
	case "dir", "prefix":
		parsed.dir = value
	case "global":
		parsed.global = value != "false"
	case "help", "version":
		parsed.help = true
	}
}
