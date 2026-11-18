// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package npm

import (
	"slices"
	"strings"
)

type npmOption struct {
	name, value string
}

// Inspect only settings consumed by proxy routing, trust, registries, and
// configuration discovery. Options accept --name value or --name=value; -C and
// -g are the prefix and global shorthands, and -g may sit in a group of npm's
// single-letter shorthands such as -gD. Abbreviations are not expanded: npm
// deprecates them, and a missed one leaves SCFW without the user's upstream,
// which fails rather than bypassing SCFW.
func parseNpmOptions(args []string) []npmOption {
	var options []npmOption
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		if isNpmShorthandGroup(argument) {
			if strings.Contains(argument, "g") {
				options = append(options, npmOption{name: "global", value: "true"})
			}
			continue
		}
		name, value, supplied := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		name = canonicalNpmOption(argument, name)
		switch {
		case name == "global" || name == "no-global" || name == "workspaces" || name == "no-workspaces":
			// Like npm's parser: a bare flag takes a following literal true or
			// false as its value, and any other =value still sets the flag.
			flag, negated := strings.CutPrefix(name, "no-")
			enabled := !negated
			switch {
			case supplied:
				enabled = (value != "false") != negated
			case index+1 < len(args) && (args[index+1] == "true" || args[index+1] == "false"):
				index++
				enabled = (args[index] == "true") != negated
			}
			name, value = flag, "true"
			if !enabled {
				value = "false"
			}
		case name == "no-strict-ssl":
			if supplied {
				continue
			}
			name, value = "strict-ssl", "false"
		case name == "strict-ssl":
			if !supplied {
				value = "true"
				if index+1 < len(args) && (args[index+1] == "true" || args[index+1] == "false") {
					index++
					value = args[index]
				}
			}
		case isScopedRegistry(name) || isNpmValueOption(name):
			if !supplied {
				index++
				if index >= len(args) {
					return options
				}
				value = args[index]
			}
		default:
			continue
		}
		options = append(options, npmOption{name: name, value: value})
	}
	return options
}

func canonicalNpmOption(argument, name string) string {
	if strings.HasPrefix(argument, "--") {
		return name
	}
	switch name {
	case "C":
		return "prefix"
	case "g":
		return "global"
	}
	return ""
}

// npxOptionsEnd returns the index of the first argument npx hands to the
// command it runs: a "--" or the first positional. It ports the option loop of
// npm's bin/npx-cli.js, including its habit of expanding a shorthand into
// separate arguments, so that SCFW's own options land before that boundary.
// The tables below are those of npm 11.
func npxOptionsEnd(args []string) int {
	type argument struct {
		text  string
		index int // position in args, shared by everything a shorthand expands to
	}
	pending := make([]argument, len(args))
	for index, text := range args {
		pending[index] = argument{text, index}
	}
	for position := 0; position < len(pending); position++ {
		current := pending[position]
		if current.text == "--" || !strings.HasPrefix(current.text, "-") {
			return current.index
		}
		key, value, assigned := strings.Cut(strings.TrimLeft(current.text, "-"), "=")
		if long, found := npxShorthands[key]; found {
			expanded := strings.Fields(long)
			if assigned {
				expanded = append(expanded, value)
			}
			tokens := make([]argument, len(expanded))
			for index, text := range expanded {
				tokens[index] = argument{text, current.index}
			}
			pending = slices.Replace(pending, position, position+1, tokens...)
			position--
			continue
		}
		if !assigned && !slices.Contains(npxSwitches, key) &&
			(slices.Contains(npxValueOptions, key) || position+1 == len(pending) || !strings.HasPrefix(pending[position+1].text, "-")) {
			position++ // the next argument is this option's value
		}
	}
	return len(args)
}

// npxShorthands are npm's shorthands, minus n, which npx removed, and p, which
// npx maps to --package before looking at them.
var npxShorthands = map[string]string{
	"d": "--loglevel info", "q": "--loglevel warn", "s": "--loglevel silent", "a": "--all", "c": "--call",
	"f": "--force", "g": "--global", "L": "--location", "l": "--long", "m": "--message", "C": "--prefix",
	"S": "--save", "B": "--save-bundle", "D": "--save-dev", "E": "--save-exact", "O": "--save-optional",
	"P": "--save-prod", "?": "--usage", "H": "--usage", "h": "--usage", "v": "--version", "w": "--workspace",
	"y": "--yes", "enjoy-by": "--before", "dd": "--loglevel verbose", "ddd": "--loglevel silly",
	"quiet": "--loglevel warn", "silent": "--loglevel silent", "verbose": "--loglevel verbose",
	"desc": "--description", "help": "--usage", "local": "--no-global", "no": "--no-yes",
	"porcelain": "--parseable", "readonly": "--read-only", "reg": "--registry",
	"iwr": "--include-workspace-root", "ws": "--workspaces",
}

// npxSwitches take no value: npm's boolean options, which npx reads from
// @npmcli/config, and the switches npx adds or removed.
var npxSwitches = strings.Fields(`all allow-same-version allow-scripts-pending allow-scripts-pin audit
	bin-links browser bypass-2fa color commit-hooks dangerously-allow-all-scripts description dev
	diff-ignore-all-space diff-name-only diff-no-prefix diff-text dry-run engine-strict expect-results force
	foreground-scripts format-package-lock fund git-tag-version global global-style if-present ignore-scripts
	include-attestations include-staged include-workspace-root init-private install-links json legacy-bundling
	legacy-peer-deps link long offline omit-lockfile-registry-resolved optional package-lock package-lock-only
	packages-all parseable prefer-dedupe prefer-offline prefer-online production progress provenance read-only
	rebuild-bundle save save-bundle save-dev save-exact save-optional save-peer save-prod shrinkwrap
	sign-git-commit sign-git-tag strict-allow-scripts strict-peer-deps strict-ssl timing unicode update-notifier
	usage version versions workspaces workspaces-update yes
	always-spawn ignore-existing shell-auto-fallback no-install`)

// npxValueOptions always take a value, even when it starts with a dash.
var npxValueOptions = strings.Fields("npm node-arg n package p cache userconfig call shell")

// npmKind is what an npm command needs from SCFW, ordered so that an ambiguous
// command line can take its most demanding reading.
type npmKind int

const (
	npmScript  npmKind = iota // only runs a package.json script: no proxy
	npmOther                  // proxied, but not inspected without the proxy
	npmInstall                // resolved with a dry run without the proxy
	npmFetch                  // fetches packages that only the proxy sees
)

// npmCommands are the npm 11 commands SCFW treats specially, with their aliases
// from lib/utils/cmd-list.js. Every other command is npmOther.
var npmCommands = []struct {
	name    string
	kind    npmKind
	aliases []string
}{
	{"install", npmInstall, []string{"add", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"}},
	{"run", npmScript, []string{"run-script", "rum", "urn"}},
	{"test", npmScript, []string{"t", "tst"}},
	{"start", npmScript, nil},
	{"stop", npmScript, nil},
	{"restart", npmScript, nil},
	{"ci", npmFetch, []string{"clean-install", "ic", "install-clean", "isntall-clean"}},
	{"install-ci-test", npmFetch, []string{"cit", "sit", "clean-install-test"}},
	{"install-test", npmFetch, []string{"it"}},
	{"update", npmFetch, []string{"u", "up", "upgrade", "udpate"}},
	{"dedupe", npmFetch, []string{"ddp"}},
	{"exec", npmFetch, []string{"x"}},
	{"link", npmFetch, []string{"ln"}},
	{"prune", npmFetch, nil},
	{"uninstall", npmFetch, []string{"unlink", "remove", "rm", "r", "un"}},
	{"audit", npmFetch, nil},                        // only audit fix
	{"cache", npmFetch, nil},                        // only cache add
	{"init", npmFetch, []string{"create", "innit"}}, // only with an initializer
}

// classifyNpmCommand returns the command word names and what it needs, given
// the positional arguments after it.
func classifyNpmCommand(word string, rest []string) (string, npmKind) {
	for _, command := range npmCommands {
		if word != command.name && !slices.Contains(command.aliases, word) {
			continue
		}
		switch {
		case command.name == "audit" && !slices.Contains(rest, "fix"),
			command.name == "cache" && !slices.Contains(rest, "add"),
			command.name == "init" && len(rest) == 0:
			return command.name, npmOther
		}
		return command.name, command.kind
	}
	return word, npmOther
}

type npmInvocation struct {
	words   []string // positional arguments, including every argument after "--"
	certain bool     // words[0] is the command
	noop    bool     // a help, version, or dry-run option keeps npm from acting
}

// parseNpmInvocation does not know which npm options take a value, so an
// option that may take one leaves the command uncertain.
func parseNpmInvocation(args []string) npmInvocation {
	invocation := npmInvocation{certain: true}
	for index, argument := range args {
		switch {
		case argument == "--":
			// npm reads everything after it as positional, even the command.
			invocation.words = append(invocation.words, args[index+1:]...)
			return invocation
		case strings.HasPrefix(argument, "-") && argument != "-":
			if slices.Contains(npmDryRunSkipOptions, argument) && (index+1 == len(args) || args[index+1] != "false") {
				invocation.noop = true
			}
			if len(invocation.words) == 0 && !strings.Contains(argument, "=") && !npmValuelessOption(argument) {
				invocation.certain = false
			}
		case (argument == "true" || argument == "false") && index > 0 && strings.HasPrefix(args[index-1], "-"):
			// the value of a Boolean option
		default:
			invocation.words = append(invocation.words, argument)
		}
	}
	return invocation
}

// command returns the command npm runs and what it needs. When the command is
// uncertain, any word could be it, so the most demanding one is taken.
func (invocation npmInvocation) command() (string, npmKind) {
	if len(invocation.words) == 0 {
		return "", npmOther
	}
	name, kind := classifyNpmCommand(invocation.words[0], invocation.words[1:])
	if invocation.certain {
		return name, kind
	}
	for index := 1; index < len(invocation.words); index++ {
		if other, otherKind := classifyNpmCommand(invocation.words[index], invocation.words[index+1:]); otherKind > kind {
			name, kind = other, otherKind
		}
	}
	return name, kind
}

// npmValuelessOption reports whether an option written without "=" certainly
// takes no value. color and browser also accept a string.
func npmValuelessOption(argument string) bool {
	name := strings.TrimLeft(argument, "-")
	if !strings.HasPrefix(argument, "--") {
		return strings.Trim(name, npmShorthandLetters) == "" && !strings.ContainsAny(name, "CLcmw")
	}
	return slices.Contains(npxSwitches, name) && name != "color" && name != "browser" ||
		slices.Contains([]string{"silent", "quiet", "verbose"}, name)
}

// withoutGlobalOptions removes every spelling of the global flag that
// parseNpmOptions recognizes, along with the true or false literal it
// consumes, so a global command can be dry-run as a local one. Any other
// assigned value is not the flag's: npm reads it as the next positional
// argument, so it stays.
func withoutGlobalOptions(command []string) []string {
	args := make([]string, 0, len(command))
	for index := 0; index < len(command); index++ {
		argument := command[index]
		if argument == "--" {
			return append(args, command[index:]...)
		}
		if !strings.HasPrefix(argument, "-") {
			args = append(args, argument)
			continue
		}
		if isNpmShorthandGroup(argument) {
			if rest := strings.ReplaceAll(argument, "g", ""); rest != "-" {
				args = append(args, rest)
			}
			continue
		}
		name, value, supplied := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if name = canonicalNpmOption(argument, name); name != "global" && name != "no-global" {
			args = append(args, argument)
			continue
		}
		if supplied && value != "true" && value != "false" {
			args = append(args, value)
		}
		if !supplied && index+1 < len(command) && (command[index+1] == "true" || command[index+1] == "false") {
			index++
		}
	}
	return args
}

// npmShorthandLetters are npm's single-letter shorthands, which npm combines
// in one argument only when every letter is one of them.
const npmShorthandLetters = "?BCDEHLOPSacdfghlmnpqsvwy"

func isNpmShorthandGroup(argument string) bool {
	letters, found := strings.CutPrefix(argument, "-")
	return found && len(letters) > 1 && strings.Trim(letters, npmShorthandLetters) == ""
}

func isNpmValueOption(name string) bool {
	switch name {
	case "https-proxy", "proxy", "noproxy", "cafile", "ca", "registry", "userconfig", "globalconfig", "prefix", "location":
		return true
	}
	return false
}

func isScopedRegistry(name string) bool {
	return strings.HasPrefix(name, "@") && strings.HasSuffix(name, ":registry")
}
