// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/supply-chain-firewall/scfw/internal/ddapi"
)

// withKeyringSet temporarily replaces ddapi.KeyringSet for the duration of a test.
func withKeyringSet(t *testing.T, fn func(service, account, value string) error) {
	t.Helper()
	original := ddapi.KeyringSet
	ddapi.KeyringSet = fn
	t.Cleanup(func() { ddapi.KeyringSet = original })
}

// withKeyringDelete temporarily replaces ddapi.KeyringDelete for the duration of a test.
func withKeyringDelete(t *testing.T, fn func(service, account string) error) {
	t.Helper()
	original := ddapi.KeyringDelete
	ddapi.KeyringDelete = fn
	t.Cleanup(func() { ddapi.KeyringDelete = original })
}

func TestMergeManagedBlock(t *testing.T) {
	const existingBlock = blockStart + "\n" +
		`alias pip="scfw run -- pip"` + "\n" +
		blockEnd

	tests := []struct {
		name     string
		original string
		content  string
		want     string
		wantErr  bool
	}{
		{
			name:     "no existing block, empty content is a no-op",
			original: "export FOO=1\n",
			content:  "",
			want:     "export FOO=1\n",
		},
		{
			name:     "no existing block, content is appended",
			original: "export FOO=1",
			content:  `alias pip="scfw run -- pip"` + "\n",
			want:     "export FOO=1\n\n" + existingBlock + "\n",
		},
		{
			name:     "no existing block, empty original",
			original: "",
			content:  `alias pip="scfw run -- pip"` + "\n",
			want:     existingBlock + "\n",
		},
		{
			name:     "existing block is replaced",
			original: "export FOO=1\n\n" + existingBlock + "\n",
			content:  `alias pip3="scfw run -- pip3"` + "\n",
			want: "export FOO=1\n\n" + blockStart + "\n" +
				`alias pip3="scfw run -- pip3"` + "\n" + blockEnd + "\n",
		},
		{
			name:     "existing block surrounded by other content is preserved",
			original: "export FOO=1\n\n" + existingBlock + "\n\nexport BAR=2\n",
			content:  `alias pip3="scfw run -- pip3"` + "\n",
			want: "export FOO=1\n\n" + blockStart + "\n" +
				`alias pip3="scfw run -- pip3"` + "\n" + blockEnd + "\n\nexport BAR=2\n",
		},
		{
			name:     "existing block is removed when content is empty",
			original: "export FOO=1\n\n" + existingBlock + "\n\nexport BAR=2\n",
			content:  "",
			want:     "export FOO=1\n\nexport BAR=2\n",
		},
		{
			name:     "removing the only content yields an empty file",
			original: existingBlock + "\n",
			content:  "",
			want:     "",
		},
		{
			name:     "no existing block, content without trailing newline is normalized",
			original: "export FOO=1\n",
			content:  `alias pip="scfw run -- pip"`,
			want:     "export FOO=1\n\n" + existingBlock + "\n",
		},
		{
			name:     "existing block, replacement content without trailing newline is normalized",
			original: existingBlock + "\n",
			content:  `alias pip3="scfw run -- pip3"`,
			want: blockStart + "\n" +
				`alias pip3="scfw run -- pip3"` + "\n" + blockEnd + "\n",
		},
		{
			name:     "missing end marker is an error",
			original: blockStart + "\nalias pip=...\n",
			content:  "anything",
			wantErr:  true,
		},
		{
			name:     "missing start marker is an error",
			original: "alias pip=...\n" + blockEnd + "\n",
			content:  "anything",
			wantErr:  true,
		},
		{
			name:     "multiple blocks is an error",
			original: existingBlock + "\n\n" + existingBlock,
			content:  "anything",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeManagedBlock(tc.original, tc.content)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("mergeManagedBlock() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("mergeManagedBlock() returned unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mergeManagedBlock() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMergeManagedBlock_Idempotent(t *testing.T) {
	original := "export FOO=1\n"
	content := `alias pip="scfw run -- pip"` + "\n"

	once, err := mergeManagedBlock(original, content)
	if err != nil {
		t.Fatalf("first mergeManagedBlock() returned unexpected error: %v", err)
	}
	twice, err := mergeManagedBlock(once, content)
	if err != nil {
		t.Fatalf("second mergeManagedBlock() returned unexpected error: %v", err)
	}
	if once != twice {
		t.Fatalf("mergeManagedBlock() not idempotent: first = %q, second = %q", once, twice)
	}
}

// withAliasNpm temporarily sets the package-level aliasNpm flag for the
// duration of a test.
func withAliasNpm(t *testing.T, value bool) {
	t.Helper()
	original := aliasNpm
	aliasNpm = value
	t.Cleanup(func() { aliasNpm = original })
}

// withAliasPip temporarily sets the package-level aliasPip flag for the
// duration of a test.
func withAliasPip(t *testing.T, value bool) {
	t.Helper()
	original := aliasPip
	aliasPip = value
	t.Cleanup(func() { aliasPip = original })
}

// withAliasPoetry temporarily sets the package-level aliasPoetry flag for
// the duration of a test.
func withAliasPoetry(t *testing.T, value bool) {
	t.Helper()
	original := aliasPoetry
	aliasPoetry = value
	t.Cleanup(func() { aliasPoetry = original })
}

func TestBuildManagedBlock(t *testing.T) {
	withAliasPip(t, false)
	if got := buildManagedBlock(); got != "" {
		t.Fatalf("buildManagedBlock() = %q, want empty string", got)
	}

	withAliasPip(t, true)
	want := `alias pip="scfw run -- pip"` + "\n" + `alias pip3="scfw run -- pip3"` + "\n"
	if got := buildManagedBlock(); got != want {
		t.Fatalf("buildManagedBlock() = %q, want %q", got, want)
	}
}

func TestBuildManagedBlock_AliasNpm(t *testing.T) {
	withAliasNpm(t, false)
	if got := buildManagedBlock(); got != "" {
		t.Fatalf("buildManagedBlock() = %q, want empty string", got)
	}

	withAliasNpm(t, true)
	want := `alias npm="scfw run -- npm"` + "\n"
	if got := buildManagedBlock(); got != want {
		t.Fatalf("buildManagedBlock() = %q, want %q", got, want)
	}
}

func TestBuildManagedBlock_AliasPoetry(t *testing.T) {
	withAliasPoetry(t, false)
	if got := buildManagedBlock(); got != "" {
		t.Fatalf("buildManagedBlock() = %q, want empty string", got)
	}

	withAliasPoetry(t, true)
	want := `alias poetry="scfw run -- poetry"` + "\n"
	if got := buildManagedBlock(); got != want {
		t.Fatalf("buildManagedBlock() = %q, want %q", got, want)
	}
}

// withDdSite temporarily sets the package-level ddSite flag for the duration
// of a test.
func withDdSite(t *testing.T, value string) {
	t.Helper()
	original := ddSite
	ddSite = value
	t.Cleanup(func() { ddSite = original })
}

func TestBuildManagedBlock_IncludesDdSite(t *testing.T) {
	withAliasPip(t, true)
	withDdSite(t, "datadoghq.eu")

	want := `alias pip="scfw run -- pip"` + "\n" + `alias pip3="scfw run -- pip3"` + "\n" + `export DD_SITE="datadoghq.eu"` + "\n"
	if got := buildManagedBlock(); got != want {
		t.Fatalf("buildManagedBlock() = %q, want %q", got, want)
	}
}

// withScfwHome temporarily sets the package-level scfwHome flag for the
// duration of a test.
func withScfwHome(t *testing.T, value string) {
	t.Helper()
	original := scfwHome
	scfwHome = value
	t.Cleanup(func() { scfwHome = original })
}

func TestBuildManagedBlock_IncludesScfwHome(t *testing.T) {
	withAliasPip(t, true)
	withScfwHome(t, "/tmp/scfw-home")

	want := `alias pip="scfw run -- pip"` + "\n" + `alias pip3="scfw run -- pip3"` + "\n" + `export SCFW_HOME="/tmp/scfw-home"` + "\n"
	if got := buildManagedBlock(); got != want {
		t.Fatalf("buildManagedBlock() = %q, want %q", got, want)
	}
}

func TestUpdateConfigFile_SkipsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bashrc")

	if err := updateConfigFile(path, "alias pip=...\n"); err != nil {
		t.Fatalf("updateConfigFile() returned unexpected error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("updateConfigFile() created %q, want it left untouched", path)
	}
}

func TestUpdateConfigFile_UpdatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bashrc")
	if err := os.WriteFile(path, []byte("export FOO=1\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	content := `alias pip="scfw run -- pip"` + "\n"
	if err := updateConfigFile(path, content); err != nil {
		t.Fatalf("updateConfigFile() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	want, err := mergeManagedBlock("export FOO=1\n", content)
	if err != nil {
		t.Fatalf("mergeManagedBlock() returned unexpected error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("updateConfigFile() wrote %q, want %q", got, want)
	}
}

func TestUpdateConfigFile_SkipsWriteWhenUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bashrc")
	original := "export FOO=1\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	if err := updateConfigFile(path, ""); err != nil {
		t.Fatalf("updateConfigFile() returned unexpected error: %v", err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat %q: %v", path, err)
	}

	if err := updateConfigFile(path, ""); err != nil {
		t.Fatalf("second updateConfigFile() returned unexpected error: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat %q: %v", path, err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("updateConfigFile() rewrote an unchanged file: mtime %v -> %v", before.ModTime(), after.ModTime())
	}
}

func TestUpdateConfigFile_ReadPermissionDeniedIsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses permission checks")
	}

	path := filepath.Join(t.TempDir(), ".bashrc")
	if err := os.WriteFile(path, []byte("export FOO=1\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("failed to chmod %q: %v", path, err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o644) })

	if err := updateConfigFile(path, "anything"); err == nil {
		t.Fatal("updateConfigFile() = nil error, want error")
	}
}

func TestUpdateConfigFile_MalformedBlockIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bashrc")
	if err := os.WriteFile(path, []byte(blockStart+"\nalias pip=...\n"), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	if err := updateConfigFile(path, "anything"); err == nil {
		t.Fatal("updateConfigFile() = nil error, want error")
	}
}

func TestRunConfigure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withAliasPip(t, true)

	present := []string{".bashrc", ".zshrc"}
	for _, name := range present {
		if err := os.WriteFile(filepath.Join(home, name), nil, 0o644); err != nil {
			t.Fatalf("failed to seed %q: %v", name, err)
		}
	}

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	for _, name := range present {
		got, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			t.Fatalf("failed to read %q: %v", name, err)
		}
		if !strings.Contains(string(got), blockStart) {
			t.Fatalf("%s = %q, want it to contain the managed block", name, got)
		}
	}

	for _, name := range []string{".bash_profile", ".zprofile"} {
		if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
			t.Fatalf("runConfigure() created %q, want it skipped since it didn't already exist", name)
		}
	}
}

func TestRunConfigure_TellsUserToRestartTerminal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withAliasPip(t, true)

	if err := os.WriteFile(filepath.Join(home, ".zshrc"), nil, 0o644); err != nil {
		t.Fatalf("failed to seed .zshrc: %v", err)
	}

	var output bytes.Buffer
	cmd := *configureCmd
	cmd.SetOut(&output)
	if err := runConfigure(&cmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}
	if want := "restart your terminal"; !strings.Contains(strings.ToLower(output.String()), want) {
		t.Fatalf("configure output %q does not contain %q", output.String(), want)
	}
}

func TestRunConfigure_WritesDdSiteExport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withDdSite(t, "datadoghq.eu")

	path := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if !strings.Contains(string(got), `export DD_SITE="datadoghq.eu"`) {
		t.Fatalf(".bashrc = %q, want it to contain the DD_SITE export", got)
	}
}

func TestRunConfigure_WritesScfwHomeExportWithoutCreatingDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	scfwHomeDir := filepath.Join(t.TempDir(), "scfw-home")
	withScfwHome(t, scfwHomeDir)

	path := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	if _, err := os.Stat(scfwHomeDir); !os.IsNotExist(err) {
		t.Fatalf("runConfigure() created %q, want it left to SCFW_HOME consumers to create", scfwHomeDir)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if !strings.Contains(string(got), fmt.Sprintf("export SCFW_HOME=%q", scfwHomeDir)) {
		t.Fatalf(".bashrc = %q, want it to contain the SCFW_HOME export", got)
	}
}

func TestRunConfigure_TogglingOffRemovesExistingBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := filepath.Join(home, ".bashrc")
	seeded := "export FOO=1\n\n" + blockStart + "\n" + `alias pip="scfw run -- pip"` + "\n" + blockEnd + "\n"
	if err := os.WriteFile(path, []byte(seeded), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	withAliasPip(t, false)
	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if strings.Contains(string(got), blockStart) {
		t.Fatalf(".bashrc = %q, want the managed block removed", got)
	}
	if want := "export FOO=1\n"; string(got) != want {
		t.Fatalf(".bashrc = %q, want %q", got, want)
	}
}

// withRemove temporarily sets the package-level remove flag for the
// duration of a test.
func withRemove(t *testing.T, value bool) {
	t.Helper()
	original := remove
	remove = value
	t.Cleanup(func() { remove = original })
}

func TestRunConfigure_RemoveStripsExistingBlockAcrossFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withRemove(t, true)
	withKeyringDelete(t, func(service, account string) error { return nil })

	present := []string{".bashrc", ".zshrc"}
	for _, name := range present {
		seeded := "export FOO=1\n\n" + blockStart + "\n" + `alias pip="scfw run -- pip"` + "\n" + blockEnd + "\n"
		if err := os.WriteFile(filepath.Join(home, name), []byte(seeded), 0o644); err != nil {
			t.Fatalf("failed to seed %q: %v", name, err)
		}
	}

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	for _, name := range present {
		got, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			t.Fatalf("failed to read %q: %v", name, err)
		}
		if want := "export FOO=1\n"; string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

// withDdAPIKey temporarily sets the package-level ddAPIKey flag for the
// duration of a test.
func withDdAPIKey(t *testing.T, value string) {
	t.Helper()
	original := ddAPIKey
	ddAPIKey = value
	t.Cleanup(func() { ddAPIKey = original })
}

// withDdAppKey temporarily sets the package-level ddAppKey flag for the
// duration of a test.
func withDdAppKey(t *testing.T, value string) {
	t.Helper()
	original := ddAppKey
	ddAppKey = value
	t.Cleanup(func() { ddAppKey = original })
}

func TestRunConfigure_StoresAPIKeyInKeychain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withDdAPIKey(t, "new-api-key")

	var gotValue string
	withKeyringSet(t, func(service, account, value string) error {
		gotValue = value
		return nil
	})

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}
	if gotValue != "new-api-key" {
		t.Fatalf("keyringSet called with value %q, want %q", gotValue, "new-api-key")
	}
}

func TestRunConfigure_StoresAppKeyInKeychain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withDdAppKey(t, "new-app-key")

	var gotValue string
	withKeyringSet(t, func(service, account, value string) error {
		gotValue = value
		return nil
	})

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}
	if gotValue != "new-app-key" {
		t.Fatalf("keyringSet called with value %q, want %q", gotValue, "new-app-key")
	}
}

func TestRunConfigure_StoresBothKeysInKeychainIndependently(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withDdAPIKey(t, "new-api-key")
	withDdAppKey(t, "new-app-key")

	gotValues := map[string]string{}
	withKeyringSet(t, func(service, account, value string) error {
		gotValues[account] = value
		return nil
	})

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}
	if gotValues[ddapi.KeychainAPIKeyAccount] != "new-api-key" {
		t.Fatalf("keyringSet(%q) = %q, want %q", ddapi.KeychainAPIKeyAccount, gotValues[ddapi.KeychainAPIKeyAccount], "new-api-key")
	}
	if gotValues[ddapi.KeychainAppKeyAccount] != "new-app-key" {
		t.Fatalf("keyringSet(%q) = %q, want %q", ddapi.KeychainAppKeyAccount, gotValues[ddapi.KeychainAppKeyAccount], "new-app-key")
	}
}

func TestRunConfigure_KeychainStoreFailureIsAggregatedNotFatal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withDdAPIKey(t, "new-api-key")
	withAliasPip(t, true)

	wantErr := "keychain unavailable"
	withKeyringSet(t, func(service, account, value string) error {
		return errors.New(wantErr)
	})

	path := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	err := runConfigure(configureCmd, nil)
	if err == nil {
		t.Fatal("runConfigure() = nil error, want error")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("runConfigure() error = %q, want it to mention %q", err, wantErr)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if !strings.Contains(string(got), blockStart) {
		t.Fatalf(".bashrc = %q, want the rc-file update to still proceed despite the keychain failure", got)
	}
}

func TestRunConfigure_RemoveDeletesKeychainEntries(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withRemove(t, true)

	var gotAccounts []string
	withKeyringDelete(t, func(service, account string) error {
		if service != ddapi.KeychainService {
			t.Fatalf("keyringDelete called with service %q, want %q", service, ddapi.KeychainService)
		}
		gotAccounts = append(gotAccounts, account)
		return nil
	})

	if err := runConfigure(configureCmd, nil); err != nil {
		t.Fatalf("runConfigure() returned unexpected error: %v", err)
	}

	wantAccounts := []string{ddapi.KeychainAPIKeyAccount, ddapi.KeychainAppKeyAccount}
	for _, want := range wantAccounts {
		if !slices.Contains(gotAccounts, want) {
			t.Fatalf("keyringDelete calls = %v, want it to include %q", gotAccounts, want)
		}
	}
}

func TestRunConfigure_RemoveKeychainFailureIsAggregatedButRcFilesStillCleaned(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withRemove(t, true)

	wantErr := "keychain locked"
	withKeyringDelete(t, func(service, account string) error {
		return errors.New(wantErr)
	})

	path := filepath.Join(home, ".bashrc")
	seeded := "export FOO=1\n\n" + blockStart + "\n" + `alias pip="scfw run -- pip"` + "\n" + blockEnd + "\n"
	if err := os.WriteFile(path, []byte(seeded), 0o644); err != nil {
		t.Fatalf("failed to seed %q: %v", path, err)
	}

	err := runConfigure(configureCmd, nil)
	if err == nil {
		t.Fatal("runConfigure() = nil error, want error")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("runConfigure() error = %q, want it to mention %q", err, wantErr)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %q: %v", path, err)
	}
	if want := "export FOO=1\n"; string(got) != want {
		t.Fatalf(".bashrc = %q, want %q (managed block removed despite the keychain failure)", got, want)
	}
}

func TestRunConfigure_AggregatesMultipleErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withAliasPip(t, true)

	malformed := blockStart + "\nalias pip=...\n"
	for _, name := range []string{".bashrc", ".zshrc"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(malformed), 0o644); err != nil {
			t.Fatalf("failed to seed %q: %v", name, err)
		}
	}

	err := runConfigure(configureCmd, nil)
	if err == nil {
		t.Fatal("runConfigure() = nil error, want error")
	}
	for _, name := range []string{".bashrc", ".zshrc"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("runConfigure() error = %q, want it to mention %q", err, name)
		}
	}
}

func TestRunConfigure_MissingHomeDirReturnsError(t *testing.T) {
	t.Setenv("HOME", "")

	if err := runConfigure(configureCmd, nil); err == nil {
		t.Fatal("runConfigure() = nil error, want error")
	}
}

func TestRunConfigure_StoreKeychainWorkHappensEvenWhenHomeDirFails(t *testing.T) {
	t.Setenv("HOME", "")
	withDdAPIKey(t, "new-api-key")

	var called bool
	withKeyringSet(t, func(service, account, value string) error {
		called = true
		return nil
	})

	if err := runConfigure(configureCmd, nil); err == nil {
		t.Fatal("runConfigure() = nil error, want error due to missing $HOME")
	}
	if !called {
		t.Fatal("runConfigure() did not store the Datadog API key in the keychain before failing on $HOME resolution")
	}
}

func TestRunConfigure_RemoveKeychainWorkHappensEvenWhenHomeDirFails(t *testing.T) {
	t.Setenv("HOME", "")
	withRemove(t, true)

	var called bool
	withKeyringDelete(t, func(service, account string) error {
		called = true
		return nil
	})

	if err := runConfigure(configureCmd, nil); err == nil {
		t.Fatal("runConfigure() = nil error, want error due to missing $HOME")
	}
	if !called {
		t.Fatal("runConfigure() did not delete the Datadog API key from the keychain before failing on $HOME resolution")
	}
}

// resetConfigureCmd restores configureCmd's flag-parsing state (bound vars,
// pflag's per-flag Changed bit, and silence settings) after a test drives it
// through actual Cobra parsing via Execute, so later tests still see the
// package's normal zero-value defaults.
func resetConfigureCmd(t *testing.T) {
	t.Helper()
	origSilenceUsage, origSilenceErrors := configureCmd.SilenceUsage, configureCmd.SilenceErrors
	configureCmd.SilenceUsage, configureCmd.SilenceErrors = true, true

	t.Cleanup(func() {
		configureCmd.SilenceUsage, configureCmd.SilenceErrors = origSilenceUsage, origSilenceErrors
		aliasNpm, aliasPip, aliasPoetry, ddAPIKey, ddAppKey, ddSite, scfwHome, remove = false, false, false, "", "", "", "", false
		for _, name := range []string{"alias-npm", "alias-pip", "alias-poetry", "dd-api-key", "dd-app-key", "dd-site", "scfw-home", "remove"} {
			configureCmd.Flags().Lookup(name).Changed = false
		}
	})
}

func TestConfigureCmd_MutualExclusivityIsEnforced(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "remove and alias-npm", args: []string{"--remove", "--alias-npm"}},
		{name: "remove and alias-pip", args: []string{"--remove", "--alias-pip"}},
		{name: "remove and alias-poetry", args: []string{"--remove", "--alias-poetry"}},
		{name: "remove and dd-api-key", args: []string{"--remove", "--dd-api-key", "some-key"}},
		{name: "remove and dd-app-key", args: []string{"--remove", "--dd-app-key", "some-key"}},
		{name: "remove and dd-site", args: []string{"--remove", "--dd-site", "some-site"}},
		{name: "remove and scfw-home", args: []string{"--remove", "--scfw-home", "/tmp/scfw-home"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetConfigureCmd(t)

			configureCmd.SetArgs(tc.args)
			if err := configureCmd.Execute(); err == nil {
				t.Fatalf("configureCmd.Execute(%v) = nil error, want error due to mutually exclusive flags", tc.args)
			}
		})
	}
}

func TestConfigureCmd_RejectsFlagLikeValues(t *testing.T) {
	resetConfigureCmd(t)

	// A missing value for --scfw-home lets it swallow --alias-npm as its value.
	configureCmd.SetArgs([]string{"--scfw-home", "--alias-npm"})
	err := configureCmd.Execute()
	if err == nil {
		t.Fatal("configureCmd.Execute() = nil error, want error for --scfw-home swallowing --alias-npm")
	}
	if !strings.Contains(err.Error(), "scfw-home") {
		t.Fatalf("configureCmd.Execute() error = %q, want it to mention scfw-home", err)
	}
	if aliasNpm {
		t.Fatal("aliasNpm = true, want false: --alias-npm should never have been parsed as its own flag")
	}
}

func TestConfigureCmd_RejectionPreventsSideEffects(t *testing.T) {
	resetConfigureCmd(t)

	var called bool
	withKeyringSet(t, func(service, account, value string) error {
		called = true
		return nil
	})

	// --dd-api-key is given a legitimate value, but --scfw-home swallowing
	// --alias-npm should still reject the whole command before runConfigure
	// (and its keychain write) ever runs.
	configureCmd.SetArgs([]string{"--dd-api-key=real-key", "--scfw-home", "--alias-npm"})
	if err := configureCmd.Execute(); err == nil {
		t.Fatal("configureCmd.Execute() = nil error, want error for --scfw-home swallowing --alias-npm")
	}
	if called {
		t.Fatal("keychain write happened despite flag validation failing; PreRunE should run before RunE")
	}
}
