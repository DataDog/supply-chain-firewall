// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	// The environment variables under which SCFW looks for a Datadog API key and
	// application key, respectively.
	ddAPIKeyVar = "DD_API_KEY"
	ddAppKeyVar = "DD_APP_KEY"

	// The system keychain entries used by SCFW to store Datadog credentials.
	KeychainService       = "scfw"
	KeychainAPIKeyAccount = "dd_api_key"
	KeychainAppKeyAccount = "dd_app_key"

	// Marks a base64-encoded keychain value, matching go-keyring's macOS storage encoding.
	keychainBase64Prefix = "go-keyring-base64:"
)

// Return the configured Datadog API key and application key. Each is
// resolved independently: the corresponding environment variable is
// preferred, falling back to the system keychain if the environment
// variable is unset or empty.
func ddCredentials() (ddAPIKey, ddAppKey string, err error) {
	if ddAPIKey, err = resolveCredential(KeychainAPIKeyAccount, ddAPIKeyVar); err != nil {
		return "", "", fmt.Errorf("failed to resolve Datadog API key: %w", err)
	}
	if ddAppKey, err = resolveCredential(KeychainAppKeyAccount, ddAppKeyVar); err != nil {
		return "", "", fmt.Errorf("failed to resolve Datadog application key: %w", err)
	}
	return ddAPIKey, ddAppKey, nil
}

// resolveCredential returns the value of a single credential, preferring
// envVar and falling back to the system keychain if envVar is unset or empty.
func resolveCredential(account, envVar string) (string, error) {
	if value := os.Getenv(envVar); value != "" {
		return value, nil
	}
	value, err := keychainSecret(account)
	if err != nil {
		return "", fmt.Errorf("not found in %s or keychain: %w", envVar, err)
	}
	return value, nil
}

// keyringGet indirects through keyring.Get so tests can substitute a fake.
var keyringGet = keyring.Get

// Reads and decode a single account's value from the system keychain.
// An empty value is treated as not found, matching keyring.ErrNotFound.
func keychainSecret(account string) (string, error) {
	value, err := keyringGet(KeychainService, account)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", keyring.ErrNotFound
	}
	return decodeKeychainValue(value)
}

// KeyringSet and KeyringDelete indirect through keyring.Set and
// keyring.Delete so tests can substitute fakes.
var (
	KeyringSet    = keyring.Set
	KeyringDelete = keyring.Delete
)

// storeCredential writes value to the system keychain under account. label
// identifies the credential in error messages (e.g. "API key").
func storeCredential(account, label, value string) error {
	if err := KeyringSet(KeychainService, account, value); err != nil {
		return fmt.Errorf("failed to store Datadog %s in system keychain: %w", label, err)
	}
	return nil
}

// removeCredential deletes account's entry from the system keychain, if
// present. A missing entry is not treated as an error. label identifies the
// credential in error messages (e.g. "API key").
func removeCredential(account, label string) error {
	if err := KeyringDelete(KeychainService, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("failed to remove Datadog %s from system keychain: %w", label, err)
	}
	return nil
}

// StoreDatadogAPIKey writes value to the system keychain as SCFW's Datadog
// API key entry.
func StoreDatadogAPIKey(value string) error {
	return storeCredential(KeychainAPIKeyAccount, "API key", value)
}

// RemoveDatadogAPIKey deletes SCFW's Datadog API key entry from the system
// keychain. A missing entry is not treated as an error.
func RemoveDatadogAPIKey() error {
	return removeCredential(KeychainAPIKeyAccount, "API key")
}

// StoreDatadogAppKey writes value to the system keychain as SCFW's Datadog
// application key entry.
func StoreDatadogAppKey(value string) error {
	return storeCredential(KeychainAppKeyAccount, "application key", value)
}

// RemoveDatadogAppKey deletes SCFW's Datadog application key entry from the
// system keychain. A missing entry is not treated as an error.
func RemoveDatadogAppKey() error {
	return removeCredential(KeychainAppKeyAccount, "application key")
}

// Normalize a keychain value that may carry go-keyring's base64 storage encoding.
func decodeKeychainValue(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	encoded, ok := strings.CutPrefix(trimmed, keychainBase64Prefix)
	if !ok {
		return trimmed, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding base64 keychain value: %w", err)
	}
	return strings.TrimSpace(string(decoded)), nil
}
