// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package ddapi

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// withKeyringGet temporarily replaces keyringGet for the duration of a test.
func withKeyringGet(t *testing.T, fn func(service, account string) (string, error)) {
	t.Helper()
	original := keyringGet
	keyringGet = fn
	t.Cleanup(func() { keyringGet = original })
}

// withKeyringSet temporarily replaces KeyringSet for the duration of a test.
func withKeyringSet(t *testing.T, fn func(service, account, value string) error) {
	t.Helper()
	original := KeyringSet
	KeyringSet = fn
	t.Cleanup(func() { KeyringSet = original })
}

// withKeyringDelete temporarily replaces KeyringDelete for the duration of a test.
func withKeyringDelete(t *testing.T, fn func(service, account string) error) {
	t.Helper()
	original := KeyringDelete
	KeyringDelete = fn
	t.Cleanup(func() { KeyringDelete = original })
}

// withEnv temporarily sets or unsets an environment variable for the duration of a test.
func withEnv(t *testing.T, key, value string) {
	t.Helper()
	if value != "" {
		t.Setenv(key, value)
		return
	}

	original, wasSet := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(key, original)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestDdCredentials_EnvTakesPrecedenceOverKeychain(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "env-api-key")
	withEnv(t, ddAppKeyVar, "env-app-key")
	withKeyringGet(t, func(service, account string) (string, error) {
		t.Fatalf("keychain should not be consulted when %q is set (account %q)", account, account)
		return "", keyring.ErrNotFound
	})

	apiKey, appKey, err := ddCredentials()
	if err != nil {
		t.Fatalf("ddCredentials() returned unexpected error: %v", err)
	}
	if apiKey != "env-api-key" || appKey != "env-app-key" {
		t.Fatalf("ddCredentials() = (%q, %q), want (%q, %q)", apiKey, appKey, "env-api-key", "env-app-key")
	}
}

func TestDdCredentials_EachCredentialFallsBackToKeychainIndependently(t *testing.T) {
	// API key: env is unset, keychain is used. App key: env is set, keychain
	// is ignored. Demonstrates the two credentials resolve independently
	// rather than as an all-or-nothing pair.
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "env-app-key")
	withKeyringGet(t, func(service, account string) (string, error) {
		switch account {
		case KeychainAPIKeyAccount:
			return "keychain-api-key", nil
		case KeychainAppKeyAccount:
			t.Fatal("app key should not be looked up in the keychain when its env var is set")
			return "", keyring.ErrNotFound
		default:
			return "", keyring.ErrNotFound
		}
	})

	apiKey, appKey, err := ddCredentials()
	if err != nil {
		t.Fatalf("ddCredentials() returned unexpected error: %v", err)
	}
	if apiKey != "keychain-api-key" || appKey != "env-app-key" {
		t.Fatalf("ddCredentials() = (%q, %q), want (%q, %q)", apiKey, appKey, "keychain-api-key", "env-app-key")
	}
}

func TestDdCredentials_KeychainFallback(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		if service != KeychainService {
			t.Fatalf("keyringGet called with service %q, want %q", service, KeychainService)
		}
		switch account {
		case KeychainAPIKeyAccount:
			return "keychain-api-key", nil
		case KeychainAppKeyAccount:
			return "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte("keychain-app-key")), nil
		default:
			return "", keyring.ErrNotFound
		}
	})

	apiKey, appKey, err := ddCredentials()
	if err != nil {
		t.Fatalf("ddCredentials() returned unexpected error: %v", err)
	}
	if apiKey != "keychain-api-key" || appKey != "keychain-app-key" {
		t.Fatalf("ddCredentials() = (%q, %q), want (%q, %q)", apiKey, appKey, "keychain-api-key", "keychain-app-key")
	}
}

func TestDdCredentials_EnvPreferredEvenWithPartialKeychain(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "env-api-key")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		switch account {
		case KeychainAPIKeyAccount:
			t.Fatal("API key should not be looked up in the keychain when its env var is set")
			return "", keyring.ErrNotFound
		case KeychainAppKeyAccount:
			return "keychain-app-key", nil
		default:
			return "", keyring.ErrNotFound
		}
	})

	apiKey, appKey, err := ddCredentials()
	if err != nil {
		t.Fatalf("ddCredentials() returned unexpected error: %v", err)
	}
	if apiKey != "env-api-key" || appKey != "keychain-app-key" {
		t.Fatalf("ddCredentials() = (%q, %q), want (%q, %q)", apiKey, appKey, "env-api-key", "keychain-app-key")
	}
}

func TestDdCredentials_MissingEverywhereReturnsError(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		return "", keyring.ErrNotFound
	})

	_, _, err := ddCredentials()
	if err == nil {
		t.Fatal("ddCredentials() = nil error, want error")
	}
	if !strings.Contains(err.Error(), ddAPIKeyVar) {
		t.Fatalf("ddCredentials() error = %v, want it to name %q", err, ddAPIKeyVar)
	}
}

func TestDdCredentials_KeychainErrorPropagatesWhenEnvAlsoMissing(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	wantErr := errors.New("keychain unavailable")
	withKeyringGet(t, func(service, account string) (string, error) {
		return "", wantErr
	})

	if _, _, err := ddCredentials(); !errors.Is(err, wantErr) {
		t.Fatalf("ddCredentials() error = %v, want wrapping %v", err, wantErr)
	}
}

func TestDdCredentials_APIKeyLookupFailureShortCircuits(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		if account == KeychainAppKeyAccount {
			t.Fatal("app key should not be looked up when the API key lookup fails")
		}
		return "", keyring.ErrNotFound
	})

	_, _, err := ddCredentials()
	if err == nil {
		t.Fatal("ddCredentials() = nil error, want error")
	}
	if !strings.Contains(err.Error(), "API key") {
		t.Fatalf("ddCredentials() error = %v, want mention of API key", err)
	}
}

func TestDdCredentials_AppKeyLookupFailure(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		if account == KeychainAPIKeyAccount {
			return "keychain-api-key", nil
		}
		return "", keyring.ErrNotFound
	})

	_, _, err := ddCredentials()
	if err == nil {
		t.Fatal("ddCredentials() = nil error, want error")
	}
	if !strings.Contains(err.Error(), "application key") {
		t.Fatalf("ddCredentials() error = %v, want mention of application key", err)
	}
	if !strings.Contains(err.Error(), ddAppKeyVar) {
		t.Fatalf("ddCredentials() error = %v, want it to name %q", err, ddAppKeyVar)
	}
}

func TestDdCredentials_EmptyKeychainValueTreatedAsNotFound(t *testing.T) {
	withEnv(t, ddAPIKeyVar, "")
	withEnv(t, ddAppKeyVar, "")
	withKeyringGet(t, func(service, account string) (string, error) {
		return "", nil
	})

	if _, _, err := ddCredentials(); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("ddCredentials() error = %v, want wrapping %v", err, keyring.ErrNotFound)
	}
}

func TestStoreDatadogAPIKey(t *testing.T) {
	var gotService, gotAccount, gotValue string
	withKeyringSet(t, func(service, account, value string) error {
		gotService, gotAccount, gotValue = service, account, value
		return nil
	})

	if err := StoreDatadogAPIKey("new-api-key"); err != nil {
		t.Fatalf("StoreDatadogAPIKey() returned unexpected error: %v", err)
	}
	if gotService != KeychainService || gotAccount != KeychainAPIKeyAccount || gotValue != "new-api-key" {
		t.Fatalf("KeyringSet called with (%q, %q, %q), want (%q, %q, %q)",
			gotService, gotAccount, gotValue, KeychainService, KeychainAPIKeyAccount, "new-api-key")
	}
}

func TestStoreDatadogAPIKey_Error(t *testing.T) {
	wantErr := errors.New("keychain unavailable")
	withKeyringSet(t, func(service, account, value string) error {
		return wantErr
	})

	if err := StoreDatadogAPIKey("new-api-key"); !errors.Is(err, wantErr) {
		t.Fatalf("StoreDatadogAPIKey() error = %v, want wrapping %v", err, wantErr)
	} else if !strings.Contains(err.Error(), "API key") {
		t.Fatalf("StoreDatadogAPIKey() error = %v, want it to mention %q", err, "API key")
	}
}

func TestRemoveDatadogAPIKey(t *testing.T) {
	var gotService, gotAccount string
	withKeyringDelete(t, func(service, account string) error {
		gotService, gotAccount = service, account
		return nil
	})

	if err := RemoveDatadogAPIKey(); err != nil {
		t.Fatalf("RemoveDatadogAPIKey() returned unexpected error: %v", err)
	}
	if gotService != KeychainService || gotAccount != KeychainAPIKeyAccount {
		t.Fatalf("KeyringDelete called with (%q, %q), want (%q, %q)", gotService, gotAccount, KeychainService, KeychainAPIKeyAccount)
	}
}

func TestRemoveDatadogAPIKey_NotFoundIsNotError(t *testing.T) {
	withKeyringDelete(t, func(service, account string) error {
		return keyring.ErrNotFound
	})

	if err := RemoveDatadogAPIKey(); err != nil {
		t.Fatalf("RemoveDatadogAPIKey() returned unexpected error: %v", err)
	}
}

func TestRemoveDatadogAPIKey_OtherErrorPropagates(t *testing.T) {
	wantErr := errors.New("keychain locked")
	withKeyringDelete(t, func(service, account string) error {
		return wantErr
	})

	if err := RemoveDatadogAPIKey(); !errors.Is(err, wantErr) {
		t.Fatalf("RemoveDatadogAPIKey() error = %v, want wrapping %v", err, wantErr)
	} else if !strings.Contains(err.Error(), "API key") {
		t.Fatalf("RemoveDatadogAPIKey() error = %v, want it to mention %q", err, "API key")
	}
}

func TestStoreDatadogAppKey(t *testing.T) {
	var gotService, gotAccount, gotValue string
	withKeyringSet(t, func(service, account, value string) error {
		gotService, gotAccount, gotValue = service, account, value
		return nil
	})

	if err := StoreDatadogAppKey("new-app-key"); err != nil {
		t.Fatalf("StoreDatadogAppKey() returned unexpected error: %v", err)
	}
	if gotService != KeychainService || gotAccount != KeychainAppKeyAccount || gotValue != "new-app-key" {
		t.Fatalf("KeyringSet called with (%q, %q, %q), want (%q, %q, %q)",
			gotService, gotAccount, gotValue, KeychainService, KeychainAppKeyAccount, "new-app-key")
	}
}

func TestStoreDatadogAppKey_Error(t *testing.T) {
	wantErr := errors.New("keychain unavailable")
	withKeyringSet(t, func(service, account, value string) error {
		return wantErr
	})

	if err := StoreDatadogAppKey("new-app-key"); !errors.Is(err, wantErr) {
		t.Fatalf("StoreDatadogAppKey() error = %v, want wrapping %v", err, wantErr)
	} else if !strings.Contains(err.Error(), "application key") {
		t.Fatalf("StoreDatadogAppKey() error = %v, want it to mention %q", err, "application key")
	}
}

func TestRemoveDatadogAppKey(t *testing.T) {
	var gotService, gotAccount string
	withKeyringDelete(t, func(service, account string) error {
		gotService, gotAccount = service, account
		return nil
	})

	if err := RemoveDatadogAppKey(); err != nil {
		t.Fatalf("RemoveDatadogAppKey() returned unexpected error: %v", err)
	}
	if gotService != KeychainService || gotAccount != KeychainAppKeyAccount {
		t.Fatalf("KeyringDelete called with (%q, %q), want (%q, %q)", gotService, gotAccount, KeychainService, KeychainAppKeyAccount)
	}
}

func TestRemoveDatadogAppKey_NotFoundIsNotError(t *testing.T) {
	withKeyringDelete(t, func(service, account string) error {
		return keyring.ErrNotFound
	})

	if err := RemoveDatadogAppKey(); err != nil {
		t.Fatalf("RemoveDatadogAppKey() returned unexpected error: %v", err)
	}
}

func TestRemoveDatadogAppKey_OtherErrorPropagates(t *testing.T) {
	wantErr := errors.New("keychain locked")
	withKeyringDelete(t, func(service, account string) error {
		return wantErr
	})

	if err := RemoveDatadogAppKey(); !errors.Is(err, wantErr) {
		t.Fatalf("RemoveDatadogAppKey() error = %v, want wrapping %v", err, wantErr)
	} else if !strings.Contains(err.Error(), "application key") {
		t.Fatalf("RemoveDatadogAppKey() error = %v, want it to mention %q", err, "application key")
	}
}

func TestKeychainSecret(t *testing.T) {
	withKeyringGet(t, func(service, account string) (string, error) {
		if service != KeychainService || account != KeychainAPIKeyAccount {
			t.Fatalf("keyringGet called with (%q, %q), want (%q, %q)", service, account, KeychainService, KeychainAPIKeyAccount)
		}
		return "keychain-value", nil
	})

	got, err := keychainSecret(KeychainAPIKeyAccount)
	if err != nil {
		t.Fatalf("keychainSecret() returned unexpected error: %v", err)
	}
	if got != "keychain-value" {
		t.Fatalf("keychainSecret() = %q, want %q", got, "keychain-value")
	}
}

func TestKeychainSecret_EmptyValueIsNotFound(t *testing.T) {
	withKeyringGet(t, func(service, account string) (string, error) {
		return "", nil
	})

	if _, err := keychainSecret(KeychainAPIKeyAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("keychainSecret() error = %v, want %v", err, keyring.ErrNotFound)
	}
}

func TestDecodeKeychainValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain value", input: "plain-secret", want: "plain-secret"},
		{name: "value with surrounding whitespace", input: "  plain-secret  ", want: "plain-secret"},
		{
			name:  "base64-encoded value",
			input: "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte("encoded-secret")),
			want:  "encoded-secret",
		},
		{name: "malformed base64", input: "go-keyring-base64:not-valid-base64!!", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeKeychainValue(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("decodeKeychainValue(%q) = %q, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeKeychainValue(%q) returned unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("decodeKeychainValue(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
