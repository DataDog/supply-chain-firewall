// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package diagnostic

import (
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const redacted = "[REDACTED]"

var (
	secretKey            = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|cookie|credential|private.?key|api.?key|app.?key|npmAuthIdent|(^|[_./-])_?auth($|[_:=/-]))`)
	urlPattern           = regexp.MustCompile(`(?i)(?:https?:)?//[^\s<>"']+`)
	assignmentPattern    = regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|app[_-]?key|_auth|npmAuthIdent)["']?\s*[:=]\s*["']?)[^\s,"'<>;&]+`)
	keyMaterial          = regexp.MustCompile(`-----BEGIN[^\n]*PRIVATE KEY-----`)
	authorizationPattern = regexp.MustCompile(`(?i)(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.:-]+`)
	secretPathPattern    = regexp.MustCompile(`(?i)(/(?:token|password|secret|api[_-]?key|auth)/)[^/]+`)
	credentialPattern    = regexp.MustCompile(`(?:eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|npm_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,})`)
)

// Redactor handles supported bounded values only; it never invokes arbitrary
// Stringer, error, LogValuer, or marshaling methods supplied by observed values.
type Redactor struct{ secrets []string }

func NewRedactor(environment, arguments []string) *Redactor {
	r := &Redactor{}
	for _, item := range environment {
		key, value, _ := strings.Cut(item, "=")
		if secretKey.MatchString(key) && len(value) >= 4 && len(value) <= 64<<10 {
			r.secrets = append(r.secrets, value)
		}
	}
	for index, arg := range arguments {
		key, value, found := strings.Cut(arg, "=")
		if (strings.HasPrefix(key, "-") || found) && secretKey.MatchString(key) {
			if !found && index+1 < len(arguments) {
				value = arguments[index+1]
			}
			if len(value) >= 4 && len(value) <= 64<<10 {
				r.secrets = append(r.secrets, value)
			}
		}
	}
	return r
}

// Text preserves full paths, but strips URL credentials/query strings and secrets.
func (r *Redactor) Text(value string) string {
	if len(value) > 64<<10 {
		return "[omitted oversized text]"
	}
	if keyMaterial.MatchString(value) {
		return "[omitted private key]"
	}
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, redacted)
		if len(value) > 64<<10 {
			return "[omitted redaction expansion]"
		}
	}
	value = urlPattern.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return "[omitted invalid URL]"
		}
		parsed.User = nil
		parsed.Path = secretPathPattern.ReplaceAllString(parsed.Path, "${1}"+redacted)
		parsed.RawPath = ""
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		return parsed.String()
	})
	value = assignmentPattern.ReplaceAllString(value, "${1}"+redacted)
	value = authorizationPattern.ReplaceAllString(value, redacted)
	return credentialPattern.ReplaceAllString(value, redacted)
}

// Reference also sanitizes relative registry/download URLs, whose signed query
// strings must not bypass the absolute-URL redactor. Filesystem context is not
// passed here, so harmless full filesystem paths remain unchanged.
func (r *Redactor) Reference(value string) string {
	value = r.Text(value)
	parsed, err := url.Parse(value)
	if err != nil {
		return "[omitted invalid URL]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.Path = secretPathPattern.ReplaceAllString(parsed.Path, "${1}"+redacted)
	parsed.RawPath = ""
	return parsed.String()
}

func urlField(key string) bool {
	switch strings.ToLower(key) {
	case "url", "source", "location", "href", "tarball", "http_proxy", "https_proxy":
		return true
	}
	return false
}

// Arguments handles secret-valued separate options without changing child args.
func (r *Redactor) Arguments(arguments []string) []string {
	result := make([]string, 0, min(len(arguments), 128))
	secretValue := false
	for index, value := range arguments {
		if index >= 128 {
			result = append(result, "[omitted additional arguments]")
			break
		}
		if secretValue {
			result = append(result, redacted)
			secretValue = false
			continue
		}
		key, _, assigned := strings.Cut(value, "=")
		if (strings.HasPrefix(key, "-") || assigned) && secretKey.MatchString(key) {
			if assigned {
				result = append(result, r.Text(key)+"="+redacted)
			} else {
				result = append(result, r.Text(key))
				secretValue = true
			}
			continue
		}
		result = append(result, r.Text(value))
	}
	return result
}

func (r *Redactor) Value(value any) any { budget := 32 << 10; return r.value(value, 0, &budget) }

func (r *Redactor) value(value any, depth int, budget *int) any {
	if *budget < 64 {
		return "[omitted document budget]"
	}
	*budget -= 64
	if depth > 6 {
		return "[omitted nested value]"
	}
	switch typed := value.(type) {
	case nil, bool, int, int32, int64, uint, uint32, uint64, float32, float64:
		return typed
	case string:
		if len(typed) > *budget {
			return "[omitted document budget]"
		}
		*budget -= len(typed)
		return r.Text(typed)
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	case *url.Error:
		if typed == nil {
			return nil
		}
		return r.value(map[string]any{"operation": typed.Op, "url": typed.URL, "cause": typed.Err}, depth+1, budget)
	case *net.OpError:
		if typed == nil {
			return nil
		}
		return r.value(map[string]any{"operation": typed.Op, "network": typed.Net, "cause": typed.Err}, depth+1, budget)
	case *os.PathError:
		if typed == nil {
			return nil
		}
		return r.value(map[string]any{"operation": typed.Op, "path": typed.Path, "cause": typed.Err}, depth+1, budget)
	case error:
		return "[omitted error details: " + reflect.TypeOf(typed).String() + "]"
	case []string:
		if len(typed) > 128 {
			return "[omitted oversized list]"
		}
		result := make([]string, len(typed))
		for i, item := range typed {
			clean, _ := r.value(item, depth+1, budget).(string)
			result[i] = clean
		}
		return result
	case []any:
		if len(typed) > 128 {
			return "[omitted oversized list]"
		}
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = r.value(item, depth+1, budget)
		}
		return result
	case map[string]any:
		if len(typed) > 128 {
			return "[omitted oversized mapping]"
		}
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if len(key) > 256 {
				continue
			}
			if reference, ok := item.(string); ok && urlField(key) {
				if len(reference) > *budget {
					result[r.Text(key)] = "[omitted document budget]"
				} else {
					*budget -= len(reference)
					result[r.Text(key)] = r.Reference(reference)
				}
			} else if secretKey.MatchString(key) {
				result[r.Text(key)] = redacted
			} else {
				result[r.Text(key)] = r.value(item, depth+1, budget)
			}
		}
		return result
	default:
		return "[omitted opaque value]"
	}
}
