// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Version
		wantErr bool
	}{
		{name: "major.minor", input: "24.0", want: Version{Major: 24, Minor: 0, Patch: 0}},
		{name: "major.minor.patch", input: "24.0.1", want: Version{Major: 24, Minor: 0, Patch: 1}},
		{name: "patch with prerelease suffix", input: "24.0.1rc1", want: Version{Major: 24, Minor: 0, Patch: 1}},
		{name: "patch with build suffix", input: "22.2.0+build.5", want: Version{Major: 22, Minor: 2, Patch: 0}},
		{name: "non-numeric patch suffix only", input: "22.2.post1", want: Version{Major: 22, Minor: 2, Patch: 0}},
		{name: "whitespace-separated remainder rejected", input: "24.0.1 from /usr/lib (python 3.12)", wantErr: true},
		{name: "whitespace-separated remainder rejected without patch", input: "24.0 from /usr/lib (python 3.12)", wantErr: true},
		{name: "missing minor", input: "24", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
		{name: "non-numeric major", input: "x.0", wantErr: true},
		{name: "non-numeric minor", input: "24.x", wantErr: true},
		{name: "negative major", input: "-1.0", wantErr: true},
		{name: "negative minor", input: "24.-1", wantErr: true},
		{name: "negative patch", input: "24.0.-1", wantErr: true},
		{name: "negative patch with suffix", input: "24.0.-1rc1", wantErr: true},
		{name: "extra dotted components ignored", input: "1.2.3.4", want: Version{Major: 1, Minor: 2, Patch: 3}},
		{name: "empty major", input: ".0.1", wantErr: true},
		{name: "empty minor", input: "24.", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVersion(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseVersion(%q) = %+v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q) returned unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseVersion(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}

func TestVersionLessThan(t *testing.T) {
	tests := []struct {
		name string
		a, b Version
		want bool
	}{
		{name: "lower major", a: Version{Major: 1, Minor: 9, Patch: 9}, b: Version{Major: 2, Minor: 0, Patch: 0}, want: true},
		{name: "higher major", a: Version{Major: 2, Minor: 0, Patch: 0}, b: Version{Major: 1, Minor: 9, Patch: 9}, want: false},
		{name: "equal major, lower minor", a: Version{Major: 1, Minor: 1, Patch: 9}, b: Version{Major: 1, Minor: 2, Patch: 0}, want: true},
		{name: "equal major, higher minor", a: Version{Major: 1, Minor: 2, Patch: 0}, b: Version{Major: 1, Minor: 1, Patch: 9}, want: false},
		{name: "equal major and minor, lower patch", a: Version{Major: 1, Minor: 1, Patch: 1}, b: Version{Major: 1, Minor: 1, Patch: 2}, want: true},
		{name: "equal major and minor, higher patch", a: Version{Major: 1, Minor: 1, Patch: 2}, b: Version{Major: 1, Minor: 1, Patch: 1}, want: false},
		{name: "equal versions", a: Version{Major: 1, Minor: 1, Patch: 1}, b: Version{Major: 1, Minor: 1, Patch: 1}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.LessThan(tc.b); got != tc.want {
				t.Fatalf("%+v.LessThan(%+v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    Version
		want string
	}{
		{v: Version{Major: 24, Minor: 0, Patch: 0}, want: "24.0.0"},
		{v: Version{Major: 22, Minor: 2, Patch: 1}, want: "22.2.1"},
	}

	for _, tc := range tests {
		if got := tc.v.String(); got != tc.want {
			t.Fatalf("%+v.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}
