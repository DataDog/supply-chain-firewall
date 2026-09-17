// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package pm

import (
	"slices"
	"testing"
)

func TestNewSet(t *testing.T) {
	tests := []struct {
		name  string
		items []int
		want  int
	}{
		{name: "no items", items: nil, want: 0},
		{name: "distinct items", items: []int{1, 2, 3}, want: 3},
		{name: "duplicate items deduped", items: []int{1, 1, 2}, want: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSet(tc.items...)
			if got := s.Len(); got != tc.want {
				t.Fatalf("NewSet(%v).Len() = %d, want %d", tc.items, got, tc.want)
			}
			for _, item := range tc.items {
				if !s.Contains(item) {
					t.Fatalf("NewSet(%v).Contains(%v) = false, want true", tc.items, item)
				}
			}
		})
	}
}

func TestSetAdd(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
		add     string
		want    int
	}{
		{name: "add new item", initial: []string{"a"}, add: "b", want: 2},
		{name: "add duplicate item is a no-op", initial: []string{"a"}, add: "a", want: 1},
		{name: "add to empty set", initial: nil, add: "a", want: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSet(tc.initial...)
			s.Add(tc.add)
			if got := s.Len(); got != tc.want {
				t.Fatalf("Len() after Add(%q) = %d, want %d", tc.add, got, tc.want)
			}
			if !s.Contains(tc.add) {
				t.Fatalf("Contains(%q) = false after Add(%q), want true", tc.add, tc.add)
			}
		})
	}

	t.Run("re-add after remove", func(t *testing.T) {
		s := NewSet("a")
		s.Remove("a")
		s.Add("a")
		if got := s.Len(); got != 1 {
			t.Fatalf("Len() after Remove then Add = %d, want 1", got)
		}
		if !s.Contains("a") {
			t.Fatalf("Contains(%q) = false after re-add, want true", "a")
		}
	})
}

func TestSetContains(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		probe string
		want  bool
	}{
		{name: "present", items: []string{"a", "b"}, probe: "a", want: true},
		{name: "absent", items: []string{"a", "b"}, probe: "c", want: false},
		{name: "empty set", items: nil, probe: "a", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSet(tc.items...)
			if got := s.Contains(tc.probe); got != tc.want {
				t.Fatalf("Contains(%q) = %v, want %v", tc.probe, got, tc.want)
			}
		})
	}
}

func TestSetRemove(t *testing.T) {
	tests := []struct {
		name    string
		initial []string
		remove  string
		want    int
	}{
		{name: "remove present item", initial: []string{"a", "b"}, remove: "a", want: 1},
		{name: "remove absent item is a no-op", initial: []string{"a", "b"}, remove: "c", want: 2},
		{name: "remove from empty set is a no-op", initial: nil, remove: "a", want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSet(tc.initial...)
			s.Remove(tc.remove)
			if got := s.Len(); got != tc.want {
				t.Fatalf("Len() after Remove(%q) = %d, want %d", tc.remove, got, tc.want)
			}
			if s.Contains(tc.remove) {
				t.Fatalf("Contains(%q) = true after Remove(%q), want false", tc.remove, tc.remove)
			}
		})
	}
}

func TestSetLen(t *testing.T) {
	tests := []struct {
		name  string
		items []int
		want  int
	}{
		{name: "empty", items: nil, want: 0},
		{name: "several items", items: []int{1, 2, 3}, want: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSet(tc.items...)
			if got := s.Len(); got != tc.want {
				t.Fatalf("Len() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSetItems(t *testing.T) {
	t.Run("iterates all items", func(t *testing.T) {
		s := NewSet(1, 2, 3)
		var got []int
		for item := range s.Items() {
			got = append(got, item)
		}
		if len(got) != s.Len() {
			t.Fatalf("Items() yielded %d items, want Len() = %d", len(got), s.Len())
		}
		slices.Sort(got)
		want := []int{1, 2, 3}
		if !slices.Equal(got, want) {
			t.Fatalf("Items() yielded %v, want %v", got, want)
		}
	})

	t.Run("empty set yields nothing", func(t *testing.T) {
		s := NewSet[int]()
		for item := range s.Items() {
			t.Fatalf("Items() on empty set yielded %v, want none", item)
		}
	})

	t.Run("stops early when yield returns false", func(t *testing.T) {
		s := NewSet(1, 2, 3)
		count := 0
		for range s.Items() {
			count++
			break
		}
		if count != 1 {
			t.Fatalf("iteration ran %d times after break, want 1", count)
		}
	})
}

// TestSetZeroValue locks in the current behavior of a Set constructed via its
// zero value rather than NewSet: reads are safe against the nil underlying
// map, but Add panics since it writes into that nil map.
func TestSetZeroValue(t *testing.T) {
	var s Set[int]

	if got := s.Len(); got != 0 {
		t.Fatalf("zero-value Len() = %d, want 0", got)
	}
	if s.Contains(1) {
		t.Fatalf("zero-value Contains(1) = true, want false")
	}
	for item := range s.Items() {
		t.Fatalf("zero-value Items() yielded %v, want none", item)
	}

	// Remove on a zero-value Set must not panic.
	s.Remove(1)

	defer func() {
		if recover() == nil {
			t.Fatalf("zero-value Add(1) did not panic, want panic on nil map write")
		}
	}()
	s.Add(1)
}
