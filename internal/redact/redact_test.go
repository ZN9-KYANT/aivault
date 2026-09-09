package redact

import (
	"fmt"
	"testing"
)

func TestPatterns(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer vk-0123456789abcdef0123456789abcdef0123456789abcdef01234567": "Authorization: Bearer [REDACTED]",
		"key vk-0123456789abcdef0123456789abcdef0123456789abcdef":             "key vk-[REDACTED]",
		"nvapi-SUPERSECRETKEY1234567890abcdef":                                              "nvapi-[REDACTED]",
		"sk-proj-abcdefghijklmnop1234":                                                      "sk-[REDACTED]",
		"AIzaSyA-0123456789abcdefghijklmnopqrstu":                                           "AIza[REDACTED]",
		"normal text stays":                                                                 "normal text stays",
		"short sk-x stays":                                                                  "short sk-x stays",
	}
	for in, want := range cases {
		if got := String(in); got != want {
			t.Errorf("String(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegisteredSecrets(t *testing.T) {
	Reset()
	defer Reset()
	Register([]string{"live-secret-value-42"})

	if got := String("upstream echoed live-secret-value-42 back"); got != "upstream echoed [REDACTED] back" {
		t.Fatalf("registered secret not redacted: %q", got)
	}
	// Superstrings get their registered prefix redacted; different strings
	// with the same shape but different content survive.
	if got := String("x live-secret-value-42 y"); got != "x [REDACTED] y" {
		t.Fatalf("substring case failed: %q", got)
	}
	// A string that extends the registered value is partially redacted
	// (plain substring semantics).
	if got := String("live-secret-value-421"); got != "[REDACTED]1" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := String("plain"); got != "plain" {
		t.Fatalf("plain mutated: %q", got)
	}
	if got := String(fmt.Sprintf("a %s b", "live-secret-value-42")); got != "a [REDACTED] b" {
		t.Fatalf("fmt case failed: %q", got)
	}
	Reset()
	if got := String("live-secret-value-42"); got != "live-secret-value-42" {
		t.Fatalf("Reset did not drop secrets: %q", got)
	}
}