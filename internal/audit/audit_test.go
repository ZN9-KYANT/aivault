package audit

import (
	"path/filepath"
	"testing"
)

func TestLogAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	if err := Log(path, Entry{Event: EventUnlock, Outcome: "ok"}); err != nil {
		t.Fatalf("Log 1: %v", err)
	}
	if err := Log(path, Entry{Event: EventKeyAdd, Provider: "openai", Outcome: "ok"}); err != nil {
		t.Fatalf("Log 2: %v", err)
	}

	got, err := Tail(path, 10)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Event != EventUnlock || got[1].Event != EventKeyAdd {
		t.Fatalf("entry order mismatch: %+v", got)
	}
	if got[1].Provider != "openai" {
		t.Errorf("provider = %q, want openai", got[1].Provider)
	}
	if got[0].Timestamp.IsZero() {
		t.Error("timestamp not set by Log")
	}

	tail, err := Tail(path, 1)
	if err != nil {
		t.Fatalf("Tail(1): %v", err)
	}
	if len(tail) != 1 || tail[0].Event != EventKeyAdd {
		t.Fatalf("Tail(1) = %+v", tail)
	}
}

func TestTailMissing(t *testing.T) {
	got, err := Tail(filepath.Join(t.TempDir(), "nope.log"), 10)
	if err != nil {
		t.Fatalf("Tail missing: %v", err)
	}
	if got != nil {
		t.Errorf("Tail missing = %+v, want nil", got)
	}
}
