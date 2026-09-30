package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestChainRoundtripAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	for i := 0; i < 3; i++ {
		if err := Log(path, Entry{Event: "key.use", Provider: "mock", Outcome: "200"}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 3 || res.ChainLen != 3 || res.Legacy != 0 {
		t.Fatalf("verify = %+v", res)
	}
	es, err := Tail(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if es[1].Prev != es[0].ID || es[2].Prev != es[1].ID {
		t.Fatalf("chain not linked: %+v", es)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	for _, e := range []Entry{
		{Event: "key.add", Provider: "one", Outcome: "ok"},
		{Event: "key.use", Provider: "two", Outcome: "200"},
		{Event: "lock", Outcome: "manual"},
	} {
		if err := Log(path, e); err != nil {
			t.Fatal(err)
		}
	}

	// Rewrite line 2's content while keeping its ORIGINAL prev/id linkage —
	// the pure content-hash check must catch the alteration.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var mid Entry
	if err := json.Unmarshal([]byte(lines[1]), &mid); err != nil {
		t.Fatal(err)
	}
	mid.Outcome = "403"
	forged, err := json.Marshal(mid)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = string(forged)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("verify must fail on tampered content: %+v", res)
	}
	if res.FirstBreak != 2 {
		t.Fatalf("expected first break at line 2, got %+v", res)
	}
}

func TestVerifyDetectsDeletedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	for i := 0; i < 3; i++ {
		if err := Log(path, Entry{Event: "key.use", Provider: "p", Outcome: "200"}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	// Delete the middle entry: its successor's prev must no longer match.
	if err := os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.FirstBreak != 2 {
		t.Fatalf("expected deletion detected at line 2: %+v", res)
	}
}

func TestLegacyEntriesThenChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	legacy := `{"timestamp":"2026-09-09T08:54:17Z","event":"key.add","provider":"nvidia","outcome":"ok"}` + "\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Log(path, Entry{Event: "key.use", Provider: "nvidia", Outcome: "200"}); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 2 || res.Legacy != 1 || res.ChainLen != 1 {
		t.Fatalf("verify = %+v", res)
	}
}

func TestChainSurvivesConcurrentLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Log(path, Entry{Event: "key.use", Provider: "p", Outcome: "200"}); err != nil {
				t.Errorf("Log: %v", err)
			}
		}()
	}
	wg.Wait()
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.ChainLen != 16 {
		t.Fatalf("verify = %+v", res)
	}
}

func TestVerifyMissingLog(t *testing.T) {
	res, err := Verify(filepath.Join(t.TempDir(), "missing.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 0 {
		t.Fatalf("verify missing = %+v", res)
	}
}
