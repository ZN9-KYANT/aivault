package cli

import "testing"

func TestTrimSecret(t *testing.T) {
	cases := []struct{ in, want string }{
		{"key", "key"},
		{"key\r", "key"},
		{"key\r\n", "key"},
		{"key\n", "key"},
		{" key", "key"},
		{"\t key \r", "key"},
		{"", ""},
		{"\r\n \t", ""},
	}
	for _, c := range cases {
		got := trimSecret([]byte(c.in))
		if string(got) != c.want {
			t.Fatalf("trimSecret(%q) = %q, want %q", c.in, string(got), c.want)
		}
	}
}

// Trimming must happen in place: the returned slice shares the backing
// array so caller Zeroize calls still erase the original buffer (the
// leading-shift path uses copy() within the array, not a new allocation).
func TestTrimSecretInPlace(t *testing.T) {
	buf := make([]byte, 0, 64)
	buf = append(buf, "  secret\r\n"...)
	out := trimSecret(buf)
	if len(out) != 6 || string(out) != "secret" {
		t.Fatalf("trimSecret = %q, want \"secret\"", string(out))
	}
	if &buf[0] != &out[0] {
		t.Fatalf("trimSecret returned a different backing array")
	}
	out[0] = 'X'
	if buf[0] != 'X' {
		t.Fatalf("mutation did not land in the original buffer: %q", string(buf))
	}
}