package cli

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ZN9-KYANT/aivault/internal/kdf"
)

// stdinLine is a shared reader so multiple piped (non-terminal) prompts see
// every line of stdin.
var stdinLine *bufio.Reader

// readSecret prompts and reads a secret without echo on a terminal, falling
// back to a plain stdin line with a warning when stdin is not a terminal
// (e.g. pipes and MSYS shells).
func readSecret(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read secret: %w", err)
		}
		return pw, nil
	}
	if stdinLine == nil {
		stdinLine = bufio.NewReader(os.Stdin)
	}
	fmt.Fprintln(os.Stderr, "(stdin is not a terminal; reading a plain line)")
	line, err := stdinLine.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	return []byte(strings.TrimRight(line, " \t\r\n")), nil
}

// promptNewPassphrase double-prompts and validates the master passphrase
// (SPEC 4.1: min 12 chars, zxcvhn strength >= 3).
func promptNewPassphrase() ([]byte, error) {
	pw, err := readSecret("New master passphrase: ")
	if err != nil {
		return nil, err
	}
	if err := kdf.ValidatePassphrase(string(pw)); err != nil {
		kdf.Zeroize(pw)
		return nil, err
	}
	pw2, err := readSecret("Confirm master passphrase: ")
	if err != nil {
		kdf.Zeroize(pw)
		return nil, err
	}
	defer kdf.Zeroize(pw2)
	if subtle.ConstantTimeCompare(pw, pw2) != 1 {
		kdf.Zeroize(pw)
		return nil, fmt.Errorf("passphrases do not match")
	}
	return pw, nil
}
