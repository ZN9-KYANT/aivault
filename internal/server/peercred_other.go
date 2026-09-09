//go:build !linux

package server

import "net"

// checkPeerCred is only enforced on Linux (SO_PEERCRED). Elsewhere (Windows,
// macOS) the 0700 home directory and 0600 socket file carry the protection;
// aivault v1.0 is single-user and local-first (SPEC 4.3).
func checkPeerCred(net.Conn) error { return nil }