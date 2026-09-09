//go:build linux

package server

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// checkPeerCred rejects admin-socket connections whose peer UID differs from
// the server's effective UID (SPEC 4.3 peer-UID check).
func checkPeerCred(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("server: non-unix connection on admin socket")
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("server: peer credential: %w", err)
	}
	var ucred *unix.Ucred
	var sockErr error
	rc.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if sockErr != nil {
		return fmt.Errorf("server: peer credential: %w", sockErr)
	}
	if ucred == nil || ucred.Uid != uint32(os.Geteuid()) {
		return errors.New("server: admin socket peer is not the vault owner")
	}
	return nil
}