//go:build windows

package vault

// CheckPerms is a Windows no-op: Go cannot see NTFS ACLs through Stat, so
// POSIX-style mode checks are meaningless here. The aivault installer flow
// relies on the profile-directory ACLs (current user only), which already
// restrict ~/.aivault to the owning user by default. See peercred_other.go
// for the same platform pattern on the admin socket.
func CheckPerms(home string) error { return nil }
