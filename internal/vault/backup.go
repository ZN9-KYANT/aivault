package vault

// Combined age-encrypted vault archives (SPEC 3.1): a tar of config.toml,
// meta.json, proxykeys.json, audit.log and every vault/*.json.age, encrypted
// with the master passphrase via an age scrypt recipient (same recipient type
// as the vault files themselves).
import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// archiveMember is one file entry captured from the home directory.
type archiveMember struct {
	name string // relative to the home dir, forward slashes
	data []byte
	mode os.FileMode
}

// collectMembers gathers every file aivault owns under home (skip sockets,
// tmp files, and the archive output itself), deterministically sorted.
func collectMembers(home string) ([]archiveMember, error) {
	var members []archiveMember
	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(home, path)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // sockets, devices, ...
		}
		base := filepath.Base(rel)
		if strings.HasSuffix(base, ".tmp") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		info, _ := d.Info()
		member := archiveMember{
			name: filepath.ToSlash(rel),
			data: data,
			mode: 0o600,
		}
		if info != nil {
			member.mode = info.Mode().Perm()
		}
		members = append(members, member)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("backup: collect: %w", err)
	}
	return members, nil
}

// Backup writes one combined age-encrypted archive of the vault home to out
// (SPEC 3.1). The master passphrase both authorizes the backup (verify it
// first) and encrypts the archive.
func Backup(home, out string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("backup: empty passphrase")
	}
	members, err := collectMembers(home)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return fmt.Errorf("backup: %s is empty — nothing to back up", home)
	}

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, m := range members {
		hdr := &tar.Header{
			Name: m.name,
			Mode: int64(m.mode),
			Size: int64(len(m.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("backup: tar header: %w", err)
		}
		if _, err := tw.Write(m.data); err != nil {
			return fmt.Errorf("backup: tar write: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("backup: tar close: %w", err)
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	nBig, err := rand.Int(rand.Reader, big.NewInt(maxScryptWorkFactor-minScryptWorkFactor+1))
	if err != nil {
		return fmt.Errorf("backup: work factor: %w", err)
	}
	recipient.SetWorkFactor(minScryptWorkFactor + int(nBig.Int64()))

	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, recipient)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if _, err := w.Write(tarBuf.Bytes()); err != nil {
		return fmt.Errorf("backup: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("backup: seal: %w", err)
	}

	return writeFileAtomic(out, ct.Bytes(), 0o600)
}

// RestoreArchive decrypts an aivault archive into home. Existing files are
// only overwritten when force is true (CLI adds its own confirmation).
// Returns the list of restored relative paths.
func RestoreArchive(home, in string, passphrase []byte, force bool) ([]string, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("restore: empty passphrase")
	}
	f, err := os.Open(in)
	if err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	defer f.Close()

	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, fmt.Errorf("restore: decrypt (wrong passphrase or damaged archive): %w", err)
	}
	tr := tar.NewReader(r)

	var restored []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("restore: tar: %w", err)
		}
		name := filepath.FromSlash(hdr.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return nil, fmt.Errorf("restore: refusing unsafe path %q in archive", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		target := filepath.Join(home, name)
		if !force {
			if _, err := os.Stat(target); err == nil {
				return nil, fmt.Errorf("restore: %s already exists (use --force to overwrite)", name)
			}
		}
		if dir := filepath.Dir(target); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("restore: %w", err)
			}
		}
		mode := os.FileMode(hdr.Mode) & 0o777
		if mode == 0 {
			mode = 0o600
		}
		if err := writeFileAtomic(target, readAllTar(tr, hdr.Size), mode); err != nil {
			return nil, err
		}
		restored = append(restored, name)
	}
	if len(restored) == 0 {
		return nil, errors.New("restore: archive contains no files")
	}
	return restored, nil
}

// readAllTar reads exactly n bytes from the current tar entry.
func readAllTar(tr *tar.Reader, n int64) []byte {
	buf := make([]byte, n)
	_, _ = io.ReadFull(tr, buf)
	return buf
}