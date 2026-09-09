package server

// Admin-plane client over the unix socket (SPEC 4.3, 6.2). The CLI holds no
// state — unlock state lives entirely server-side (SPEC 4.2); the socket's
// peer-UID check is the authentication.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ZN9-KYANT/aivault/internal/audit"
)

// Client dials the aivault admin plane over its unix socket.
type Client struct {
	sock string
	hc   *http.Client
}

// NewClient returns an admin-plane client for the socket at sockPath. The
// timeout covers a full unlock: argon2id verification plus per-file age
// scrypt decryption (~1 s each, SPEC 3.2).
func NewClient(sockPath string) *Client {
	return &Client{
		sock: sockPath,
		hc: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sockPath)
				},
			},
		},
	}
}

// Status returns the server status (SPEC 6.2 GET /v1admin/status).
func (c *Client) Status() (*Status, error) { return c.do("GET", "/v1admin/status", nil) }

// Lock zeroizes the server keyring (SPEC 6.2 POST /v1admin/lock).
func (c *Client) Lock() (*Status, error) {
	return c.do("POST", "/v1admin/lock", struct{}{})
}

// Unlock sends the master passphrase over the socket; the server verifies it
// and decrypts every enabled provider into the keyring (SPEC 4.2, 6.2). The
// passphrase is serialized to a JSON string — a copy the GC reclaims; the
// CLI zeroizes its own buffer.
func (c *Client) Unlock(passphrase []byte) (*Status, error) {
	return c.do("POST", "/v1admin/unlock", map[string]string{"passphrase": string(passphrase)})
}

// AuditTail fetches the last n audit entries (SPEC 6.2 GET /v1admin/audit).
func (c *Client) AuditTail(n int) ([]audit.Entry, error) {
	resp, err := c.hc.Get("http://aivault/v1admin/audit?tail=" + strconv.Itoa(n))
	if err != nil {
		return nil, fmt.Errorf("admin audit: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("admin audit: read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp.StatusCode, data)
	}
	var out struct {
		Entries []audit.Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("admin audit: parse response: %w", err)
	}
	return out.Entries, nil
}

func (c *Client) do(method, path string, body any) (*Status, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("admin %s: encode: %w", path, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://aivault"+path, rd)
	if err != nil {
		return nil, fmt.Errorf("admin %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("admin %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("admin %s: read: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp.StatusCode, data)
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("admin %s: parse response: %w", path, err)
	}
	return &st, nil
}

// decodeError turns a non-200 admin response into an error carrying the
// server's {"error": …} message when present.
func decodeError(code int, data []byte) error {
	var eb struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &eb); err == nil && eb.Error != "" {
		return fmt.Errorf("admin: %s (HTTP %d)", eb.Error, code)
	}
	return fmt.Errorf("admin: unexpected HTTP %d", code)
}