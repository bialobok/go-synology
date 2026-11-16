package api

// DSM's web UI login does a Noise IK handshake and then signs each request
// with an X-SYNO-HASH header. Some calls (SYNO.Core.User create, set and
// delete, at least) return error 105 "no permission" for an admin session
// that lacks the signature, while most others work without it.
//
// The handshake:
//  1. POST SYNO.API.Auth.UIConfig get. The response sets a _SSID cookie:
//     the server's static X25519 public key, base64url without padding.
//  2. As initiator of Noise_IK_25519_ChaChaPoly_BLAKE2b (empty prologue),
//     write the first message with payload {"time": <unix seconds>} and send
//     it as ik_message with the login.
//  3. Read the login response's ik_message to finish the handshake.
//
// Each request then carries
//
//	X-SYNO-HASH: <first 8 chars of b64(handshake hash)><b64(tag)>.<b64(nonce)>
//
// where tag is the initiator's send cipher encrypting an empty plaintext with
// empty associated data, nonce is the cipher's nonce before that encryption,
// and b64 is base64url without padding. This follows N4S4/synology-api's
// implementation, which works against DSM 7.3.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/hashicorp/go-retryablehttp"
)

const (
	noiseCookie  = "_SSID"
	uiConfigPath = "/webapi/entry.cgi/SYNO.API.Auth.UIConfig"
)

var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)

// noiseSession signs requests once the handshake is done. Requests are
// signed and sent one at a time (see beginSigned), so DSM sees the nonces in
// order.
type noiseSession struct {
	hs *noise.HandshakeState

	mu     sync.Mutex
	send   *noise.CipherState
	prefix string
}

func noiseB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func noiseUnB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// newNoiseInitiator starts the handshake against the server's static key and
// returns the encoded first message.
func newNoiseInitiator(serverStatic []byte, now time.Time, rng io.Reader) (*noiseSession, string, error) {
	if len(serverStatic) != 32 {
		return nil, "", fmt.Errorf("noise: server key is %d bytes, want 32", len(serverStatic))
	}
	kp, err := noiseSuite.GenerateKeypair(rng)
	if err != nil {
		return nil, "", err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite,
		Random:        rng,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: kp,
		PeerStatic:    serverStatic,
	})
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(map[string]int64{"time": now.Unix()})
	if err != nil {
		return nil, "", err
	}
	msg, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, "", err
	}
	return &noiseSession{hs: hs}, noiseB64(msg), nil
}

// finish reads the server's reply from the login response.
func (s *noiseSession) finish(reply string) error {
	msg, err := noiseUnB64(reply)
	if err != nil {
		return fmt.Errorf("noise: decoding reply: %w", err)
	}
	_, send, _, err := s.hs.ReadMessage(nil, msg)
	if err != nil {
		return fmt.Errorf("noise: reading reply: %w", err)
	}
	if send == nil {
		return errors.New("noise: handshake not complete after reply")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.send = send
	s.prefix = noiseB64(s.hs.ChannelBinding())
	if len(s.prefix) > 8 {
		s.prefix = s.prefix[:8]
	}
	return nil
}

// beginSigned returns the X-SYNO-HASH value for the next request, and holds
// the session until done is called, so signed requests go out one at a time.
func (s *noiseSession) beginSigned() (hash string, done func(), err error) {
	s.mu.Lock()
	if s.send == nil {
		s.mu.Unlock()
		return "", func() {}, nil
	}
	nonce := s.send.Nonce()
	tag, err := s.send.Encrypt(nil, nil, nil)
	if err != nil {
		s.mu.Unlock()
		return "", func() {}, err
	}
	hash = s.prefix + noiseB64(tag) + "." + noiseB64([]byte(strconv.FormatUint(nonce, 10)))
	return hash, s.mu.Unlock, nil
}

// requestSigner is implemented by clients that sign requests (Client after a
// Noise login). It's optional so other Api implementations keep working.
type requestSigner interface {
	beginSigned() (hash string, done func(), err error)
}

func (c *Client) beginSigned() (string, func(), error) {
	if c.noise == nil {
		return "", func() {}, nil
	}
	return c.noise.beginSigned()
}

// startNoise fetches the server's key and starts the handshake. It returns
// "" (and no error) when DSM doesn't offer the handshake, so older DSM
// versions keep logging in as before.
func (c *Client) startNoise(ctx context.Context) (string, error) {
	u := new(url.URL)
	*u = *c.BaseURL
	u.Path = uiConfigPath
	u.RawQuery = ""

	form := url.Values{"api": {"SYNO.API.Auth.UIConfig"}, "method": {"get"}, "version": {"1"}}
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, u.String(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	var ssid string
	for _, ck := range resp.Cookies() {
		if ck.Name == noiseCookie {
			ssid = ck.Value
		}
	}
	if ssid == "" {
		return "", nil
	}
	key, err := noiseUnB64(ssid)
	if err != nil {
		return "", fmt.Errorf("noise: decoding %s: %w", noiseCookie, err)
	}
	s, msg, err := newNoiseInitiator(key, time.Now(), rand.Reader)
	if err != nil {
		return "", err
	}
	c.noise = s
	return msg, nil
}
