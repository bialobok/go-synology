package api

import (
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// fakeDSM is the responder side of the handshake, as DSM runs it.
type fakeDSM struct {
	static noise.DHKey
	hs     *noise.HandshakeState
	recv   *noise.CipherState
	hh     []byte
}

func newFakeDSM(t *testing.T) *fakeDSM {
	t.Helper()
	kp, err := noiseSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: kp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeDSM{static: kp, hs: hs}
}

// login reads the client's ik_message and returns the reply ik_message.
func (d *fakeDSM) login(t *testing.T, ik string) (payload []byte, reply string) {
	t.Helper()
	msg, err := noiseUnB64(ik)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, _, err = d.hs.ReadMessage(nil, msg)
	if err != nil {
		t.Fatalf("server reading ik_message: %v", err)
	}
	out, recv, _, err := d.hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.recv = recv
	d.hh = d.hs.ChannelBinding()
	return payload, noiseB64(out)
}

// check verifies an X-SYNO-HASH the way the server would.
func (d *fakeDSM) check(t *testing.T, hash string, wantNonce uint64) {
	t.Helper()
	prefix := noiseB64(d.hh)[:8]
	if !strings.HasPrefix(hash, prefix) {
		t.Fatalf("hash %q doesn't start with handshake-hash prefix %q", hash, prefix)
	}
	rest := strings.TrimPrefix(hash, prefix)
	tagB64, nonceB64, ok := strings.Cut(rest, ".")
	if !ok {
		t.Fatalf("hash %q has no '.'", hash)
	}
	nb, err := noiseUnB64(nonceB64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := strconv.ParseUint(string(nb), 10, 64)
	if err != nil || nonce != wantNonce {
		t.Fatalf("nonce = %q, want %d", nb, wantNonce)
	}
	tag, err := noiseUnB64(tagB64)
	if err != nil {
		t.Fatal(err)
	}
	d.recv.SetNonce(nonce)
	if _, err := d.recv.Decrypt(nil, nil, tag); err != nil {
		t.Fatalf("server can't verify tag for nonce %d: %v", nonce, err)
	}
}

func TestNoiseHandshakeAndSigning(t *testing.T) {
	t.Parallel()
	dsm := newFakeDSM(t)
	now := time.Unix(1_763_300_000, 0)

	s, ik, err := newNoiseInitiator(dsm.static.Public, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Before the reply, nothing is signed.
	hash, done, err := s.beginSigned()
	done()
	if err != nil || hash != "" {
		t.Fatalf("before finish: hash=%q err=%v, want empty", hash, err)
	}

	payload, reply := dsm.login(t, ik)
	var body map[string]int64
	if err := json.Unmarshal(payload, &body); err != nil || body["time"] != now.Unix() {
		t.Fatalf("handshake payload = %s, want {\"time\":%d}", payload, now.Unix())
	}
	if err := s.finish(reply); err != nil {
		t.Fatal(err)
	}

	// Each request gets the next nonce, and the server can verify it.
	for want := uint64(0); want < 3; want++ {
		hash, done, err := s.beginSigned()
		if err != nil {
			t.Fatal(err)
		}
		done()
		dsm.check(t, hash, want)
	}
}

func TestNoiseRejectsBadInput(t *testing.T) {
	t.Parallel()
	if _, _, err := newNoiseInitiator(make([]byte, 31), time.Now(), rand.Reader); err == nil {
		t.Error("31-byte server key accepted")
	}
	dsm := newFakeDSM(t)
	s, _, err := newNoiseInitiator(dsm.static.Public, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.finish("not-a-noise-message"); err == nil {
		t.Error("garbage reply accepted")
	}
}

func TestNoiseB64RoundTrip(t *testing.T) {
	t.Parallel()
	for _, in := range [][]byte{{}, {0xfb}, {0xfb, 0xff}, []byte("hello, dsm")} {
		enc := noiseB64(in)
		if strings.ContainsAny(enc, "+/=") {
			t.Errorf("noiseB64(%x) = %q, want URL alphabet without padding", in, enc)
		}
		out, err := noiseUnB64(enc)
		if err != nil || string(out) != string(in) {
			t.Errorf("round trip %x -> %q -> %x (%v)", in, enc, out, err)
		}
		// DSM may send padded values too.
		if out, err := noiseUnB64(enc + strings.Repeat("=", (4-len(enc)%4)%4)); err != nil ||
			string(out) != string(in) {
			t.Errorf("padded round trip of %x failed: %v", in, err)
		}
	}
}
