package noise

import (
	"bytes"
	"testing"
)

func zeroed(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func completedPair(t *testing.T) (initiator, responder *HandshakeState, iSend, iRecv, rSend, rRecv *CipherState) {
	t.Helper()
	initiator, responder = failurePair(t, HandshakeXX(), true)
	cur, other := initiator, responder
	for i := 0; i < len(HandshakeXX().Messages); i++ {
		msg, a, b, err := cur.WriteMessage(nil, []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		_, c, d, err := other.ReadMessage(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		if i == len(HandshakeXX().Messages)-1 {
			// XX is written last by the initiator: a,b belong to the initiator, c,d to the responder.
			iSend, iRecv, rSend, rRecv = a, b, c, d
		}
		cur, other = other, cur
	}
	return
}

func TestCompletedHandshakeWipesSecrets(t *testing.T) {
	initiator, responder, iSend, iRecv, rSend, rRecv := completedPair(t)
	for name, h := range map[string]*HandshakeState{"initiator": initiator, "responder": responder} {
		if !zeroed(h.ss.ck) || !zeroed(h.ss.k[:]) || len(h.psk) != 0 {
			t.Errorf("%s: chaining key, handshake key or psk survived completion", name)
		}
		if !zeroed(h.s.Private) || !zeroed(h.e.Private) {
			t.Errorf("%s: private keys survived completion", name)
		}
		if h.ss.c != nil || h.ss.hasK {
			t.Errorf("%s: handshake cipher survived completion", name)
		}
		if zeroed(h.ss.h) || len(h.ChannelBinding()) == 0 {
			t.Errorf("%s: transcript hash must remain for ChannelBinding", name)
		}
		if le := h.LocalEphemeral(); len(le.Private) != 0 || len(le.Public) != 0 {
			t.Errorf("%s: LocalEphemeral must be empty after completion, got %d/%d bytes", name, len(le.Private), len(le.Public))
		}
		if len(h.s.Private) != 0 || len(h.e.Private) != 0 {
			t.Errorf("%s: wiped private keys must be released, not left as zero bytes", name)
		}
	}
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
		t.Fatal("channel binding differs after wiping")
	}
	if len(initiator.PeerStatic()) == 0 || len(responder.PeerStatic()) == 0 {
		t.Fatal("peer static keys must remain readable")
	}
	// the transport states are independent of the wiped handshake and must still work
	ct, err := iSend.Encrypt(nil, nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := rRecv.Decrypt(nil, nil, ct); err != nil || string(pt) != "hello" {
		t.Fatalf("transport broke after wiping: %v", err)
	}
	ct, _ = rSend.Encrypt(nil, nil, []byte("world"))
	if pt, err := iRecv.Decrypt(nil, nil, ct); err != nil || string(pt) != "world" {
		t.Fatalf("reverse transport broke after wiping: %v", err)
	}
	// a completed handshake cannot be driven further
	if _, _, _, err := initiator.WriteMessage(nil, nil); err == nil {
		t.Error("WriteMessage succeeded after completion")
	}
	if err := initiator.SetPresharedKey(bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Error("SetPresharedKey succeeded after completion")
	}
}

func TestDestroyAbandonedHandshake(t *testing.T) {
	initiator, _ := failurePair(t, HandshakeXX(), true)
	if _, _, _, err := initiator.WriteMessage(nil, nil); err != nil {
		t.Fatal(err)
	}
	if zeroed(initiator.LocalEphemeral().Private) {
		t.Fatal("test setup: the ephemeral key should exist before Destroy")
	}
	initiator.Destroy()
	if !zeroed(initiator.ss.ck) || !zeroed(initiator.ss.k[:]) || len(initiator.psk) != 0 ||
		!zeroed(initiator.s.Private) || !zeroed(initiator.e.Private) {
		t.Error("Destroy left secret material behind")
	}
	if len(initiator.ChannelBinding()) != 0 {
		t.Error("Destroy must discard the transcript hash")
	}
	if _, _, _, err := initiator.WriteMessage(nil, nil); err != ErrHandshakeFailed {
		t.Errorf("WriteMessage after Destroy = %v, want ErrHandshakeFailed", err)
	}
	if _, _, _, err := initiator.ReadMessage(nil, make([]byte, 64)); err != ErrHandshakeFailed {
		t.Errorf("ReadMessage after Destroy = %v, want ErrHandshakeFailed", err)
	}
	if le := initiator.LocalEphemeral(); len(le.Private) != 0 || len(le.Public) != 0 {
		t.Error("LocalEphemeral must be empty after Destroy")
	}
	initiator.Destroy() // idempotent
}

// A failed handshake keeps the ephemeral key, because the fallback flow needs it.
func TestFailedHandshakeKeepsEphemeralForFallback(t *testing.T) {
	initiator, _ := failurePair(t, HandshakeXX(), false)
	if _, _, _, err := initiator.WriteMessage(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := initiator.ReadMessage(nil, []byte("garbage")); err == nil {
		t.Fatal("expected an error")
	}
	if zeroed(initiator.LocalEphemeral().Private) {
		t.Error("a failed handshake must not erase the ephemeral key; call Destroy to erase it")
	}
	if !zeroed(initiator.ss.ck) || !zeroed(initiator.ss.k[:]) || initiator.ss.c != nil || initiator.ss.hasK {
		t.Error("a failed handshake kept its chaining key or handshake key")
	}
	if len(initiator.s.Private) != 0 || len(initiator.psk) != 0 {
		t.Error("a failed handshake kept its static private key or preshared key")
	}
	initiator.Destroy()
	if len(initiator.LocalEphemeral().Private) != 0 {
		t.Error("Destroy must erase the ephemeral key kept after a failure")
	}
}

// Every way a handshake can fail must erase all secrets but the ephemeral key.
func TestEveryFailureWipesAllButEphemeral(t *testing.T) {
	check := func(name string, h *HandshakeState) {
		t.Helper()
		if !h.failed {
			t.Fatalf("%s: handshake not marked failed", name)
		}
		if !zeroed(h.ss.ck) || !zeroed(h.ss.k[:]) || h.ss.c != nil || len(h.s.Private) != 0 || len(h.psk) != 0 {
			t.Errorf("%s: secrets survived the failure", name)
		}
	}
	// Authentication failure with a PSK and a static key in play (XX message 2, read by the initiator).
	d := driveTo(t, HandshakeXX(), true, 1)
	bad := append([]byte(nil), d.honest...)
	bad[len(bad)-1] ^= 1
	if _, _, _, err := d.reader.ReadMessage(nil, bad); err == nil {
		t.Fatal("tampered message accepted")
	}
	check("tampered", d.reader)

	// Truncated message.
	d = driveTo(t, HandshakeXX(), true, 1)
	if _, _, _, err := d.reader.ReadMessage(nil, d.honest[:10]); err == nil {
		t.Fatal("truncated message accepted")
	}
	check("truncated", d.reader)

	// Oversized message.
	d = driveTo(t, HandshakeXX(), true, 1)
	if _, _, _, err := d.reader.ReadMessage(nil, make([]byte, MaxMsgLen+1)); err != ErrMessageTooLong {
		t.Fatalf("oversized message: %v", err)
	}
	check("oversized", d.reader)

	// Failure while writing: the random source runs dry before the ephemeral key.
	h, _ := failurePair(t, HandshakeXX(), true)
	h.rng = bytes.NewReader(nil)
	if _, _, _, err := h.WriteMessage(nil, nil); err == nil {
		t.Fatal("WriteMessage succeeded without randomness")
	}
	check("write", h)
}
