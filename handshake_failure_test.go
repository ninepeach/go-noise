package noise

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

var failureSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)

// failureRand returns 64 deterministic bytes. GenerateKeypair reads the first 32,
// so failureRand(x) and a Config.Random built from it agree on the key.
func failureRand(label string) *bytes.Reader {
	a := sha256.Sum256([]byte(label + "/1"))
	b := sha256.Sum256([]byte(label + "/2"))
	return bytes.NewReader(append(a[:], b[:]...))
}

func failureHas(list []MessagePattern, token MessagePattern) bool {
	for _, t := range list {
		if t == token {
			return true
		}
	}
	return false
}

// failurePair builds a deterministic initiator and responder for any standard pattern.
func failurePair(t testing.TB, p HandshakePattern, psk bool) (*HandshakeState, *HandshakeState) {
	t.Helper()
	is, _ := DH25519.GenerateKeypair(failureRand("init-static"))
	rs, _ := DH25519.GenerateKeypair(failureRand("resp-static"))
	ie, _ := DH25519.GenerateKeypair(failureRand("init-eph"))
	re, _ := DH25519.GenerateKeypair(failureRand("resp-eph"))
	ic := Config{CipherSuite: failureSuite, Pattern: p, Initiator: true, StaticKeypair: is, Random: failureRand("init-eph"), Prologue: []byte("failure-test")}
	rc := Config{CipherSuite: failureSuite, Pattern: p, Initiator: false, StaticKeypair: rs, Random: failureRand("resp-eph"), Prologue: []byte("failure-test")}
	if failureHas(p.ResponderPreMessages, MessagePatternS) {
		ic.PeerStatic = rs.Public
	}
	if failureHas(p.InitiatorPreMessages, MessagePatternS) {
		rc.PeerStatic = is.Public
	}
	if failureHas(p.ResponderPreMessages, MessagePatternE) {
		rc.EphemeralKeypair, ic.PeerEphemeral = re, re.Public
	}
	if failureHas(p.InitiatorPreMessages, MessagePatternE) {
		ic.EphemeralKeypair, rc.PeerEphemeral = ie, ie.Public
	}
	if psk {
		key := sha256.Sum256([]byte("failure-test-psk"))
		ic.PresharedKey, rc.PresharedKey = key[:], key[:]
		ic.UsePresharedKey, rc.UsePresharedKey = true, true
	}
	ih, err := NewHandshakeState(ic)
	if err != nil {
		t.Fatalf("%s initiator: %v", p.Name, err)
	}
	rh, err := NewHandshakeState(rc)
	if err != nil {
		t.Fatalf("%s responder: %v", p.Name, err)
	}
	return ih, rh
}

// driven is a handshake that has been run honestly up to message k.
type driven struct {
	writer, reader *HandshakeState
	honest         []byte
	wSend, wRecv   *CipherState // non-nil when message k completed the writer's handshake
}

func driveTo(t testing.TB, p HandshakePattern, psk bool, k int) driven {
	t.Helper()
	ih, rh := failurePair(t, p, psk)
	cur, other := ih, rh
	for i := 0; ; i++ {
		out, a, b, err := cur.WriteMessage(nil, []byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			t.Fatalf("%s message %d: %v", p.Name, i, err)
		}
		if i == k {
			return driven{cur, other, out, a, b}
		}
		if _, _, _, err := other.ReadMessage(nil, out); err != nil {
			t.Fatalf("%s message %d read: %v", p.Name, i, err)
		}
		cur, other = other, cur
	}
}

func cloneCipherState(c *CipherState) *CipherState {
	if c == nil {
		return nil
	}
	return UnsafeNewCipherState(c.cs, c.UnsafeKey(), c.Nonce())
}

// cloneHandshake returns an independent copy of a handshake in progress, so that one honest run can be
// reused for many tampered deliveries. TestCloneHandshakeIsFaithful guards it against drifting from the
// real struct.
func cloneHandshake(h *HandshakeState) *HandshakeState {
	c := &HandshakeState{
		s: cloneDHKey(h.s), e: cloneDHKey(h.e),
		rs: append([]byte(nil), h.rs...), re: append([]byte(nil), h.re...), psk: append([]byte(nil), h.psk...),
		willPsk: h.willPsk, messagePatterns: h.messagePatterns, shouldWrite: h.shouldWrite,
		initiator: h.initiator, msgIdx: h.msgIdx, failed: h.failed,
	}
	if r, ok := h.rng.(*bytes.Reader); ok {
		cp := *r
		c.rng = &cp
	} else {
		c.rng = h.rng
	}
	c.ss.cs, c.ss.hasK, c.ss.k, c.ss.n, c.ss.invalid = h.ss.cs, h.ss.hasK, h.ss.k, h.ss.n, h.ss.invalid
	c.ss.ck = append([]byte(nil), h.ss.ck...)
	c.ss.h = append([]byte(nil), h.ss.h...)
	if h.ss.hasK {
		c.ss.c = c.ss.cs.Cipher(c.ss.k)
	}
	return c
}

func (d driven) clone() driven {
	return driven{cloneHandshake(d.writer), cloneHandshake(d.reader), d.honest, cloneCipherState(d.wSend), cloneCipherState(d.wRecv)}
}

func transportMatches(wSend, wRecv, rSend, rRecv *CipherState, twoWay bool) bool {
	if wSend == nil || rRecv == nil {
		return false
	}
	ct, err := wSend.Encrypt(nil, nil, []byte("probe"))
	if err != nil {
		return false
	}
	if pt, err := rRecv.Decrypt(nil, nil, ct); err != nil || string(pt) != "probe" {
		return false
	}
	if !twoWay {
		return true
	}
	if rSend == nil || wRecv == nil {
		return false
	}
	ct, err = rSend.Encrypt(nil, nil, []byte("probe"))
	if err != nil {
		return false
	}
	pt, err := wRecv.Decrypt(nil, nil, ct)
	return err == nil && string(pt) == "probe"
}

// deliver gives `delivered` to a fresh copy of the reader of message k in place of the honest bytes, lets
// the handshake continue honestly, and reports whether the reader accepted it and whether both peers
// ended with matching transport keys.
func deliver(base driven, p HandshakePattern, k int, delivered []byte) (accepted, agreed bool) {
	d := base.clone()
	twoWay := len(p.Messages) > 1
	_, rs, rr, err := d.reader.ReadMessage(nil, delivered)
	if err != nil {
		return false, false
	}
	if k == len(p.Messages)-1 {
		return true, transportMatches(d.wSend, d.wRecv, rs, rr, twoWay)
	}
	cur, other := d.reader, d.writer
	for i := k + 1; i < len(p.Messages); i++ {
		out, ws, wr, err := cur.WriteMessage(nil, []byte("continue"))
		if err != nil {
			return true, false
		}
		_, rs2, rr2, err := other.ReadMessage(nil, out)
		if err != nil {
			return true, false
		}
		if i == len(p.Messages)-1 {
			return true, transportMatches(ws, wr, rs2, rr2, twoWay)
		}
		cur, other = other, cur
	}
	return true, false
}

// eachFailureCase runs fn once per (pattern, preshared key or not, message) with a ready honest run.
func eachFailureCase(t *testing.T, fn func(t *testing.T, name string, p HandshakePattern, base driven, k int)) {
	t.Helper()
	for _, p := range standardPatterns {
		for _, psk := range []bool{false, true} {
			for k := range p.Messages {
				fn(t, fmt.Sprintf("%s psk=%v message=%d", p.Name, psk, k), p, driveTo(t, p, psk, k), k)
			}
		}
	}
}

// The clone must behave exactly like the original it was copied from.
func TestCloneHandshakeIsFaithful(t *testing.T) {
	for _, p := range standardPatterns {
		for _, psk := range []bool{false, true} {
			for k := range p.Messages {
				a, b := driveTo(t, p, psk, k), driveTo(t, p, psk, k)
				c := b.clone()
				if !bytes.Equal(a.honest, c.honest) {
					t.Fatalf("%s psk=%v message %d: honest bytes differ", p.Name, psk, k)
				}
				// reader copy and untouched original must produce the same result for the same input
				_, s1, r1, e1 := a.reader.ReadMessage(nil, a.honest)
				_, s2, r2, e2 := c.reader.ReadMessage(nil, a.honest)
				if (e1 == nil) != (e2 == nil) || (s1 == nil) != (s2 == nil) || !bytes.Equal(a.reader.ChannelBinding(), c.reader.ChannelBinding()) {
					t.Fatalf("%s psk=%v message %d: clone diverged from the original", p.Name, psk, k)
				}
				if s1 != nil && r1 != nil && s2 != nil && r2 != nil {
					x, _ := s1.Encrypt(nil, nil, []byte("same"))
					y, _ := s2.Encrypt(nil, nil, []byte("same"))
					if !bytes.Equal(x, y) {
						t.Fatalf("%s psk=%v message %d: clone derived different transport keys", p.Name, psk, k)
					}
				}
				// a writer copy must produce the same next message as the original writer
				if k+1 < len(p.Messages) {
					n1, _, _, _ := a.reader.WriteMessage(nil, []byte("next"))
					n2, _, _, _ := c.reader.WriteMessage(nil, []byte("next"))
					if !bytes.Equal(n1, n2) {
						t.Fatalf("%s psk=%v message %d: the next message differs after cloning", p.Name, psk, k)
					}
				}
			}
		}
	}
}

// Control: with the honest bytes the same bookkeeping must report agreement, otherwise the
// "never agrees" assertions below would be vacuous.
func TestHandshakeAgreementControl(t *testing.T) {
	eachFailureCase(t, func(t *testing.T, name string, p HandshakePattern, base driven, k int) {
		if accepted, agreed := deliver(base, p, k, base.honest); !accepted || !agreed {
			t.Errorf("%s: honest delivery accepted=%v agreed=%v", name, accepted, agreed)
		}
	})
}

// A truncated handshake message must never panic, must lock the handshake when it is
// rejected, and must never lead to a session in which both peers hold matching keys.
func TestHandshakeTruncatedMessages(t *testing.T) {
	eachFailureCase(t, func(t *testing.T, name string, p HandshakePattern, base driven, k int) {
		for n := 0; n < len(base.honest); n++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s: panic on a %d byte prefix: %v", name, n, r)
					}
				}()
				d := base.clone()
				if _, _, _, err := d.reader.ReadMessage(nil, base.honest[:n]); err != nil {
					if _, _, _, err2 := d.reader.ReadMessage(nil, base.honest); !errors.Is(err2, ErrHandshakeFailed) {
						t.Errorf("%s: after rejecting a %d byte prefix, the honest message gave %v, want ErrHandshakeFailed", name, n, err2)
					}
					return
				}
				// Accepted: only possible when the cut-off bytes were an unauthenticated payload.
				if _, agreed := deliver(base, p, k, base.honest[:n]); agreed {
					t.Errorf("%s: a %d byte prefix led to matching transport keys", name, n)
				}
			}()
		}
	})
}

// Flipping any byte of any handshake message must never yield matching transport keys.
func TestHandshakeTamperedMessages(t *testing.T) {
	eachFailureCase(t, func(t *testing.T, name string, p HandshakePattern, base driven, k int) {
		for pos := range base.honest {
			bad := append([]byte(nil), base.honest...)
			bad[pos] ^= 0xff
			if _, agreed := deliver(base, p, k, bad); agreed {
				t.Errorf("%s: flipping byte %d still produced matching transport keys", name, pos)
			}
		}
	})
}

func TestHandshakeShortMessageLocksHandshake(t *testing.T) {
	_, rh := failurePair(t, HandshakeNN(), false)
	if _, _, _, err := rh.ReadMessage(nil, make([]byte, 31)); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("31 bytes for a 32 byte ephemeral key = %v, want ErrShortMessage", err)
	}
	if _, _, _, err := rh.ReadMessage(nil, make([]byte, 32)); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("after a short message = %v, want ErrHandshakeFailed", err)
	}
}

func TestHandshakeOrderingAndReplay(t *testing.T) {
	ih, rh := failurePair(t, HandshakeXX(), false)

	// Wrong-direction calls are refused without consuming or poisoning the state.
	if _, _, _, err := ih.ReadMessage(nil, make([]byte, 48)); err == nil {
		t.Error("initiator read before writing was accepted")
	}
	if _, _, _, err := rh.WriteMessage(nil, nil); err == nil {
		t.Error("responder write before reading was accepted")
	}
	m0, _, _, err := ih.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("initiator was poisoned by a refused call: %v", err)
	}
	if _, _, _, err := ih.WriteMessage(nil, nil); err == nil {
		t.Error("writing twice in a row was accepted")
	}

	// Replay: the same message cannot be consumed twice.
	if _, _, _, err := rh.ReadMessage(nil, m0); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rh.ReadMessage(nil, m0); err == nil {
		t.Error("a replayed message was accepted")
	}
	m1, _, _, err := rh.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("responder was poisoned by a refused replay: %v", err)
	}
	if _, _, _, err := ih.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}

	// Out of order content: message 0 delivered where message 2 belongs fails and locks.
	m2, _, _, err := ih.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rh.ReadMessage(nil, m0); err == nil {
		t.Error("message 0 accepted in place of message 2")
	}
	if _, _, _, err := rh.ReadMessage(nil, m2); !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("honest message after an out-of-order one = %v, want ErrHandshakeFailed", err)
	}
}

func TestHandshakeCannotContinueAfterCompletion(t *testing.T) {
	ih, rh := failurePair(t, HandshakeNN(), false)
	m0, _, _, _ := ih.WriteMessage(nil, nil)
	rh.ReadMessage(nil, m0)
	m1, _, _, _ := rh.WriteMessage(nil, nil)
	if _, _, _, err := ih.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*HandshakeState{"initiator": ih, "responder": rh} {
		if _, _, _, err := h.WriteMessage(nil, nil); err == nil {
			t.Errorf("%s: WriteMessage succeeded after completion", name)
		}
		if _, _, _, err := h.ReadMessage(nil, m1); err == nil {
			t.Errorf("%s: ReadMessage succeeded after completion", name)
		}
	}
}

// X25519 rejects low-order points. Reading such an ephemeral key succeeds, because no DH
// has happened yet, and the failure surfaces at the first DH token and locks the handshake.
func TestHandshakeRejectsLowOrderEphemeral(t *testing.T) {
	one := make([]byte, 32)
	one[0] = 1
	for name, point := range map[string][]byte{"zero point": make([]byte, 32), "point 1": one} {
		_, rh := failurePair(t, HandshakeNN(), false)
		if _, _, _, err := rh.ReadMessage(nil, point); err != nil {
			t.Fatalf("%s: reading the ephemeral key alone failed: %v", name, err)
		}
		if _, _, _, err := rh.WriteMessage(nil, nil); err == nil {
			t.Errorf("%s: a DH with a low-order point was accepted", name)
		}
		if _, _, _, err := rh.WriteMessage(nil, nil); !errors.Is(err, ErrHandshakeFailed) {
			t.Errorf("%s: after the failed DH = %v, want ErrHandshakeFailed", name, err)
		}
	}
}

// The documented use of LocalEphemeral and PeerEphemeral: an IK attempt fails because the
// initiator holds a stale responder key, and both peers continue with XXfallback.
func TestIKFallbackToXXfallback(t *testing.T) {
	aliceStatic, _ := DH25519.GenerateKeypair(failureRand("alice-static"))
	bobStatic, _ := DH25519.GenerateKeypair(failureRand("bob-static"))
	staleBob, _ := DH25519.GenerateKeypair(failureRand("bob-old-static"))
	prologue := []byte("fallback-test")

	alice, err := NewHandshakeState(Config{CipherSuite: failureSuite, Pattern: HandshakeIK(), Initiator: true,
		StaticKeypair: aliceStatic, PeerStatic: staleBob.Public, Prologue: prologue, Random: failureRand("alice-eph")})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewHandshakeState(Config{CipherSuite: failureSuite, Pattern: HandshakeIK(), Initiator: false,
		StaticKeypair: bobStatic, Prologue: prologue, Random: failureRand("bob-eph")})
	if err != nil {
		t.Fatal(err)
	}
	m0, _, _, err := alice.WriteMessage(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := bob.ReadMessage(nil, m0); err == nil {
		t.Fatal("IK with a stale responder key must fail")
	}

	aliceEphemeral := alice.LocalEphemeral()
	bobSawEphemeral := bob.PeerEphemeral()
	if !bytes.Equal(bobSawEphemeral, aliceEphemeral.Public) {
		t.Fatal("the responder must still know the initiator's ephemeral key after the failure")
	}
	alice.Destroy()
	bob.Destroy()

	fbBob, err := NewHandshakeState(Config{CipherSuite: failureSuite, Pattern: HandshakeXXfallback(), Initiator: true,
		StaticKeypair: bobStatic, PeerEphemeral: bobSawEphemeral, Prologue: prologue, Random: failureRand("bob-fallback-eph")})
	if err != nil {
		t.Fatal(err)
	}
	fbAlice, err := NewHandshakeState(Config{CipherSuite: failureSuite, Pattern: HandshakeXXfallback(), Initiator: false,
		StaticKeypair: aliceStatic, EphemeralKeypair: aliceEphemeral, Prologue: prologue})
	if err != nil {
		t.Fatal(err)
	}
	f1, _, _, err := fbBob.WriteMessage(nil, []byte("fallback-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fbAlice.ReadMessage(nil, f1); err != nil {
		t.Fatal(err)
	}
	f2, aSend, aRecv, err := fbAlice.WriteMessage(nil, []byte("fallback-2"))
	if err != nil {
		t.Fatal(err)
	}
	_, bSend, bRecv, err := fbBob.ReadMessage(nil, f2)
	if err != nil {
		t.Fatal(err)
	}
	if !transportMatches(bSend, bRecv, aSend, aRecv, true) {
		t.Fatal("the fallback session does not carry traffic in both directions")
	}
	if !bytes.Equal(fbAlice.PeerStatic(), bobStatic.Public) || !bytes.Equal(fbBob.PeerStatic(), aliceStatic.Public) {
		t.Fatal("the fallback handshake did not authenticate both static keys")
	}
	if !bytes.Equal(fbAlice.ChannelBinding(), fbBob.ChannelBinding()) {
		t.Fatal("channel binding differs")
	}
}
