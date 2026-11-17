package noise

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestHandshakeRejectsInlinePSKToken(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	pattern := HandshakePattern{Name: "customPSK", Messages: [][]MessagePattern{{MessagePatternE, MessagePatternPSK}, {MessagePatternE, MessagePatternDHEE}}}
	for _, placement := range []int{-1, 0, 2} {
		var err error
		if placement == -1 {
			_, err = NewHandshakeState(Config{CipherSuite: cs, Pattern: pattern, Initiator: true})
		} else {
			_, err = NewHandshakeState(Config{CipherSuite: cs, Pattern: pattern, Initiator: true, UsePresharedKey: true, PresharedKeyPlacement: placement, PresharedKey: bytes.Repeat([]byte{1}, 32)})
		}
		if err == nil || !strings.Contains(err.Error(), "PSK token") {
			t.Fatalf("placement %d: expected inline PSK rejection, got %v", placement, err)
		}
	}
}

func TestHandshakePeerStaticMustBePreMessage(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	peer := bytes.Repeat([]byte{3}, cs.DHLen())
	staticKey, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		pattern   HandshakePattern
		initiator bool
		wantErr   bool
	}{
		{"NN initiator", HandshakeNN(), true, true},
		{"NN responder", HandshakeNN(), false, true},
		{"XX initiator", HandshakeXX(), true, true},
		{"XX responder", HandshakeXX(), false, true},
		{"NK initiator", HandshakeNK(), true, false},
		{"NK responder", HandshakeNK(), false, true},
		{"KN initiator", HandshakeKN(), true, true},
		{"KN responder", HandshakeKN(), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHandshakeState(Config{CipherSuite: cs, Pattern: tc.pattern, Initiator: tc.initiator, PeerStatic: peer, StaticKeypair: staticKey})
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "peer static key is not")) {
				t.Fatalf("expected unrelated peer static rejection, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected valid peer pre-message: %v", err)
			}
		})
	}
}

func TestHandshakePSKPlacementStillWorks(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	for _, placement := range []int{0, 1, 2} {
		testPatternExchange(t, cs, HandshakeNN(), placement)
	}
}

func TestHandshakeRejectsDuplicateLocalStaticToken(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	key, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []HandshakePattern{
		{Name: "duplicateS", Messages: [][]MessagePattern{{MessagePatternE, MessagePatternS, MessagePatternS}, {MessagePatternE, MessagePatternDHEE}}},
		{Name: "preMessageDuplicateS", InitiatorPreMessages: []MessagePattern{MessagePatternS}, Messages: [][]MessagePattern{{MessagePatternE, MessagePatternS}, {MessagePatternE, MessagePatternDHEE}}},
	} {
		_, err := NewHandshakeState(Config{CipherSuite: cs, Pattern: pattern, Initiator: true, StaticKeypair: key})
		if err == nil || !strings.Contains(err.Error(), "duplicate local static token") {
			t.Fatalf("%s: expected duplicate local static rejection, got %v", pattern.Name, err)
		}
	}
}
