package noise

import (
	"bytes"
	"errors"
	"testing"
)

func TestSafetyAPIRejectsInvalidOperations(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	hs, err := NewHandshakeState(Config{CipherSuite: suite, Pattern: HandshakeNN(), Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.SetPresharedKey(bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("non-PSK handshake accepted PSK")
	}
	k, err := suite.GenerateKeypair(nil)
	if err != nil {
		t.Fatal(err)
	}
	k.Public[0] ^= 1
	if _, err := NewHandshakeState(Config{CipherSuite: suite, Pattern: HandshakeXX(), Initiator: true, StaticKeypair: k}); err == nil {
		t.Fatal("mismatched static keypair accepted")
	}
	cs := UnsafeNewCipherState(suite, [32]byte{1}, 5)
	if err := cs.SetNonce(4); !errors.Is(err, ErrNonceRollback) {
		t.Fatalf("rollback error: %v", err)
	}
	if _, err := cs.Encrypt(nil, nil, []byte("x")); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("invalid state encrypt: %v", err)
	}
	if err := cs.Rekey(); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("invalid state rekey: %v", err)
	}
	cs2 := UnsafeNewCipherState(suite, [32]byte{2}, 0)
	if err := cs2.SetNonce(MaxNonce + 1); !errors.Is(err, ErrMaxNonce) {
		t.Fatalf("nonce overflow: %v", err)
	}
	if cs2.Nonce() != 0 {
		t.Fatal("invalid nonce was committed")
	}
}

func TestUnsafeNewCipherStateRejectsInvalidInputs(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	for _, tc := range []struct {
		name  string
		suite CipherSuite
		nonce uint64
	}{
		{"nil suite", nil, 0},
		{"reserved nonce", suite, MaxNonce + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic on invalid unsafe state")
				}
			}()
			_ = UnsafeNewCipherState(tc.suite, [32]byte{}, tc.nonce)
		})
	}
}

func TestCustomPatternValidationBoundaries(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	cases := []HandshakePattern{
		{Name: "NN", Messages: [][]MessagePattern{{MessagePatternE}, {MessagePatternE}}},
		{Name: "duplicateDH", Messages: [][]MessagePattern{{MessagePatternE}, {MessagePatternE, MessagePatternDHEE, MessagePatternDHEE}}},
		{Name: "duplicatePre", InitiatorPreMessages: []MessagePattern{MessagePatternE, MessagePatternE}, Messages: [][]MessagePattern{{MessagePatternE}}},
		{Name: "emptyMessage", Messages: [][]MessagePattern{{MessagePatternE}, {}}},
	}
	for _, p := range cases {
		if _, err := NewHandshakeState(Config{CipherSuite: suite, Pattern: p, Initiator: true}); err == nil {
			t.Errorf("%s: invalid pattern accepted", p.Name)
		}
	}
}
