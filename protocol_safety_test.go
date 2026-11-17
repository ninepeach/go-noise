package noise

import (
	"bytes"
	"errors"
	"testing"
)

func TestCipherSuiteNameIsImmutable(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	original := append([]byte(nil), suite.Name()...)
	name := suite.Name()
	name[0] ^= 0xff
	if !bytes.Equal(suite.Name(), original) {
		t.Fatal("cipher suite name was modified through returned slice")
	}
}

func TestNoiseNNRejectsTamperedCiphertext(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	initiator, err := NewHandshakeState(Config{CipherSuite: suite, Pattern: HandshakeNN(), Initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewHandshakeState(Config{CipherSuite: suite, Pattern: HandshakeNN()})
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := initiator.WriteMessage(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = responder.ReadMessage(nil, first); err != nil {
		t.Fatal(err)
	}
	second, _, _, err := responder.WriteMessage(nil, []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	second[len(second)-1] ^= 1
	if _, _, _, err = initiator.ReadMessage(nil, second); err == nil {
		t.Fatal("tampered authenticated handshake message was accepted")
	}
	if _, _, _, err = initiator.ReadMessage(nil, second); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("expected terminal handshake failure, got %v", err)
	}
}
