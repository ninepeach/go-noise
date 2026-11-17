package noise

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func testCipherStateSuite() CipherSuite {
	return NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
}

func TestCipherStateNonceRewindDisablesAutomaticEncryption(t *testing.T) {
	var key [32]byte
	state := UnsafeNewCipherState(testCipherStateSuite(), key, 5)
	state.SetNonce(4)
	if _, err := state.Encrypt(nil, nil, []byte("message")); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("nonce rewind must invalidate automatic encryption, got %v", err)
	}
	if _, err := state.Decrypt(nil, nil, make([]byte, 16)); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("nonce rewind must invalidate automatic decryption, got %v", err)
	}
}

func TestCipherStateNonceAdvance(t *testing.T) {
	var key [32]byte
	state := UnsafeNewCipherState(testCipherStateSuite(), key, 5)
	state.SetNonce(8)
	if state.Nonce() != 8 {
		t.Fatalf("nonce = %d, want 8", state.Nonce())
	}
	if _, err := state.Encrypt(nil, nil, []byte("message")); err != nil {
		t.Fatal(err)
	}
	if state.Nonce() != 9 {
		t.Fatalf("nonce = %d, want 9", state.Nonce())
	}
}

func TestCipherStateAuthenticationFailureDoesNotAdvanceNonce(t *testing.T) {
	var key [32]byte
	sender := UnsafeNewCipherState(testCipherStateSuite(), key, 0)
	receiver := UnsafeNewCipherState(testCipherStateSuite(), key, 0)
	ct, err := sender.Encrypt(nil, []byte("ad"), []byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	if _, err := receiver.Decrypt(nil, []byte("ad"), tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if receiver.Nonce() != 0 {
		t.Fatal("failed decryption advanced nonce")
	}
	pt, err := receiver.Decrypt(nil, []byte("ad"), ct)
	if err != nil || string(pt) != "message" {
		t.Fatalf("valid decrypt after failure: %v", err)
	}
	if receiver.Nonce() != 1 {
		t.Fatal("successful decryption did not advance nonce")
	}
}

func TestCipherStateMaxNonce(t *testing.T) {
	var key [32]byte
	s := UnsafeNewCipherState(testCipherStateSuite(), key, MaxNonce)
	if _, err := s.Encrypt(nil, nil, []byte("last")); err != nil {
		t.Fatal(err)
	}
	if s.Nonce() != math.MaxUint64 {
		t.Fatal("nonce not exhausted")
	}
	if _, err := s.Encrypt(nil, nil, nil); !errors.Is(err, ErrMaxNonce) {
		t.Fatalf("encrypt after exhaustion: %v", err)
	}
	if _, err := s.Decrypt(nil, nil, make([]byte, 16)); !errors.Is(err, ErrMaxNonce) {
		t.Fatalf("decrypt after exhaustion: %v", err)
	}
}

func TestCipherStateRekeyPreservesNonce(t *testing.T) {
	var key [32]byte
	s := UnsafeNewCipherState(testCipherStateSuite(), key, 7)
	oldKey := s.UnsafeKey()
	s.Rekey()
	newKey := s.UnsafeKey()
	if bytes.Equal(newKey[:], oldKey[:]) {
		t.Fatal("rekey did not change key")
	}
	if s.Nonce() != 7 {
		t.Fatal("rekey changed nonce")
	}
	peer := UnsafeNewCipherState(testCipherStateSuite(), key, 7)
	peer.Rekey()
	ct, err := s.Encrypt(nil, nil, []byte("after rekey"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := peer.Decrypt(nil, nil, ct)
	if err != nil || string(pt) != "after rekey" {
		t.Fatalf("post-rekey exchange: %v", err)
	}
}

func TestCipherStateManualCipherDisablesAutomaticAPI(t *testing.T) {
	var key [32]byte
	s := UnsafeNewCipherState(testCipherStateSuite(), key, 0)
	c := s.Cipher()
	ct := c.Encrypt(nil, 12, nil, []byte("manual"))
	pt, err := c.Decrypt(nil, 12, nil, ct)
	if err != nil || string(pt) != "manual" {
		t.Fatalf("manual cipher: %v", err)
	}
	if _, err := s.Encrypt(nil, nil, nil); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("automatic encryption after Cipher(): %v", err)
	}
	if _, err := s.Decrypt(nil, nil, ct); !errors.Is(err, ErrNonceManagementDisabled) {
		t.Fatalf("automatic decryption after Cipher(): %v", err)
	}
}

func TestCipherStateRestoreAtCurrentNonce(t *testing.T) {
	var key [32]byte
	s := UnsafeNewCipherState(testCipherStateSuite(), key, 0)
	if _, err := s.Encrypt(nil, nil, []byte("first")); err != nil {
		t.Fatal(err)
	}
	restored := UnsafeNewCipherState(testCipherStateSuite(), s.UnsafeKey(), s.Nonce())
	ct, err := s.Encrypt(nil, nil, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := restored.Decrypt(nil, nil, ct)
	if err != nil || string(pt) != "second" {
		t.Fatalf("restored state: %v", err)
	}
}
