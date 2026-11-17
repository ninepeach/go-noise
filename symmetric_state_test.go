package noise

import (
	"bytes"
	"testing"
)

func TestSymmetricStateReinitializeAliasedName(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	s := symmetricState{CipherState: CipherState{cs: cs}}
	s.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))
	name := append([]byte(nil), s.h...)
	s.MixKey([]byte("first key material"))
	s.InitializeSymmetric(s.h)
	if !bytes.Equal(s.h, name) || !bytes.Equal(s.ck, name) {
		t.Fatal("reinitialization changed aliased handshake name")
	}
	if s.hasK || s.n != 0 || s.c != nil {
		t.Fatal("reinitialization retained cipher state")
	}
}

func TestSymmetricStateMixHashAliasedInput(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	a := symmetricState{CipherState: CipherState{cs: cs}}
	b := symmetricState{CipherState: CipherState{cs: cs}}
	a.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))
	b.InitializeSymmetric([]byte("Noise_NN_25519_ChaChaPoly_SHA256"))
	original := append([]byte(nil), a.h...)
	a.MixHash(a.h)
	b.MixHash(original)
	if !bytes.Equal(a.h, b.h) {
		t.Fatal("aliased MixHash input changed transcript")
	}
}

func TestSymmetricStateInPlaceDecryptAndHash(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	var sender, receiver symmetricState
	sender.cs, receiver.cs = cs, cs
	name := []byte("Noise_NN_25519_ChaChaPoly_SHA256")
	sender.InitializeSymmetric(name)
	receiver.InitializeSymmetric(name)
	keyMaterial := []byte("same shared secret for test")
	sender.MixKey(keyMaterial)
	receiver.MixKey(keyMaterial)
	ciphertext, err := sender.EncryptAndHash(nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := receiver.DecryptAndHash(ciphertext[:0], ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "payload" {
		t.Fatal("wrong plaintext")
	}
	if !bytes.Equal(sender.h, receiver.h) {
		t.Fatal("in-place decrypt changed transcript hash")
	}
}

func TestSymmetricStateDecryptFailureDoesNotCommitHash(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	var sender, receiver symmetricState
	sender.cs, receiver.cs = cs, cs
	name := []byte("Noise_NN_25519_ChaChaPoly_SHA256")
	sender.InitializeSymmetric(name)
	receiver.InitializeSymmetric(name)
	sender.MixKey([]byte("shared key material"))
	receiver.MixKey([]byte("shared key material"))
	ciphertext, err := sender.EncryptAndHash(nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	before := append([]byte(nil), receiver.h...)
	nonce := receiver.n
	if _, err := receiver.DecryptAndHash(nil, ciphertext); err == nil {
		t.Fatal("expected authentication failure")
	}
	if !bytes.Equal(before, receiver.h) || receiver.n != nonce {
		t.Fatal("failed authentication modified state")
	}
}
