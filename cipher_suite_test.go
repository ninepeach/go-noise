package noise

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func TestCipherSuitePrimitiveNamesAndHashes(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    HashFunc
		size int
	}{
		{"SHA256", HashSHA256, 32},
		{"SHA512", HashSHA512, 64},
		{"BLAKE2b", HashBLAKE2b, 64},
		{"BLAKE2s", HashBLAKE2s, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.h.HashName() != tc.name || tc.h.Hash().Size() != tc.size {
				t.Fatalf("hash name/size mismatch: %s / %d", tc.h.HashName(), tc.h.Hash().Size())
			}
		})
	}
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	if got := string(cs.Name()); got != "25519_ChaChaPoly_SHA256" {
		t.Fatalf("suite name = %q", got)
	}
	name := cs.Name()
	name[0] = 'X'
	if string(cs.Name()) != "25519_ChaChaPoly_SHA256" {
		t.Fatal("Name exposes mutable backing storage")
	}
}

func TestCipherSuiteX25519(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 32)
	a, err := DH25519.GenerateKeypair(bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DH25519.GenerateKeypair(bytes.NewReader(bytes.Repeat([]byte{0x13}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	wantA, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Public, wantA) || DH25519.DHLen() != 32 || DH25519.DHName() != "25519" {
		t.Fatal("unexpected X25519 keypair")
	}
	ab, err := DH25519.DH(a.Private, b.Public)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := DH25519.DH(b.Private, a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("DH shared secrets differ")
	}
	if _, err := DH25519.GenerateKeypair(bytes.NewReader(seed[:31])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short randomness: %v", err)
	}
	if _, err := DH25519.DH(a.Private, make([]byte, 32)); err == nil {
		t.Fatal("low-order peer public key accepted")
	}
	if _, err := DH25519.DH(a.Private[:31], b.Public); err == nil {
		t.Fatal("short private key accepted")
	}
	if _, err := DH25519.DH(a.Private, b.Public[:31]); err == nil {
		t.Fatal("short public key accepted")
	}
}

func TestCipherSuiteAEADReferenceAndAuthentication(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	const nonce = uint64(0x0102030405060708)
	ad := []byte("associated data")
	plaintext := []byte("noise cipher suite reference")
	for _, tc := range []struct {
		name      string
		fn        CipherFunc
		reference func([32]byte) (cipher.AEAD, error)
		order     binary.ByteOrder
	}{
		{"AESGCM", CipherAESGCM, func(k [32]byte) (cipher.AEAD, error) {
			block, err := aes.NewCipher(k[:])
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(block)
		}, binary.BigEndian},
		{"ChaChaPoly", CipherChaChaPoly, func(k [32]byte) (cipher.AEAD, error) {
			return chacha20poly1305.New(k[:])
		}, binary.LittleEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := tc.reference(key)
			if err != nil {
				t.Fatal(err)
			}
			var nonceBytes [12]byte
			tc.order.PutUint64(nonceBytes[4:], nonce)
			want := ref.Seal(nil, nonceBytes[:], plaintext, ad)
			got := tc.fn.Cipher(key).Encrypt(nil, nonce, ad, plaintext)
			if !bytes.Equal(got, want) {
				t.Fatal("ciphertext differs from independent AEAD reference")
			}
			prefix := []byte("prefix")
			appended := tc.fn.Cipher(key).Encrypt(append([]byte(nil), prefix...), nonce, ad, plaintext)
			if !bytes.Equal(appended[:len(prefix)], prefix) || !bytes.Equal(appended[len(prefix):], want) {
				t.Fatal("Encrypt did not append correctly")
			}
			decoded, err := tc.fn.Cipher(key).Decrypt(nil, nonce, ad, got)
			if err != nil || !bytes.Equal(decoded, plaintext) {
				t.Fatalf("decrypt: %v", err)
			}
			for _, bad := range []struct {
				name string
				n    uint64
				ad   []byte
				ct   []byte
			}{
				{"nonce", nonce + 1, ad, got},
				{"associated-data", nonce, []byte("wrong"), got},
				{"ciphertext", nonce, ad, func() []byte {
					cp := append([]byte(nil), got...)
					cp[0] ^= 1
					return cp
				}()},
				{"short-tag", nonce, ad, got[:15]},
			} {
				t.Run(bad.name, func(t *testing.T) {
					if _, err := tc.fn.Cipher(key).Decrypt(nil, bad.n, bad.ad, bad.ct); err == nil {
						t.Fatal("unauthenticated ciphertext accepted")
					}
				})
			}
			// Sanity-check the reference uses a standard 128-bit authentication tag.
			if len(want) != len(plaintext)+16 {
				t.Fatal("unexpected AEAD tag length")
			}
		})
	}
}

func TestCipherSuiteSHA256Reference(t *testing.T) {
	h := HashSHA256.Hash()
	h.Write([]byte("abc"))
	want := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatal("SHA256 mismatch")
	}
}
