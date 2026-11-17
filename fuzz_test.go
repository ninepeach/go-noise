package noise

import (
	"bytes"
	"testing"
)

// FuzzReadMessage feeds arbitrary bytes to a handshake reader at a fuzzed
// position of a fuzzed standard pattern. It must never panic, and a rejected
// message must lock the handshake.
func FuzzReadMessage(f *testing.F) {
	patterns := []HandshakePattern{
		HandshakeNN(), HandshakeKN(), HandshakeNK(), HandshakeKK(),
		HandshakeNX(), HandshakeKX(), HandshakeXN(), HandshakeIN(),
		HandshakeXK(), HandshakeIK(), HandshakeXX(), HandshakeXXfallback(),
		HandshakeIX(), HandshakeN(), HandshakeK(), HandshakeX(),
	}
	for i, p := range patterns {
		d := driveTo(f, p, false, 0)
		f.Add(uint8(i), uint8(0), false, d.honest)
	}
	f.Fuzz(func(t *testing.T, pi, k uint8, psk bool, msg []byte) {
		p := patterns[int(pi)%len(patterns)]
		d := driveTo(t, p, psk, int(k)%len(p.Messages))
		_, _, _, err := d.reader.ReadMessage(nil, msg)
		if err == nil {
			return
		}
		if _, _, _, again := d.reader.ReadMessage(nil, d.honest); again != ErrHandshakeFailed {
			t.Fatalf("handshake not locked after rejected message: %v", again)
		}
	})
}

// FuzzDecrypt checks that transport decryption never panics on arbitrary input
// and that a failed decryption does not advance the nonce.
func FuzzDecrypt(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0xaa}, 16), []byte("ad"))
	f.Fuzz(func(t *testing.T, ct, ad []byte) {
		var k [32]byte
		for _, suite := range []CipherSuite{
			NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256),
			NewCipherSuite(DH25519, CipherAESGCM, HashSHA256),
		} {
			cs := UnsafeNewCipherState(suite, k, 7)
			if _, err := cs.Decrypt(nil, ad, ct); err != nil && cs.Nonce() != 7 {
				t.Fatalf("failed decryption advanced the nonce to %d", cs.Nonce())
			}
		}
	})
}
