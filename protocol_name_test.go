package noise

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// The Noise specification separates modifiers with a plus sign: adding psk0 to
// XXfallback gives "XXfallback+psk0", while adding it to a plain XX gives "XXpsk0".
func TestProtocolNameModifiers(t *testing.T) {
	suite := failureSuite.Name()
	cases := []struct{ pattern, psk, want string }{
		{"XX", "", "Noise_XX_25519_ChaChaPoly_SHA256"},
		{"XX", "psk0", "Noise_XXpsk0_25519_ChaChaPoly_SHA256"},
		{"IK", "psk2", "Noise_IKpsk2_25519_ChaChaPoly_SHA256"},
		{"XXfallback", "", "Noise_XXfallback_25519_ChaChaPoly_SHA256"},
		{"XXfallback", "psk0", "Noise_XXfallback+psk0_25519_ChaChaPoly_SHA256"},
		{"XXfallback", "psk2", "Noise_XXfallback+psk2_25519_ChaChaPoly_SHA256"},
		{"XXfallback+psk0", "psk2", "Noise_XXfallback+psk0+psk2_25519_ChaChaPoly_SHA256"},
		{"custom", "psk1", "Noise_custompsk1_25519_ChaChaPoly_SHA256"},
	}
	for _, c := range cases {
		if got := protocolName(c.pattern, c.psk, suite); got != c.want {
			t.Errorf("protocolName(%q, %q) = %q, want %q", c.pattern, c.psk, got, c.want)
		}
	}
}

// The name must actually reach the transcript. The expected hash is derived here
// from the specification's spelling, independently of the implementation.
func TestXXfallbackPSKTranscriptUsesSpecName(t *testing.T) {
	static, _ := DH25519.GenerateKeypair(failureRand("fallback-static"))
	remoteEphemeral, _ := DH25519.GenerateKeypair(failureRand("fallback-remote-ephemeral"))
	prologue := []byte("prologue")
	hs, err := NewHandshakeState(Config{
		CipherSuite: failureSuite, Pattern: HandshakeXXfallback(), Initiator: true,
		StaticKeypair: static, PeerEphemeral: remoteEphemeral.Public,
		UsePresharedKey: true, PresharedKey: bytes.Repeat([]byte{0x42}, 32), PresharedKeyPlacement: 0, Prologue: prologue,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("Noise_XXfallback+psk0_25519_ChaChaPoly_SHA256")) // longer than the hash length, so it is hashed
	h = sha256.Sum256(append(h[:], prologue...))
	h = sha256.Sum256(append(h[:], remoteEphemeral.Public...)) // responder pre-message: e
	if !bytes.Equal(hs.ss.h, h[:]) {
		t.Fatalf("transcript hash does not start from the specification's protocol name\ngot  %x\nwant %x", hs.ss.h, h)
	}
}

// The exported Handshake* variables can be modified by importing code. Validation
// compares against a private snapshot, so a modified pattern keeps its standard
// name only if it is still the standard definition.
func TestModifiedStandardPatternIsRejected(t *testing.T) {
	accept := func(p HandshakePattern) error {
		_, err := NewHandshakeState(Config{CipherSuite: failureSuite, Pattern: p, Initiator: true})
		return err
	}
	if err := accept(HandshakeNN()); err != nil {
		t.Fatalf("unmodified NN rejected: %v", err)
	}

	nn := HandshakeNN()
	nn.Messages[1] = []MessagePattern{MessagePatternE} // drop the ee token
	if err := accept(nn); err == nil {
		t.Error("NN without ee was accepted under its standard name")
	}

	xx := HandshakeXX()
	xx.Messages[0][0] = MessagePatternS // in-place edit of a nested slice
	if err := accept(xx); err == nil {
		t.Error("in-place modified XX was accepted under its standard name")
	}

	// Editing a returned copy must never reach the package's definitions.
	if HandshakeXX().Messages[0][0] != MessagePatternE || len(HandshakeNN().Messages[1]) != 2 {
		t.Fatal("modifying a returned pattern changed the standard definition")
	}
	if err := accept(HandshakeNN()); err != nil {
		t.Fatalf("fresh NN rejected: %v", err)
	}
}
