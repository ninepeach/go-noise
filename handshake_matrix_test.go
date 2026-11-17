package noise

import (
	"bytes"
	"fmt"
	"testing"
)

// These are deterministic cross-peer regression tests, not external reference
// vectors. Known-answer vectors in noise_test.go additionally check exact bytes.
func TestHandshakePatternMatrix(t *testing.T) {
	patterns := []HandshakePattern{
		HandshakeNN(), HandshakeKN(), HandshakeNK(), HandshakeKK(),
		HandshakeNX(), HandshakeKX(), HandshakeXN(), HandshakeIN(),
		HandshakeXK(), HandshakeIK(), HandshakeXX(), HandshakeIX(),
		HandshakeN(), HandshakeK(), HandshakeX(),
	}
	suites := []struct {
		name string
		cs   CipherSuite
	}{
		{"ChaChaPoly_SHA256", NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)},
		{"AESGCM_BLAKE2s", NewCipherSuite(DH25519, CipherAESGCM, HashBLAKE2s)},
	}
	for _, suite := range suites {
		for _, pattern := range patterns {
			placements := []int{-1}
			if len(pattern.Messages) > 1 {
				placements = append(placements, 0, len(pattern.Messages))
			} else {
				placements = append(placements, 0, 1)
			}
			for _, placement := range placements {
				name := fmt.Sprintf("%s/%s/psk%d", suite.name, pattern.Name, placement)
				t.Run(name, func(t *testing.T) {
					testPatternExchange(t, suite.cs, pattern, placement)
				})
			}
		}
	}
}

func testPatternExchange(t *testing.T, cs CipherSuite, pattern HandshakePattern, placement int) {
	t.Helper()
	rngI, rngR := new(RandomInc), new(RandomInc)
	*rngR = 97
	staticI, err := cs.GenerateKeypair(rngI)
	if err != nil {
		t.Fatal(err)
	}
	staticR, err := cs.GenerateKeypair(rngR)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralI, err := cs.GenerateKeypair(rngI)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralR, err := cs.GenerateKeypair(rngR)
	if err != nil {
		t.Fatal(err)
	}

	// A pre-message ephemeral key must be provided by the configuration.
	// Other patterns generate their ephemeral keys during the handshake.
	needsPreE := func(tokens []MessagePattern) bool {
		for _, token := range tokens {
			if token == MessagePatternE {
				return true
			}
		}
		return false
	}
	configI := Config{
		CipherSuite: cs, Pattern: pattern, Initiator: true,
		StaticKeypair: staticI,
		Prologue:      []byte("matrix"), Random: rngI,
	}
	configR := Config{
		CipherSuite: cs, Pattern: pattern, Initiator: false,
		StaticKeypair: staticR,
		Prologue:      []byte("matrix"), Random: rngR,
	}
	needsPreS := func(tokens []MessagePattern) bool {
		for _, token := range tokens {
			if token == MessagePatternS {
				return true
			}
		}
		return false
	}
	if needsPreS(pattern.InitiatorPreMessages) {
		configR.PeerStatic = staticI.Public
	}
	if needsPreS(pattern.ResponderPreMessages) {
		configI.PeerStatic = staticR.Public
	}
	if needsPreE(pattern.InitiatorPreMessages) {
		configI.EphemeralKeypair = ephemeralI
		configR.PeerEphemeral = ephemeralI.Public
	}
	if needsPreE(pattern.ResponderPreMessages) {
		configR.EphemeralKeypair = ephemeralR
		configI.PeerEphemeral = ephemeralR.Public
	}
	if placement >= 0 {
		psk := bytes.Repeat([]byte{0x5a}, 32)
		configI.UsePresharedKey, configR.UsePresharedKey = true, true
		configI.PresharedKeyPlacement, configR.PresharedKeyPlacement = placement, placement
		configI.PresharedKey = psk
		configR.PresharedKey = psk
	}
	initiator, err := NewHandshakeState(configI)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewHandshakeState(configR)
	if err != nil {
		t.Fatal(err)
	}

	var iSend, iReceive, rSend, rReceive *CipherState
	for index := range pattern.Messages {
		writer, reader := initiator, responder
		if index%2 != 0 {
			writer, reader = responder, initiator
		}
		payload := []byte(fmt.Sprintf("payload-%d", index))
		message, send, receive, err := writer.WriteMessage(nil, payload)
		if err != nil {
			t.Fatalf("write message %d: %v", index, err)
		}
		got, peerSend, peerReceive, err := reader.ReadMessage(nil, message)
		if err != nil {
			t.Fatalf("read message %d: %v", index, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("message %d payload mismatch", index)
		}
		if index == len(pattern.Messages)-1 {
			if send == nil || receive == nil || peerSend == nil || peerReceive == nil {
				t.Fatal("missing transport cipher states")
			}
			if index%2 == 0 {
				iSend, iReceive, rSend, rReceive = send, receive, peerSend, peerReceive
			} else {
				iSend, iReceive, rSend, rReceive = peerSend, peerReceive, send, receive
			}
		}
	}
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
		t.Fatal("handshake hash mismatch")
	}
	for _, pair := range []struct {
		sender, receiver *CipherState
	}{
		{iSend, rReceive}, {rSend, iReceive},
	} {
		encrypted, err := pair.sender.Encrypt(nil, nil, []byte("transport"))
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := pair.receiver.Decrypt(nil, nil, encrypted)
		if err != nil {
			t.Fatal(err)
		}
		if string(decrypted) != "transport" {
			t.Fatal("transport payload mismatch")
		}
	}
}
