package noise

import "testing"

func TestInvalidHandshakeConfig(t *testing.T) {
	suite := NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2s)
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil suite", Config{Pattern: HandshakeNN()}},
		{"empty pattern", Config{CipherSuite: suite}},
		{"negative psk position", Config{CipherSuite: suite, Pattern: HandshakeNN(), UsePresharedKey: true, PresharedKeyPlacement: -1, PresharedKey: make([]byte, 32)}},
		{"psk position beyond messages", Config{CipherSuite: suite, Pattern: HandshakeNN(), UsePresharedKey: true, PresharedKeyPlacement: 3, PresharedKey: make([]byte, 32)}},
		{"missing psk0 key", Config{CipherSuite: suite, Pattern: HandshakeNN(), UsePresharedKey: true}},
		{"missing psk1 key", Config{CipherSuite: suite, Pattern: HandshakeNN(), UsePresharedKey: true, PresharedKeyPlacement: 1}},
		{"psk key without UsePresharedKey", Config{CipherSuite: suite, Pattern: HandshakeNN(), PresharedKey: make([]byte, 32)}},
		{"psk placement without UsePresharedKey", Config{CipherSuite: suite, Pattern: HandshakeNN(), PresharedKeyPlacement: 2}},
		{"missing XX initiator static", Config{CipherSuite: suite, Pattern: HandshakeXX(), Initiator: true}},
		{"missing IK responder static", Config{CipherSuite: suite, Pattern: HandshakeIK(), Initiator: false, PeerStatic: make([]byte, 32)}},
		{"invalid psk length", Config{CipherSuite: suite, Pattern: HandshakeNN(), UsePresharedKey: true, PresharedKey: []byte{1}}},
		{"missing responder static", Config{CipherSuite: suite, Pattern: HandshakeNK(), Initiator: true}},
		{"missing local static", Config{CipherSuite: suite, Pattern: HandshakeNK(), Initiator: false}},
		{"invalid peer static length", Config{CipherSuite: suite, Pattern: HandshakeNN(), PeerStatic: []byte{1}}},
		{"partial local keypair", Config{CipherSuite: suite, Pattern: HandshakeNN(), StaticKeypair: DHKey{Public: make([]byte, 32)}}},
		{"invalid premessage token", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "bad", InitiatorPreMessages: []MessagePattern{MessagePatternDHEE}, Messages: [][]MessagePattern{{MessagePatternE}}}}},
		{"ee before ephemeral exchange", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "badEE", Messages: [][]MessagePattern{{MessagePatternDHEE}}}, Initiator: true}},
		{"es before peer static", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "badES", Messages: [][]MessagePattern{{MessagePatternE, MessagePatternDHES}}}, Initiator: true}},
		{"duplicate ephemeral", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "duplicateE", Messages: [][]MessagePattern{{MessagePatternE, MessagePatternE}}}, Initiator: true}},
		{"static read before remote ephemeral", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "badSE", Messages: [][]MessagePattern{{MessagePatternDHSE}}}, Initiator: true}},
		{"invalid handshake token", Config{CipherSuite: suite, Pattern: HandshakePattern{Name: "bad", Messages: [][]MessagePattern{{MessagePattern(99)}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHandshakeState(tc.cfg); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
