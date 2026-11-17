package noise

import (
	"errors"
	"testing"
)

func TestHandshakeMessageLengthPreflight(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	initiator, err := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      new(RandomInc),
		Pattern:     HandshakeNN(),
		Initiator:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// NN's first message has a 32-byte ephemeral public key and no tag.
	if _, _, _, err := initiator.WriteMessage(nil, make([]byte, MaxMsgLen-31)); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("expected message-too-long error, got %v", err)
	}
	if initiator.MessageIndex() != 0 || initiator.failed {
		t.Fatal("preflight error changed handshake state")
	}
	first, _, _, err := initiator.WriteMessage(nil, make([]byte, MaxMsgLen-32))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != MaxMsgLen {
		t.Fatalf("first message length = %d", len(first))
	}

	responder, err := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      new(RandomInc),
		Pattern:     HandshakeNN(),
		Initiator:   false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := responder.ReadMessage(nil, first); err != nil {
		t.Fatal(err)
	}

	// NN's second message contains the ephemeral key and a 16-byte tag.
	if _, _, _, err := responder.WriteMessage(nil, make([]byte, MaxMsgLen-47)); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("expected second-message length error, got %v", err)
	}
	if responder.MessageIndex() != 1 || responder.failed {
		t.Fatal("second-message preflight changed handshake state")
	}
	second, _, _, err := responder.WriteMessage(nil, make([]byte, MaxMsgLen-48))
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != MaxMsgLen {
		t.Fatalf("second message length = %d", len(second))
	}
}
