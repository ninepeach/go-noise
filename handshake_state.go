package noise

import (
	"errors"
	"io"
)

// MaxMsgLen is the maximum number of bytes that can be sent in a single Noise
// message.
const MaxMsgLen = 65535

// A HandshakeState tracks the state of a Noise handshake. It may be discarded
// after the handshake is complete.
type HandshakeState struct {
	ss              symmetricState
	s               DHKey  // local static keypair
	e               DHKey  // local ephemeral keypair
	rs              []byte // remote party's static public key
	re              []byte // remote party's ephemeral public key
	psk             []byte // preshared key, maybe zero length
	willPsk         bool   // indicates if preshared key will be used (even if not yet set)
	messagePatterns [][]MessagePattern
	shouldWrite     bool
	initiator       bool
	msgIdx          int
	rng             io.Reader
	failed          bool // an error after processing begins permanently invalidates the handshake
}

// WriteMessage appends a handshake message to out. The message will include the
// optional payload if provided. If the handshake is completed by the call, two
// CipherStates will be returned, one is used for encryption of messages to the
// remote peer, the other is used for decryption of messages from the remote
// peer. It is an error to call this method out of sync with the handshake
// pattern.
func (s *HandshakeState) WriteMessage(out, payload []byte) (result []byte, send, receive *CipherState, err error) {
	if s.failed {
		return nil, nil, nil, ErrHandshakeFailed
	}
	if !s.shouldWrite {
		return nil, nil, nil, errors.New("noise: unexpected call to WriteMessage should be ReadMessage")
	}
	if s.msgIdx >= len(s.messagePatterns) {
		return nil, nil, nil, errors.New("noise: no handshake messages left")
	}
	if !s.messageFits(len(payload)) {
		return nil, nil, nil, ErrMessageTooLong
	}

	defer func() {
		if err != nil {
			s.fail()
		}
	}()
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE:
			e, err := s.ss.cs.GenerateKeypair(s.rng)
			if err != nil {
				return nil, nil, nil, err
			}
			s.e = e
			out = append(out, s.e.Public...)
			s.ss.MixHash(s.e.Public)
			if s.willPsk {
				s.ss.MixKey(s.e.Public)
			}
		case MessagePatternS:
			if len(s.s.Public) == 0 {
				return nil, nil, nil, errors.New("noise: invalid state, s.Public is nil")
			}
			out, err = s.ss.EncryptAndHash(out, s.s.Public)
			if err != nil {
				return nil, nil, nil, err
			}
		case MessagePatternDHEE, MessagePatternDHES, MessagePatternDHSE, MessagePatternDHSS:
			if err := s.mixDH(msg); err != nil {
				return nil, nil, nil, err
			}
		case MessagePatternPSK:
			if len(s.psk) != 32 {
				return nil, nil, nil, errors.New("noise: cannot send psk message without psk set")
			}
			s.ss.MixKeyAndHash(s.psk)
		default:
			return nil, nil, nil, errors.New("noise: invalid handshake token")
		}
	}
	out, err = s.ss.EncryptAndHash(out, payload)
	if err != nil {
		return nil, nil, nil, err
	}

	s.shouldWrite = false
	s.msgIdx++
	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		s.wipe()
		if s.initiator {
			return out, cs1, cs2, nil
		}
		return out, cs2, cs1, nil
	}

	return out, nil, nil, nil
}

// messageFits checks the complete wire length before any handshake state
// changes. The caller's existing output prefix is not part of the message.
func (s *HandshakeState) messageFits(payloadLen int) bool {
	size := payloadLen
	hasKey := s.ss.hasK
	dhLen := s.ss.cs.DHLen()
	for _, token := range s.messagePatterns[s.msgIdx] {
		switch token {
		case MessagePatternE:
			size += dhLen
			if s.willPsk {
				hasKey = true
			}
		case MessagePatternS:
			size += dhLen
			if hasKey {
				size += 16
			}
		case MessagePatternDHEE, MessagePatternDHES, MessagePatternDHSE, MessagePatternDHSS, MessagePatternPSK:
			hasKey = true
		}
		if size > MaxMsgLen {
			return false
		}
	}
	if hasKey {
		size += 16
	}
	return size <= MaxMsgLen
}

// mixDH executes a Noise DH token. The token selects local and remote
// keys; initiator role determines the orientation of es and se.
func (s *HandshakeState) mixDH(token MessagePattern) error {
	var private, public []byte
	switch token {
	case MessagePatternDHEE:
		private, public = s.e.Private, s.re
	case MessagePatternDHES:
		if s.initiator {
			private, public = s.e.Private, s.rs
		} else {
			private, public = s.s.Private, s.re
		}
	case MessagePatternDHSE:
		if s.initiator {
			private, public = s.s.Private, s.re
		} else {
			private, public = s.e.Private, s.rs
		}
	case MessagePatternDHSS:
		private, public = s.s.Private, s.rs
	default:
		return errors.New("noise: invalid DH token")
	}
	shared, err := s.ss.cs.DH(private, public)
	if err != nil {
		return err
	}
	defer clear(shared)
	s.ss.MixKey(shared)
	return nil
}

// ErrShortMessage is returned by ReadMessage if a message is not as long as it should be.
var (
	// ErrShortMessage indicates a truncated handshake message.
	ErrShortMessage = errors.New("noise: message is too short")
	// ErrMessageTooLong indicates a handshake message exceeding 65535 bytes.
	ErrMessageTooLong = errors.New("noise: message exceeds 65535 bytes")
	// ErrHandshakeFailed indicates a handshake that cannot be continued.
	ErrHandshakeFailed = errors.New("noise: handshake failed and cannot be reused")
)

func (s *HandshakeState) SetPresharedKey(psk []byte) error {
	if !s.willPsk {
		return errors.New("noise: handshake does not use a preshared key")
	}
	if s.failed || s.msgIdx >= len(s.messagePatterns) {
		return ErrHandshakeFailed
	}
	// A PSK already mixed into the transcript cannot be changed.
	// For psk2 and later, the caller may supply or replace the key before its token.
	if s.willPsk {
		for i := 0; i < s.msgIdx; i++ {
			for _, token := range s.messagePatterns[i] {
				if token == MessagePatternPSK {
					return ErrHandshakeFailed
				}
			}
		}
	}
	if len(psk) != 32 {
		return errors.New("noise: specification mandates 256-bit preshared keys")
	}
	if len(s.psk) != 0 {
		clear(s.psk)
	}
	s.psk = make([]byte, 32)
	copy(s.psk, psk)
	return nil
}

// ReadMessage processes a received handshake message and appends the payload,
// if any to out. If the handshake is completed by the call, two CipherStates
// will be returned, one is used for encryption of messages to the remote peer,
// the other is used for decryption of messages from the remote peer. It is an
// error to call this method out of sync with the handshake pattern.
func (s *HandshakeState) ReadMessage(out, message []byte) (result []byte, send, receive *CipherState, err error) {
	if s.failed {
		return nil, nil, nil, ErrHandshakeFailed
	}
	if len(message) > MaxMsgLen {
		s.fail()
		return nil, nil, nil, ErrMessageTooLong
	}
	if s.shouldWrite {
		return nil, nil, nil, errors.New("noise: unexpected call to ReadMessage should be WriteMessage")
	}
	if s.msgIdx >= len(s.messagePatterns) {
		return nil, nil, nil, errors.New("noise: no handshake messages left")
	}

	defer func() {
		if err != nil {
			s.fail()
		}
	}()

	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE, MessagePatternS:
			expected := s.ss.cs.DHLen()
			if msg == MessagePatternS && s.ss.hasK {
				expected += 16
			}
			if len(message) < expected {
				return nil, nil, nil, ErrShortMessage
			}
			switch msg {
			case MessagePatternE:
				if cap(s.re) < s.ss.cs.DHLen() {
					s.re = make([]byte, s.ss.cs.DHLen())
				}
				s.re = s.re[:s.ss.cs.DHLen()]
				copy(s.re, message)
				s.ss.MixHash(s.re)
				if s.willPsk {
					s.ss.MixKey(s.re)
				}
			case MessagePatternS:
				if len(s.rs) > 0 {
					return nil, nil, nil, errors.New("noise: invalid state, rs is not nil")
				}
				s.rs, err = s.ss.DecryptAndHash(s.rs[:0], message[:expected])
			}
			if err != nil {

				return nil, nil, nil, err
			}
			message = message[expected:]
		case MessagePatternDHEE, MessagePatternDHES, MessagePatternDHSE, MessagePatternDHSS:
			if err := s.mixDH(msg); err != nil {
				return nil, nil, nil, err
			}
		case MessagePatternPSK:
			if len(s.psk) != 32 {
				return nil, nil, nil, errors.New("noise: preshared key is not set")
			}
			s.ss.MixKeyAndHash(s.psk)
		default:
			return nil, nil, nil, errors.New("noise: invalid handshake token")
		}
	}
	out, err = s.ss.DecryptAndHash(out, message)
	if err != nil {

		return nil, nil, nil, err
	}
	s.shouldWrite = true
	s.msgIdx++

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.ss.Split()
		s.wipe()
		if s.initiator {
			return out, cs1, cs2, nil
		}
		return out, cs2, cs1, nil
	}

	return out, nil, nil, nil
}

// wipe erases the key material that is no longer needed once the transport
// CipherStates exist: the chaining key (from which the transport keys derive),
// the last handshake key, the preshared key and both private keys held by the
// handshake. The transcript hash and the peers' public keys stay, so that
// ChannelBinding, PeerStatic and PeerEphemeral keep working.
//
// This is best effort. Go cannot erase copies held inside the standard
// library's AEAD objects, and the garbage collector may have left earlier
// copies. The caller still owns, and must protect, the Config it passed in.
func (s *HandshakeState) wipe() {
	s.wipeAllButEphemeral()
	clear(s.e.Private)
	s.e.Private = nil
}

// wipeAllButEphemeral erases every secret except the local ephemeral private key.
func (s *HandshakeState) wipeAllButEphemeral() {
	clear(s.ss.ck)
	clear(s.ss.k[:])
	s.ss.c = nil
	s.ss.hasK = false
	s.ss.n = 0
	clear(s.psk)
	s.psk = nil
	clear(s.s.Private)
	s.s.Private = nil
}

// fail permanently invalidates the handshake after an error. It erases the
// chaining key, handshake key, preshared key and static private key at once.
// Only the local ephemeral private key survives, because an IK initiator whose
// attempt was rejected needs it for XXfallback (see LocalEphemeral); Destroy
// erases it too.
func (s *HandshakeState) fail() {
	s.failed = true
	s.wipeAllButEphemeral()
}

// Destroy erases the handshake's secret material and makes the HandshakeState
// unusable. A handshake that completes is wiped automatically, and a failed one
// keeps only its ephemeral private key, so Destroy is for handshakes that are
// abandoned or have failed. It also discards the
// transcript hash, so ChannelBinding returns nothing afterwards. Call
// LocalEphemeral first if a fallback handshake needs the ephemeral key.
func (s *HandshakeState) Destroy() {
	s.wipe()
	clear(s.ss.h)
	s.ss.h = nil
	s.failed = true
}

// ChannelBinding returns a copy of the current handshake hash.
// It is suitable for channel binding only after the handshake is complete.
func (s *HandshakeState) ChannelBinding() []byte {
	return append([]byte(nil), s.ss.h...)
}

// PeerStatic returns the static key provided by the remote peer during
// a handshake. It is an error to call this method if a handshake message
// containing a static key has not been read.
func (s *HandshakeState) PeerStatic() []byte {
	return append([]byte(nil), s.rs...)
}

// MessageIndex returns the current handshake message id
func (s *HandshakeState) MessageIndex() int {
	return s.msgIdx
}

// PeerEphemeral returns a copy of the remote ephemeral public key, if known.
func (s *HandshakeState) PeerEphemeral() []byte {
	return append([]byte(nil), s.re...)
}

// LocalEphemeral returns a copy of the local ephemeral key pair, including its
// private key. Its purpose is the Noise "fallback" flow: after a failed IK
// attempt, the initiator reuses this key as the pre-message ephemeral of an
// XXfallback handshake (Config.EphemeralKeypair), while the peer supplies
// PeerEphemeral() as Config.PeerEphemeral. Call it before the handshake
// completes or is destroyed: completion and Destroy erase the private key (a
// failed handshake keeps it for exactly this purpose), and
// LocalEphemeral then returns an empty DHKey (no private and no public key).
func (s *HandshakeState) LocalEphemeral() DHKey {
	if len(s.e.Private) == 0 {
		return DHKey{}
	}
	return DHKey{Private: append([]byte(nil), s.e.Private...), Public: append([]byte(nil), s.e.Public...)}
}
