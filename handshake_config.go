package noise

import (
	"crypto/rand"
	"crypto/subtle"

	"errors"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"io"
	"reflect"
	"strings"
)

// A Config provides the details necessary to process a Noise handshake. It is
// never modified by this package, and can be reused.
type Config struct {
	// CipherSuite is the set of cryptographic primitives that will be used.
	CipherSuite CipherSuite

	// Random is the source for cryptographically appropriate random bytes. If
	// zero, it is automatically configured.
	Random io.Reader

	// Pattern is the pattern for the handshake.
	Pattern HandshakePattern

	// Initiator must be true if the first message in the handshake will be sent
	// by this peer.
	Initiator bool

	// Prologue is an optional message that has already be communicated and must
	// be identical on both sides for the handshake to succeed.
	Prologue []byte

	// UsePresharedKey enables PSK mode: a psk token is added at
	// PresharedKeyPlacement and the protocol name gains the pskN modifier.
	// When it is false, PresharedKey must be empty and PresharedKeyPlacement 0.
	UsePresharedKey bool

	// PresharedKey is the 32-byte preshared key. psk0 and psk1 need it here;
	// for psk2 and later it may be left empty and supplied later with
	// HandshakeState.SetPresharedKey, before its token is processed.
	PresharedKey []byte

	// PresharedKeyPlacement is N in pskN: 0 places the psk token at the start of
	// the first message, N > 0 at the end of message N. It is only read when
	// UsePresharedKey is true.
	PresharedKeyPlacement int

	// StaticKeypair is this peer's static keypair, required if part of the
	// handshake.
	StaticKeypair DHKey

	// EphemeralKeypair is this peer's ephemeral keypair that was provided as
	// a pre-message in the handshake.
	EphemeralKeypair DHKey

	// PeerStatic is the static public key of the remote peer that was provided
	// as a pre-message in the handshake.
	PeerStatic []byte

	// PeerEphemeral is the ephemeral public key of the remote peer that was
	// provided as a pre-message in the handshake.
	PeerEphemeral []byte
}

// NewHandshakeState starts a new handshake using the provided configuration.
func NewHandshakeState(c Config) (*HandshakeState, error) {
	if c.CipherSuite == nil {
		return nil, errors.New("noise: cipher suite is required")
	}
	if c.Pattern.Name == "" || len(c.Pattern.Messages) == 0 {
		return nil, errors.New("noise: handshake pattern must contain messages")
	}
	if err := validatePresharedKeyConfig(c); err != nil {
		return nil, err
	}
	if err := validatePatternDefinition(c.Pattern); err != nil {
		return nil, err
	}
	if err := validateHandshakeKeysAndTokens(c); err != nil {
		return nil, err
	}
	if err := validateHandshakeDependencies(c); err != nil {
		return nil, err
	}
	hs := &HandshakeState{
		s:               cloneDHKey(c.StaticKeypair),
		e:               cloneDHKey(c.EphemeralKeypair),
		rs:              append([]byte(nil), c.PeerStatic...),
		messagePatterns: clonePatterns(c.Pattern.Messages),
		shouldWrite:     c.Initiator,
		initiator:       c.Initiator,
		rng:             c.Random,
	}
	if hs.rng == nil {
		hs.rng = rand.Reader
	}
	if len(c.PeerEphemeral) > 0 {
		hs.re = make([]byte, len(c.PeerEphemeral))
		copy(hs.re, c.PeerEphemeral)
	}
	hs.ss.cs = c.CipherSuite

	pskModifier, err := configureHandshakePSK(hs, c)
	if err != nil {
		return nil, err
	}

	hs.ss.InitializeSymmetric([]byte(protocolName(c.Pattern.Name, pskModifier, hs.ss.cs.Name())))
	hs.ss.MixHash(c.Prologue)
	initializeHandshakePreMessages(hs, c)
	return hs, nil
}

// standardPatterns lists the built-in definitions. A custom pattern that uses
// one of these names must match the definition exactly.
var standardPatterns = []HandshakePattern{
	handshakeNN, handshakeKN, handshakeNK, handshakeKK,
	handshakeNX, handshakeKX, handshakeXN, handshakeIN,
	handshakeXK, handshakeIK, handshakeXX, handshakeXXfallback,
	handshakeIX, handshakeN, handshakeK, handshakeX,
}

func clonePattern(p HandshakePattern) HandshakePattern {
	return HandshakePattern{
		Name:                 p.Name,
		InitiatorPreMessages: append([]MessagePattern(nil), p.InitiatorPreMessages...),
		ResponderPreMessages: append([]MessagePattern(nil), p.ResponderPreMessages...),
		Messages:             clonePatterns(p.Messages),
	}
}

// protocolName builds the Noise protocol name, for example
// "Noise_XXpsk2_25519_ChaChaPoly_SHA256". The Noise specification separates
// modifiers with a plus sign, so a pattern whose name already carries a
// modifier ("XXfallback") gets "+psk0" appended, not "psk0".
func protocolName(patternName, pskModifier string, suite []byte) string {
	if pskModifier != "" && patternHasModifier(patternName) {
		pskModifier = "+" + pskModifier
	}
	return "Noise_" + patternName + pskModifier + "_" + string(suite)
}

// patternHasModifier reports whether a pattern name already contains a Noise
// pattern modifier. "fallback" is the only modifier among the built-in patterns.
func patternHasModifier(name string) bool {
	return strings.Contains(name, "+") || strings.HasSuffix(name, "fallback")
}

// validatePatternDefinition rejects malformed custom patterns and prevents a
// custom token sequence from claiming a standard Noise handshake name.
// Standard definitions remain the canonical source of protocol names.
func validatePatternDefinition(p HandshakePattern) error {
	for _, known := range standardPatterns {
		if p.Name == known.Name && !reflect.DeepEqual(p, known) {
			return fmt.Errorf("noise: pattern %q does not match standard definition", p.Name)
		}
	}
	for _, pre := range [][]MessagePattern{p.InitiatorPreMessages, p.ResponderPreMessages} {
		seen := make(map[MessagePattern]bool)
		for _, token := range pre {
			if seen[token] {
				return errors.New("noise: duplicate pre-message token")
			}
			seen[token] = true
		}
	}
	for _, msg := range p.Messages {
		if len(msg) == 0 {
			return errors.New("noise: empty handshake message pattern")
		}
		seenDH := make(map[MessagePattern]bool)
		for _, token := range msg {
			switch token {
			case MessagePatternDHEE, MessagePatternDHES, MessagePatternDHSE, MessagePatternDHSS:
				if seenDH[token] {
					return errors.New("noise: duplicate DH token in handshake message")
				}
				seenDH[token] = true
			}
		}
	}
	return nil
}

func validateHandshakeKeysAndTokens(c Config) error {
	// Validate key material before hashing pre-messages or creating state.
	dhLen := c.CipherSuite.DHLen()
	if dhLen <= 0 {
		return errors.New("noise: invalid DH public key length")
	}
	if err := validateDHKey(c.StaticKeypair, dhLen); err != nil {
		return fmt.Errorf("noise: static keypair: %w", err)
	}
	if err := validateDHKey(c.EphemeralKeypair, dhLen); err != nil {
		return fmt.Errorf("noise: ephemeral keypair: %w", err)
	}
	// Verify supplied X25519 keypairs before they enter a handshake transcript.
	// Other DH implementations remain responsible for their own key validation.
	if c.CipherSuite.DHName() == "25519" && dhLen == 32 {
		for _, entry := range []struct {
			name string
			key  DHKey
		}{
			{"static", c.StaticKeypair}, {"ephemeral", c.EphemeralKeypair},
		} {
			if len(entry.key.Private) == 0 {
				continue
			}
			derived, err := curve25519.X25519(entry.key.Private, curve25519.Basepoint)
			if err != nil || subtle.ConstantTimeCompare(derived, entry.key.Public) != 1 {
				return fmt.Errorf("noise: %s public key does not match private key", entry.name)
			}
		}
	}
	if len(c.PeerStatic) != 0 && len(c.PeerStatic) != dhLen {
		return errors.New("noise: invalid peer static key length")
	}
	if len(c.PeerEphemeral) != 0 && len(c.PeerEphemeral) != dhLen {
		return errors.New("noise: invalid peer ephemeral key length")
	}
	for _, pre := range []struct {
		tokens []MessagePattern
		local  bool
	}{
		{c.Pattern.InitiatorPreMessages, c.Initiator},
		{c.Pattern.ResponderPreMessages, !c.Initiator},
	} {
		for _, token := range pre.tokens {
			var key []byte
			switch token {
			case MessagePatternS:
				if pre.local {
					key = c.StaticKeypair.Public
				} else {
					key = c.PeerStatic
				}
			case MessagePatternE:
				if pre.local {
					key = c.EphemeralKeypair.Public
				} else {
					key = c.PeerEphemeral
				}
			default:
				return errors.New("noise: invalid pre-message token")
			}
			if len(key) != dhLen {
				return errors.New("noise: required pre-message public key is missing")
			}
		}
	}
	// PSK tokens are injected exclusively by UsePresharedKey and PresharedKeyPlacement.
	// Accepting them directly would omit the required protocol-name modifier
	// and PSK-mode ephemeral key mixing.
	for _, message := range c.Pattern.Messages {
		for _, token := range message {
			if token == MessagePatternPSK {
				return errors.New("noise: PSK token must be configured via preshared key placement")
			}
			if token < MessagePatternS || token > MessagePatternPSK {
				return errors.New("noise: invalid handshake token")
			}
		}
	}
	return nil
}

func validateHandshakeDependencies(c Config) error {
	dhLen := c.CipherSuite.DHLen()
	// Validate the pattern's key dependencies in message order. A token
	// cannot use a remote ephemeral/static key before it is available.
	seenLocalE := false
	for _, token := range c.Pattern.InitiatorPreMessages {
		if c.Initiator && token == MessagePatternE {
			seenLocalE = true
		}
	}
	for _, token := range c.Pattern.ResponderPreMessages {
		if !c.Initiator && token == MessagePatternE {
			seenLocalE = true
		}
	}
	seenRemoteE := false
	for _, token := range c.Pattern.InitiatorPreMessages {
		if !c.Initiator && token == MessagePatternE {
			seenRemoteE = true
		}
	}
	for _, token := range c.Pattern.ResponderPreMessages {
		if c.Initiator && token == MessagePatternE {
			seenRemoteE = true
		}
	}
	remotePreStatic := false
	if c.Initiator {
		for _, token := range c.Pattern.ResponderPreMessages {
			if token == MessagePatternS {
				remotePreStatic = true
			}
		}
	} else {
		for _, token := range c.Pattern.InitiatorPreMessages {
			if token == MessagePatternS {
				remotePreStatic = true
			}
		}
	}
	if len(c.PeerStatic) != 0 && !remotePreStatic {
		return errors.New("noise: peer static key is not a remote pre-message")
	}
	seenRemoteS := remotePreStatic
	seenLocalS := len(c.StaticKeypair.Private) == dhLen
	localStaticSent := false
	for _, token := range c.Pattern.InitiatorPreMessages {
		if c.Initiator && token == MessagePatternS {
			localStaticSent = true
		}
	}
	for _, token := range c.Pattern.ResponderPreMessages {
		if !c.Initiator && token == MessagePatternS {
			localStaticSent = true
		}
	}
	for i, message := range c.Pattern.Messages {
		writing := (i%2 == 0) == c.Initiator
		for _, token := range message {
			switch token {
			case MessagePatternE:
				if writing {
					if seenLocalE {
						return errors.New("noise: duplicate local ephemeral token")
					}
					seenLocalE = true
				} else {
					if seenRemoteE {
						return errors.New("noise: duplicate remote ephemeral token")
					}
					seenRemoteE = true
				}
			case MessagePatternS:
				if writing {
					if !seenLocalS {
						return errors.New("noise: local static keypair required")
					}
					if localStaticSent {
						return errors.New("noise: duplicate local static token")
					}
					localStaticSent = true
				} else {
					if seenRemoteS {
						return errors.New("noise: duplicate remote static token")
					}
					seenRemoteS = true
				}
			case MessagePatternDHEE:
				if !seenLocalE || !seenRemoteE {
					return errors.New("noise: ee requires both ephemeral keys")
				}
			case MessagePatternDHES:
				if c.Initiator {
					if !seenLocalE || !seenRemoteS {
						return errors.New("noise: es requires local ephemeral and remote static")
					}
				} else if !seenLocalS || !seenRemoteE {
					return errors.New("noise: es requires local static and remote ephemeral")
				}
			case MessagePatternDHSE:
				if c.Initiator {
					if !seenLocalS || !seenRemoteE {
						return errors.New("noise: se requires local static and remote ephemeral")
					}
				} else if !seenLocalE || !seenRemoteS {
					return errors.New("noise: se requires local ephemeral and remote static")
				}
			case MessagePatternDHSS:
				if !seenLocalS || !seenRemoteS {
					return errors.New("noise: ss requires both static keys")
				}
			}
		}
	}
	return nil
}

func validatePresharedKeyConfig(c Config) error {
	if !c.UsePresharedKey {
		if len(c.PresharedKey) != 0 || c.PresharedKeyPlacement != 0 {
			return errors.New("noise: PresharedKey and PresharedKeyPlacement require UsePresharedKey")
		}
		return nil
	}
	if c.PresharedKeyPlacement < 0 || c.PresharedKeyPlacement > len(c.Pattern.Messages) {
		return errors.New("noise: invalid preshared key placement")
	}
	if len(c.PresharedKey) != 0 && len(c.PresharedKey) != 32 {
		return errors.New("noise: preshared key must be 32 bytes")
	}
	if c.PresharedKeyPlacement < 2 && len(c.PresharedKey) == 0 {
		return fmt.Errorf("noise: psk%d requires a 32-byte preshared key at initialization", c.PresharedKeyPlacement)
	}
	return nil
}

func configureHandshakePSK(hs *HandshakeState, c Config) (string, error) {
	pskModifier := ""
	// psk0 and psk1 have their key from the Config (validatePresharedKeyConfig
	// enforces it); for psk2 and later it may arrive later through SetPresharedKey.
	if c.UsePresharedKey {
		hs.willPsk = true
		if len(c.PresharedKey) > 0 {
			if err := hs.SetPresharedKey(c.PresharedKey); err != nil {
				return "", err
			}
		}

		pskModifier = fmt.Sprintf("psk%d", c.PresharedKeyPlacement)
		// The message patterns have already been deep-copied.
		if c.PresharedKeyPlacement == 0 {
			hs.messagePatterns[0] = append([]MessagePattern{MessagePatternPSK}, hs.messagePatterns[0]...)
		} else {
			hs.messagePatterns[c.PresharedKeyPlacement-1] = append(hs.messagePatterns[c.PresharedKeyPlacement-1], MessagePatternPSK)
		}
	}

	return pskModifier, nil
}

func initializeHandshakePreMessages(hs *HandshakeState, c Config) {
	for _, m := range c.Pattern.InitiatorPreMessages {
		switch {
		case c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.Public)
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case !c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.rs)
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
	for _, m := range c.Pattern.ResponderPreMessages {
		switch {
		case !c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.s.Public)
		case !c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.e.Public)
		case c.Initiator && m == MessagePatternS:
			hs.ss.MixHash(hs.rs)
		case c.Initiator && m == MessagePatternE:
			hs.ss.MixHash(hs.re)
		}
	}
}

func cloneDHKey(k DHKey) DHKey {
	return DHKey{Private: append([]byte(nil), k.Private...), Public: append([]byte(nil), k.Public...)}
}
func clonePatterns(in [][]MessagePattern) [][]MessagePattern {
	out := make([][]MessagePattern, len(in))
	for i := range in {
		out[i] = append([]MessagePattern(nil), in[i]...)
	}
	return out
}

func validateDHKey(key DHKey, size int) error {
	if len(key.Private) != 0 && len(key.Private) != size {
		return errors.New("invalid private key length")
	}
	if len(key.Public) != 0 && len(key.Public) != size {
		return errors.New("invalid public key length")
	}
	if (len(key.Private) == 0) != (len(key.Public) == 0) {
		return errors.New("private and public keys must be provided together")
	}
	return nil
}
