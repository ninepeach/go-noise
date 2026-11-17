package noise

import (
	"errors"
	"math"
)

// A CipherState provides symmetric encryption and decryption after a successful
// handshake.
// A CipherState must not be copied after first use: copying it can reuse a
// key/nonce pair and compromise AEAD confidentiality and authenticity.
// It is not safe for concurrent use without external synchronization.
type CipherState struct {
	noCopy noCopy

	cs CipherSuite
	c  Cipher
	k  [32]byte
	n  uint64

	invalid bool
}

// MaxNonce is the maximum value of n that is allowed. ErrMaxNonce is returned
// by Encrypt and Decrypt after this has been reached. 2^64-1 is reserved for rekeys.
const MaxNonce = uint64(math.MaxUint64) - 1

var ErrMaxNonce = errors.New("noise: cipherstate has reached maximum n, a new handshake must be performed")

// ErrNonceManagementDisabled is returned by Encrypt, Decrypt, SetNonce and Rekey
// once automatic nonce management has been switched off, either by Cipher() or
// by an attempted nonce rollback.
var ErrNonceManagementDisabled = errors.New("noise: automatic nonce management is disabled")

// ErrNonceRollback indicates an attempted nonce rewind; the state is invalidated.
var ErrNonceRollback = errors.New("noise: nonce rollback attempted")

// UnsafeNewCipherState reconstructs a CipherState from exported components.
// It is important that, when resuming from an exported state, care is taken
// to synchronize the nonce state and not allow rollbacks.
// It panics on a nil cipher suite or a nonce beyond MaxNonce. A caller must
// independently guarantee that the supplied key/nonce has never been reused.
func UnsafeNewCipherState(cs CipherSuite, k [32]byte, n uint64) *CipherState {
	if cs == nil {
		panic("noise: UnsafeNewCipherState requires a cipher suite")
	}
	if n > MaxNonce {
		panic("noise: UnsafeNewCipherState nonce exceeds MaxNonce")
	}
	return &CipherState{
		cs: cs,
		c:  cs.Cipher(k),
		k:  k,
		n:  n,
	}
}

// Encrypt encrypts the plaintext and then appends the ciphertext and an
// authentication tag across the ciphertext and optional authenticated data to
// out. This method automatically increments the nonce after every call, so
// messages must be decrypted in the same order. ErrMaxNonce is returned after
// the maximum nonce of 2^64-2 is reached.
func (s *CipherState) Encrypt(out, ad, plaintext []byte) ([]byte, error) {
	if s.invalid {
		return nil, ErrNonceManagementDisabled
	}
	if s.n > MaxNonce {
		return nil, ErrMaxNonce
	}
	out = s.c.Encrypt(out, s.n, ad, plaintext)
	s.n++
	return out, nil
}

// Decrypt checks the authenticity of the ciphertext and authenticated data and
// then decrypts and appends the plaintext to out. This method automatically
// increments the nonce after every call, messages must be provided in the same
// order that they were encrypted with no missing messages. ErrMaxNonce is
// returned after the maximum nonce of 2^64-2 is reached.
func (s *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	if s.invalid {
		return nil, ErrNonceManagementDisabled
	}
	if s.n > MaxNonce {
		return nil, ErrMaxNonce
	}
	out, err := s.c.Decrypt(out, s.n, ad, ciphertext)
	if err != nil {
		return nil, err
	}
	s.n++
	return out, nil
}

// Cipher returns the low-level symmetric encryption primitive. It should only
// be used if nonces need to be managed manually, for example with a network
// protocol that can deliver out-of-order messages. This is dangerous, users
// must ensure that they are incrementing a nonce after every encrypt operation.
// After calling this method, it is an error to call Encrypt/Decrypt on the
// CipherState.
//
// The returned Cipher tracks nothing. The caller alone guarantees that no
// (key, nonce) pair is ever used for Encrypt twice; one repeat breaks
// confidentiality and authenticity for every message under that key.
func (s *CipherState) Cipher() Cipher {
	s.invalid = true
	return s.c
}

// Nonce returns the current value of n. This can be used to determine if a
// new handshake should be performed due to approaching MaxNonce.
func (s *CipherState) Nonce() uint64 {
	return s.n
}

// SetNonce advances the current nonce. A backward move permanently disables
// automatic Encrypt and Decrypt and returns an error.
//
// Moving forward can never repeat a nonce, so it cannot weaken the cipher. Its
// purpose is a receiver that must skip nonces the sender consumed, for example
// after packet loss. Setting a value other than the sender's next nonce makes the
// following Decrypt fail authentication: that costs availability, not secrecy.
// A sender has no reason to call it unless it deliberately skips nonces.
//
// NEVER reuse a nonce with the same key. For externally managed nonces, use Cipher().
func (s *CipherState) SetNonce(n uint64) error {
	if s.invalid {
		return ErrNonceManagementDisabled
	}
	if n > MaxNonce {
		return ErrMaxNonce
	}
	// Do not permit rewinding the nonce through the automatic encryption API.
	// Callers managing out-of-order packets should use Cipher() instead.
	if n < s.n {
		s.invalid = true
		return ErrNonceRollback
	}
	s.n = n
	return nil
}

// UnsafeKey returns the current value of k. This exports the current key for the
// CipherState. Intended to be used alongside UnsafeNewCipherState to resume a
// CipherState at a later point. The caller must store the key as carefully as the
// session itself: a copy outside the CipherState is not erased by this package.
func (s *CipherState) UnsafeKey() [32]byte {
	return s.k
}

// Rekey derives a new encryption key using the Noise reserved nonce.
// It preserves the current transport nonce. Both peers must rekey in sync.
func (s *CipherState) Rekey() error {
	if s.invalid {
		return ErrNonceManagementDisabled
	}
	if s.c == nil || s.cs == nil {
		return errors.New("noise: uninitialized cipher state")
	}
	var zeros [32]byte
	var out []byte
	out = s.c.Encrypt(out, math.MaxUint64, nil, zeros[:])
	copy(s.k[:], out[:32])
	clear(out)
	s.c = s.cs.Cipher(s.k)
	return nil
}
