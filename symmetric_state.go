package noise

type symmetricState struct {
	CipherState
	hasK bool
	ck   []byte
	h    []byte
}

func (s *symmetricState) InitializeSymmetric(handshakeName []byte) {
	// Preserve the cipher suite while discarding any previous handshake cipher state.
	cs := s.cs
	// The caller may pass a slice of the previous h or ck as handshakeName.
	// Preserve it before clearing the old state.
	if len(s.h) != 0 || len(s.ck) != 0 {
		handshakeName = append([]byte(nil), handshakeName...)
	}
	clear(s.k[:])
	clear(s.ck)
	clear(s.h)
	s.CipherState = CipherState{cs: cs}
	s.hasK = false

	h := s.cs.Hash()
	if len(handshakeName) <= h.Size() {
		s.h = make([]byte, h.Size())
		copy(s.h, handshakeName)
	} else {
		h.Write(handshakeName)
		s.h = h.Sum(nil)
	}
	s.ck = make([]byte, len(s.h))
	copy(s.ck, s.h)
}

func (s *symmetricState) MixKey(dhOutput []byte) {
	var hk []byte
	s.ck, hk, _ = hkdf(s.cs.Hash, 2, s.ck[:0], s.k[:0], nil, s.ck, dhOutput)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
	s.n = 0
	s.hasK = true
}

func (s *symmetricState) MixHash(data []byte) {
	h := s.cs.Hash()
	_, _ = h.Write(s.h)
	_, _ = h.Write(data)
	// Use a fresh destination: data may alias the previous handshake hash.
	s.h = h.Sum(nil)
}

func (s *symmetricState) MixKeyAndHash(data []byte) {
	var hk []byte
	var temp []byte
	s.ck, temp, hk = hkdf(s.cs.Hash, 3, s.ck[:0], temp, s.k[:0], s.ck, data)
	s.MixHash(temp)
	clear(temp)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
	s.n = 0
	s.hasK = true
}

// EncryptAndHash appends the encrypted payload and hashes only the new bytes.
// As with cipher.AEAD, the output must not overlap the handshake hash.
func (s *symmetricState) EncryptAndHash(out, plaintext []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(plaintext)
		return append(out, plaintext...), nil
	}
	ciphertext, err := s.Encrypt(out, s.h, plaintext)
	if err != nil {
		return nil, err
	}
	s.MixHash(ciphertext[len(out):])
	return ciphertext, nil
}

// DecryptAndHash commits the transcript hash only after successful authentication.
// Calculate the prospective hash before decrypting so an in-place decrypt cannot
// overwrite the ciphertext before it is incorporated into the transcript.
func (s *symmetricState) DecryptAndHash(out, data []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(data)
		return append(out, data...), nil
	}
	h := s.cs.Hash()
	_, _ = h.Write(s.h)
	_, _ = h.Write(data)
	nextHash := h.Sum(nil)
	plaintext, err := s.Decrypt(out, s.h, data)
	if err != nil {
		clear(nextHash)
		return nil, err
	}
	s.h = nextHash
	return plaintext, nil
}

func (s *symmetricState) Split() (*CipherState, *CipherState) {
	s1, s2 := &CipherState{cs: s.cs}, &CipherState{cs: s.cs}
	hk1, hk2, _ := hkdf(s.cs.Hash, 2, s1.k[:0], s2.k[:0], nil, s.ck, nil)
	copy(s1.k[:], hk1)
	copy(s2.k[:], hk2)
	s1.c = s.cs.Cipher(s1.k)
	s2.c = s.cs.Cipher(s2.k)
	return s1, s2
}
