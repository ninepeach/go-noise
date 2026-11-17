package noise

import (
	"crypto/hmac"
	"hash"
)

// hkdf implements the Noise HKDF construction, returning up to three
// consecutive HMAC-derived outputs.
//
// Destination slices must be empty and their writable regions must not
// overlap each other. An output may reuse the storage of chainingKey or
// inputKeyMaterial: extraction finishes before any output is written.
func hkdf(newHash func() hash.Hash, outputs int, out1, out2, out3, chainingKey, inputKeyMaterial []byte) ([]byte, []byte, []byte) {
	if outputs < 1 || outputs > 3 {
		panic("noise: HKDF requires between one and three outputs")
	}
	if len(out1) != 0 || len(out2) != 0 || len(out3) != 0 {
		panic("noise: HKDF output buffers must be empty")
	}

	extract := hmac.New(newHash, chainingKey)
	_, _ = extract.Write(inputKeyMaterial)
	secret := extract.Sum(nil)
	defer clear(secret)

	expand := func(previous []byte, counter byte, dst []byte) []byte {
		mac := hmac.New(newHash, secret)
		_, _ = mac.Write(previous)
		var c [1]byte
		c[0] = counter
		_, _ = mac.Write(c[:])
		return mac.Sum(dst)
	}

	first := expand(nil, 1, out1)
	if outputs == 1 {
		return first, nil, nil
	}
	second := expand(first, 2, out2)
	if outputs == 2 {
		return first, second, nil
	}
	third := expand(second, 3, out3)
	return first, second, third
}
