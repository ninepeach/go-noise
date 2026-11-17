package noise

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Reference ciphertexts are maintained by go-noise and generated using
// flynn/noise as an independent reference implementation.
//
// noise_vectors.txt holds NN, NK, IK and XX with SHA256 and BLAKE2s. The extended file is written by
// tools/genvectors (run `make vectors`) and holds every other standard pattern, plus SHA512 and BLAKE2b.
var referenceVectorFiles = []struct {
	path  string
	count int
}{
	{"testdata/noise_vectors.txt", 68},
	{"testdata/noise_vectors_extended.txt", 210},
}

func readVectorFile(t *testing.T, path string) []map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var blocks []map[string]string
	var current map[string]string
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			if current != nil {
				blocks = append(blocks, current)
				current = nil
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: malformed vector line %q", path, line)
		}
		if current == nil {
			current = make(map[string]string)
		}
		current[k] = v
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if current != nil {
		blocks = append(blocks, current)
	}
	return blocks
}

func TestReferenceNoiseVectors(t *testing.T) {
	seen := make(map[string]bool)
	for _, file := range referenceVectorFiles {
		blocks := readVectorFile(t, file.path)
		if len(blocks) != file.count {
			t.Fatalf("%s: expected %d independent vectors, got %d", file.path, file.count, len(blocks))
		}
		for _, v := range blocks {
			name := v["handshake"]
			if name == "" || seen[name] {
				t.Fatalf("missing or duplicate handshake %q", name)
			}
			seen[name] = true
			v := v
			t.Run(name, func(t *testing.T) { runReferenceNoiseVector(t, v) })
		}
	}
}

// Every standard pattern, every hash and every cipher must be covered by an independent vector.
func TestReferenceVectorsCoverEverySupportedSuite(t *testing.T) {
	patterns, hashes, ciphers := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, file := range referenceVectorFiles {
		for _, v := range readVectorFile(t, file.path) {
			parts := strings.Split(v["handshake"], "_")
			patName, _, _ := strings.Cut(parts[1], "psk")
			patterns[patName], ciphers[parts[3]], hashes[parts[4]] = true, true, true
		}
	}
	for _, p := range standardPatterns {
		if !patterns[p.Name] {
			t.Errorf("no independent vector for pattern %s", p.Name)
		}
	}
	for _, h := range []string{"SHA256", "SHA512", "BLAKE2b", "BLAKE2s"} {
		if !hashes[h] {
			t.Errorf("no independent vector for hash %s", h)
		}
	}
	for _, c := range []string{"AESGCM", "ChaChaPoly"} {
		if !ciphers[c] {
			t.Errorf("no independent vector for cipher %s", c)
		}
	}
}

func vectorHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorHasToken(list []MessagePattern, token MessagePattern) bool {
	for _, t := range list {
		if t == token {
			return true
		}
	}
	return false
}

func vectorKeypair(t *testing.T, value string) DHKey {
	t.Helper()
	if value == "" {
		return DHKey{}
	}
	k, err := DH25519.GenerateKeypair(bytes.NewReader(vectorHex(t, value)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func runReferenceNoiseVector(t *testing.T, v map[string]string) {
	t.Helper()
	parts := strings.Split(v["handshake"], "_")
	if len(parts) != 5 || parts[2] != "25519" {
		t.Fatalf("unsupported vector %q", v["handshake"])
	}
	patName := parts[1]
	placement := -1
	if base, position, ok := strings.Cut(patName, "psk"); ok {
		patName = base
		n, err := strconv.Atoi(position)
		if err != nil {
			t.Fatal(err)
		}
		placement = n
	}
	var pattern HandshakePattern
	found := false
	for _, p := range standardPatterns {
		if p.Name == patName {
			pattern, found = p, true
		}
	}
	if !found {
		t.Fatalf("unsupported pattern %s", patName)
	}
	ciphers := map[string]CipherFunc{"AESGCM": CipherAESGCM, "ChaChaPoly": CipherChaChaPoly}
	hashes := map[string]HashFunc{"SHA256": HashSHA256, "SHA512": HashSHA512, "BLAKE2b": HashBLAKE2b, "BLAKE2s": HashBLAKE2s}
	cipher, ok := ciphers[parts[3]]
	if !ok {
		t.Fatalf("unsupported cipher %q", parts[3])
	}
	hash, ok := hashes[parts[4]]
	if !ok {
		t.Fatalf("unsupported hash %q", parts[4])
	}
	suite := NewCipherSuite(DH25519, cipher, hash)
	initStatic := vectorKeypair(t, v["init_static"])
	respStatic := vectorKeypair(t, v["resp_static"])
	ci := Config{CipherSuite: suite, Pattern: pattern, Initiator: true, Random: bytes.NewReader(vectorHex(t, v["gen_init_ephemeral"])), Prologue: vectorHex(t, v["prologue"])}
	cr := Config{CipherSuite: suite, Pattern: pattern, Initiator: false, Random: bytes.NewReader(vectorHex(t, v["gen_resp_ephemeral"])), Prologue: vectorHex(t, v["prologue"])}
	// The vector carries a static key exactly for the parties that use one.
	ci.StaticKeypair = initStatic
	cr.StaticKeypair = respStatic
	initEphemeral := vectorKeypair(t, v["gen_init_ephemeral"])
	respEphemeral := vectorKeypair(t, v["gen_resp_ephemeral"])
	if vectorHasToken(pattern.ResponderPreMessages, MessagePatternS) {
		ci.PeerStatic = respStatic.Public
	}
	if vectorHasToken(pattern.InitiatorPreMessages, MessagePatternS) {
		cr.PeerStatic = initStatic.Public
	}
	if vectorHasToken(pattern.ResponderPreMessages, MessagePatternE) {
		cr.EphemeralKeypair, ci.PeerEphemeral = respEphemeral, respEphemeral.Public
	}
	if vectorHasToken(pattern.InitiatorPreMessages, MessagePatternE) {
		ci.EphemeralKeypair, cr.PeerEphemeral = initEphemeral, initEphemeral.Public
	}
	if placement >= 0 {
		ci.UsePresharedKey, cr.UsePresharedKey = true, true
		ci.PresharedKeyPlacement = placement
		cr.PresharedKeyPlacement = placement
		ci.PresharedKey = vectorHex(t, v["preshared_key"])
		cr.PresharedKey = vectorHex(t, v["preshared_key"])
	}
	initiator, err := NewHandshakeState(ci)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewHandshakeState(cr)
	if err != nil {
		t.Fatal(err)
	}
	var i1, i2, r1, r2 *CipherState
	messageCount := 0
	for idx := 0; ; idx++ {
		payloadHex, exists := v[fmt.Sprintf("msg_%d_payload", idx)]
		if !exists {
			break
		}
		ciphertextHex, ok := v[fmt.Sprintf("msg_%d_ciphertext", idx)]
		if !ok {
			t.Fatalf("missing ciphertext for message %d", idx)
		}
		expected := vectorHex(t, ciphertextHex)
		messageCount++
		payload := vectorHex(t, payloadHex)
		if idx < len(pattern.Messages) {
			writer, reader := initiator, responder
			if idx%2 == 1 {
				writer, reader = responder, initiator
			}
			got, w1, w2, err := writer.WriteMessage(nil, payload)
			if err != nil {
				t.Fatalf("handshake %d write: %v", idx, err)
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("handshake %d ciphertext mismatch\ngot %x\nwant %x", idx, got, expected)
			}
			plain, x1, x2, err := reader.ReadMessage(nil, got)
			if err != nil {
				t.Fatalf("handshake %d read: %v", idx, err)
			}
			if !bytes.Equal(plain, payload) {
				t.Fatalf("handshake %d payload mismatch", idx)
			}
			if idx == len(pattern.Messages)-1 {
				// Split returns directional cipher 1 (initiator -> responder)
				// and cipher 2 (responder -> initiator), on both peers.
				if idx%2 == 0 {
					i1, i2 = w1, w2
					r1, r2 = x2, x1
				} else {
					r1, r2 = w2, w1
					i1, i2 = x1, x2
				}
				if i1 == nil || i2 == nil || r1 == nil || r2 == nil {
					t.Fatal("missing transport states")
				}
				if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
					t.Fatal("handshake hash mismatch")
				}
			}
			continue
		}
		enc, dec := i1, r1
		if (idx-len(pattern.Messages))%2 == 1 {
			enc, dec = r2, i2
		}
		got, err := enc.Encrypt(nil, nil, payload)
		if err != nil {
			t.Fatalf("transport %d encrypt: %v", idx, err)
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("transport %d ciphertext mismatch\ngot %x\nwant %x", idx, got, expected)
		}
		plain, err := dec.Decrypt(nil, nil, got)
		if err != nil {
			t.Fatalf("transport %d decrypt: %v", idx, err)
		}
		if !bytes.Equal(plain, payload) {
			t.Fatalf("transport %d payload mismatch", idx)
		}
	}
	transportMessages := 2
	if len(pattern.Messages) == 1 { // one-way patterns (N, K, X) have no responder-to-initiator direction
		transportMessages = 1
	}
	if want := len(pattern.Messages) + transportMessages; messageCount != want {
		t.Fatalf("expected %d messages, got %d", want, messageCount)
	}
}
