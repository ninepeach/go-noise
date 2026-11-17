# go-noise

A small, easy-to-use Go implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html).

**Noise helps two peers establish shared encryption keys over an untrusted connection.** Once the handshake finishes, they can encrypt and decrypt messages. This library handles the cryptography; you choose how to send bytes over TCP, UDP, WebSocket, or another transport.

## Architecture & code map (3-minute refresher)

**Purpose:** Implement the Noise handshake state machine and its resulting symmetric transport ciphers. This package does **not** own sockets, framing, retransmission, identity trust, or session recovery.

**Execution path:**

```text
Config + CipherSuite + HandshakePattern
              |
              v
NewHandshakeState (handshake_config.go)
  validate pattern / keys / dependencies
  initialize protocol name, prologue, pre-messages
              |
              v
HandshakeState.WriteMessage / ReadMessage (handshake_state.go)
  consume pattern tokens: e, s, ee, es, se, ss, psk
  mix DH secrets and transcript; encrypt/decrypt handshake payload
              |
              v
symmetricState (symmetric_state.go)
  h = transcript hash; ck = chaining key; k = temporary cipher key
  MixHash / MixKey / MixKeyAndHash / EncryptAndHash / DecryptAndHash
              |
              v
Split() -> two CipherStates (send, receive for THIS peer)
              |
              v
CipherState.Encrypt / Decrypt / Rekey (cipher_state.go)
```

| File | Read it when you need to... |
| --- | --- |
| `patterns.go` | Understand built-in Noise patterns and token order |
| `handshake_config.go` | Change configuration validation, PSK placement, or pre-message initialization |
| `handshake_state.go` | Trace handshake message order, token execution, DH selection, and completion |
| `symmetric_state.go` | Trace transcript hashing, chaining-key updates, handshake AEAD, and Split |
| `cipher_state.go` | Understand transport encryption, nonce ownership, rekey, and unsafe restoration |
| `cipher_suite.go` | Locate DH/cipher/hash implementations and suite selection |
| `hkdf.go` | Understand Noise-specific key derivation |
| `*_test.go`, `vectors_test.go` | Find regressions, handshake combinations, and reference-vector checks |

**Invariants to preserve:**

- `WriteMessage` and `ReadMessage` alternate according to the pattern; the final call returns **local send, local receive**, not fixed initiator/responder order.
- Handshake transcript hash `h` must only commit authenticated ciphertext after successful decryption; `ck` drives `Split`.
- A live `CipherState` is pointer-owned and not concurrency-safe. Automatic nonces must never move backwards or repeat with the same key; rekey is coordinated by the application.
- Invalid custom patterns are rejected at initialization, but custom-pattern validation is **not** a proof of protocol security.
- An in-progress handshake that fails must be discarded. Peer identity verification and transport framing remain the application's responsibility.

**Returning after a long break:** read this section, then `handshake_state.go` and `symmetric_state.go`; run:

```sh
make fmt-check
make vet
make test
go test -race ./...
```

## Install

Requires Go 1.23 or newer.

```sh
go get github.com/ninepeach/go-noise
```

## Quick start: two peers talking

This example uses **NN**, the simplest handshake pattern. It demonstrates the *whole* flow in memory: handshake, obtain transport keys, encrypt, and decrypt. No network setup is needed.

> **NN does not authenticate either peer.** It is useful for learning, but an active attacker can impersonate either side. Choose an authenticated pattern for real applications.

```go
package main

import (
	"fmt"
	"log"

	noise "github.com/ninepeach/go-noise"
)

func main() {
	suite := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashSHA256,
	)

	initiator, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Pattern:     noise.HandshakeNN(),
		Initiator:   true,
	})
	if err != nil {
		log.Fatal(err)
	}

	responder, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Pattern:     noise.HandshakeNN(),
		Initiator:   false,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 1. Initiator -> responder: first handshake message.
	msg1, _, _, err := initiator.WriteMessage(nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, _, _, err = responder.ReadMessage(nil, msg1); err != nil {
		log.Fatal(err)
	}

	// 2. Responder -> initiator: final handshake message.
	msg2, responderSend, _, err := responder.WriteMessage(nil, nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, _, initiatorReceive, err := initiator.ReadMessage(nil, msg2); err != nil {
		log.Fatal(err)
	} else {
		// 3. Handshake is complete. Both sides have transport keys.
		ciphertext, err := responderSend.Encrypt(nil, nil, []byte("Hello from responder!"))
		if err != nil {
			log.Fatal(err)
		}
		plaintext, err := initiatorReceive.Decrypt(nil, nil, ciphertext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(plaintext))
	}
}
```

Output:

```text
Hello from responder!
```

### What just happened?

1. **Handshake:** each peer calls `WriteMessage` or `ReadMessage` in the order required by the pattern.
2. **Key agreement:** the final handshake call returns two `*CipherState` values: `send` for outgoing traffic and `receive` for incoming traffic.
3. **Encrypted traffic:** call `send.Encrypt(...)` and the other peer's `receive.Decrypt(...)`. The library advances the nonce automatically.

The example only shows responder-to-initiator traffic. The two returned cipher states are always oriented to the local peer: first is **send**, second is **receive**, regardless of initiator or responder role.

## Choosing a handshake pattern

| Pattern | When to consider it |
| --- | --- |
| `HandshakeNN()` | Learning or unauthenticated key exchange; **not safe against active impersonation** |
| `HandshakeNK()` | Initiator already knows and trusts the responder's static public key |
| `HandshakeXX()` | Both sides exchange static identities during the handshake; **verify those identities** |
| `HandshakeIK()` | Initiator knows the responder's static key and also presents its own static key |
| `HandshakeXXfallback()` | Continue after an `IK` attempt fails; see [Fallback](#fallback-ik-to-xxfallback) |

These are examples, not an exhaustive list: all 16 standard patterns of the Noise specification are available, and each is covered by independent reference vectors (see [Testing](#testing)). Each `Handshake*()` function returns a fresh copy, so editing it never changes the standard definition, and `NewHandshakeState` rejects a pattern that carries a standard name but differs from its definition. Custom patterns are checked for malformed tokens and dependencies, but are not a substitute for a protocol security analysis. A standard Noise pattern name cannot be paired with a different token sequence. Patterns have different identity and key requirements. **A successful handshake does not automatically mean you trust the peer.** Supply and verify static public keys according to your application's trust model.

## Common API

| API | Purpose |
| --- | --- |
| `NewCipherSuite(dh, cipher, hash)` | Select Noise cryptographic primitives |
| `NewHandshakeState(Config{...})` | Create one side of a handshake |
| `WriteMessage(out, payload)` | Produce the next handshake message |
| `ReadMessage(out, message)` | Process a received handshake message |
| `CipherState.Encrypt(out, ad, plaintext)` | Encrypt transport data |
| `CipherState.Decrypt(out, ad, ciphertext)` | Authenticate and decrypt transport data |
| `CipherState.Rekey()` | Derive a new transport key; both sides must coordinate |
| `GenerateKeypair(nil)` | Generate a static keypair using secure randomness |
| `SetPresharedKey(key)` | Provide a 32-byte key before its PSK token is processed |
| `PeerStatic()` / `ChannelBinding()` | Inspect peer identity material and handshake binding |
| `Destroy()` | Erase an abandoned or failed handshake's secrets and make it unusable |
| `Nonce()` / `SetNonce(n)` | Inspect or advance the automatic transport nonce; handle errors on rewind |
| `Cipher()` | Access the low-level cipher and disable automatic nonce handling |
| `UnsafeKey()` / `UnsafeNewCipherState(...)` | Advanced state export and restoration; risk of nonce reuse |

`out` is an optional destination slice (use `nil` to allocate). `ad` is optional authenticated data: it is authenticated but not encrypted. `payload` is optional data carried within a handshake message.

## Handshake API: complete message exchange

The handshake is a state machine. For a three-message pattern such as `HandshakeXX()`, the order is:

```text
Initiator                      Responder
WriteMessage  --------------> ReadMessage
ReadMessage   <-------------- WriteMessage
WriteMessage  --------------> ReadMessage
   send/receive                send/receive
```

Each `WriteMessage` returns the encoded message to deliver to the other peer. Each `ReadMessage` accepts exactly that encoded message. The final call on **each side** returns `send` and `receive` transport cipher states. Before the final call these values are `nil`. Do not use transport encryption before both sides complete the handshake.

For authenticated patterns, create static keys with `suite.GenerateKeypair(nil)` and supply `StaticKeypair` where required. When a peer must know the remote static key in advance, set `PeerStatic` to its trusted public key. For patterns that exchange static keys, use `PeerStatic()` after receiving them and verify the identity against a trusted source before accepting the session.

### Complete two-way transport example

After the NN handshake in Quick Start, keep **both** cipher states returned by each peer's final handshake call. The following example shows the exact API calls for both directions:

```go
// initiatorSend, initiatorReceive: returned by initiator.ReadMessage(...)
// responderSend, responderReceive: returned by responder.WriteMessage(...)

request, err := initiatorSend.Encrypt(nil, nil, []byte("ping"))
if err != nil { log.Fatal(err) }
receivedRequest, err := responderReceive.Decrypt(nil, nil, request)
if err != nil { log.Fatal(err) }
fmt.Println(string(receivedRequest)) // ping

reply, err := responderSend.Encrypt(nil, nil, []byte("pong"))
if err != nil { log.Fatal(err) }
receivedReply, err := initiatorReceive.Decrypt(nil, nil, reply)
if err != nil { log.Fatal(err) }
fmt.Println(string(receivedReply)) // pong
```

### Rekey and session inspection

```go
// Rekey the sender and matching receiver together, before the next message.
initiatorSend.Rekey()
responderReceive.Rekey()

// These values help inspect a handshake or transport state.
_ = initiator.MessageIndex()
_ = initiator.ChannelBinding() // meaningful for binding after completion
_ = initiator.PeerStatic()     // verify when the pattern exchanges a static key
_ = initiator.PeerEphemeral()
_ = initiator.LocalEphemeral()
_ = initiatorSend.Nonce()
```

The two-way and rekey snippets extend the Quick Start: they assume those cipher states were saved under the shown names. Rekeying one direction does not automatically rekey the other direction.

## Library boundary

go-noise is transport-independent. It only creates and processes Noise handshake messages and encrypted payloads; your application handles message delivery, framing, trust decisions, and session lifecycle. If messages arrive out of order, `Cipher()` supports advanced manual nonce management, which must never reuse a key/nonce pair.

## Optional pre-shared keys (PSK)

A PSK is **exactly 32 bytes**, and both peers must use the same key and placement.

```go
config := noise.Config{
	CipherSuite:           suite,
	Pattern:               noise.HandshakeNN(),
	Initiator:             true,
	UsePresharedKey:       true,
	PresharedKey:          my32ByteKey,
	PresharedKeyPlacement: 0, // psk0
}
```

The protocol name follows the Noise specification, so `psk2` on `XX` is `Noise_XXpsk2_...`, and a modifier added to a pattern that already has one is joined with a plus sign: `XXfallback` with `psk0` is `Noise_XXfallback+psk0_...`.

PSK mode is switched on only by `UsePresharedKey: true`; `PresharedKeyPlacement` is then N in `pskN`. Without it, setting `PresharedKey` or a non-zero `PresharedKeyPlacement` is a configuration error, so a forgotten switch cannot silently produce a non-PSK handshake. `psk0` and `psk1` need their key at initialization. For `psk2` and later, the key may be supplied before the relevant handshake token using `SetPresharedKey`.

## Important safety notes

- **Never copy a live `CipherState`.** Copying can reuse a key/nonce pair. Treat it as a pointer-owned, non-concurrent state.
- **Never reuse a nonce with the same key.** `Encrypt` and `Decrypt` advance it automatically. Calling `Cipher()` disables automatic nonce management.
- **Do not rewind `SetNonce`.** A backward value is rejected with an error; automatic encryption/decryption is disabled for that state. Moving forward never repeats a nonce, so it cannot weaken the cipher; it is for a receiver that must skip nonces after loss. A value other than the sender's next nonce makes the next `Decrypt` fail, which costs availability, not secrecy.
- **`Cipher()` hands you the nonce.** The returned `Cipher` tracks nothing; one repeated (key, nonce) pair breaks confidentiality and authenticity for the whole key.
- **Handle errors.** A handshake that fails after processing begins must be discarded and restarted.
- **Use key export/restore APIs with extreme care.** `UnsafeKey` and `UnsafeNewCipherState` require safe key storage and a guarantee against nonce rollback. `UnsafeNewCipherState` panics if the cipher suite is nil or the nonce is greater than `MaxNonce`; it cannot detect previously used key/nonce pairs.
- **Use secure randomness.** The default uses `crypto/rand`.
- **Secrets are wiped, best effort.** When a handshake completes, its chaining key, last handshake key, preshared key and private keys are erased; the transcript hash and peers' public keys stay, so `ChannelBinding`, `PeerStatic` and `PeerEphemeral` keep working. When a handshake fails, the same secrets are erased at once except the local ephemeral private key, which the fallback flow needs; call `Destroy()` to erase that too, and on any handshake you abandon. Go cannot erase copies inside its standard AEAD objects or from memory the garbage collector already moved, and the `Config` you passed in is yours to protect. After completion `LocalEphemeral()` returns an empty `DHKey`.

## Fallback: IK to XXfallback

`LocalEphemeral()` and `PeerEphemeral()` exist for this flow. The initiator tried `IK` with a responder key that has since changed, so the responder cannot decrypt the first message. Both sides then continue with `XXfallback`, reusing the initiator's ephemeral key as a pre-message:

```go
// initiator, after its IK message was rejected (before Destroy erases the key):
ephemeral := initiator.LocalEphemeral()        // responder-side pre-message for XXfallback
// responder, after its ReadMessage failed:
seen := responder.PeerEphemeral()

// The original responder now INITIATES XXfallback, the original initiator RESPONDS.
fbInitiator, _ := noise.NewHandshakeState(noise.Config{
	CipherSuite: suite, Pattern: noise.HandshakeXXfallback(), Initiator: true,
	StaticKeypair: responderStatic, PeerEphemeral: seen, Prologue: prologue,
})
fbResponder, _ := noise.NewHandshakeState(noise.Config{
	CipherSuite: suite, Pattern: noise.HandshakeXXfallback(), Initiator: false,
	StaticKeypair: initiatorStatic, EphemeralKeypair: ephemeral, Prologue: prologue,
})
```

`TestIKFallbackToXXfallback` runs this exchange end to end. The prologue must match on both sides.

## Testing

```sh
make test
go test -race ./...
```

- **Reference vectors.** `testdata/noise_vectors.txt` (68) and `testdata/noise_vectors_extended.txt` (210) were generated with [flynn/noise](https://github.com/flynn/noise) as an independent implementation. Together they cover all 16 standard patterns, every PSK placement (except `XXfallback`, below), both ciphers and all four hashes (`SHA256`, `SHA512`, `BLAKE2b`, `BLAKE2s`). The extended file is written by `tools/genvectors`, a separate module so that go-noise gains no dependency: `make vectors` regenerates it and `make vectors-check` verifies it is current.
- **One deliberate gap.** `XXfallback` with a preshared key has no reference vector. flynn/noise spells that protocol name `XXfallbackpsk0`, but the Noise specification requires `XXfallback+psk0`, so flynn is not a valid reference there. go-noise follows the specification and `protocol_name_test.go` derives the expected transcript hash from the specification's spelling.
- **Failure paths.** `handshake_failure_test.go` truncates every handshake message at every length, flips every byte, replays and reorders messages, and feeds low-order curve points, for all patterns. None may panic, a rejected message must lock the handshake, and no tampered session may end with matching transport keys.

## Coming from flynn/noise

- **Cipher state order.** flynn returns the same `(cs1, cs2)` order to initiator and responder, so a responder must swap them. go-noise returns **(send, receive)** to both roles.
- **Patterns are functions.** Write `noise.HandshakeXX()`, not `noise.HandshakeXX`. Each call returns a fresh copy.
- **PSK mode is explicit.** Set `UsePresharedKey: true` together with `PresharedKey` and `PresharedKeyPlacement`.
- **`XXfallback` with a PSK** uses the protocol name `Noise_XXfallback+psk0_...` the specification requires; flynn writes `XXfallbackpsk0`, so the two do not interoperate for that one combination.
- **Secrets are wiped on completion.** Read `LocalEphemeral()` before the handshake completes; afterwards it returns an empty `DHKey`.
- **Disabled nonce management** is reported as `ErrNonceManagementDisabled` (flynn: `ErrCipherSuiteCopied`).

## Development

```sh
make test       # run tests
make vet        # static checks
make fmt        # format Go files
make fmt-check  # check formatting without changes
make fuzz       # short fuzz runs of ReadMessage and Decrypt
```

## Scope and credits

This project focuses on Noise handshakes, standard patterns, PSK modifiers, transport cipher states, and rekeying. **It is not a networking stack or a session-recovery protocol.**
