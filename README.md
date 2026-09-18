# babel

A TCP chat protocol built from python sockets, with RSA used for establishing an AES-GCM session.  RSA encryption implemented from raw math rather than importing a library.

## What this is

Started as a plain socket chat script and turned into a small cryptography project. Instead of wrapping the connection in TLS, the goal was to build the handshake myself: generate real RSA keypairs, do the modular exponentiation by hand, use that to bootstrap a proper AES-256-GCM session, and see where the protocol actually breaks.

It broke a few times. That's mostly the point.

## How it works

```
Client                              Server
  |----- RSA public key (N,e) ------>|
  |<---- RSA public key (N,e) -------|
  |<------------- ACK ---------------|
  |--- AES-256 key, RSA-wrapped ---->|
  |<===== AES-GCM chat stream ======>|
```

1. **Framing.** Every message on the wire gets a 4-byte, network-byte-order length prefix (`struct.pack("!I", len(payload))`), so the receiving side knows exactly how many bytes to pull off the socket instead of guessing at TCP's stream boundaries.
2. **Handshake.** Client and server each generate their own 2048-bit RSA keypair (two random 1024-bit primes multiplied together for N) and exchange public keys `(N, e)` in the clear. This step isn't meant to secure the whole conversation, just to get both sides a key to wrap the next thing in.
3. **Session key.** The client generates a random 256-bit AES key, encrypts it under the server's RSA public key, and sends it once. From that point on both sides share a symmetric key that was never sent as plaintext.
4. **Transport.** Chat messages are encrypted with AES-256-GCM: a fresh random nonce per message, shipped as `nonce || tag || ciphertext`. The GCM tag means a tampered packet gets rejected instead of silently decrypting into garbage.

All of this lives in `SecureNODE`, a class that wraps a raw socket and exposes clean methods so `client.py` and `server.py` only deal with UI and connection lifecycle, not the math.

## Running it

Only external dependency is pycryptodome.

```bash
pip install pycryptodome

# terminal 1
python src/server.py --host 127.0.0.1 --port 65432

# terminal 2
python src/client.py --host 127.0.0.1 --port 65432
```

## Known limitations

- The RSA handshake uses raw modular exponentiation with no OAEP padding.
- MITM attacks can be carried out easily with the interceptor exchanging their own keys. No way to authenticate identity yet
- The chat loop is a strict send-then-receive ping-pong, no threading yet, so you can't type while waiting on the other side.
- One client, one server, one connection at a time.

## What's next

- OAEP padding on the RSA handshake
- Swap the static RSA session key for ECDH, so one compromised session doesn't compromise the ones before it
- Thread the chat loop for real full-duplex messaging
- Multi-client support on the server

The full math (Euler's totient, why the tag in AES-GCM matters, why RSA overflowed on longer messages before AES came in) is worked out by hand in `docs/writeup.txt`.