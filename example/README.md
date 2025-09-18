# Crypto Flow Demo

This example demonstrates the complete encrypted WebSocket communication flow with clear visibility into the cryptographic operations.

## What it shows

✅ **Secure handshake process**

- ECDH key exchange with proper nonce handling
- Mutual key confirmation with HMAC verification
- Key derivation using HKDF

✅ **Encryption in action**

- Shows raw plaintext before encryption
- Displays encrypted data being transmitted over the wire
- Shows successful decryption on both sides

✅ **Separate processes**

- Server and client run as independent processes
- Clear separation of concerns
- Real network communication over WebSocket

## Running the demo

```bash
bun run demo
```

## What you'll see

The demo will show:

1. **Handshake Phase**: Key exchange and derivation with clear logging of public keys and nonces
2. **Encryption Phase**: Plaintext messages being encrypted into unreadable binary data
3. **Transmission Phase**: The actual encrypted bytes sent over the WebSocket
4. **Decryption Phase**: Successful recovery of the original plaintext

## Key Features Demonstrated

- **Real encryption**: Messages are actually encrypted using AES-256-GCM
- **Perfect Forward Secrecy**: New keys derived for each session using ECDH
- **Authentication**: HMAC-based message authentication
- **Proper cleanup**: Sensitive key material is securely destroyed after use

This is much clearer than the other examples - you can actually see the crypto working!
