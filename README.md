# Subtyl Socket
[![Test](https://github.com/geoffsee/subtyl-socket/actions/workflows/test.yml/badge.svg)](https://github.com/geoffsee/subtyl-socket/actions/workflows/test.yml)
[![CI](https://github.com/geoffsee/subtyl-socket/actions/workflows/ci.yml/badge.svg)](https://github.com/geoffsee/subtyl-socket/actions/workflows/ci.yml)
[![Release](https://github.com/geoffsee/subtyl-socket/actions/workflows/release.yml/badge.svg)](https://github.com/geoffsee/subtyl-socket/actions/workflows/release.yml)


_Being a Most Excellent Library for the Secure Exchange of Cryptographic Keys Between Networked Parties_

---

## Preface

> _"An investment in knowledge pays the best interest."_
> — B. Franklin, Poor Richard's Almanack

Dear Reader, permit me to introduce to your consideration this most ingenious contrivance for the safe passage of communications through the treacherous waters of the modern internet. As I have often observed that "he that goes a borrowing goes a sorrowing," so too must we acknowledge that he who transmits secrets without proper encryption goes a-weeping.

## What Manner of Thing Is This?

**Subtyl Socket** provides two distinct implementations for secure key exchange:

### The Secure Implementation (Recommended)

- **SecureProvider** & **SecureConsumer** - Built upon RFC 5869 HKDF with proper key confirmation
- **Mutual Authentication** - Both parties verify each other's identity cryptographically
- **Context Separation** - Different keys derived for different purposes
- **Forward Secrecy** - Session keys are ephemeral and cannot be recovered
- **Memory Security** - Sensitive data is properly zeroed after use

### The Legacy Implementation (Deprecated)

- **Provider** & **Consumer** - Simple but flawed SHA-256 approach
- _Use only for educational purposes or when upgrading existing systems_

## The Art of Secure Usage

### Installing the Apparatus

```bash
npm install subtyl-socket
```

### The Proper Method (Secure Implementation)

#### Server Side (Provider)

```typescript
// server.ts
import { SecureProvider } from 'subtyl-socket';
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', socket => {
  const provider = new SecureProvider();
  let keys: { encryptionKey: Buffer; authenticationKey: Buffer } | null = null;

  // Step 1: Initiate handshake
  provider.startHandshake(socket);

  socket.on('message', data => {
    const message = JSON.parse(data.toString());

    if (message.type === 'handshake-response') {
      // Step 2: Process client's response
      const result = provider.handleResponse(message);

      if (result.type === 'send-confirmation') {
        socket.send(
          JSON.stringify({
            type: 'key-confirmation-request',
            confirmationMac: result.confirmationMac,
          }),
        );
      }
    } else if (message.type === 'key-confirmation') {
      // Step 3: Verify final confirmation
      const result = provider.handleResponse(message);

      if (result.confirmed) {
        keys = provider.getDerivedKeys();
        console.log('🔐 Server: Secure keys established!');
        // Now use keys for encrypted communication
      }
    }
  });

  socket.on('close', () => provider.destroy());
});
```

#### Client Side (Consumer)

```typescript
// client.ts
import { SecureConsumer } from 'subtyl-socket';
import { WebSocket } from 'ws';

const consumer = new SecureConsumer();
const socket = new WebSocket('ws://localhost:8080');
let keys: { encryptionKey: Buffer; authenticationKey: Buffer } | null = null;

socket.on('message', data => {
  const result = consumer.handleMessage(data.toString());

  if (result.type === 'handshake-response') {
    // Step 1: Respond to server's handshake
    socket.send(JSON.stringify(result.response));
  } else if (result.type === 'key-confirmation') {
    // Step 2: Send final confirmation
    keys = consumer.getDerivedKeys();
    socket.send(JSON.stringify(result.response));
    console.log('🔐 Client: Secure keys established!');
    // Now use keys for encrypted communication
  } else if (result.type === 'error') {
    console.error('Handshake failed:', result.error);
  }
});

socket.on('close', () => consumer.destroy());
```

### Message Encryption Plugin Architecture

For those seeking to implement secure message encryption atop the established keys, we provide an extensible plugin architecture:

#### The Abstract Foundation

```typescript
import { BaseEncryptionPlugin, EncryptionKeys } from 'subtyl-socket';

// Extend for custom encryption algorithms
abstract class MyCustomPlugin extends BaseEncryptionPlugin {
  constructor(keys?: EncryptionKeys) {
    super('my-algorithm-name', keys);
  }

  abstract encrypt(plaintext: string): EncryptionResult;
  abstract decrypt(encrypted: EncryptionResult): string;
}
```

#### The AES-256-GCM Implementation

```typescript
import { MessageEncryptionPlugin } from 'subtyl-socket';

// After successful key exchange
const keys = provider.getDerivedKeys();
const encryption = new MessageEncryptionPlugin(keys);

// Encrypt and send messages
const encryptedMessage = encryption.wrapMessage('chat', 'Secret message');
socket.send(encryptedMessage);

// Receive and decrypt messages
const decryptedData = encryption.unwrapMessage(receivedData);
console.log('Decrypted:', decryptedData?.payload);

// Always clean up
encryption.destroy();
```

#### Plugin Features

- **Algorithm Identification**: Messages include algorithm metadata for compatibility
- **Transparent Processing**: Automatic encryption/decryption with simple API
- **Extensible Design**: Easy to implement additional algorithms (ChaCha20-Poly1305, etc.)
- **Memory Security**: Proper cleanup of encryption keys
- **Error Handling**: Comprehensive validation and secure failure modes

### Testing the Implementation

To witness these marvels in operation and verify their security properties:

```bash
bun test  # Runs all tests including cryptographic property verification
bun run demo  # Demonstrates secure handshake with MessageEncryptionPlugin
bun run encryption-plugin.test.ts  # Tests the encryption plugin specifically
```

## The Philosophical and Technical Foundation

> _"By failing to prepare, you are preparing to fail."_

This library embodies the highest principles of cryptographic engineering:

### 1. **Proper Key Derivation (HKDF)**

- Follows RFC 5869 specification precisely
- Uses HMAC-SHA256 for both extract and expand phases
- Provides computational security guarantees
- Supports context separation for different key purposes

### 2. **Mutual Authentication**

- Both parties prove knowledge of the shared secret
- Prevents man-in-the-middle attacks through key confirmation
- Uses constant-time comparison to prevent timing attacks
- Session IDs prevent replay attacks

### 3. **Forward Secrecy**

- Ephemeral ECDH keys (prime256v1 curve)
- Session keys cannot be recovered even if long-term keys are compromised
- Each handshake creates unique key material

### 4. **Memory Security**

- All sensitive buffers are zeroed after use
- Explicit `destroy()` methods for secure cleanup
- Prevents key material from remaining in memory

### 5. **Protocol Security**

- Version negotiation prevents downgrade attacks
- Algorithm negotiation ensures strong cryptography
- Proper nonce handling prevents replay attacks

## Technical Particulars for the Learned Reader

The secure protocol operates through these carefully orchestrated phases:

### Phase I: Initialization

- Provider generates ephemeral ECDH key pair
- Creates cryptographically secure nonce (32 bytes)
- Announces supported algorithms and protocol version

### Phase II: Key Agreement

- Consumer generates ephemeral ECDH key pair
- Creates cryptographically secure nonce (32 bytes)
- Both parties compute identical ECDH shared secret

### Phase III: Key Derivation

- Combined nonces form HKDF salt
- Shared secret becomes HKDF input key material
- Three distinct keys derived with context separation:
  - Encryption key: `HKDF(secret, salt, "SubtylSocket-Encryption")`
  - Authentication key: `HKDF(secret, salt, "SubtylSocket-Authentication")`
  - Confirmation key: `HKDF(secret, salt, "SubtylSocket-KeyConfirmation")`

### Phase IV: Mutual Confirmation

- Each party proves possession of derived keys
- HMAC-SHA256 used for key confirmation messages
- Constant-time comparison prevents timing attacks
- Protocol fails securely if confirmation fails

## Words of Gravest Caution

> _"Security without liberty is tyranny; liberty without security is anarchy."_

While this implementation provides strong cryptographic foundations, the prudent engineer must remember:

### Critical Security Requirements

- **Always use the Secure\* classes** - The legacy classes are cryptographically broken
- **Verify handshake completion** - Check `isHandshakeConfirmed()` before using keys
- **Handle errors properly** - Any error during handshake indicates potential attack
- **Use authenticated encryption** - The derived keys require proper AEAD construction
- **Implement proper transport security** - This library handles key agreement, not message encryption

### Recommended Practices

- Generate fresh instances for each connection
- Never reuse session keys across connections
- Implement proper certificate validation for initial authentication
- Use the MessageEncryptionPlugin for secure message encryption, or implement custom plugins for ChaCha20-Poly1305, etc.
- Always call `destroy()` methods to ensure proper memory cleanup
- Log security events for monitoring

### Known Limitations

- No built-in replay protection beyond session scope
- Requires secure transport for initial key exchange messages
- Does not handle key rotation or rekeying
- Maximum derived key length limited by HKDF specification

## Contributing to the Common Good

> _"Tell me and I forget, teach me and I may remember, involve me and I learn."_

This implementation has been subjected to rigorous testing:

- **17 comprehensive test cases** covering all security properties
- **HKDF implementation tested** against known vectors
- **Constant-time operations verified** to prevent side-channel attacks
- **Error handling tested** to ensure secure failure modes
- **Memory security verified** through key destruction tests

Should you discover improvements or wish to contribute additional security measures, such endeavors are most welcome.

## Final Observations

In the spirit of Franklin's dedication to both practical utility and scientific rigor, this library represents what cryptographic software should be:

- **Secure by design** - No shortcuts or compromises with security
- **Well-tested** - Every security property is verified
- **Properly documented** - Clear warnings about limitations and requirements
- **Memory-safe** - Sensitive data is handled with appropriate care

Remember always that in cryptography, as in Franklin's electrical experiments, "an ounce of prevention is worth a pound of cure." Use this library as the foundation for secure communications, but never assume that key agreement alone constitutes complete security.

---

_Benjamin Franklin would have marveled at the mathematical elegance of elliptic curves and the precision with which we can now prove the security of our cryptographic constructions. In his spirit of careful experimentation and clear documentation of results, may this library serve as a reliable foundation for your secure communications._

**Version**: Cryptographically sound
**License**: Use freely, but use wisely
**Security Audit**: Self-audited with comprehensive test coverage
**Author**: A humble servant of proper cryptography

> _"The Constitution only gives people the right to pursue happiness. You have to catch it yourself."_
> — And you must secure it yourself, with proper cryptography.
