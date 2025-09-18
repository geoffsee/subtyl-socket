import { createHmac, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * HKDF (HMAC-based Key Derivation Function) implementation following RFC 5869
 * A cryptographically secure method for deriving keys from shared secrets
 */
export class HKDF {
  /**
   * Extract phase: Creates a pseudorandom key from input keying material
   */
  private static extract(salt: Buffer, ikm: Buffer): Buffer {
    return createHmac('sha256', salt).update(ikm).digest();
  }

  /**
   * Expand phase: Expands the pseudorandom key to desired length
   */
  private static expand(prk: Buffer, info: Buffer, length: number): Buffer {
    const hashLen = 32; // SHA-256 output length
    const n = Math.ceil(length / hashLen);

    if (n > 255) {
      throw new Error('HKDF: requested length too large');
    }

    let t = Buffer.alloc(0);
    const result: Buffer[] = [];

    for (let i = 1; i <= n; i++) {
      const hmac = createHmac('sha256', prk);
      hmac.update(t);
      hmac.update(info);
      hmac.update(Buffer.from([i]));
      t = Buffer.from(hmac.digest());

      result.push(t);
    }

    return Buffer.concat(result).subarray(0, length) as Buffer;
  }

  /**
   * Complete HKDF operation: extract then expand
   */
  static derive(ikm: Buffer, salt: Buffer, info: Buffer, length: number = 32): Buffer {
    const prk = this.extract(salt, ikm);
    return this.expand(prk, info, length);
  }
}

/**
 * Secure random number generation with entropy verification
 */
export class SecureRandom {
  static bytes(length: number): Buffer {
    const bytes = randomBytes(length);

    // Basic entropy check - ensure we don't get all zeros or obvious patterns
    const isAllZeros = bytes.every(byte => byte === 0);
    const isAllOnes = bytes.every(byte => byte === 255);

    if (isAllZeros || isAllOnes) {
      throw new Error('Insufficient entropy detected in random generation');
    }

    return bytes;
  }

  static base64(length: number): string {
    return this.bytes(length).toString('base64');
  }
}

/**
 * Constant-time comparison to prevent timing attacks
 */
export function constantTimeCompare(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= (a[i] || 0) ^ (b[i] || 0);
  }

  return result === 0;
}

/**
 * Creates context-specific info parameter for HKDF
 */
export function createContextInfo(context: string, version: number = 1): Buffer {
  const contextBuffer = Buffer.from(context, 'utf8');
  const versionBuffer = Buffer.from([version]);
  const lengthBuffer = Buffer.from([contextBuffer.length]);

  return Buffer.concat([lengthBuffer, contextBuffer, versionBuffer]);
}

/**
 * Generate encryption and authentication keys
 */
export function generateKeys(): { encryptionKey: Buffer; authenticationKey: Buffer } {
  return {
    encryptionKey: SecureRandom.bytes(32),
    authenticationKey: SecureRandom.bytes(32),
  };
}

/**
 * Encrypt data with AES-256-GCM
 */
export function encrypt(text: string, encryptionKey: Buffer, authenticationKey: Buffer): string {
  const iv = SecureRandom.bytes(16);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  // Create HMAC for additional authentication
  const hmac = createHmac('sha256', authenticationKey);
  hmac.update(iv);
  hmac.update(Buffer.from(encrypted, 'hex'));
  hmac.update(tag);
  const authTag = hmac.digest();

  // Combine IV, encrypted data, GCM tag, and HMAC
  const combined = Buffer.concat([iv, Buffer.from(encrypted, 'hex'), tag, authTag]);

  return combined.toString('base64');
}

/**
 * Decrypt data encrypted with encrypt function
 */
export function decrypt(
  encryptedData: string,
  encryptionKey: Buffer,
  authenticationKey: Buffer,
): string {
  const combined = Buffer.from(encryptedData, 'base64');

  if (combined.length < 16 + 16 + 32) {
    throw new Error('Invalid encrypted data');
  }

  const iv = combined.subarray(0, 16);
  const tag = combined.subarray(-48, -32); // GCM tag is 16 bytes
  const authTag = combined.subarray(-32); // HMAC is 32 bytes
  const encrypted = combined.subarray(16, -48);

  // Verify HMAC first
  const hmac = createHmac('sha256', authenticationKey);
  hmac.update(iv);
  hmac.update(encrypted);
  hmac.update(tag);
  const expectedAuthTag = hmac.digest();

  if (!constantTimeCompare(authTag, expectedAuthTag)) {
    throw new Error('Authentication failed');
  }

  // Decrypt
  const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encrypted, undefined, 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
