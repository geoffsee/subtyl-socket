import { test, expect, describe } from 'bun:test';
import { generateKeys, encrypt, decrypt } from '../crypto-utils.ts';

describe('crypto-utils', () => {
  test('should generate keys of the correct length', () => {
    const keys = generateKeys();
    expect(keys.encryptionKey.length).toBe(32);
    expect(keys.authenticationKey.length).toBe(32);
  });

  test('should encrypt and decrypt data successfully', () => {
    const { encryptionKey, authenticationKey } = generateKeys();
    const text = 'hello world';
    const encrypted = encrypt(text, encryptionKey, authenticationKey);
    const decrypted = decrypt(encrypted, encryptionKey, authenticationKey);
    expect(decrypted).toBe(text);
  });

  test('should fail decryption with wrong encryption key', () => {
    const { encryptionKey, authenticationKey } = generateKeys();
    const wrongKeys = generateKeys();
    const text = 'hello world';
    const encrypted = encrypt(text, encryptionKey, authenticationKey);
    expect(() => decrypt(encrypted, wrongKeys.encryptionKey, authenticationKey)).toThrow();
  });

  test('should fail decryption with wrong authentication key', () => {
    const { encryptionKey, authenticationKey } = generateKeys();
    const wrongKeys = generateKeys();
    const text = 'hello world';
    const encrypted = encrypt(text, encryptionKey, authenticationKey);
    expect(() => decrypt(encrypted, encryptionKey, wrongKeys.authenticationKey)).toThrow();
  });
});
