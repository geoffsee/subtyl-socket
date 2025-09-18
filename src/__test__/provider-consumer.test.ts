import { test, expect, beforeEach, describe } from 'bun:test';
import { Provider } from '../Provider';
import { Consumer } from '../Consumer';
import { EventEmitter } from 'events';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

class FakeSocket extends EventEmitter {
  sent: any[] = [];
  send(message: string) {
    this.sent.push(message);
    this.emit('message', { data: message });
  }
}

// Simple AES-GCM helpers
function encrypt(key: Buffer, plaintext: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

function decrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer) {
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
}

describe('Provider ↔ Consumer handshake', () => {
  let provider: Provider;
  let consumer: Consumer;
  let socket: FakeSocket;

  beforeEach(() => {
    provider = new Provider();
    consumer = new Consumer();
    socket = new FakeSocket();

    // Hook Consumer to listen for messages from socket
    socket.on('message', event => {
      consumer.handleMessage(event.data);
    });
  });

  test('derives matching shared keys', () => {
    provider.startHandshake(socket);

    const message = JSON.parse(socket.sent[0]);
    const consumerKey = consumer.getSharedKey();
    expect(consumerKey).toBeInstanceOf(Buffer);
    expect(consumerKey!.length).toBe(32);

    const providerKey = provider.deriveSharedKey(
      consumer['ecdh'].getPublicKey('base64'),
      message.salt,
    );

    expect(providerKey.equals(consumerKey!)).toBe(true);
  });

  test('can encrypt and decrypt with shared key', () => {
    provider.startHandshake(socket);
    const message = JSON.parse(socket.sent[0]);
    const consumerKey = consumer.getSharedKey()!;
    const providerKey = provider.deriveSharedKey(
      consumer['ecdh'].getPublicKey('base64'),
      message.salt,
    );

    // Provider encrypts, Consumer decrypts
    const secretMsg = 'geoff’s socket handshake 🔑';
    const { iv, ciphertext, tag } = encrypt(providerKey, secretMsg);
    const decrypted = decrypt(consumerKey, iv, ciphertext, tag);

    expect(decrypted).toBe(secretMsg);
  });

  test('tampered salt yields different keys', () => {
    provider.startHandshake(socket);
    const message = JSON.parse(socket.sent[0]);
    const consumerKey = consumer.getSharedKey()!;

    // Maliciously flip salt before Provider derives
    const badSalt = Buffer.from(message.salt, 'base64');
    badSalt[0] = (badSalt[0] || 0) ^ 0xff; // flip a byte
    const providerKey = provider.deriveSharedKey(
      consumer['ecdh'].getPublicKey('base64'),
      badSalt.toString('base64'),
    );

    expect(providerKey.equals(consumerKey)).toBe(false);
  });
});
