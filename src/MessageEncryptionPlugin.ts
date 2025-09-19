/*
 * Copyright (c) 2025 Geoff Seemueller. All rights reserved.
 * This software and associated documentation files are proprietary and confidential.
 * Unauthorized copying, distribution, or use is strictly prohibited.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import {
  BaseEncryptionPlugin,
  type EncryptionKeys,
  type EncryptionResult,
} from './BaseEncryptionPlugin';

interface AESGCMResult extends EncryptionResult {
  data: string;
  metadata: {
    iv: string;
    tag: string;
  };
}

/**
 * AES-256-GCM implementation of the encryption plugin
 * Provides authenticated encryption with additional data protection
 */
export class MessageEncryptionPlugin extends BaseEncryptionPlugin {
  constructor(keys?: EncryptionKeys) {
    super('aes-256-gcm', keys);
  }

  /**
   * Encrypts plaintext using AES-256-GCM
   */
  encrypt(plaintext: string): AESGCMResult {
    if (!this.keys) {
      throw new Error('Encryption keys not set');
    }

    const iv = randomBytes(12); // 96-bit IV for GCM
    const cipher = createCipheriv('aes-256-gcm', this.keys.encryptionKey, iv);

    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

    const tag = cipher.getAuthTag();

    return {
      data: ciphertext.toString('base64'),
      metadata: {
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
      },
    };
  }

  /**
   * Decrypts ciphertext using AES-256-GCM
   */
  decrypt(encrypted: EncryptionResult): string {
    if (!this.keys) {
      throw new Error('Encryption keys not set');
    }

    if (!encrypted.metadata?.iv || !encrypted.metadata?.tag) {
      throw new Error('Missing required metadata for AES-GCM decryption');
    }

    const iv = Buffer.from(encrypted.metadata.iv, 'base64');
    const ciphertext = Buffer.from(encrypted.data, 'base64');
    const tag = Buffer.from(encrypted.metadata.tag, 'base64');

    const decipher = createDecipheriv('aes-256-gcm', this.keys.encryptionKey, iv);
    decipher.setAuthTag(tag);

    return decipher.update(ciphertext, undefined, 'utf8') + decipher.final('utf8');
  }
}
