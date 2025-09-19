/*
 * Copyright (c) 2025 Geoff Seemueller. All rights reserved.
 * This software and associated documentation files are proprietary and confidential.
 * Unauthorized copying, distribution, or use is strictly prohibited.
 */

import { createECDH, createHmac } from 'crypto';
import { HKDF, SecureRandom, createContextInfo, constantTimeCompare } from './crypto-utils.ts';

interface HandshakeState {
  sessionId: string;
  providerNonce: Buffer;
  consumerNonce?: Buffer;
  sharedSecret?: Buffer;
  derivedKeys?: {
    encryptionKey: Buffer;
    authenticationKey: Buffer;
    confirmationKey: Buffer;
  };
  confirmed: boolean;
}

export class SecureProvider {
  private ecdh = createECDH('prime256v1');
  private handshakeState: HandshakeState;

  constructor() {
    this.ecdh.generateKeys();
    this.handshakeState = {
      sessionId: SecureRandom.base64(16),
      providerNonce: SecureRandom.bytes(32),
      confirmed: false,
    };
  }

  /**
   * Initiates the secure handshake with proper key confirmation
   */
  startHandshake(socket: any): void {
    const message = {
      type: 'handshake-init',
      version: 1,
      sessionId: this.handshakeState.sessionId,
      publicKey: this.ecdh.getPublicKey('base64'),
      providerNonce: this.handshakeState.providerNonce.toString('base64'),
      supportedCiphers: ['aes-256-gcm'],
      supportedHashes: ['sha256'],
    };

    socket.send(JSON.stringify(message));
  }

  /**
   * Handles the consumer's response and completes key confirmation
   */
  handleResponse(message: any): {
    type: string;
    confirmed: boolean;
    error?: string;
    confirmationMac?: string;
  } {
    try {
      const data = this._normalizeMessage(message);

      if (data.type === 'handshake-response') {
        return this._processHandshakeResponse(data);
      } else if (data.type === 'key-confirmation') {
        return this._processKeyConfirmation(data);
      }

      return { type: 'error', confirmed: false, error: 'Unknown message type' };
    } catch (error) {
      return { type: 'error', confirmed: false, error: (error as Error).message };
    }
  }

  private _processHandshakeResponse(data: any): {
    type: string;
    confirmed: boolean;
    confirmationMac?: string;
  } {
    // Validate session ID
    if (data.sessionId !== this.handshakeState.sessionId) {
      throw new Error('Session ID mismatch');
    }

    // Store consumer's nonce and public key
    this.handshakeState.consumerNonce = Buffer.from(data.consumerNonce, 'base64');
    const consumerPublicKey = Buffer.from(data.publicKey, 'base64');

    // Compute shared secret
    this.handshakeState.sharedSecret = this.ecdh.computeSecret(consumerPublicKey);

    // Derive keys using HKDF with proper context separation
    this._deriveKeys();

    // Generate key confirmation MAC
    const confirmationData = Buffer.concat([
      this.handshakeState.providerNonce,
      this.handshakeState.consumerNonce!,
      this.ecdh.getPublicKey(),
      consumerPublicKey,
    ]);

    const confirmationMac = createHmac('sha256', this.handshakeState.derivedKeys!.confirmationKey)
      .update(confirmationData)
      .digest();

    return {
      type: 'send-confirmation',
      confirmed: false,
      confirmationMac: confirmationMac.toString('base64'),
    };
  }

  private _processKeyConfirmation(data: any): { type: string; confirmed: boolean } {
    const receivedMac = Buffer.from(data.confirmationMac, 'base64');

    // Compute expected confirmation MAC from consumer
    const confirmationData = Buffer.concat([
      this.handshakeState.consumerNonce!,
      this.handshakeState.providerNonce,
      Buffer.from(data.publicKey, 'base64'),
      this.ecdh.getPublicKey(),
    ]);

    const expectedMac = createHmac('sha256', this.handshakeState.derivedKeys!.confirmationKey)
      .update(confirmationData)
      .digest();

    // Use constant-time comparison to prevent timing attacks
    if (constantTimeCompare(receivedMac, expectedMac)) {
      this.handshakeState.confirmed = true;
      return { type: 'handshake-complete', confirmed: true };
    }

    throw new Error('Key confirmation failed - potential MITM attack');
  }

  private _deriveKeys(): void {
    if (!this.handshakeState.sharedSecret || !this.handshakeState.consumerNonce) {
      throw new Error('Cannot derive keys without shared secret and nonces');
    }

    const salt = Buffer.concat([
      this.handshakeState.providerNonce,
      this.handshakeState.consumerNonce,
    ]);

    // Derive multiple keys with proper context separation
    const encryptionInfo = createContextInfo('SubtylSocket-Encryption');
    const authInfo = createContextInfo('SubtylSocket-Authentication');
    const confirmationInfo = createContextInfo('SubtylSocket-KeyConfirmation');

    this.handshakeState.derivedKeys = {
      encryptionKey: HKDF.derive(this.handshakeState.sharedSecret, salt, encryptionInfo, 32),
      authenticationKey: HKDF.derive(this.handshakeState.sharedSecret, salt, authInfo, 32),
      confirmationKey: HKDF.derive(this.handshakeState.sharedSecret, salt, confirmationInfo, 32),
    };
  }

  /**
   * Returns the derived keys if handshake is confirmed
   */
  getDerivedKeys(): { encryptionKey: Buffer; authenticationKey: Buffer } | null {
    if (!this.handshakeState.confirmed || !this.handshakeState.derivedKeys) {
      return null;
    }

    return {
      encryptionKey: this.handshakeState.derivedKeys.encryptionKey,
      authenticationKey: this.handshakeState.derivedKeys.authenticationKey,
    };
  }

  /**
   * Checks if the handshake has been successfully completed and confirmed
   */
  isHandshakeConfirmed(): boolean {
    return this.handshakeState.confirmed;
  }

  /**
   * Gets the session ID for this handshake
   */
  getSessionId(): string {
    return this.handshakeState.sessionId;
  }

  private _normalizeMessage(raw: any): any {
    try {
      return typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      throw new Error('Invalid message format');
    }
  }

  /**
   * Securely clears sensitive data from memory
   */
  destroy(): void {
    if (this.handshakeState.sharedSecret) {
      this.handshakeState.sharedSecret.fill(0);
    }
    if (this.handshakeState.derivedKeys) {
      this.handshakeState.derivedKeys.encryptionKey.fill(0);
      this.handshakeState.derivedKeys.authenticationKey.fill(0);
      this.handshakeState.derivedKeys.confirmationKey.fill(0);
      this.handshakeState.derivedKeys = undefined;
    }
    this.handshakeState.providerNonce.fill(0);
    if (this.handshakeState.consumerNonce) {
      this.handshakeState.consumerNonce.fill(0);
    }
    this.handshakeState.confirmed = false;
  }
}
