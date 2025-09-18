export interface EncryptionKeys {
  encryptionKey: Buffer;
  authenticationKey: Buffer;
}

export interface EncryptionResult {
  data: string;
  metadata?: Record<string, any>;
}

export interface PluginMessage {
  type: string;
  algorithm: string;
  payload: any;
  encrypted?: EncryptionResult;
}

/**
 * Abstract base class for encryption plugins
 * Provides a common interface for different encryption algorithms
 */
export abstract class BaseEncryptionPlugin {
  protected keys: EncryptionKeys | null = null;
  protected enabled: boolean = false;
  protected readonly algorithmName: string;

  constructor(algorithmName: string, keys?: EncryptionKeys) {
    this.algorithmName = algorithmName;
    if (keys) {
      this.setKeys(keys);
    }
  }

  /**
   * Sets the encryption keys derived from secure handshake
   */
  setKeys(keys: EncryptionKeys): void {
    this.keys = keys;
    this.enabled = true;
  }

  /**
   * Enables or disables encryption
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /**
   * Checks if encryption is available and enabled
   */
  isEnabled(): boolean {
    return this.enabled && this.keys !== null;
  }

  /**
   * Gets the algorithm name used by this plugin
   */
  getAlgorithmName(): string {
    return this.algorithmName;
  }

  /**
   * Abstract method to encrypt plaintext
   * Must be implemented by concrete classes
   */
  abstract encrypt(_plaintext: string): EncryptionResult;

  /**
   * Abstract method to decrypt ciphertext
   * Must be implemented by concrete classes
   */
  abstract decrypt(_encrypted: EncryptionResult): string;

  /**
   * Processes an outgoing message, encrypting if enabled
   */
  processOutgoingMessage(message: any): string {
    if (!this.isEnabled()) {
      return typeof message === 'string' ? message : JSON.stringify(message);
    }

    const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
    const encrypted = this.encrypt(messageStr);

    const pluginMessage: PluginMessage = {
      type: 'encrypted-plugin-message',
      algorithm: this.algorithmName,
      payload: null,
      encrypted,
    };

    return JSON.stringify(pluginMessage);
  }

  /**
   * Processes an incoming message, decrypting if encrypted
   */
  processIncomingMessage(rawMessage: string | Buffer): any {
    const messageStr = rawMessage.toString();

    try {
      const parsed = JSON.parse(messageStr);

      // Check if this is an encrypted plugin message
      if (parsed.type === 'encrypted-plugin-message' && parsed.encrypted) {
        if (!this.isEnabled()) {
          throw new Error('Received encrypted message but encryption not enabled');
        }

        // Verify algorithm compatibility
        if (parsed.algorithm && parsed.algorithm !== this.algorithmName) {
          throw new Error(
            `Algorithm mismatch: expected ${this.algorithmName}, got ${parsed.algorithm}`,
          );
        }

        const decrypted = this.decrypt(parsed.encrypted);
        return JSON.parse(decrypted);
      }

      // Return as-is if not encrypted
      return parsed;
    } catch {
      // If JSON parsing fails, return raw message
      return messageStr;
    }
  }

  /**
   * Creates a secure message wrapper for non-JSON payloads
   */
  wrapMessage(type: string, payload: any, encrypt: boolean = true): string {
    const message = { type, payload };

    if (encrypt && this.isEnabled()) {
      return this.processOutgoingMessage(message);
    }

    return JSON.stringify(message);
  }

  /**
   * Extracts message type and payload from wrapped messages
   */
  unwrapMessage(rawMessage: string | Buffer): { type: string; payload: any } | null {
    try {
      const processed = this.processIncomingMessage(rawMessage);

      if (typeof processed === 'object' && processed.type) {
        return {
          type: processed.type,
          payload: processed.payload || processed,
        };
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Securely clears encryption keys from memory
   * Can be overridden by subclasses for additional cleanup
   */
  destroy(): void {
    if (this.keys) {
      this.keys.encryptionKey.fill(0);
      this.keys.authenticationKey.fill(0);
      this.keys = null;
    }
    this.enabled = false;
  }
}
