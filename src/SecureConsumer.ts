import { createECDH, createHmac } from "crypto";
import { HKDF, SecureRandom, createContextInfo, constantTimeCompare } from "./crypto-utils.ts";

interface HandshakeState {
    sessionId?: string;
    providerNonce?: Buffer;
    consumerNonce: Buffer;
    sharedSecret?: Buffer;
    derivedKeys?: {
        encryptionKey: Buffer;
        authenticationKey: Buffer;
        confirmationKey: Buffer;
    };
    confirmed: boolean;
    providerPublicKey?: Buffer;
}

export class SecureConsumer {
    private ecdh = createECDH("prime256v1");
    private handshakeState: HandshakeState;

    constructor() {
        this.ecdh.generateKeys();
        this.handshakeState = {
            consumerNonce: SecureRandom.bytes(32),
            confirmed: false
        };
    }

    /**
     * Handles incoming messages and manages the handshake state machine
     */
    handleMessage(raw: any): { type: string; response?: any; confirmed: boolean; error?: string } {
        try {
            const data = this._normalizeMessage(raw);

            if (data.type === "handshake-init") {
                return this._processHandshakeInit(data);
            } else if (data.type === "key-confirmation-request") {
                return this._processKeyConfirmationRequest(data);
            }

            return { type: "error", confirmed: false, error: "Unknown message type" };
        } catch (error) {
            return { type: "error", confirmed: false, error: (error as Error).message };
        }
    }

    private _processHandshakeInit(data: any): { type: string; response: any; confirmed: boolean } {
        // Validate protocol version
        if (data.version !== 1) {
            throw new Error("Unsupported protocol version");
        }

        // Validate supported algorithms
        if (!data.supportedCiphers?.includes("aes-256-gcm") ||
            !data.supportedHashes?.includes("sha256")) {
            throw new Error("Unsupported cryptographic algorithms");
        }

        // Store handshake parameters
        this.handshakeState.sessionId = data.sessionId;
        this.handshakeState.providerNonce = Buffer.from(data.providerNonce, "base64");
        this.handshakeState.providerPublicKey = Buffer.from(data.publicKey, "base64");

        // Compute shared secret
        this.handshakeState.sharedSecret = this.ecdh.computeSecret(this.handshakeState.providerPublicKey);

        // Derive keys using HKDF
        this._deriveKeys();

        // Prepare response
        const response = {
            type: "handshake-response",
            sessionId: this.handshakeState.sessionId,
            publicKey: this.ecdh.getPublicKey("base64"),
            consumerNonce: this.handshakeState.consumerNonce.toString("base64"),
            selectedCipher: "aes-256-gcm",
            selectedHash: "sha256"
        };

        return {
            type: "handshake-response",
            response,
            confirmed: false
        };
    }

    private _processKeyConfirmationRequest(data: any): { type: string; response?: any; confirmed: boolean } {
        const receivedMac = Buffer.from(data.confirmationMac, "base64");

        // Compute expected confirmation MAC from provider
        const confirmationData = Buffer.concat([
            this.handshakeState.providerNonce!,
            this.handshakeState.consumerNonce,
            this.handshakeState.providerPublicKey!,
            this.ecdh.getPublicKey()
        ]);

        const expectedMac = createHmac("sha256", this.handshakeState.derivedKeys!.confirmationKey)
            .update(confirmationData)
            .digest();

        // Verify provider's confirmation MAC
        if (!constantTimeCompare(receivedMac, expectedMac)) {
            throw new Error("Provider key confirmation failed - potential MITM attack");
        }

        // Generate our own confirmation MAC
        const ourConfirmationData = Buffer.concat([
            this.handshakeState.consumerNonce,
            this.handshakeState.providerNonce!,
            this.ecdh.getPublicKey(),
            this.handshakeState.providerPublicKey!
        ]);

        const ourConfirmationMac = createHmac("sha256", this.handshakeState.derivedKeys!.confirmationKey)
            .update(ourConfirmationData)
            .digest();

        // Mark handshake as confirmed
        this.handshakeState.confirmed = true;

        const response = {
            type: "key-confirmation",
            sessionId: this.handshakeState.sessionId,
            publicKey: this.ecdh.getPublicKey("base64"),
            confirmationMac: ourConfirmationMac.toString("base64")
        };

        return {
            type: "key-confirmation",
            response,
            confirmed: true
        };
    }

    private _deriveKeys(): void {
        if (!this.handshakeState.sharedSecret || !this.handshakeState.providerNonce) {
            throw new Error("Cannot derive keys without shared secret and nonces");
        }

        const salt = Buffer.concat([
            this.handshakeState.providerNonce,
            this.handshakeState.consumerNonce
        ]);

        // Derive multiple keys with proper context separation
        const encryptionInfo = createContextInfo("SubtylSocket-Encryption");
        const authInfo = createContextInfo("SubtylSocket-Authentication");
        const confirmationInfo = createContextInfo("SubtylSocket-KeyConfirmation");

        this.handshakeState.derivedKeys = {
            encryptionKey: HKDF.derive(this.handshakeState.sharedSecret, salt, encryptionInfo, 32),
            authenticationKey: HKDF.derive(this.handshakeState.sharedSecret, salt, authInfo, 32),
            confirmationKey: HKDF.derive(this.handshakeState.sharedSecret, salt, confirmationInfo, 32)
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
            authenticationKey: this.handshakeState.derivedKeys.authenticationKey
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
    getSessionId(): string | undefined {
        return this.handshakeState.sessionId;
    }

    private _normalizeMessage(raw: any): any {
        try {
            return typeof raw === "string" ? JSON.parse(raw) : raw;
        } catch {
            throw new Error("Invalid message format");
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
        this.handshakeState.consumerNonce.fill(0);
        if (this.handshakeState.providerNonce) {
            this.handshakeState.providerNonce.fill(0);
        }
        this.handshakeState.confirmed = false;
    }
}