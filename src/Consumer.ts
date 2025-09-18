import { createECDH, createHash } from "crypto";

interface Message {
    type: string;
    publicKey?: string;
    salt?: string;
}

export class Consumer {
    private ecdh = createECDH("prime256v1");
    private sharedKey?: Buffer;

    constructor() {
        this.ecdh.generateKeys();
    }

    handleMessage(raw: any) {
        const data = this._normalize(raw) as Message | null;
        if (!data) return;

        if (data.type === "public-key") {
            if (!data.salt) throw new Error("Handshake missing salt");
            this.deriveSharedKey(data.publicKey!, data.salt);
        }
    }

    deriveSharedKey(peerPublicKeyBase64: string, salt: string): Buffer {
        const peerKey = Buffer.from(peerPublicKeyBase64, "base64");
        const sharedSecret = this.ecdh.computeSecret(peerKey);
        this.sharedKey = createHash("sha256")
            .update(sharedSecret)
            .update(salt)
            .digest();

        return this.sharedKey;
    }

    getSharedKey(): Buffer | undefined {
        return this.sharedKey;
    }

    private _normalize(raw: any): Message | null {
        try {
            return typeof raw === "string" ? JSON.parse(raw) : raw;
        } catch {
            return null;
        }
    }
}
