import { createECDH, createHash, randomBytes } from "crypto";

export class Provider {
    private ecdh = createECDH("prime256v1");

    constructor() {
        this.ecdh.generateKeys();
    }

    startHandshake(socket: any) {
        const salt = randomBytes(16).toString("base64");
        const message = {
            type: "public-key",
            publicKey: this.ecdh.getPublicKey("base64"),
            salt,
        };
        socket.send(JSON.stringify(message));
    }

    deriveSharedKey(peerPublicKeyBase64: string, salt: string): Buffer {
        const peerKey = Buffer.from(peerPublicKeyBase64, "base64");
        const sharedSecret = this.ecdh.computeSecret(peerKey);
        return createHash("sha256").update(sharedSecret).update(salt).digest();
    }
}
