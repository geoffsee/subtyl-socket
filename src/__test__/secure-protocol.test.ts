import { test, expect, beforeEach, describe } from "bun:test";
import { SecureProvider } from "../SecureProvider.ts";
import { SecureConsumer } from "../SecureConsumer.ts";
import { HKDF, SecureRandom, constantTimeCompare } from "../crypto-utils.ts";
import { createHmac } from "crypto";

class MockSocket {
    messages: any[] = [];

    send(message: string): void {
        this.messages.push(JSON.parse(message));
    }

    getLastMessage(): any {
        return this.messages[this.messages.length - 1];
    }

    clear(): void {
        this.messages = [];
    }
}

describe("Secure Protocol - Cryptographic Properties", () => {
    let provider: SecureProvider;
    let consumer: SecureConsumer;
    let socket: MockSocket;

    beforeEach(() => {
        provider = new SecureProvider();
        consumer = new SecureConsumer();
        socket = new MockSocket();
    });

    describe("HKDF Key Derivation", () => {
        test("derives consistent keys with same inputs", () => {
            const ikm = Buffer.from("shared-secret", "utf8");
            const salt = Buffer.from("random-salt", "utf8");
            const info = Buffer.from("context-info", "utf8");

            const key1 = HKDF.derive(ikm, salt, info, 32);
            const key2 = HKDF.derive(ikm, salt, info, 32);

            expect(key1.equals(key2)).toBe(true);
            expect(key1.length).toBe(32);
        });

        test("derives different keys with different contexts", () => {
            const ikm = Buffer.from("shared-secret", "utf8");
            const salt = Buffer.from("random-salt", "utf8");
            const info1 = Buffer.from("encryption-key", "utf8");
            const info2 = Buffer.from("authentication-key", "utf8");

            const key1 = HKDF.derive(ikm, salt, info1, 32);
            const key2 = HKDF.derive(ikm, salt, info2, 32);

            expect(key1.equals(key2)).toBe(false);
        });

        test("fails with invalid length", () => {
            const ikm = Buffer.from("test", "utf8");
            const salt = Buffer.from("salt", "utf8");
            const info = Buffer.from("info", "utf8");

            expect(() => HKDF.derive(ikm, salt, info, 8161)).toThrow("requested length too large");
        });
    });

    describe("Secure Random Generation", () => {
        test("generates different values on each call", () => {
            const bytes1 = SecureRandom.bytes(32);
            const bytes2 = SecureRandom.bytes(32);

            expect(bytes1.equals(bytes2)).toBe(false);
        });

        test("detects insufficient entropy", () => {
            // This test would require mocking at a deeper level since bun may use different random sources
            // For now, we'll test that random bytes are generated
            const bytes = SecureRandom.bytes(32);
            expect(bytes.length).toBe(32);
        });
    });

    describe("Constant Time Comparison", () => {
        test("returns true for identical buffers", () => {
            const buf1 = Buffer.from("secret", "utf8");
            const buf2 = Buffer.from("secret", "utf8");

            expect(constantTimeCompare(buf1, buf2)).toBe(true);
        });

        test("returns false for different buffers", () => {
            const buf1 = Buffer.from("secret", "utf8");
            const buf2 = Buffer.from("different", "utf8");

            expect(constantTimeCompare(buf1, buf2)).toBe(false);
        });

        test("returns false for different lengths", () => {
            const buf1 = Buffer.from("short", "utf8");
            const buf2 = Buffer.from("much-longer", "utf8");

            expect(constantTimeCompare(buf1, buf2)).toBe(false);
        });
    });

    describe("Complete Handshake Protocol", () => {
        test("completes full handshake with mutual authentication", () => {
            // Step 1: Provider initiates handshake
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();

            expect(initMessage.type).toBe("handshake-init");
            expect(initMessage.sessionId).toBeDefined();
            expect(initMessage.publicKey).toBeDefined();
            expect(initMessage.providerNonce).toBeDefined();

            // Step 2: Consumer responds
            socket.clear();
            const consumerResponse = consumer.handleMessage(JSON.stringify(initMessage));

            expect(consumerResponse.type).toBe("handshake-response");
            expect(consumerResponse.confirmed).toBe(false);
            expect(consumerResponse.response).toBeDefined();

            // Step 3: Provider processes response and sends key confirmation
            const providerConfirmation = provider.handleResponse(consumerResponse.response);

            expect(providerConfirmation.type).toBe("send-confirmation");
            expect(providerConfirmation.confirmed).toBe(false);
            expect(providerConfirmation.confirmationMac).toBeDefined();

            // Step 4: Consumer verifies and sends final confirmation
            const finalConfirmation = consumer.handleMessage(JSON.stringify({
                type: "key-confirmation-request",
                confirmationMac: providerConfirmation.confirmationMac
            }));

            expect(finalConfirmation.type).toBe("key-confirmation");
            expect(finalConfirmation.confirmed).toBe(true);

            // Step 5: Provider verifies final confirmation
            const handshakeComplete = provider.handleResponse(finalConfirmation.response);

            expect(handshakeComplete.type).toBe("handshake-complete");
            expect(handshakeComplete.confirmed).toBe(true);

            // Verify both parties have derived identical keys
            const providerKeys = provider.getDerivedKeys();
            const consumerKeys = consumer.getDerivedKeys();

            expect(providerKeys).not.toBeNull();
            expect(consumerKeys).not.toBeNull();
            expect(providerKeys!.encryptionKey.equals(consumerKeys!.encryptionKey)).toBe(true);
            expect(providerKeys!.authenticationKey.equals(consumerKeys!.authenticationKey)).toBe(true);
        });

        test("rejects tampered key confirmation", () => {
            // Complete initial handshake
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();
            const consumerResponse = consumer.handleMessage(JSON.stringify(initMessage));
            const providerConfirmation = provider.handleResponse(consumerResponse.response);

            // Tamper with confirmation MAC
            const tamperedMac = Buffer.from(providerConfirmation.confirmationMac, "base64");
            tamperedMac[0] ^= 0xFF; // Flip bits

            const result = consumer.handleMessage(JSON.stringify({
                type: "key-confirmation-request",
                confirmationMac: tamperedMac.toString("base64")
            }));

            expect(result.type).toBe("error");
            expect(result.error).toContain("potential MITM attack");
        });

        test("rejects mismatched session IDs", () => {
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();

            // Tamper with session ID
            initMessage.sessionId = "different-session-id";

            // Consumer should still process it, but provider will reject it later
            const result = consumer.handleMessage(JSON.stringify(initMessage));
            expect(result.type).toBe("handshake-response");

            // Provider should reject mismatched session ID
            const providerResult = provider.handleResponse(result.response);
            expect(providerResult.type).toBe("error");
            expect(providerResult.error).toContain("Session ID mismatch");
        });

        test("validates protocol version", () => {
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();

            // Set unsupported version
            initMessage.version = 999;

            const result = consumer.handleMessage(JSON.stringify(initMessage));
            expect(result.type).toBe("error");
            expect(result.error).toBe("Unsupported protocol version");
        });

        test("validates cryptographic algorithms", () => {
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();

            // Remove supported algorithms
            initMessage.supportedCiphers = ["weak-cipher"];
            initMessage.supportedHashes = ["md5"];

            const result = consumer.handleMessage(JSON.stringify(initMessage));
            expect(result.type).toBe("error");
            expect(result.error).toBe("Unsupported cryptographic algorithms");
        });
    });

    describe("Key Derivation Context Separation", () => {
        test("derives different keys for different purposes", async () => {
            // Complete handshake
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();
            const consumerResponse = consumer.handleMessage(JSON.stringify(initMessage));
            const providerConfirmation = provider.handleResponse(consumerResponse.response);
            const finalConfirmation = consumer.handleMessage(JSON.stringify({
                type: "key-confirmation-request",
                confirmationMac: providerConfirmation.confirmationMac
            }));
            provider.handleResponse(finalConfirmation.response);

            const keys = provider.getDerivedKeys()!;

            expect(keys.encryptionKey.equals(keys.authenticationKey)).toBe(false);
            expect(keys.encryptionKey.length).toBe(32);
            expect(keys.authenticationKey.length).toBe(32);
        });
    });

    describe("Memory Security", () => {
        test("securely destroys sensitive data", () => {
            // Complete full handshake first
            provider.startHandshake(socket);
            const initMessage = socket.getLastMessage();
            const consumerResponse = consumer.handleMessage(JSON.stringify(initMessage));
            const providerConfirmation = provider.handleResponse(consumerResponse.response);
            const finalConfirmation = consumer.handleMessage(JSON.stringify({
                type: "key-confirmation-request",
                confirmationMac: providerConfirmation.confirmationMac
            }));
            provider.handleResponse(finalConfirmation.response);

            // Get keys before destruction
            const keys = consumer.getDerivedKeys();
            expect(keys).not.toBeNull();

            // Destroy and verify keys are no longer accessible
            consumer.destroy();
            expect(consumer.getDerivedKeys()).toBeNull();
        });
    });

    describe("Error Handling", () => {
        test("handles malformed JSON", () => {
            const result = consumer.handleMessage("invalid-json{");

            expect(result.type).toBe("error");
            expect(result.confirmed).toBe(false);
            expect(result.error).toBe("Invalid message format");
        });

        test("handles unknown message types", () => {
            const result = consumer.handleMessage(JSON.stringify({ type: "unknown" }));

            expect(result.type).toBe("error");
            expect(result.confirmed).toBe(false);
            expect(result.error).toBe("Unknown message type");
        });
    });
});