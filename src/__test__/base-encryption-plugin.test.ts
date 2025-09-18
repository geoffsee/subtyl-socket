import { BaseEncryptionPlugin, type EncryptionKeys } from "../BaseEncryptionPlugin";
import { randomBytes } from "crypto";
import { expect, test, describe } from "bun:test";

class TestPlugin extends BaseEncryptionPlugin {
    constructor(keys?: EncryptionKeys) {
        super("test-algo", keys);
    }

    encrypt(data: string): { data: string; metadata: any } {
        if (!this.keys) {
            throw new Error("No encryption keys available");
        }
        return { data: `encrypted:${data}`, metadata: {} };
    }

    decrypt(encrypted: { data: string; metadata: any }): string {
        if (!this.keys) {
            throw new Error("No encryption keys available");
        }
        return encrypted.data.replace("encrypted:", "");
    }
}

describe("BaseEncryptionPlugin", () => {
    const testKeys: EncryptionKeys = {
        encryptionKey: randomBytes(32),
        authenticationKey: randomBytes(32),
    };

    test("should be enabled by default", () => {
        const plugin = new TestPlugin(testKeys);
        expect(plugin.isEnabled()).toBe(true);
    });

    test("can be disabled", () => {
        const plugin = new TestPlugin(testKeys);
        plugin.setEnabled(false);
        expect(plugin.isEnabled()).toBe(false);
    });

    test("should throw if keys are not provided", () => {
        const plugin = new TestPlugin();
        expect(() => plugin.encrypt("test")).toThrow();
    });

    test("processOutgoingMessage should encrypt when enabled", () => {
        const plugin = new TestPlugin(testKeys);
        const message = { type: "test", payload: "hello" };
        const processed = plugin.processOutgoingMessage(message);
        const parsed = JSON.parse(processed);
        expect(parsed.algorithm).toBe("test-algo");
        expect(parsed.encrypted.data).toBe("encrypted:{\"type\":\"test\",\"payload\":\"hello\"}");
    });

    test("processOutgoingMessage should not encrypt when disabled", () => {
        const plugin = new TestPlugin(testKeys);
        plugin.setEnabled(false);
        const message = { type: "test", payload: "hello" };
        const processed = plugin.processOutgoingMessage(message);
        expect(processed).toBe(JSON.stringify(message));
    });

    test("processIncomingMessage should decrypt when encrypted", () => {
        const plugin = new TestPlugin(testKeys);
        const message = { type: "test", payload: "hello" };
        const encrypted = plugin.processOutgoingMessage(message);
        const decrypted = plugin.processIncomingMessage(encrypted);
        expect(decrypted).toEqual(message);
    });

    test("processIncomingMessage should pass through when not encrypted", () => {
        const plugin = new TestPlugin(testKeys);
        const message = { type: "test", payload: "hello" };
        const processed = plugin.processIncomingMessage(JSON.stringify(message));
        expect(processed).toEqual(message);
    });

    test("wrap and unwrap message", () => {
        const plugin = new TestPlugin(testKeys);
        const wrapped = plugin.wrapMessage("test-type", { value: 42 });
        const unwrapped = plugin.unwrapMessage(wrapped);
        expect(unwrapped).toEqual({ type: "test-type", payload: { value: 42 } });
    });

    test("destroy should clear keys and disable plugin", () => {
        const plugin = new TestPlugin(testKeys);
        plugin.destroy();
        expect(plugin.isEnabled()).toBe(false);
        expect(() => plugin.encrypt("test")).toThrow();
    });
});
