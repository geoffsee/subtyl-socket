import { MessageEncryptionPlugin } from "../MessageEncryptionPlugin";
import { generateKeys } from "../crypto-utils";
import { expect, test, describe } from "bun:test";

describe("MessageEncryptionPlugin", () => {
    test("should encrypt and decrypt a message", () => {
        const keys = generateKeys();
        const plugin = new MessageEncryptionPlugin(keys);
        const message = "hello world";

        const encrypted = plugin.encrypt(message);
        const decrypted = plugin.decrypt(encrypted);

        expect(decrypted).toBe(message);
    });

    test("getAlgorithmName should return correct algorithm", () => {
        const plugin = new MessageEncryptionPlugin();
        expect(plugin.getAlgorithmName()).toBe("aes-256-gcm");
    });
});
