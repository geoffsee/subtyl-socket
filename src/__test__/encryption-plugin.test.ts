import { MessageEncryptionPlugin } from "../MessageEncryptionPlugin.ts";
import { EncryptionKeys } from "../BaseEncryptionPlugin.ts";
import { randomBytes } from "crypto";

console.log("🔒 Testing MessageEncryptionPlugin");
console.log("=================================");

// Create test encryption keys
const testKeys: EncryptionKeys = {
    encryptionKey: randomBytes(32), // 256-bit key for AES-256
    authenticationKey: randomBytes(32)
};

// Test 1: Basic encryption/decryption
console.log("\n1. Testing basic encryption/decryption:");
const plugin = new MessageEncryptionPlugin(testKeys);

const plaintext = "Hello, secure world!";
console.log("Original message:", plaintext);

const encrypted = plugin.encrypt(plaintext);
console.log("Encrypted data length:", encrypted.data.length);
console.log("IV length:", encrypted.metadata.iv.length);
console.log("Tag length:", encrypted.metadata.tag.length);

const decrypted = plugin.decrypt(encrypted);
console.log("Decrypted message:", decrypted);
console.log("✅ Basic encryption/decryption:", plaintext === decrypted ? "PASSED" : "FAILED");

// Test 2: Message processing
console.log("\n2. Testing message processing:");
const testMessage = { type: "chat", content: "Secret message", timestamp: Date.now() };
const processedOut = plugin.processOutgoingMessage(testMessage);
console.log("Processed outgoing message type:", JSON.parse(processedOut).type);

const processedIn = plugin.processIncomingMessage(processedOut);
console.log("Processed incoming message:", processedIn);
console.log("✅ Message processing:", JSON.stringify(testMessage) === JSON.stringify(processedIn) ? "PASSED" : "FAILED");

// Test 3: Message wrapping
console.log("\n3. Testing message wrapping:");
const wrappedMessage = plugin.wrapMessage("test-type", { data: "test-payload" });
const unwrappedMessage = plugin.unwrapMessage(wrappedMessage);
console.log("Wrapped message algorithm:", JSON.parse(wrappedMessage).algorithm);
console.log("Unwrapped message:", unwrappedMessage);
console.log("✅ Message wrapping:", unwrappedMessage?.type === "test-type" ? "PASSED" : "FAILED");

// Test 4: Disabled encryption
console.log("\n4. Testing disabled encryption:");
plugin.setEnabled(false);
const unencryptedOut = plugin.processOutgoingMessage(testMessage);
const unencryptedIn = plugin.processIncomingMessage(unencryptedOut);
console.log("Unencrypted message processing:", JSON.stringify(testMessage) === JSON.stringify(unencryptedIn) ? "PASSED" : "FAILED");

// Test 5: Algorithm verification
console.log("\n5. Testing algorithm verification:");
plugin.setEnabled(true);
console.log("Algorithm name:", plugin.getAlgorithmName());
console.log("✅ Algorithm verification:", plugin.getAlgorithmName() === "aes-256-gcm" ? "PASSED" : "FAILED");

// Test 6: Error handling
console.log("\n6. Testing error handling:");
try {
    const pluginWithoutKeys = new MessageEncryptionPlugin();
    pluginWithoutKeys.encrypt("test");
    console.log("❌ Error handling: FAILED (should have thrown error)");
} catch (error) {
    console.log("✅ Error handling: PASSED (correctly threw error for missing keys)");
}

// Test 7: Memory cleanup
console.log("\n7. Testing memory cleanup:");
const keysBefore = plugin.isEnabled();
plugin.destroy();
const keysAfter = plugin.isEnabled();
console.log("✅ Memory cleanup:", keysBefore === true && keysAfter === false ? "PASSED" : "FAILED");

console.log("\n🎉 All tests completed!");