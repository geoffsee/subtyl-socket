import { WebSocketServer, WebSocket } from "ws";
import { SecureProvider, SecureConsumer } from "../src/index";
import { MessageEncryptionPlugin } from "../src/MessageEncryptionPlugin";

/**
 * A demonstration of secure key exchange in the spirit of Benjamin Franklin's
 * careful experimental method - with proper documentation and verification
 * Now using the MessageEncryptionPlugin for secure message handling
 */

console.log("🔬 Franklin's Secure Socket Demonstration");
console.log("========================================");
console.log("Demonstrating proper cryptographic key exchange with mutual authentication");
console.log("");

// Provider side - The generous party who initiates discourse
const wss = new WebSocketServer({ port: 7438 });
const provider = new SecureProvider();
let providerKeys: { encryptionKey: Buffer; authenticationKey: Buffer } | null = null;
let providerEncryption: MessageEncryptionPlugin;

wss.on("connection", (ws) => {
    console.log("📡 Consumer has connected to our secure establishment");

    // Step 1: Provider initiates the handshake
    console.log("🤝 Provider: Initiating secure handshake...");
    provider.startHandshake(ws);

    ws.on("message", (data) => {
        try {
            const msg = JSON.parse(data.toString());

            if (msg.type === "handshake-response") {
                console.log("📝 Provider: Received consumer's response, processing...");
                const confirmation = provider.handleResponse(msg);

                if (confirmation.type === "send-confirmation") {
                    console.log("🔐 Provider: Sending key confirmation...");
                    ws.send(JSON.stringify({
                        type: "key-confirmation-request",
                        confirmationMac: confirmation.confirmationMac
                    }));
                } else if (confirmation.type === "error") {
                    console.log("❌ Provider: Handshake failed:", confirmation.error);
                }

            } else if (msg.type === "key-confirmation") {
                console.log("✅ Provider: Verifying final confirmation...");
                const complete = provider.handleResponse(msg);

                if (complete.confirmed) {
                    providerKeys = provider.getDerivedKeys();
                    console.log("🎉 Provider: Handshake successfully completed!");
                    console.log("🔑 Provider: Derived encryption key:", providerKeys?.encryptionKey.toString("hex").substring(0, 16) + "...");

                    // Initialize encryption plugin with derived keys
                    providerEncryption = new MessageEncryptionPlugin(providerKeys!);
                    console.log("🔐 Provider: Encryption plugin initialized with algorithm:", providerEncryption.getAlgorithmName());

                    // Send encrypted greeting using the plugin
                    const secret = "Greetings! This message encrypted with MessageEncryptionPlugin. -B. Franklin";
                    const encryptedMessage = providerEncryption.wrapMessage("chat", secret);
                    ws.send(encryptedMessage);

                } else {
                    console.log("❌ Provider: Final confirmation failed:", complete.error);
                }

            } else if (msg.type === "encrypted-plugin-message" && providerEncryption) {
                const unwrapped = providerEncryption.unwrapMessage(data.toString());
                console.log("📨 Provider received encrypted reply:", unwrapped?.payload);

                // Clean up
                setTimeout(() => {
                    providerEncryption.destroy();
                    provider.destroy();
                    console.log("🧹 Provider: Securely destroyed sensitive key material and plugin");
                    process.exit(0);
                }, 1000);
            }

        } catch (error) {
            console.log("❌ Provider: Error processing message:", error);
        }
    });

    ws.on("close", () => {
        console.log("📡 Consumer disconnected");
        provider.destroy();
    });
});

// Consumer side - The cautious party who receives and verifies
setTimeout(() => {
    const consumer = new SecureConsumer();
    const ws = new WebSocket("ws://localhost:7438");
    let consumerKeys: { encryptionKey: Buffer; authenticationKey: Buffer } | null = null;
    let consumerEncryption: MessageEncryptionPlugin;

    ws.on("open", () => {
        console.log("📡 Consumer: Connected to Provider's establishment");
    });

    ws.on("message", (data) => {
        try {
            const msg = JSON.parse(data.toString());

            if (msg.type === "handshake-init") {
                console.log("📝 Consumer: Received handshake initiation, responding...");
                const response = consumer.handleMessage(data.toString());

                if (response.type === "handshake-response") {
                    ws.send(JSON.stringify(response.response));
                } else if (response.type === "error") {
                    console.log("❌ Consumer: Handshake initiation failed:", response.error);
                }

            } else if (msg.type === "key-confirmation-request") {
                console.log("🔐 Consumer: Received key confirmation request, verifying...");
                const confirmation = consumer.handleMessage(data.toString());

                if (confirmation.confirmed) {
                    consumerKeys = consumer.getDerivedKeys();
                    console.log("🎉 Consumer: Handshake successfully completed!");
                    console.log("🔑 Consumer: Derived encryption key:", consumerKeys?.encryptionKey.toString("hex").substring(0, 16) + "...");

                    // Initialize encryption plugin with derived keys
                    consumerEncryption = new MessageEncryptionPlugin(consumerKeys!);
                    console.log("🔐 Consumer: Encryption plugin initialized with algorithm:", consumerEncryption.getAlgorithmName());

                    ws.send(JSON.stringify(confirmation.response));
                } else {
                    console.log("❌ Consumer: Key confirmation failed:", confirmation.error);
                }

            } else if (msg.type === "encrypted-plugin-message" && consumerEncryption) {
                const unwrapped = consumerEncryption.unwrapMessage(data.toString());
                console.log("📨 Consumer received encrypted message:", unwrapped?.payload);

                // Send an encrypted reply using the plugin
                const reply = "Your secure message received with gratitude. The MessageEncryptionPlugin experiment succeeds! -A Fellow Natural Philosopher";
                const encryptedReply = consumerEncryption.wrapMessage("chat-reply", reply);
                ws.send(encryptedReply);

                // Clean up
                setTimeout(() => {
                    consumerEncryption.destroy();
                    consumer.destroy();
                    console.log("🧹 Consumer: Securely destroyed sensitive key material and plugin");
                    ws.close();
                }, 500);
            }

        } catch (error) {
            console.log("❌ Consumer: Error processing message:", error);
        }
    });

    ws.on("error", (error) => {
        console.log("❌ Consumer: WebSocket error:", error);
        consumer.destroy();
    });

    ws.on("close", () => {
        console.log("📡 Consumer: Connection closed");
        consumer.destroy();
    });

}, 1000); // Give server time to start

console.log("");
console.log("🔬 Observe the careful progression of the secure handshake:");
console.log("   1. Provider initiates with public key and nonce");
console.log("   2. Consumer responds with its public key and nonce");
console.log("   3. Both parties derive identical keys using HKDF");
console.log("   4. Mutual authentication through key confirmation");
console.log("   5. Secure message exchange using derived encryption keys");
console.log("   6. Proper cleanup of sensitive key material");
console.log("");