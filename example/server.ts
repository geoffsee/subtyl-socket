import { WebSocketServer } from "ws";
import { SecureProvider } from "../src/SecureProvider";
import { MessageEncryptionPlugin } from "../src/MessageEncryptionPlugin";

const PORT = 9876;

console.log(`🏛️  Server starting on port ${PORT}`);
console.log("📡 Waiting for client connection...");

const wss = new WebSocketServer({ port: PORT });
const provider = new SecureProvider();

let encryptionPlugin: MessageEncryptionPlugin | null = null;
let messageCount = 0;

wss.on("connection", (ws) => {
    console.log("✅ Client connected!");
    console.log("");

    console.log("🤝 STEP 1: Initiating secure handshake");
    provider.startHandshake(ws);

    ws.on("message", (data) => {
        try {
            const message = data.toString();

            // Show raw message received
            console.log("📨 Raw message received:");
            console.log(`   ${message.length} bytes: ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`);

            const msg = JSON.parse(message);

            if (msg.type === "handshake-response") {
                console.log("");
                console.log("🔄 STEP 2: Processing handshake response");
                const confirmation = provider.handleResponse(msg);

                if (confirmation.type === "send-confirmation") {
                    console.log("✅ Handshake response valid, sending key confirmation...");
                    ws.send(JSON.stringify({
                        type: "key-confirmation-request",
                        confirmationMac: confirmation.confirmationMac
                    }));
                } else if (confirmation.type === "error") {
                    console.log("❌ Handshake failed:", confirmation.error);
                }

            } else if (msg.type === "key-confirmation") {
                console.log("");
                console.log("🔒 STEP 3: Verifying key confirmation");
                const complete = provider.handleResponse(msg);

                if (complete.confirmed) {
                    const keys = provider.getDerivedKeys();
                    console.log("🎉 Handshake complete! Keys derived:");
                    console.log(`   Encryption key: ${keys!.encryptionKey.toString("hex").substring(0, 32)}...`);
                    console.log(`   Auth key: ${keys!.authenticationKey.toString("hex").substring(0, 32)}...`);

                    // Initialize encryption
                    encryptionPlugin = new MessageEncryptionPlugin(keys!);
                    console.log(`   Algorithm: ${encryptionPlugin.getAlgorithmName()}`);

                    console.log("");
                    console.log("💬 STEP 4: Sending encrypted message");

                    // Send first encrypted message
                    const plaintext = "Hello from server! This message is encrypted. 🔐";
                    console.log(`📝 Plaintext to encrypt: "${plaintext}"`);

                    const encrypted = encryptionPlugin.wrapMessage("greeting", plaintext);
                    console.log(`🔒 Encrypted message (${encrypted.length} bytes):`);
                    console.log(`   ${encrypted.substring(0, 150)}...`);

                    ws.send(encrypted);
                } else {
                    console.log("❌ Key confirmation failed:", complete.error);
                }

            } else if (msg.type === "encrypted-plugin-message" && encryptionPlugin) {
                console.log("");
                console.log(`📨 ENCRYPTED MESSAGE #${++messageCount} RECEIVED:`);
                console.log(`   Raw encrypted (${message.length} bytes): ${message.substring(0, 100)}...`);

                const unwrapped = encryptionPlugin.unwrapMessage(message);
                if (unwrapped) {
                    console.log(`✅ Decrypted successfully:`);
                    console.log(`   Message type: ${unwrapped.messageType}`);
                    console.log(`   Plaintext: "${unwrapped.payload}"`);

                    // Send a reply
                    if (messageCount < 3) {
                        console.log("");
                        console.log(`💬 Sending encrypted reply #${messageCount}:`);
                        const replyText = `Server reply #${messageCount}: Message received and decrypted successfully! 🎯`;
                        console.log(`📝 Reply plaintext: "${replyText}"`);

                        const encryptedReply = encryptionPlugin.wrapMessage("reply", replyText);
                        console.log(`🔒 Encrypted reply (${encryptedReply.length} bytes): ${encryptedReply.substring(0, 100)}...`);
                        ws.send(encryptedReply);
                    } else {
                        // End demo after a few exchanges
                        console.log("");
                        console.log("🏁 Demo complete! Cleaning up...");
                        setTimeout(() => {
                            encryptionPlugin?.destroy();
                            provider.destroy();
                            ws.close();
                            process.exit(0);
                        }, 1000);
                    }
                } else {
                    console.log("❌ Failed to decrypt message!");
                }
            }

        } catch (error) {
            console.log("❌ Error processing message:", error);
        }
    });

    ws.on("close", () => {
        console.log("📡 Client disconnected");
        encryptionPlugin?.destroy();
        provider.destroy();
    });

    ws.on("error", (error) => {
        console.log("❌ WebSocket error:", error);
    });
});

console.log("");