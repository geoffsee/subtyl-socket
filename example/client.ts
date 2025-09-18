import { WebSocket } from 'ws';
import { SecureConsumer } from '../src/SecureConsumer';
import { MessageEncryptionPlugin } from '../src/MessageEncryptionPlugin';

const SERVER_URL = 'ws://localhost:9876';

console.log(`🔌 Client connecting to ${SERVER_URL}`);

const consumer = new SecureConsumer();
let encryptionPlugin: MessageEncryptionPlugin | null = null;
let messageCount = 0;

const ws = new WebSocket(SERVER_URL);

ws.on('open', () => {
  console.log('✅ Connected to server!');
  console.log('');
});

ws.on('message', data => {
  try {
    const message = data.toString();

    // Show raw message received
    console.log('📨 Raw message received:');
    console.log(
      `   ${message.length} bytes: ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`,
    );

    const msg = JSON.parse(message);

    if (msg.type === 'handshake-init') {
      console.log('');
      console.log('🤝 STEP 1: Received handshake initiation');
      console.log(`   Server public key: ${msg.publicKey.substring(0, 32)}...`);
      console.log(`   Server nonce: ${msg.providerNonce.substring(0, 32)}...`);

      const response = consumer.handleMessage(message);

      if (response.type === 'handshake-response') {
        console.log('✅ Sending handshake response with our public key');
        ws.send(JSON.stringify(response.response));
      } else if (response.type === 'error') {
        console.log('❌ Handshake initiation failed:', response.error);
      }
    } else if (msg.type === 'key-confirmation-request') {
      console.log('');
      console.log('🔒 STEP 2: Received key confirmation request');
      console.log(`   Confirmation MAC: ${msg.confirmationMac.substring(0, 32)}...`);

      const confirmation = consumer.handleMessage(message);

      if (confirmation.confirmed) {
        const keys = consumer.getDerivedKeys();
        console.log('🎉 Handshake complete! Keys derived:');
        console.log(
          `   Encryption key: ${keys!.encryptionKey.toString('hex').substring(0, 32)}...`,
        );
        console.log(`   Auth key: ${keys!.authenticationKey.toString('hex').substring(0, 32)}...`);

        // Initialize encryption
        encryptionPlugin = new MessageEncryptionPlugin(keys!);
        console.log(`   Algorithm: ${encryptionPlugin.getAlgorithmName()}`);

        console.log('✅ Sending final confirmation');
        ws.send(JSON.stringify(confirmation.response));
      } else {
        console.log('❌ Key confirmation failed:', confirmation.error);
      }
    } else if (msg.type === 'encrypted-plugin-message' && encryptionPlugin) {
      console.log('');
      console.log(`📨 ENCRYPTED MESSAGE #${++messageCount} RECEIVED:`);
      console.log(`   Raw encrypted (${message.length} bytes): ${message.substring(0, 100)}...`);

      const unwrapped = encryptionPlugin.unwrapMessage(message);
      if (unwrapped) {
        console.log(`✅ Decrypted successfully:`);
        console.log(`   Message type: ${unwrapped.type}`);
        console.log(`   Plaintext: "${unwrapped.payload}"`);

        // Send a reply
        console.log('');
        console.log(`💬 Sending encrypted reply #${messageCount}:`);
        const replyText = `Client reply #${messageCount}: Got your encrypted message! Here's my encrypted response. 🚀`;
        console.log(`📝 Reply plaintext: "${replyText}"`);

        const encryptedReply = encryptionPlugin.wrapMessage('client-reply', replyText);
        console.log(
          `🔒 Encrypted reply (${encryptedReply.length} bytes): ${encryptedReply.substring(0, 100)}...`,
        );
        ws.send(encryptedReply);

        // Close after a few exchanges
        if (messageCount >= 3) {
          console.log('');
          console.log('🏁 Demo complete! Closing connection...');
          setTimeout(() => {
            encryptionPlugin?.destroy();
            consumer.destroy();
            ws.close();
          }, 500);
        }
      } else {
        console.log('❌ Failed to decrypt message!');
      }
    }
  } catch (error) {
    console.log('❌ Error processing message:', error);
  }
});

ws.on('error', error => {
  console.log('❌ WebSocket error:', error);
  consumer.destroy();
});

ws.on('close', () => {
  console.log('📡 Connection closed');
  encryptionPlugin?.destroy();
  consumer.destroy();
  setTimeout(() => process.exit(0), 100);
});
