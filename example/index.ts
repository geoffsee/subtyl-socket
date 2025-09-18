#!/usr/bin/env bun

/**
 * Crypto Flow Demonstration
 *
 * This example spawns separate server and client processes to clearly demonstrate
 * the encrypted message flow over WebSocket. Watch the console output to see
 * exactly what data is encrypted, transmitted, and decrypted.
 */

import { spawn } from 'child_process';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

console.log('🔐 Subtyl Socket Encryption Flow Demo');
console.log('====================================');
console.log('');
console.log('This demo will:');
console.log('1. Start a secure server process');
console.log('2. Start a client process that connects to it');
console.log('3. Show you the actual encrypted data being transmitted');
console.log('4. Show the decrypted plaintext on both sides');
console.log('');

// Start server process
console.log('🚀 Starting server process...');
const server = spawn('bun', [join(__dirname, 'server.ts')], {
  stdio: ['inherit', 'pipe', 'pipe'],
});

server.stdout?.on('data', data => {
  process.stdout.write(`[SERVER] ${data}`);
});

server.stderr?.on('data', data => {
  process.stderr.write(`[SERVER ERROR] ${data}`);
});

// Wait a moment for server to start, then start client
setTimeout(() => {
  console.log('🚀 Starting client process...');
  console.log('');

  const client = spawn('bun', [join(__dirname, 'client.ts')], {
    stdio: ['inherit', 'pipe', 'pipe'],
  });

  client.stdout?.on('data', data => {
    process.stdout.write(`[CLIENT] ${data}`);
  });

  client.stderr?.on('data', data => {
    process.stderr.write(`[CLIENT ERROR] ${data}`);
  });

  // Clean up after demo completes
  client.on('exit', () => {
    setTimeout(() => {
      server.kill();
      console.log('');
      console.log('✅ Demo completed! You should have seen:');
      console.log('   • Key exchange and derivation');
      console.log('   • Raw encrypted data transmission');
      console.log('   • Successful decryption on both sides');
      console.log('');
      process.exit(0);
    }, 1000);
  });
}, 2000);

// Handle cleanup on exit
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down demo...');
  server.kill();
  process.exit(0);
});
