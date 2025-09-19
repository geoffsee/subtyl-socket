import { WebSocketServer, WebSocket } from 'ws';
import { SecureProvider } from '../src/SecureProvider';
import { SecureConsumer } from '../src/SecureConsumer';
import { MessageEncryptionPlugin } from '../src/MessageEncryptionPlugin';
import * as fs from 'fs';

const PORT = 9877;
const TEST_SIZES = [
  1024 * 1024, // 1MB
  5 * 1024 * 1024, // 5MB
  10 * 1024 * 1024, // 10MB
];
const TEST_ITERATIONS = 20;
const WARMUP_ITERATIONS = 3;

const wss = new WebSocketServer({ port: PORT });

wss.on('connection', ws => {
  const provider = new SecureProvider();
  let encryptionPlugin: MessageEncryptionPlugin | null = null;

  provider.startHandshake(ws);

  ws.on('message', data => {
    const message = data.toString();
    const msg = JSON.parse(message);

    if (msg.type === 'handshake-response') {
      const confirmation = provider.handleResponse(msg);
      if (confirmation.type === 'send-confirmation') {
        ws.send(
          JSON.stringify({
            type: 'key-confirmation-request',
            confirmationMac: confirmation.confirmationMac,
          }),
        );
      }
    } else if (msg.type === 'key-confirmation') {
      const complete = provider.handleResponse(msg);
      if (complete.confirmed) {
        const keys = provider.getDerivedKeys();
        encryptionPlugin = new MessageEncryptionPlugin(keys!);
      }
    } else if (msg.type === 'encrypted-plugin-message' && encryptionPlugin) {
      const unwrapped = encryptionPlugin.unwrapMessage(message);
      if (unwrapped) {
        // Echo back the payload
        const encryptedReply = encryptionPlugin.wrapMessage(
          'throughput-response',
          unwrapped.payload as string,
        );
        ws.send(encryptedReply);
      }
    } else if (msg.type === 'unencrypted-test') {
      // Echo back unencrypted payload for baseline testing
      ws.send(
        JSON.stringify({
          type: 'unencrypted-response',
          payload: msg.payload,
        }),
      );
    }
  });

  ws.on('close', () => {
    encryptionPlugin?.destroy();
    provider.destroy();
  });
});

interface TestResult {
  size: number;
  times: number[];
  avgTime: number;
  stdDev: number;
  throughputMBps: number;
  confidenceInterval: [number, number];
  pooledTime?: number;
}

async function runThroughputTest() {
  const results: TestResult[] = [];
  const baselineResults: TestResult[] = [];

  console.log('Starting throughput tests...');

  for (const size of TEST_SIZES) {
    console.log(`\nTesting ${size / (1024 * 1024)}MB payload...`);

    // Warmup iterations
    console.log('  Running warmup iterations...');
    for (let i = 0; i < WARMUP_ITERATIONS; i++) {
      await runSingleTest(size, false);
    }

    // Encrypted test iterations with connection pooling test
    console.log('  Running encrypted iterations...');
    const times = [];
    for (let i = 0; i < TEST_ITERATIONS; i++) {
      const time = await runSingleTest(size, false);
      times.push(time);
    }

    // Connection pooling test (reuse existing connection for pure encryption overhead)
    console.log('  Running connection-pooled test...');
    const pooledTime = await runPooledTest(size);

    // Baseline unencrypted iterations
    console.log('  Running unencrypted baseline...');
    const baselineTimes = [];
    for (let i = 0; i < TEST_ITERATIONS; i++) {
      const time = await runSingleTest(size, true);
      baselineTimes.push(time);
    }

    const encryptedStats = calculateStatistics(times, size);
    const baselineStats = calculateStatistics(baselineTimes, size);

    // Add pooled result note
    encryptedStats.pooledTime = pooledTime;

    results.push(encryptedStats);
    baselineResults.push(baselineStats);
  }

  generateAdvancedReport(results, baselineResults);
  console.log('Throughput test complete. Report generated at throughput-report.md');
  wss.close();
  process.exit(0);
}

function calculateStatistics(times: number[], size: number): TestResult {
  const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
  const variance = times.reduce((sum, time) => sum + Math.pow(time - avgTime, 2), 0) / times.length;
  const stdDev = Math.sqrt(variance);
  const throughputMBps = size / (1024 * 1024) / (avgTime / 1000);

  // 95% confidence interval (assuming normal distribution)
  const marginOfError = 1.96 * (stdDev / Math.sqrt(times.length));
  const confidenceInterval: [number, number] = [avgTime - marginOfError, avgTime + marginOfError];

  return {
    size,
    times,
    avgTime,
    stdDev,
    throughputMBps,
    confidenceInterval,
  };
}

function generateAdvancedReport(results: TestResult[], baselineResults: TestResult[]) {
  let report = '# 🚀 Subtyl Socket Throughput Analysis\n\n';
  report += `**Test Date:** ${new Date().toUTCString()}\n`;
  report += `**Framework:** Encrypted WebSocket with Secure Handshake\n`;
  report += `**Iterations per test:** ${TEST_ITERATIONS}\n\n`;

  // Performance Summary
  const maxThroughput = Math.max(...results.map(r => r.throughputMBps));
  const avgLatency = results.reduce((sum, r) => sum + r.avgTime, 0) / results.length;

  report += '## 📊 Performance Summary\n\n';
  report += `- **Peak Throughput:** ${maxThroughput.toFixed(1)} MB/s\n`;
  report += `- **Average Latency:** ${avgLatency.toFixed(1)}ms\n`;
  // Calculate actual encryption overhead
  const overheadPercentages = results.map((r, i) => {
    const baseline = baselineResults[i];
    if (!baseline) return 0;
    return ((r.avgTime - baseline.avgTime) / baseline.avgTime) * 100;
  });
  const avgOverhead = overheadPercentages.reduce((a, b) => a + b, 0) / overheadPercentages.length;

  report += `- **Encryption Overhead:** ${avgOverhead.toFixed(1)}% (measured)\n`;
  report += `- **Test Range:** 1MB - 10MB payloads\n\n`;

  // ASCII Chart
  report += '## 📈 Throughput Performance\n\n';
  report += '```\n';
  report += 'Throughput (MB/s)\n';
  const maxBar = 50;
  results.forEach(r => {
    const sizeLabel = `${r.size / (1024 * 1024)}MB`;
    const barLength = Math.round((r.throughputMBps / maxThroughput) * maxBar);
    const bar = '█'.repeat(barLength) + '░'.repeat(maxBar - barLength);
    report += `${sizeLabel.padEnd(5)} │${bar}│ ${r.throughputMBps.toFixed(1)} MB/s\n`;
  });
  report += '```\n\n';

  // Latency Chart
  report += '## ⚡ Latency Analysis\n\n';
  report += '```\n';
  report += 'Response Time (ms)\n';
  const maxLatency = Math.max(...results.map(r => r.avgTime));
  results.forEach(r => {
    const sizeLabel = `${r.size / (1024 * 1024)}MB`;
    const barLength = Math.round((r.avgTime / maxLatency) * maxBar);
    const bar = '█'.repeat(barLength) + '░'.repeat(maxBar - barLength);
    report += `${sizeLabel.padEnd(5)} │${bar}│ ${r.avgTime.toFixed(1)}ms\n`;
  });
  report += '```\n\n';

  // Detailed Results Table with Statistical Analysis
  report += '## 📋 Detailed Results\n\n';
  report +=
    '| Data Size | Encrypted (ms) | Baseline (ms) | Overhead | Throughput (MB/s) | Std Dev | 95% CI |\n';
  report +=
    '|-----------|----------------|---------------|----------|-------------------|---------|--------|\n';

  results.forEach((r, i) => {
    const sizeStr = `${r.size / (1024 * 1024)}MB`;
    const baseline = baselineResults[i];
    if (!baseline) return;
    const overhead = (((r.avgTime - baseline.avgTime) / baseline.avgTime) * 100).toFixed(1);
    const ciLower = r.confidenceInterval[0].toFixed(1);
    const ciUpper = r.confidenceInterval[1].toFixed(1);
    report += `| ${sizeStr} | ${r.avgTime.toFixed(1)} | ${baseline.avgTime.toFixed(1)} | +${overhead}% | ${r.throughputMBps.toFixed(1)} | ±${r.stdDev.toFixed(1)} | [${ciLower}, ${ciUpper}] |\n`;
  });

  // Add performance flow diagram
  report += '\n## 🔄 Test Flow Architecture\n\n';
  report += '```mermaid\n';
  report += 'graph TB\n';
  report += '    A[Client Connects] --> B{Encrypted Test?}\n';
  report += '    B -->|Yes| C[Secure Handshake]\n';
  report += '    B -->|No| G[Skip to Payload]\n';
  report += '    C --> D[Key Derivation]\n';
  report += '    D --> E[AES-256-GCM Encryption]\n';
  report += '    E --> F[Send Encrypted Payload]\n';
  report += '    G --> H[Send Plain Payload]\n';
  report += '    F --> I[Server Echo]\n';
  report += '    H --> I\n';
  report += '    I --> J[Measure Round-trip Time]\n';
  report += '    J --> K[Statistical Analysis]\n';
  report += '```\n\n';

  // Add performance comparison chart
  const maxLatencyForChart = Math.max(...results.map(r => r.avgTime)) * 1.1;
  const baselineData = baselineResults.map(r => r.avgTime.toFixed(1)).join(', ');
  const encryptedData = results.map(r => r.avgTime.toFixed(1)).join(', ');

  report += '## 📊 Encryption Overhead Analysis\n\n';
  report += '```mermaid\n';
  report += 'xychart-beta\n';
  report += '    title "Encryption vs Baseline Performance"\n';
  report += '    x-axis ["1MB", "5MB", "10MB"]\n';
  report += `    y-axis "Response Time (ms)" 0 --> ${maxLatencyForChart.toFixed(1)}\n`;
  report += `    line "Unencrypted Baseline" [${baselineData}]\n`;
  report += `    line "Encrypted (AES-256-GCM)" [${encryptedData}]\n`;
  report += '```\n\n';

  // Add security architecture diagram
  report += '## 🔐 Security Architecture\n\n';
  report += '```mermaid\n';
  report += 'sequenceDiagram\n';
  report += '    participant C as Client\n';
  report += '    participant S as Server\n';
  report += '    \n';
  report += '    Note over C,S: Secure Channel Establishment\n';
  report += '    C->>S: Handshake Init (ephemeral keys)\n';
  report += '    S->>C: Handshake Response\n';
  report += '    C->>S: Key Confirmation\n';
  report += '    S->>C: Confirmation ACK\n';
  report += '    \n';
  report += '    Note over C,S: Encrypted Data Transfer\n';
  report += '    C->>S: AES-256-GCM Encrypted Payload\n';
  report += '    S->>C: AES-256-GCM Encrypted Echo\n';
  report += '    \n';
  report += '    Note over C,S: Keys destroyed after session\n';
  report += '```\n\n';

  report += '\n## 🔒 Security Notes\n\n';
  report += '- End-to-end encryption with key derivation\n';
  report += '- Secure handshake protocol prevents MITM attacks\n';
  report += '- Performance includes full cryptographic overhead\n';
  report += '- Keys are ephemeral and destroyed after each test\n\n';

  report += '---\n';
  report += '*Generated by Subtyl Socket Performance Suite*\n';

  fs.writeFileSync('throughput-report.md', report);
}

function runSingleTest(size: number, unencrypted = false): Promise<number> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${PORT}`);
    const consumer = new SecureConsumer();
    let encryptionPlugin: MessageEncryptionPlugin | null = null;
    const largeData = 'a'.repeat(size);
    let handshakeComplete = false;
    let startTime: bigint;

    ws.on('message', data => {
      try {
        const message = data.toString();
        const msg = JSON.parse(message);

        if (unencrypted) {
          // For unencrypted baseline testing
          if (msg.type === 'handshake-init') {
            // Skip handshake for unencrypted test
            startTime = process.hrtime.bigint();
            ws.send(
              JSON.stringify({
                type: 'unencrypted-test',
                payload: largeData,
              }),
            );
          } else if (msg.type === 'unencrypted-response') {
            if (msg.payload === largeData) {
              const endTime = process.hrtime.bigint();
              const durationNs = Number(endTime - startTime);
              const durationMs = durationNs / 1_000_000;
              resolve(durationMs);
              ws.close();
            }
          }
        } else {
          // Encrypted testing
          if (!handshakeComplete) {
            if (msg.type === 'handshake-init') {
              const response = consumer.handleMessage(message);
              if (response.type === 'handshake-response') {
                ws.send(JSON.stringify(response.response));
              }
            } else if (msg.type === 'key-confirmation-request') {
              const confirmation = consumer.handleMessage(message);
              if (confirmation.confirmed) {
                const keys = consumer.getDerivedKeys();
                encryptionPlugin = new MessageEncryptionPlugin(keys!);
                ws.send(JSON.stringify(confirmation.response));
                handshakeComplete = true;

                // Handshake complete, start sending data
                startTime = process.hrtime.bigint();
                const encrypted = encryptionPlugin.wrapMessage('throughput-test', largeData);
                ws.send(encrypted);
              }
            }
          } else {
            if (msg.type === 'encrypted-plugin-message' && encryptionPlugin) {
              const unwrapped = encryptionPlugin.unwrapMessage(message);
              if (unwrapped && unwrapped.payload === largeData) {
                const endTime = process.hrtime.bigint();
                const durationNs = Number(endTime - startTime);
                const durationMs = durationNs / 1_000_000;
                resolve(durationMs);
                ws.close();
              }
            }
          }
        }
      } catch (error) {
        reject(error);
      }
    });

    ws.on('close', () => {
      encryptionPlugin?.destroy();
      consumer.destroy();
    });

    ws.on('error', err => {
      reject(err);
      encryptionPlugin?.destroy();
      consumer.destroy();
    });
  });
}

// Simplified pooled test - measures pure encryption overhead on established connection
function runPooledTest(size: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${PORT}`);
    const consumer = new SecureConsumer();
    let encryptionPlugin: MessageEncryptionPlugin | null = null;
    const largeData = 'a'.repeat(size);
    let handshakeComplete = false;
    let measurementCount = 0;
    const measurements: number[] = [];
    const POOL_MEASUREMENTS = 5;

    ws.on('message', data => {
      try {
        const message = data.toString();
        const msg = JSON.parse(message);

        if (!handshakeComplete) {
          if (msg.type === 'handshake-init') {
            const response = consumer.handleMessage(message);
            if (response.type === 'handshake-response') {
              ws.send(JSON.stringify(response.response));
            }
          } else if (msg.type === 'key-confirmation-request') {
            const confirmation = consumer.handleMessage(message);
            if (confirmation.confirmed) {
              const keys = consumer.getDerivedKeys();
              encryptionPlugin = new MessageEncryptionPlugin(keys!);
              ws.send(JSON.stringify(confirmation.response));
              handshakeComplete = true;

              // Start first measurement immediately after handshake
              sendPooledMessage();
            }
          }
        } else {
          if (msg.type === 'encrypted-plugin-message' && encryptionPlugin) {
            const unwrapped = encryptionPlugin.unwrapMessage(message);
            if (unwrapped && unwrapped.payload === largeData) {
              const endTime = process.hrtime.bigint();
              const durationNs = Number(endTime - (ws as any).startTime);
              const durationMs = durationNs / 1_000_000;
              measurements.push(durationMs);
              measurementCount++;

              if (measurementCount < POOL_MEASUREMENTS) {
                // Send next measurement after small delay
                setTimeout(sendPooledMessage, 10);
              } else {
                // Calculate average and resolve
                const avgTime = measurements.reduce((a, b) => a + b, 0) / measurements.length;
                resolve(avgTime);
                ws.close();
              }
            }
          }
        }
      } catch (error) {
        reject(error);
      }
    });

    function sendPooledMessage() {
      if (encryptionPlugin) {
        (ws as any).startTime = process.hrtime.bigint();
        const encrypted = encryptionPlugin.wrapMessage('throughput-test', largeData);
        ws.send(encrypted);
      }
    }

    ws.on('close', () => {
      encryptionPlugin?.destroy();
      consumer.destroy();
    });

    ws.on('error', err => {
      reject(err);
      encryptionPlugin?.destroy();
      consumer.destroy();
    });
  });
}

runThroughputTest();
