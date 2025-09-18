import { SecureProvider } from '../SecureProvider.ts';
import { SecureConsumer } from '../SecureConsumer.ts';
import { expect, test, describe } from 'bun:test';

describe('SecureProvider and SecureConsumer', () => {
  test('should complete secure handshake', () => {
    const provider = new SecureProvider();
    const consumer = new SecureConsumer();

    // Mock socket for provider to start handshake
    let providerMessage: string = '';
    const mockSocket = {
      send: (message: string) => {
        providerMessage = message;
      },
    };

    // Provider starts handshake
    provider.startHandshake(mockSocket);
    expect(providerMessage).toBeTruthy();

    // Consumer processes handshake init
    const consumerResult = consumer.handleMessage(providerMessage);
    expect(consumerResult.type).toBe('handshake-response');
    expect(consumerResult.confirmed).toBe(false);

    // Provider handles consumer response
    const providerResult = provider.handleResponse(consumerResult.response!);
    expect(providerResult.type).toBe('send-confirmation');
    expect(providerResult.confirmed).toBe(false);

    // Create confirmation request message
    const confirmationRequest = {
      type: 'key-confirmation-request',
      confirmationMac: (providerResult as any).confirmationMac,
    };

    // Consumer processes confirmation request
    const consumerConfirm = consumer.handleMessage(confirmationRequest);
    expect(consumerConfirm.type).toBe('key-confirmation');
    expect(consumerConfirm.confirmed).toBe(true);

    // Provider processes final confirmation
    const finalResult = provider.handleResponse(consumerConfirm.response!);
    expect(finalResult.type).toBe('handshake-complete');
    expect(finalResult.confirmed).toBe(true);

    // Both should have derived keys
    expect(provider.getDerivedKeys()).toBeTruthy();
    expect(consumer.getDerivedKeys()).toBeTruthy();
    expect(provider.isHandshakeConfirmed()).toBe(true);
    expect(consumer.isHandshakeConfirmed()).toBe(true);
  });
});
