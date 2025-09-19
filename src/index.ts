/*
 * Copyright (c) 2025 Geoff Seemueller. All rights reserved.
 * This software and associated documentation files are proprietary and confidential.
 * Unauthorized copying, distribution, or use is strictly prohibited.
 */

import { Consumer } from './Consumer.ts';
import { Provider } from './Provider.ts';
import { SecureConsumer } from './SecureConsumer.ts';
import { SecureProvider } from './SecureProvider.ts';
import { HKDF, SecureRandom, constantTimeCompare, createContextInfo } from './crypto-utils.ts';
import { BaseEncryptionPlugin, type EncryptionKeys } from './BaseEncryptionPlugin.ts';
import { MessageEncryptionPlugin } from './MessageEncryptionPlugin.ts';

export {
  // Legacy implementations (deprecated - use Secure* variants)
  Consumer,
  Provider,

  // Secure implementations with proper cryptographic properties
  SecureConsumer,
  SecureProvider,

  // Message encryption plugins
  BaseEncryptionPlugin,
  MessageEncryptionPlugin,
  type EncryptionKeys,

  // Cryptographic utilities
  HKDF,
  SecureRandom,
  constantTimeCompare,
  createContextInfo,
};
