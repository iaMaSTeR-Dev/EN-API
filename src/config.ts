import os from 'node:os';
import { isValidToken } from './auth/bank-auth-client.ts';

/**
 * Central configuration for Bank Eghtesad Novin Personal Daemon.
 * Strictly enforces security, secret validation, loopback binding, and network safety.
 */

export interface AppConfig {
  server: {
    host: '127.0.0.1'; // Enforced literal for security
    port: number;
  };
  security: {
    localApiKey: string;
    vaultSecret: string;
    deviceToken?: string;
  };
  bank: {
    baseUrl: string;
    origin: string;
    platform: string;
    version: string;
    buildNo: string;
    idleTimeoutMs: number;
    requestTimeoutMs: number;
    outboundIp?: string;
  };
}

const DISALLOWED_DEFAULT_KEYS = new Set([
  'enbank-local-dev-key-phase2-secure',
  'default-phase2-vault-secret-key-32b!',
  'replace-with-secure-random-key-at-least-16-chars',
  'replace-with-secure-random-vault-key-at-least-32-chars',
  '1234567890123456',
  'passwordpassword',
  'secretsecretsecret',
]);

/**
 * Attempts to load .env file using Node.js native process.loadEnvFile() without external dependencies.
 */
function tryLoadEnvFile(): void {
  if (typeof process.loadEnvFile === 'function') {
    try {
      process.loadEnvFile();
    } catch {
      // Ignored if .env does not exist in root
    }
  }
}

/**
 * Verifies whether an IP address belongs to an active local network interface.
 */
export function isIpOnLocalInterface(ip: string): boolean {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const list = interfaces[name];
    if (list) {
      for (const iface of list) {
        if (iface.family === 'IPv4' && iface.address === ip) {
          return true;
        }
      }
    }
  }
  return false;
}

export function loadConfig(customEnv?: Record<string, string | undefined>): AppConfig {
  tryLoadEnvFile();

  const env = customEnv || process.env;
  const isTest = env.NODE_ENV === 'test' || env.npm_lifecycle_event === 'test';

  // 1. Port Validation
  const rawPort = env.LOCAL_PORT || '8080';
  const port = parseInt(rawPort, 10);
  if (isNaN(port) || port < 1024 || port > 65535) {
    throw new Error(`Configuration error: Invalid LOCAL_PORT (${rawPort}). Port must be between 1024 and 65535.`);
  }

  // 2. Local API Key Validation
  let localApiKey = env.LOCAL_API_KEY?.trim();
  if (!localApiKey) {
    if (isTest) {
      localApiKey = 'test-environment-deterministic-key-32b!';
    } else {
      throw new Error(
        'Configuration error: Missing LOCAL_API_KEY environment variable. ' +
        'A secure secret of at least 16 characters is required. See .env.example.'
      );
    }
  }

  if (DISALLOWED_DEFAULT_KEYS.has(localApiKey)) {
    throw new Error(
      'Configuration error: LOCAL_API_KEY matches an insecure default placeholder. ' +
      'Please generate a cryptographically random key (at least 16 characters).'
    );
  }

  if (localApiKey.length < 16) {
    throw new Error(
      `Configuration error: LOCAL_API_KEY must be at least 16 characters long (got ${localApiKey.length}).`
    );
  }

  // 3. Vault Secret Key Validation
  let vaultSecret = env.ENBANK_VAULT_KEY?.trim();
  if (!vaultSecret) {
    if (isTest) {
      vaultSecret = 'test-environment-vault-secret-32b!!';
    } else {
      throw new Error(
        'Configuration error: Missing ENBANK_VAULT_KEY environment variable. ' +
        'A secure secret of at least 16 characters is required for the session vault. See .env.example.'
      );
    }
  }

  if (DISALLOWED_DEFAULT_KEYS.has(vaultSecret)) {
    throw new Error(
      'Configuration error: ENBANK_VAULT_KEY matches an insecure default placeholder. ' +
      'Please generate a secure random vault key (at least 16 characters).'
    );
  }

  if (vaultSecret.length < 16) {
    throw new Error(
      `Configuration error: ENBANK_VAULT_KEY must be at least 16 characters long (got ${vaultSecret.length}).`
    );
  }

  // 4. Optional Pre-Registered Device Token (mobileUserToken from PWA)
  let deviceToken = env.ENBANK_DEVICE_TOKEN?.trim();
  if (deviceToken) {
    if (!isValidToken(deviceToken)) {
      throw new Error(
        'Configuration error: Configured ENBANK_DEVICE_TOKEN is invalid (cannot be empty, "null", or sentinel string).'
      );
    }
  } else {
    deviceToken = undefined;
  }

  // 5. Base URL Validation
  const baseUrl = (env.BANK_BASE_URL || 'https://neobank.enbank.ir').trim();
  if (!baseUrl.startsWith('https://')) {
    throw new Error(`Configuration error: BANK_BASE_URL must use HTTPS protocol (got: ${baseUrl}).`);
  }

  // 6. Outbound Domestic IP Validation
  let outboundIp = env.BANK_OUTBOUND_IP?.trim();
  if (outboundIp) {
    // If explicitly specified, verify it exists on the host machine to avoid EADDRNOTAVAIL
    if (!isTest && !isIpOnLocalInterface(outboundIp)) {
      throw new Error(
        `Configuration error: Configured BANK_OUTBOUND_IP (${outboundIp}) does not match any active local network interface on this machine.`
      );
    }
  } else {
    outboundIp = undefined;
  }

  return {
    server: {
      host: '127.0.0.1',
      port,
    },
    security: {
      localApiKey,
      vaultSecret,
      deviceToken,
    },
    bank: {
      baseUrl,
      origin: baseUrl,
      platform: 'PWA',
      version: '2.8.4',
      buildNo: '284',
      idleTimeoutMs: 5 * 60 * 1000, // 5 minutes local sliding window
      requestTimeoutMs: 15 * 1000,   // 15 seconds HTTP timeout
      outboundIp,
    },
  };
}
