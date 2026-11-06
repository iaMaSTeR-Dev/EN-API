import https from 'node:https';
import { loadConfig } from './config.ts';
import { SessionStore } from './auth/session-store.ts';
import { SessionValidator } from './auth/session-validator.ts';
import { SessionRefreshManager } from './auth/session-refresh-manager.ts';
import { AuthManager } from './auth/auth-manager.ts';
import { BankReadOnlyClient } from './client/bank-read-only-client.ts';
import { BankAuthClient } from './auth/bank-auth-client.ts';
import type { TransportFn, TransportResponse } from './client/bank-read-only-client.ts';
import { AccountService } from './services/account-service.ts';
import { CardService } from './services/card-service.ts';
import { GeneralService } from './services/general-service.ts';
import { buildServer } from './server.ts';
import { RedactingLogger } from './logger.ts';

const logger = new RedactingLogger('Bootstrap');

/**
 * Production HTTPS transport using Node.js native https module with domestic IP binding and legacy TLS options.
 */
export const defaultHttpsTransport: TransportFn = (urlStr, options) => {
  return new Promise<TransportResponse>((resolve, reject) => {
    const url = new URL(urlStr);
    const config = loadConfig();

    const reqOptions: https.RequestOptions = {
      hostname: url.hostname,
      port: url.port || 443,
      path: `${url.pathname}${url.search}`,
      method: options.method,
      headers: options.headers,
      timeout: options.timeoutMs,
      localAddress: config.bank.outboundIp, // Domestic interface binding
      rejectUnauthorized: true,
      secureOptions: 0x00000004, // SSL_OP_LEGACY_SERVER_CONNECT for bank renegotiation
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        let parsedData: unknown = data;
        try {
          parsedData = JSON.parse(data);
        } catch {
          // Keep raw string if not JSON
        }
        resolve({
          status: res.statusCode || 200,
          headers: res.headers as Record<string, string>,
          data: parsedData,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request timed out after ${options.timeoutMs}ms`));
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
};

async function main() {
  const config = loadConfig();
  logger.info('Initializing Eghtesad Novin Personal Daemon', {
    host: config.server.host,
    port: config.server.port,
    mode: 'READ_ONLY',
  });

  const sessionStore = new SessionStore(config.security.vaultSecret);
  const sessionValidator = new SessionValidator(config.bank.idleTimeoutMs);
  const refreshManager = new SessionRefreshManager(sessionStore, sessionValidator, config.bank.idleTimeoutMs);
  const authManager = new AuthManager(sessionStore, sessionValidator, refreshManager, config.bank.idleTimeoutMs);

  // Automatic Session Restoration on startup
  const restored = authManager.restorePersistedSession();
  if (restored) {
    logger.info('Restored valid local session from encrypted storage (LOCAL_ACTIVE)');
  } else {
    logger.info('No valid persisted session found; initial login required');
  }

  const initialDeviceToken = config.security.deviceToken || sessionStore.getDeviceToken();
  const bankAuthClient = new BankAuthClient(
    config.bank.baseUrl,
    defaultHttpsTransport,
    sessionValidator,
    config.bank.requestTimeoutMs,
    initialDeviceToken,
    true
  );

  const bankClient = new BankReadOnlyClient(
    authManager,
    sessionValidator,
    config.bank.baseUrl,
    defaultHttpsTransport,
    config.bank.requestTimeoutMs,
    bankAuthClient
  );

  const accountService = new AccountService(bankClient);
  const cardService = new CardService(bankClient);
  const generalService = new GeneralService(bankClient);

  const app = buildServer({
    config,
    authManager,
    accountService,
    cardService,
    generalService,
    bankAuthClient,
    bankClient,
  });

  try {
    const address = await app.listen({
      host: config.server.host,
      port: config.server.port,
    });
    logger.info(`Daemon successfully listening on ${address} (Loopback Only)`);
  } catch (err) {
    logger.error('Failed to start daemon', err);
    process.exit(1);
  }
}

// Start if invoked directly
if (process.argv[1] && process.argv[1].endsWith('index.ts')) {
  main();
}
