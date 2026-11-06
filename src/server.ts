import Fastify from 'fastify';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { AppConfig } from './config.ts';
import type { AuthManager } from './auth/auth-manager.ts';
import { ReauthenticationRequiredError } from './auth/auth-manager.ts';
import type { AccountService } from './services/account-service.ts';
import type { CardService } from './services/card-service.ts';
import { GeneralService } from './services/general-service.ts';
import type { BankAuthClient } from './auth/bank-auth-client.ts';
import { isValidToken } from './auth/bank-auth-client.ts';
import { BankReadOnlyClient, BankClientError } from './client/bank-read-only-client.ts';
import { redactSensitiveData, RedactingLogger } from './logger.ts';
import type { RequestContext } from './types.ts';
import { runWithRequestContext, getRequestContext } from './request-context.ts';

export interface ServerDependencies {
  config: AppConfig;
  authManager: AuthManager;
  accountService: AccountService;
  cardService: CardService;
  generalService?: GeneralService;
  bankAuthClient?: BankAuthClient;
  bankClient?: BankReadOnlyClient;
}

const FORBIDDEN_MUTATION_KEYWORDS = [
  'transfer',
  'payment',
  'withdraw',
  'block',
  'fundtransfer',
  'payloan',
  'beneficiary',
  'cheque/issue',
];

export function buildServer(deps: ServerDependencies): FastifyInstance {
  const { config, authManager, accountService, cardService, bankAuthClient } = deps;
  const client: BankReadOnlyClient | undefined = deps.bankClient || (accountService as any).client;
  if (client && bankAuthClient && typeof (client as any).setBankAuthClient === 'function') {
    (client as any).setBankAuthClient(bankAuthClient);
  }
  const generalService = deps.generalService || (client ? new GeneralService(client) : undefined);
  const logger = new RedactingLogger('HttpServer');

  const app = Fastify({
    logger: false, // Use our redacting logger instead of raw stream
    trustProxy: false,
    bodyLimit: 1048576, // 1MB payload limit to prevent memory exhaustion / DoS
    connectionTimeout: 10000,
    keepAliveTimeout: 5000,
  });

  // Global Error Handler
  app.setErrorHandler((error: Error & { code?: string; statusCode?: number }, request: FastifyRequest, reply: FastifyReply) => {
    logger.error(`Unhandled error during request: ${request.method} ${request.url}`, error);

    if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE') {
      return reply.status(413).send({
        error: 'PAYLOAD_TOO_LARGE',
        message: 'Request payload exceeds maximum allowed size limit (1MB).',
        statusCode: 413,
      });
    }

    if (error instanceof ReauthenticationRequiredError) {
      return reply.status(401).send({
        error: 'REAUTHENTICATION_REQUIRED',
        message: error.message,
        statusCode: 401,
      });
    }

    if (error instanceof BankClientError) {
      const status = error.isAuthError
        ? 401
        : error.isRateLimited
        ? 429
        : error.isNetworkError
        ? 503
        : error.statusCode && error.statusCode >= 400 && error.statusCode < 500
        ? error.statusCode
        : 502;

      const errorLabel = error.isAuthError
        ? 'BANK_AUTH_FAILED'
        : error.isNetworkError
        ? 'BANK_UNREACHABLE'
        : error.statusCode === 404
        ? 'BANK_ENDPOINT_NOT_FOUND'
        : 'BANK_ERROR';

      return reply.status(status).send({
        error: errorLabel,
        message: error.message,
        statusCode: status,
        bankCode: error.bankCode,
      });
    }

    if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.status(error.statusCode).send({
        error: error.code || 'BAD_REQUEST',
        message: error.message,
        statusCode: error.statusCode,
      });
    }

    return reply.status(500).send({
      error: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected internal error occurred.',
      statusCode: 500,
    });
  });

  // Request Context Initialization: establish request-scoped AsyncLocalStorage
  app.addHook('onRequest', (request: FastifyRequest, _reply: FastifyReply, done: () => void) => {
    const rawReqId = request.headers['x-request-id'];
    const requestId = typeof rawReqId === 'string' && rawReqId.trim().length > 0
      ? rawReqId.trim()
      : `req-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

    const context: RequestContext = {
      requestId,
    };
    (request as any).requestContext = context;
    (request as any).requestStartTime = Date.now();

    runWithRequestContext(context, () => {
      done();
    });
  });

  // Security Middleware: Enforce Loopback, Host Validation, Origin Check, Global Mutation Blocking, and API Key
  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {

    // 1. Strict Loopback Check (IPv4 and IPv6)
    const ip = request.ip || request.socket.remoteAddress || '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') {
      logger.warn('Forbidden non-loopback connection attempted', { remoteIp: ip });
      return reply.status(403).send({
        error: 'FORBIDDEN',
        message: 'This personal API daemon strictly rejects non-loopback network interfaces.',
        statusCode: 403,
      });
    }

    // 2. DNS Rebinding Guard: Validate Host Header
    const hostHeader = (request.headers.host || '').toLowerCase();
    const hostWithoutPort = hostHeader.split(':')[0];
    const allowedHosts = ['localhost', '127.0.0.1', '[::1]'];
    if (!allowedHosts.includes(hostWithoutPort)) {
      logger.warn('Forbidden Host header attempted (DNS rebinding protection)', { host: hostHeader });
      return reply.status(403).send({
        error: 'FORBIDDEN_HOST',
        message: 'Host header must match local loopback origin (localhost / 127.0.0.1).',
        statusCode: 403,
      });
    }

    // 3. Cross-Origin Browser Protection (Origin Header Guard)
    if (request.headers.origin) {
      try {
        const originUrl = new URL(request.headers.origin);
        const originHost = originUrl.hostname.toLowerCase();
        if (!allowedHosts.includes(originHost)) {
          logger.warn('Forbidden cross-origin browser request attempted', { origin: request.headers.origin });
          return reply.status(403).send({
            error: 'FORBIDDEN_ORIGIN',
            message: 'Cross-origin browser requests to this personal API daemon are strictly rejected.',
            statusCode: 403,
          });
        }
      } catch {
        return reply.status(403).send({
          error: 'FORBIDDEN_ORIGIN',
          message: 'Malformed Origin header received.',
          statusCode: 403,
        });
      }
    }

    // 4. Global Decoded Mutation URL Inspector (blocks all forms of write routes, encoded or nested)
    let decodedPath = '';
    try {
      decodedPath = decodeURIComponent(request.url).toLowerCase().split('?')[0];
    } catch {
      decodedPath = request.url.toLowerCase().split('?')[0];
    }

    // Read-only whitelist for specific safe query endpoints
    const isSafeReadOnlyTransferRoute =
      request.method === 'GET' &&
      (decodedPath === '/api/v1/transfers/recent' ||
       decodedPath === '/api/v1/transfers/scheduled' ||
       decodedPath === '/api/v1/destinations' ||
       decodedPath === '/api/v1/destinations/recent' ||
       decodedPath === '/api/v1/scheduled-transfers');

    if (!isSafeReadOnlyTransferRoute) {
      for (const keyword of FORBIDDEN_MUTATION_KEYWORDS) {
        if (decodedPath.includes(keyword)) {
          logger.warn(`Blocked attempt to invoke forbidden financial mutation route: ${request.url}`);
          return reply.status(405).send({
            error: 'METHOD_NOT_ALLOWED',
            message: 'Financial write and mutation operations are strictly forbidden in this read-only integration.',
            statusCode: 405,
          });
        }
      }
    }

    // 5. Restrict HTTP Methods: only GET and POST are permitted across the daemon
    if (request.method !== 'GET' && request.method !== 'POST') {
      return reply.status(405).send({
        error: 'METHOD_NOT_ALLOWED',
        message: `HTTP method ${request.method} is not allowed on this read-only API daemon.`,
        statusCode: 405,
      });
    }

    // 6. Health check endpoint does not require local API key
    if (request.url === '/api/v1/health') {
      return;
    }

    // 7. Local API Key Authorization
    const authHeader = request.headers['x-local-api-key'];
    if (!authHeader || authHeader !== config.security.localApiKey) {
      logger.warn('Unauthorized local API request received');
      return reply.status(401).send({
        error: 'UNAUTHORIZED_LOCAL_CLIENT',
        message: 'Missing or invalid X-Local-API-Key header.',
        statusCode: 401,
      });
    }
  });

  // Attach session renewal notification headers ONLY if renewal occurred for THIS specific request and operation succeeded
  app.addHook('onSend', async (request: FastifyRequest, reply: FastifyReply, payload) => {
    if (reply.statusCode >= 200 && reply.statusCode < 300) {
      const ctx = (request as any).requestContext || getRequestContext();
      if (ctx?.renewal?.renewed) {
        reply.header('x-session-renewed', 'true');
        reply.header('x-session-expired-locally', ctx.renewal.expiredLocally ? 'true' : 'false');
      }
    }
    return payload;
  });

  // Health Endpoint
  app.get('/api/v1/health', async () => {
    return {
      status: 'OK',
      timestamp: new Date().toISOString(),
      binding: config.server.host,
      mode: 'READ_ONLY_FOUNDATION',
    };
  });

  // Session Status (Zero secret leakage)
  app.get('/api/v1/session/status', async () => {
    return authManager.getStatus();
  });

  // Direct Bank Login with Credentials
  app.post('/api/v1/session/login', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as Record<string, unknown> | null;
    if (!body || typeof body.cifOrUsername !== 'string' || typeof body.password !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Request body must include string "cifOrUsername" and "password" properties.',
        statusCode: 400,
      });
    }

    const cifOrUsername = body.cifOrUsername.trim();
    const password = body.password;
    const otp = typeof body.otp === 'string' ? body.otp.trim() : undefined;
    const deviceToken = typeof body.deviceToken === 'string' ? body.deviceToken.trim() : undefined;
    const saveCredentials = body.saveCredentials === true || body.saveCredentials === 'true';

    if (!cifOrUsername || !password) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'cifOrUsername and password cannot be empty.',
        statusCode: 400,
      });
    }

    if (!bankAuthClient) {
      return reply.status(503).send({
        error: 'AUTH_CLIENT_UNAVAILABLE',
        message: 'Bank authentication client is not configured on this daemon instance.',
        statusCode: 503,
      });
    }

    const result = await authManager.loginWithCredentials(
      { cifOrUsername, password, otp, deviceToken, saveCredentials },
      bankAuthClient
    );

    if (result.success) {
      return {
        message: result.message,
        status: authManager.getStatus(),
      };
    }

    if (result.requiresOtp) {
      return reply.status(200).send({
        requiresOtp: true,
        message: result.message,
        status: authManager.getStatus(),
      });
    }

    if (result.requiresCaptcha) {
      return reply.status(200).send({
        requiresCaptcha: true,
        message: result.message,
        status: authManager.getStatus(),
      });
    }

    if (result.requiresDeviceToken) {
      return reply.status(401).send({
        error: 'DEVICE_TOKEN_REQUIRED',
        requiresDeviceToken: true,
        message: result.message,
        status: authManager.getStatus(),
        statusCode: 401,
      });
    }

    return reply.status(401).send({
      error: 'LOGIN_FAILED',
      message: result.message,
      status: authManager.getStatus(),
      statusCode: 401,
    });
  });

  // Request Device Registration (SMS OTP)
  app.post('/api/v1/session/device/register', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as Record<string, unknown> | null;
    if (!body || typeof body.mobileNo !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Request body must include string "mobileNo" property.',
        statusCode: 400,
      });
    }

    if (!bankAuthClient) {
      return reply.status(503).send({
        error: 'AUTH_CLIENT_UNAVAILABLE',
        message: 'Bank authentication client is not configured on this daemon instance.',
        statusCode: 503,
      });
    }

    const mobileNo = body.mobileNo.trim();
    const captcha = typeof body.captcha === 'string' ? body.captcha.trim() : undefined;

    const outcome = await bankAuthClient.requestDeviceRegistration(mobileNo, captcha);
    if (outcome.kind === 'otp_sent') {
      return {
        success: true,
        message: outcome.message,
        validationCode: outcome.validationCode,
      };
    }

    if (outcome.kind === 'captcha_required') {
      return reply.status(400).send({
        error: 'CAPTCHA_REQUIRED',
        message: outcome.message,
        statusCode: 400,
      });
    }

    if (outcome.kind === 'rate_limited') {
      return reply.status(429).send({
        error: 'RATE_LIMITED',
        message: outcome.message,
        statusCode: 429,
      });
    }

    if (outcome.kind === 'bank_error') {
      return reply.status(outcome.statusCode || 400).send({
        error: 'BANK_ERROR',
        message: outcome.message,
        bankCode: outcome.bankCode,
        statusCode: outcome.statusCode || 400,
      });
    }

    return reply.status(502).send({
      error: 'NETWORK_ERROR',
      message: outcome.error.message,
      statusCode: 502,
    });
  });

  // Validate Device Registration (SMS OTP -> mobileUserToken)
  app.post('/api/v1/session/device/validate', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as Record<string, unknown> | null;
    if (!body || typeof body.mobileNo !== 'string' || typeof body.activationCode !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Request body must include string "mobileNo" and "activationCode" properties.',
        statusCode: 400,
      });
    }

    if (!bankAuthClient) {
      return reply.status(503).send({
        error: 'AUTH_CLIENT_UNAVAILABLE',
        message: 'Bank authentication client is not configured on this daemon instance.',
        statusCode: 503,
      });
    }

    const mobileNo = body.mobileNo.trim();
    const activationCode = body.activationCode.trim();

    const outcome = await bankAuthClient.validateDeviceRegistration(mobileNo, activationCode);
    if (outcome.kind === 'success') {
      authManager.setRegisteredDeviceToken(outcome.deviceToken);
      return {
        success: true,
        message: outcome.message,
        status: authManager.getStatus(),
      };
    }

    if (outcome.kind === 'invalid_code') {
      return reply.status(400).send({
        error: 'INVALID_ACTIVATION_CODE',
        message: outcome.message,
        bankCode: outcome.bankCode,
        statusCode: 400,
      });
    }

    if (outcome.kind === 'bank_error') {
      return reply.status(outcome.statusCode || 400).send({
        error: 'BANK_ERROR',
        message: outcome.message,
        bankCode: outcome.bankCode,
        statusCode: outcome.statusCode || 400,
      });
    }

    return reply.status(502).send({
      error: 'NETWORK_ERROR',
      message: outcome.error.message,
      statusCode: 502,
    });
  });

  // Browser-Assisted Login Handoff Init
  app.post('/api/v1/session/handoff/init', async () => {
    const ticket = authManager.createHandoffTicket(config.bank.baseUrl);
    return {
      handoffId: ticket.handoffId,
      handoffSecret: ticket.handoffSecret,
      loginUrl: ticket.loginUrl,
      expiresAt: new Date(ticket.expiresAt).toISOString(),
    };
  });

  // Browser-Assisted Login Handoff Complete
  app.post('/api/v1/session/handoff/complete', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as Record<string, unknown> | null;
    if (!body || typeof body.handoffSecret !== 'string' || typeof body.token !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Request body must include "handoffSecret" and "token" properties.',
        statusCode: 400,
      });
    }

    const secret = body.handoffSecret.trim();
    const token = body.token.trim();
    const yaghootToken = typeof body.yaghootToken === 'string' && isValidToken(body.yaghootToken) ? body.yaghootToken.trim() : undefined;
    const mobileUserToken = typeof body.mobileUserToken === 'string' && isValidToken(body.mobileUserToken) ? body.mobileUserToken.trim() : undefined;
    const cifOrUsername = typeof body.cifOrUsername === 'string' ? body.cifOrUsername.trim() : undefined;

    // Prefer yaghootToken if available from browser session
    const effectiveToken = yaghootToken || token;

    if (!isValidToken(effectiveToken) || effectiveToken.length < 20 || effectiveToken.length > 4096) {
      return reply.status(400).send({
        error: 'INVALID_TOKEN_FORMAT',
        message: 'Handoff session token must be a valid, non-empty bearer token between 20 and 4096 characters.',
        statusCode: 400,
      });
    }

    // Guard against importing device registration token as a banking session token
    if (mobileUserToken && effectiveToken.toLowerCase() === mobileUserToken.toLowerCase()) {
      return reply.status(400).send({
        error: 'DEVICE_TOKEN_MISUSE',
        message: 'The submitted token is the device registration token (mobileUserToken), not an authenticated banking session token. Session tokens must be copied after logging into the bank portal (e.g. yaghootToken).',
        statusCode: 400,
      });
    }

    if (config.security.deviceToken && effectiveToken.toLowerCase() === config.security.deviceToken.toLowerCase()) {
      return reply.status(400).send({
        error: 'DEVICE_TOKEN_MISUSE',
        message: 'The submitted token is the configured device registration token (mobileUserToken), not an authenticated banking session token. Session tokens must be obtained after logging into the bank portal.',
        statusCode: 400,
      });
    }

    const consumed = authManager.consumeHandoffTicket(secret, effectiveToken, cifOrUsername, yaghootToken, mobileUserToken);
    if (!consumed) {
      return reply.status(400).send({
        error: 'INVALID_HANDOFF',
        message: 'Handoff ticket is invalid, expired, or already consumed.',
        statusCode: 400,
      });
    }

    if (mobileUserToken && bankAuthClient) {
      bankAuthClient.setDeviceToken(mobileUserToken);
    }

    return {
      message: 'Browser session successfully linked and stored.',
      status: authManager.getStatus(),
    };
  });

  // Session Import (Interactive seeding by authorized user)
  app.post('/api/v1/session/import', async (request: FastifyRequest, reply: FastifyReply) => {
    const body = request.body as Record<string, unknown> | null;
    if (!body || typeof body.token !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Request body must include a string "token" property.',
        statusCode: 400,
      });
    }

    const token = body.token.trim();
    if (!isValidToken(token) || token.length < 20 || token.length > 4096) {
      return reply.status(400).send({
        error: 'INVALID_TOKEN_FORMAT',
        message: 'Session token must be a valid, non-empty bearer token between 20 and 4096 characters.',
        statusCode: 400,
      });
    }

    if (config.security.deviceToken && token.toLowerCase() === config.security.deviceToken.toLowerCase()) {
      return reply.status(400).send({
        error: 'DEVICE_TOKEN_MISUSE',
        message: 'The submitted token is the configured device registration token (mobileUserToken), not an authenticated banking session token. Session tokens must be obtained after logging into the bank portal.',
        statusCode: 400,
      });
    }

    authManager.importSession(
      token,
      typeof body.yaghootToken === 'string' ? body.yaghootToken.trim() : undefined,
      typeof body.f5Cookie === 'string' ? body.f5Cookie.trim() : undefined,
      typeof body.cifOrUsername === 'string' ? body.cifOrUsername.trim() : undefined
    );

    return {
      message: 'Session successfully imported and stored in memory.',
      status: authManager.getStatus(),
    };
  });

  // Safe Read-Only Remote Session Verification
  app.post('/api/v1/session/verify', async (_request: FastifyRequest, reply: FastifyReply) => {
    const session = authManager.getSession();
    if (!session || !session.token) {
      return reply.status(401).send({
        error: 'NO_SESSION',
        message: 'No active or persisted session found to verify. Please log in or import a session.',
        statusCode: 401,
      });
    }

    const client: BankReadOnlyClient | undefined = deps.bankClient || (accountService as any).client;
    if (!client) {
      return reply.status(500).send({
        error: 'CLIENT_UNAVAILABLE',
        message: 'Bank read-only client is not available for remote verification.',
        statusCode: 500,
      });
    }

    try {
      const outcome = await client.verifySession(session.token);
      return reply.status(200).send({
        verified: outcome.verified,
        status: authManager.getStatus(),
        message: outcome.message,
      });
    } catch (err: unknown) {
      if (err instanceof BankClientError) {
        const status = err.isAuthError ? 401 : err.isRateLimited ? 429 : err.isNetworkError ? 503 : 502;
        return reply.status(status).send({
          error: err.isAuthError ? 'BANK_AUTH_FAILED' : err.isNetworkError ? 'BANK_UNREACHABLE' : 'BANK_ERROR',
          message: err.message,
          statusCode: status,
          bankCode: err.bankCode,
        });
      }
      throw err;
    }
  });

  // Session Logout
  app.post('/api/v1/session/logout', async () => {
    await authManager.logout(bankAuthClient);
    return {
      message: 'Local session cleared successfully.',
      status: authManager.getStatus(),
    };
  });

  // Read-Only: List Accounts & Balances
  app.get('/api/v1/accounts', async () => {
    const accounts = await accountService.getAccounts();
    return {
      count: accounts.length,
      accounts,
    };
  });

  // Read-Only: Specific Account Balance
  app.get('/api/v1/accounts/:depositNumber/balance', async (request: FastifyRequest, reply: FastifyReply) => {
    const params = request.params as { depositNumber: string };
    const depositNumber = (params.depositNumber || '').trim();
    if (!/^[a-zA-Z0-9.\-_/]{1,64}$/.test(depositNumber)) {
      return reply.status(400).send({
        error: 'INVALID_DEPOSIT_FORMAT',
        message: 'Deposit number contains invalid characters or exceeds 64 characters.',
        statusCode: 400,
      });
    }

    const balance = await accountService.getAccountBalance(depositNumber);
    if (!balance) {
      return reply.status(404).send({
        error: 'ACCOUNT_NOT_FOUND',
        message: `Account with depositNumber ${depositNumber} was not found.`,
        statusCode: 404,
      });
    }
    return balance;
  });

  // Read-Only: Deposit Transaction Statement
  app.get('/api/v1/accounts/:depositNumber/statement', async (request: FastifyRequest, reply: FastifyReply) => {
    const params = request.params as { depositNumber: string };
    const depositNumber = (params.depositNumber || '').trim();
    if (!/^[a-zA-Z0-9.\-_/]{1,64}$/.test(depositNumber)) {
      return reply.status(400).send({
        error: 'INVALID_DEPOSIT_FORMAT',
        message: 'Deposit number contains invalid characters or exceeds 64 characters.',
        statusCode: 400,
      });
    }

    const query = request.query as { fromDate?: string; toDate?: string; page?: string; limit?: string };
    const page = Math.max(0, parseInt(query.page || '0', 10) || 0);
    const rawLimit = parseInt(query.limit || '20', 10) || 20;
    const limit = Math.min(Math.max(1, rawLimit), 100);

    const statement = await accountService.getAccountStatement(depositNumber, {
      fromDate: query.fromDate?.trim(),
      toDate: query.toDate?.trim(),
      page,
      limit,
    });

    return statement;
  });

  // Read-Only: List Registered Cards (Masked PANs)
  app.get('/api/v1/cards', async () => {
    const cards = await cardService.getCards();
    return {
      count: cards.length,
      cards,
    };
  });

  // Read-Only: Inquire Card Recipient Name
  app.get('/api/v1/cards/inquiry', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { pan?: string };
    if (!query.pan || typeof query.pan !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Query parameter "pan" is required.',
        statusCode: 400,
      });
    }

    const cleanPan = query.pan.replace(/[\s-]/g, '');
    if (!/^\d{16,19}$/.test(cleanPan)) {
      return reply.status(400).send({
        error: 'INVALID_PAN_FORMAT',
        message: 'Card PAN must consist of 16 to 19 numeric digits.',
        statusCode: 400,
      });
    }

    const inquiry = await cardService.inquireCardRecipient(cleanPan);
    return inquiry;
  });

  // Read-Only: Combined Balance across all deposits
  app.get('/api/v1/balance', async () => {
    return accountService.getCombinedBalance();
  });

  // Read-Only: Balances List
  app.get('/api/v1/balances', async () => {
    const accounts = await accountService.getAccounts();
    return {
      count: accounts.length,
      accounts,
    };
  });

  // Read-Only: User Profile and Identity Summary
  app.get('/api/v1/profile', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    return generalService.getProfile();
  });

  // Read-Only: Transaction Search by Reference or Tracking Code
  app.get('/api/v1/transactions/find/:code', async (request: FastifyRequest, reply: FastifyReply) => {
    const params = request.params as { code: string };
    const code = (params.code || '').trim();
    if (!code) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Transaction reference or receipt code is required in path.',
        statusCode: 400,
      });
    }

    const query = request.query as { pages?: string; deposit?: string };
    const maxPages = Math.min(Math.max(1, parseInt(query.pages || '10', 10) || 10), 50);

    const found = await accountService.findTransaction(code, {
      maxPages,
      depositNumber: query.deposit?.trim(),
    });

    if (!found) {
      return reply.status(404).send({
        error: 'TRANSACTION_NOT_FOUND',
        message: `No transaction found matching code "${code}".`,
        statusCode: 404,
      });
    }

    return found;
  });

  // Read-Only: Recent Transfers (ACH / Paya Transfer History)
  app.get('/api/v1/transfers/recent', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const transfers = await generalService.getAchReports({ limit: 20, page: 0 });
    return {
      count: transfers.length,
      transfers,
    };
  });

  // Read-Only: Saved / Recent Transfer Destinations (Contacts)
  const handleRecentDestinations = async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const destinations = await generalService.getContacts();
    return {
      count: destinations.length,
      destinations,
    };
  };
  app.get('/api/v1/destinations', handleRecentDestinations);
  app.get('/api/v1/destinations/recent', handleRecentDestinations);

  // Read-Only: Scheduled Auto-Transfers
  const handleScheduledTransfers = async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const query = request.query as { type?: string };
    const transferType: 'NORMAL' | 'ACH' = query.type?.toUpperCase() === 'ACH' ? 'ACH' : 'NORMAL';
    const scheduledTransfers = await generalService.getScheduledTransfers(transferType);
    return {
      count: scheduledTransfers.length,
      scheduledTransfers,
    };
  };
  app.get('/api/v1/transfers/scheduled', handleScheduledTransfers);
  app.get('/api/v1/scheduled-transfers', handleScheduledTransfers);

  // Read-Only: Bank Directory
  app.get('/api/v1/banks', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const query = request.query as { q?: string };
    const banks = await generalService.getBanks(query.q);
    return {
      count: banks.length,
      banks,
    };
  });

  // Read-Only: Dashboard Banners and Announcements
  app.get('/api/v1/banners', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const query = request.query as { type?: string };
    const banners = await generalService.getBanners(query.type || 'PopUp');
    return {
      count: banners.length,
      banners,
    };
  });

  // Read-Only: Sayad Cheque Cartable
  app.get('/api/v1/cheques', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const query = request.query as { page?: string; limit?: string; status?: string };
    const page = Math.max(0, parseInt(query.page || '0', 10) || 0);
    const limit = Math.min(Math.max(1, parseInt(query.limit || '20', 10) || 20), 100);
    const cheques = await generalService.getCheques({ page, limit, status: query.status?.trim() });
    return {
      count: cheques.length,
      cheques,
    };
  });

  // Read-Only: Single Sayad Cheque Detail
  app.get('/api/v1/cheques/:id', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const params = request.params as { id: string };
    const cleanId = (params.id || '').trim();
    if (!cleanId) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Cheque identifier is required.',
        statusCode: 400,
      });
    }

    const cheque = await generalService.getChequeDetail(cleanId);
    if (!cheque) {
      return reply.status(404).send({
        error: 'CHEQUE_NOT_FOUND',
        message: `Sayad cheque with identifier "${cleanId}" was not found.`,
        statusCode: 404,
      });
    }
    return cheque;
  });

  // Read-Only: Customer Loans
  app.get('/api/v1/loans', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const loans = await generalService.getLoans();
    return {
      count: loans.length,
      loans,
    };
  });

  // Read-Only: Loan Installments
  app.get('/api/v1/loans/:loanId/installments', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const params = request.params as { loanId: string };
    const loanId = (params.loanId || '').trim();
    if (!loanId) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Loan identifier is required.',
        statusCode: 400,
      });
    }

    const installments = await generalService.getLoanInstallments(loanId);
    return {
      loanId,
      count: installments.length,
      installments,
    };
  });

  // Read-Only: Aggregated Banking Contacts
  app.get('/api/v1/contacts', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const contacts = await generalService.getContacts();
    return {
      count: contacts.length,
      contacts,
    };
  });

  // Read-Only: Saved Utility Bills
  app.get('/api/v1/bills', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const bills = await generalService.getBills();
    return {
      count: bills.length,
      bills,
    };
  });

  // Read-Only: IBAN Account and Owner Inquiry
  app.get('/api/v1/iban/inquiry', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { iban?: string };
    if (!query.iban || typeof query.iban !== 'string') {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Query parameter "iban" is required.',
        statusCode: 400,
      });
    }

    const cleanIban = query.iban.replace(/[\s-]/g, '').toUpperCase();
    if (!/^IR\d{24}$/.test(cleanIban)) {
      return reply.status(400).send({
        error: 'INVALID_IBAN_FORMAT',
        message: 'IBAN must be a valid 26-character Iranian Sheba (IR followed by 24 digits).',
        statusCode: 400,
      });
    }

    const inquiry = await cardService.inquireIban(cleanIban);
    return inquiry;
  });

  // Read-Only: Central Bank ACH Reason Codes
  app.get('/api/v1/ach/reasons', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const reasons = await generalService.getAchReasons();
    return {
      count: reasons.length,
      reasons,
    };
  });

  // Read-Only: ACH Transfer Reports
  app.get('/api/v1/ach/reports', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const query = request.query as { page?: string; limit?: string };
    const page = Math.max(0, parseInt(query.page || '0', 10) || 0);
    const limit = Math.min(Math.max(1, parseInt(query.limit || '20', 10) || 20), 100);
    const reports = await generalService.getAchReports({ page, limit });
    return {
      count: reports.length,
      reports,
    };
  });

  // Read-Only: List Destination / Favorite Cards
  const handleDestinationCards = async () => {
    const cards = await cardService.getDestinationCards();
    return {
      count: cards.length,
      cards,
    };
  };
  app.get('/api/v1/cards/destination', handleDestinationCards);
  app.get('/api/v1/cards/recent', handleDestinationCards);

  // Read-Only: Unified Owner Inquiry for Card PAN, IBAN, or Deposit
  app.get('/api/v1/owner/:identifier', async (request: FastifyRequest, reply: FastifyReply) => {
    const params = request.params as { identifier: string };
    const rawId = (params.identifier || '').trim();
    if (!rawId) {
      return reply.status(400).send({
        error: 'BAD_REQUEST',
        message: 'Identifier is required.',
        statusCode: 400,
      });
    }

    try {
      const result = await cardService.inquireOwner(rawId);
      return result;
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      return reply.status(400).send({
        error: 'OWNER_INQUIRY_FAILED',
        message: error.message,
        statusCode: 400,
      });
    }
  });

  // Read-Only: Saved Top-Up Numbers
  const handleTopups = async () => {
    if (!generalService) {
      return { count: 0, topups: [] };
    }
    const topups = await generalService.getTopups();
    return {
      count: topups.length,
      topups,
    };
  };
  app.get('/api/v1/charge/recent-phones', handleTopups);
  app.get('/api/v1/topups', handleTopups);
  app.get('/api/v1/topups/recent', handleTopups);

  // Read-Only: Saved Internet Packages
  const handlePackages = async () => {
    if (!generalService) {
      return { count: 0, packages: [] };
    }
    const packages = await generalService.getPackages();
    return {
      count: packages.length,
      packages,
    };
  };
  app.get('/api/v1/internet/recent-phones', handlePackages);
  app.get('/api/v1/packages', handlePackages);
  app.get('/api/v1/packages/recent', handlePackages);

  // Read-Only: Active Client Sessions / Connected Devices
  app.get('/api/v1/sessions/active', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    const sessions = await generalService.getActiveSessions();
    return { count: sessions.length, sessions };
  });

  // Read-Only: User Notification and Email/SMS Settings
  app.get('/api/v1/user/settings', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({
        error: 'SERVICE_UNAVAILABLE',
        message: 'General banking services client is not initialized on this daemon.',
        statusCode: 503,
      });
    }
    return generalService.getEmailSettings();
  });

  // Read-Only: Owned Deposits for Investment Funds
  app.get('/api/v1/deposits/fund', async () => {
    const deposits = await accountService.getFundDeposits();
    return { count: deposits.length, deposits };
  });

  // Read-Only: Owned Deposits for Cash Cheques
  app.get('/api/v1/deposits/cash-checks', async () => {
    const deposits = await accountService.getCashCheckDeposits();
    return { count: deposits.length, deposits };
  });

  // Read-Only: Deposit Approvers
  app.get('/api/v1/accounts/:depositNumber/approvers', async (request: FastifyRequest) => {
    const params = request.params as { depositNumber: string };
    const approvers = await accountService.getApprovers(params.depositNumber);
    return { depositNumber: params.depositNumber, count: approvers.length, approvers };
  });

  // Read-Only: Deposit Cheque Books
  app.get('/api/v1/accounts/:depositNumber/cheque-books', async (request: FastifyRequest) => {
    const params = request.params as { depositNumber: string };
    const query = request.query as { limit?: string; page?: string };
    const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10) || 20));
    const page = Math.max(0, parseInt(query.page || '0', 10) || 0);
    return accountService.getChequeBooks(params.depositNumber, { limit, page });
  });

  // Read-Only: Cheque Sheets for a Cheque Book
  app.get('/api/v1/accounts/:depositNumber/cheque-books/:bookNumber/sheets', async (request: FastifyRequest) => {
    const params = request.params as { depositNumber: string; bookNumber: string };
    const query = request.query as { isDigital?: string };
    const isDigital = query.isDigital !== 'false';
    const sheets = await accountService.getCheckSheets(params.depositNumber, params.bookNumber, isDigital);
    return { count: sheets.length, chequeBookNumber: params.bookNumber, sheets };
  });

  // Read-Only: Card Real-time Balance
  app.get('/api/v1/cards/:cardId/balance', async (request: FastifyRequest) => {
    const params = request.params as { cardId: string };
    return cardService.getCardBalance(params.cardId);
  });

  // Read-Only: Card Transaction Statement
  app.get('/api/v1/cards/:cardId/statement', async (request: FastifyRequest) => {
    const params = request.params as { cardId: string };
    const query = request.query as { page?: string; limit?: string; fromDate?: string; toDate?: string };
    const page = Math.max(0, parseInt(query.page || '0', 10) || 0);
    const limit = Math.min(100, Math.max(1, parseInt(query.limit || '20', 10) || 20));
    return cardService.getCardStatement(params.cardId, { page, limit, fromDate: query.fromDate, toDate: query.toDate });
  });

  // Read-Only: Convert Deposit Number to IBAN
  app.get('/api/v1/iban/convert/deposit-to-iban', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { depositNumber?: string };
    if (!query.depositNumber) {
      return reply.status(400).send({ error: 'BAD_REQUEST', message: 'Query parameter "depositNumber" is required.', statusCode: 400 });
    }
    const iban = await cardService.convertDepositToIban(query.depositNumber);
    return { depositNumber: query.depositNumber, iban };
  });

  // Read-Only: Convert Card PAN to IBAN
  app.get('/api/v1/iban/convert/pan-to-iban', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { pan?: string };
    if (!query.pan) {
      return reply.status(400).send({ error: 'BAD_REQUEST', message: 'Query parameter "pan" is required.', statusCode: 400 });
    }
    const iban = await cardService.convertPanToIban(query.pan);
    return { pan: query.pan, iban };
  });

  // Read-Only: Convert IBAN to Deposit Number
  app.get('/api/v1/iban/convert/iban-to-deposit', async (request: FastifyRequest, reply: FastifyReply) => {
    const query = request.query as { iban?: string };
    if (!query.iban) {
      return reply.status(400).send({ error: 'BAD_REQUEST', message: 'Query parameter "iban" is required.', statusCode: 400 });
    }
    const depositNumber = await cardService.convertIbanToDeposit(query.iban);
    return { iban: query.iban, depositNumber };
  });

  // Read-Only: Utility Bill Types
  app.get('/api/v1/bills/types', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const billTypes = await generalService.getBillTypes();
    return { count: billTypes.length, billTypes };
  });

  // Read-Only: Utility Bill Companies
  app.get('/api/v1/bills/companies', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const companies = await generalService.getBillCompanies();
    return { count: companies.length, companies };
  });

  // Read-Only: Specific Utility Bill Inquiry
  app.get('/api/v1/bills/inquiry/:type/:billId', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const params = request.params as { type: string; billId: string };
    return generalService.inquireBill(params.type, params.billId);
  });

  // Read-Only: Customer Notifications / Messages
  app.get('/api/v1/messages', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const query = request.query as { pageSize?: string };
    const pageSize = Math.min(500, Math.max(1, parseInt(query.pageSize || '100', 10) || 100));
    const messages = await generalService.getMessages(pageSize);
    return { count: messages.length, messages };
  });

  // Read-Only: Mobile Telecommunication Operators
  app.get('/api/v1/mobile/operators', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const operators = await generalService.getMobileOperators();
    return { count: operators.length, operators };
  });

  // Read-Only: Base Top-Up Amounts
  app.get('/api/v1/charge/amounts', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const amounts = await generalService.getTopUpAmounts();
    return { count: amounts.length, amounts };
  });

  // Read-Only: Available PIN Charges
  app.get('/api/v1/charge/pins', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const pins = await generalService.getAvailablePinCharges();
    return { count: pins.length, pins };
  });

  // Read-Only: Internet Package Catalog Options
  app.get('/api/v1/internet/options', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const options = await generalService.getPackageAvailableOptions();
    return { count: options.length, options };
  });

  // Read-Only: Interbank Transfer Rules (Paya / Satna)
  app.get('/api/v1/interbank/rules', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    return generalService.getInterBankRules();
  });

  // Read-Only: Useful Banking Services
  app.get('/api/v1/services/useful', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const services = await generalService.getUsefulServices();
    return { count: services.length, services };
  });

  // Read-Only: Useful External Links
  app.get('/api/v1/links/useful', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const links = await generalService.getUsefulLinks();
    return { count: links.length, links };
  });

  // Read-Only: Search Transactions Across Resources
  app.get('/api/v1/transactions/search', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const query = request.query as { resourceType?: string; pageSize?: string; fromDate?: string; toDate?: string; upperBound?: string };
    const resourceType = query.resourceType?.trim() || 'Deposit';
    const pageSize = Math.min(100, Math.max(1, parseInt(query.pageSize || '20', 10) || 20));
    const transactions = await generalService.searchTransactions(resourceType, {
      pageSize,
      fromDate: query.fromDate,
      toDate: query.toDate,
      upperBound: query.upperBound,
    });
    return { resourceType, count: transactions.length, transactions };
  });

  // Read-Only: Chakad Cheque Actions
  app.get('/api/v1/chakad/actions', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!generalService) {
      return reply.status(503).send({ error: 'SERVICE_UNAVAILABLE', message: 'General banking services client is not initialized on this daemon.', statusCode: 503 });
    }
    const actions = await generalService.getChakadActions();
    return { count: actions.length, actions };
  });

  // Financial Mutation Boundaries (Explicit 405 Prohibitions for financial write operations)
  app.post('/api/v1/transfers', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Financial mutations (fund transfers) are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  app.post('/api/v1/transfers/:id/cancel', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Transfer cancellation mutations are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  app.post('/api/v1/bills/pay', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Bill payments are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  app.post('/api/v1/cards/block', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Card blocking mutations are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  app.post('/api/v1/charge/purchase', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Top-up purchases are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  app.post('/api/v1/internet/purchase', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(405).send({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Package purchases are strictly prohibited by the read-only daemon security policy.',
      statusCode: 405,
    });
  });

  return app;
}
