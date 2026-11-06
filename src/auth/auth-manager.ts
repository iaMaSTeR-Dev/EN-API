import crypto from 'node:crypto';
import type { SessionData, AuthStatus, SessionStatusResponse, LoginCredentials, LoginResult, HandoffTicket, RequestContext } from '../types.ts';
import type { SessionStore } from './session-store.ts';
import type { SessionValidator } from './session-validator.ts';
import type { SessionRefreshManager, KeepAliveClient } from './session-refresh-manager.ts';
import type { BankAuthClient } from './bank-auth-client.ts';
import { isValidToken } from './bank-auth-client.ts';
import { AuthStateManager, type AuthenticationState } from './auth-state.ts';
import { RedactingLogger } from '../logger.ts';
import { recordRequestContextRenewal } from '../request-context.ts';

export class ReauthenticationRequiredError extends Error {
  constructor(message: string = 'Bank session has expired or is invalid. Interactive re-authentication is required.') {
    super(message);
    this.name = 'ReauthenticationRequiredError';
  }
}

export class AuthManager {
  private logger = new RedactingLogger('AuthManager');
  private store: SessionStore;
  private validator: SessionValidator;
  private refreshManager: SessionRefreshManager;
  private stateManager: AuthStateManager = new AuthStateManager('UNAUTHENTICATED');
  private idleTimeoutMs: number;
  private currentGeneration: number = 0;
  private verifiedGeneration: number | null = null;
  private verifiedSessionToken: string | null = null;
  private lastVerifiedAt: number | null = null;
  private isReauthRequired: boolean = false;
  private pendingHandoff: HandoffTicket | null = null;
  private memoryCredentials: { cifOrUsername: string; password: string } | null = null;
  private isCredentialsPersisted: boolean = false;
  private renewalPromise: Promise<{ renewed: boolean; expiredLocally: boolean }> | null = null;
  private lastRenewalTimestamp: number = 0;
  private lastRenewalExpiredLocally: boolean = false;

  constructor(
    store: SessionStore,
    validator: SessionValidator,
    refreshManager: SessionRefreshManager,
    idleTimeoutMs: number
  ) {
    this.store = store;
    this.validator = validator;
    this.refreshManager = refreshManager;
    this.idleTimeoutMs = idleTimeoutMs;
  }

  /**
   * Automatically restores persisted session metadata on application startup.
   * If valid locally, restores session as LOCAL_ACTIVE without prematurely claiming remote verification.
   */
  restorePersistedSession(): boolean {
    const loaded = this.store.loadPersisted();
    if (!loaded) {
      return false;
    }

    const session = this.store.getSession();
    const validation = this.validator.validateLocal(session);

    if (validation === 'VALID' && session && isValidToken(session.token)) {
      this.currentGeneration = session.generation ?? 1;
      this.verifiedSessionToken = null;
      this.verifiedGeneration = null;
      this.lastVerifiedAt = null;
      this.isReauthRequired = false;

      // Restore encrypted credentials if saved by opt-in user
      if (session.savedCredentials && typeof session.savedCredentials === 'object') {
        try {
          const password = this.store.decryptSecret(session.savedCredentials);
          this.memoryCredentials = {
            cifOrUsername: session.savedCredentials.cifOrUsername,
            password,
          };
          this.isCredentialsPersisted = true;
          this.logger.info('Restored encrypted credentials for automatic session renewal');
        } catch (err) {
          this.logger.warn('Failed to decrypt saved credentials; clearing credential cache', err);
          this.memoryCredentials = null;
          this.isCredentialsPersisted = false;
        }
      }

      this.logger.info('Persisted session successfully restored into memory as LOCAL_ACTIVE', {
        generation: this.currentGeneration,
      });
      if (this.stateManager.canTransitionTo('AUTHENTICATED')) {
        this.stateManager.transitionTo('AUTHENTICATED', 'Persisted session restored into memory');
      } else {
        this.stateManager.reset('AUTHENTICATED', 'Persisted session restored into memory');
      }
      return true;
    }

    // If the session token is expired locally, but saved renewal credentials and/or device token exist,
    // preserve the credentials and device token rather than wiping the storage file.
    if (session && (session.savedCredentials || session.deviceToken)) {
      if (session.deviceToken) {
        this.store.setDeviceToken(session.deviceToken);
      }
      if (session.savedCredentials && typeof session.savedCredentials === 'object') {
        try {
          const password = this.store.decryptSecret(session.savedCredentials);
          this.memoryCredentials = {
            cifOrUsername: session.savedCredentials.cifOrUsername,
            password,
          };
          this.isCredentialsPersisted = true;
          this.logger.info('Restored encrypted credentials for automatic session renewal (from expired session)');
        } catch (err) {
          this.logger.warn('Failed to decrypt saved credentials; clearing credential cache', err);
          this.memoryCredentials = null;
          this.isCredentialsPersisted = false;
        }
      }
      this.logger.warn('Persisted session token was expired locally, but renewal credentials/device token were preserved');
      if (this.stateManager.canTransitionTo('EXPIRED')) {
        this.stateManager.transitionTo('EXPIRED', 'Persisted session expired locally');
      }
      return false;
    }

    this.logger.warn('Persisted session was expired or invalid; local session cleared', { validation });
    this.store.clear();
    if (this.stateManager.canTransitionTo('UNAUTHENTICATED')) {
      this.stateManager.transitionTo('UNAUTHENTICATED', 'Persisted session cleared');
    }
    return false;
  }

  /**
   * Authenticates using bank username/CIF and password through the BankAuthClient.
   * Updates session generation, stores session, marks remotely verified, and persists to disk.
   */
  async loginWithCredentials(
    credentials: LoginCredentials,
    authClient: BankAuthClient
  ): Promise<LoginResult> {
    this.logger.info('Initiating bank login with credentials');
    if (this.stateManager.canTransitionTo('AUTHENTICATING')) {
      this.stateManager.transitionTo('AUTHENTICATING', 'Credentials login started');
    } else {
      this.stateManager.reset('AUTHENTICATING', 'Credentials login started');
    }
    // Maintain strict separation between device registration tokens and user session tokens.
    // If a registered device token exists in session store, attach it to authClient
    const effectiveDeviceToken = credentials.deviceToken || this.store.getDeviceToken();
    if (effectiveDeviceToken && !authClient.hasConfiguredDeviceToken()) {
      authClient.setDeviceToken(effectiveDeviceToken);
    }
    if (credentials.deviceToken && isValidToken(credentials.deviceToken)) {
      this.store.setDeviceToken(credentials.deviceToken);
    }

    const outcome = await authClient.login(credentials);

    if (outcome.kind === 'success') {
      if (!isValidToken(outcome.token)) {
        if (this.stateManager.canTransitionTo('INVALID')) {
          this.stateManager.transitionTo('INVALID', 'Received invalid token from bank');
        }
        return {
          success: false,
          status: this.getStatus().status,
          message: 'Bank returned success, but the received token was invalid or sentinel string.',
        };
      }
      this.importSession(outcome.token, outcome.yaghootToken, undefined, outcome.cifOrUsername);
      this.markRemotelyVerified(outcome.token, this.currentGeneration);
      this.setCredentials(credentials.cifOrUsername, credentials.password, Boolean(credentials.saveCredentials));
      if (this.stateManager.canTransitionTo('AUTHENTICATED')) {
        this.stateManager.transitionTo('AUTHENTICATED', 'Credentials login succeeded');
      }
      return {
        success: true,
        status: 'VERIFIED',
        message: 'Authentication successful. Session verified against bank server.',
      };
    }

    if (outcome.kind === 'invalid_credentials') {
      if (this.stateManager.canTransitionTo('UNAUTHENTICATED')) {
        this.stateManager.transitionTo('UNAUTHENTICATED', 'Invalid credentials');
      }
      return {
        success: false,
        status: this.getStatus().status,
        message: outcome.message || 'Invalid username/CIF or password.',
        bankCode: outcome.bankCode,
      };
    }

    if (outcome.kind === 'otp_required') {
      if (this.stateManager.canTransitionTo('OTP_REQUIRED')) {
        this.stateManager.transitionTo('OTP_REQUIRED', 'Bank requires OTP');
      }
      return {
        success: false,
        status: this.getStatus().status,
        requiresOtp: true,
        message: outcome.message || 'Bank requires one-time password (OTP) verification.',
        bankCode: outcome.bankCode,
      };
    }

    if (outcome.kind === 'captcha_required') {
      if (this.stateManager.canTransitionTo('CAPTCHA_REQUIRED')) {
        this.stateManager.transitionTo('CAPTCHA_REQUIRED', 'Bank requires CAPTCHA');
      }
      return {
        success: false,
        status: this.getStatus().status,
        requiresCaptcha: true,
        message: outcome.message || 'Bank enforced CAPTCHA challenge. Browser-assisted login recommended.',
        bankCode: outcome.bankCode,
      };
    }

    if (outcome.kind === 'device_token_required') {
      if (this.stateManager.canTransitionTo('UNAUTHENTICATED')) {
        this.stateManager.transitionTo('UNAUTHENTICATED', 'Device token required');
      }
      return {
        success: false,
        status: this.getStatus().status,
        requiresDeviceToken: true,
        message: outcome.message,
        bankCode: outcome.bankCode,
      };
    }

    if (this.stateManager.canTransitionTo('UNAUTHENTICATED')) {
      this.stateManager.transitionTo('UNAUTHENTICATED', 'Authentication failed');
    }

    const message = 'message' in outcome && outcome.message ? outcome.message : `Bank authentication failed (${outcome.kind}).`;
    return {
      success: false,
      status: this.getStatus().status,
      message,
      bankCode: 'bankCode' in outcome ? outcome.bankCode : undefined,
    };
  }

  /**
   * Creates a single-use, short-lived handoff ticket for secure browser-assisted login.
   */
  createHandoffTicket(loginUrl: string = 'https://neobank.enbank.ir'): HandoffTicket {
    const handoffId = crypto.randomBytes(16).toString('hex');
    const handoffSecret = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes validity

    this.pendingHandoff = {
      handoffId,
      handoffSecret,
      expiresAt,
      loginUrl,
    };

    this.logger.info('Single-use browser handoff ticket generated', { handoffId });
    return { ...this.pendingHandoff };
  }

  /**
   * Consumes a single-use handoff ticket to import session material obtained via browser login.
   */
  consumeHandoffTicket(secret: string, token: string, cifOrUsername?: string, yaghootToken?: string, mobileUserToken?: string): boolean {
    if (!this.pendingHandoff) {
      this.logger.warn('Browser handoff rejected: no active ticket');
      return false;
    }

    if (Date.now() > this.pendingHandoff.expiresAt) {
      this.logger.warn('Browser handoff rejected: ticket expired');
      this.pendingHandoff = null;
      return false;
    }

    if (this.pendingHandoff.handoffSecret !== secret) {
      this.logger.warn('Browser handoff rejected: secret mismatch');
      return false;
    }

    // Destroy single-use ticket immediately
    this.pendingHandoff = null;

    if (mobileUserToken && isValidToken(mobileUserToken)) {
      this.store.setDeviceToken(mobileUserToken);
    }

    // Import session with authenticated yaghootToken
    this.importSession(token, yaghootToken || token, undefined, cifOrUsername, mobileUserToken);
    this.logger.info('Browser handoff ticket successfully consumed');
    return true;
  }

  /**
   * Imports an active authenticated session seeded by the authorized account owner.
   * Increments the monotonic lifecycle generation counter (Finding L-2).
   * Produces status LOCAL_ACTIVE with isRemotelyVerified = false.
   */
  importSession(token: string, yaghootToken?: string, f5Cookie?: string, cifOrUsername?: string, deviceToken?: string): void {
    if (!isValidToken(token)) {
      throw new Error('Invalid token provided for session import: token must be a non-empty, non-sentinel bearer token.');
    }

    const trimmed = token.trim();
    const now = Date.now();
    this.currentGeneration += 1;
    const generation = this.currentGeneration;

    const session: SessionData = {
      token: trimmed,
      yaghootToken: yaghootToken?.trim(),
      f5Cookie: f5Cookie?.trim(),
      deviceToken: deviceToken?.trim() || this.store.getDeviceToken(),
      createdAt: now,
      lastActivityAt: now,
      expiresAt: now + this.idleTimeoutMs,
      cifOrUsername,
      generation,
    };

    // Reset verification metadata so newly imported session starts unverified
    this.verifiedSessionToken = null;
    this.verifiedGeneration = null;
    this.lastVerifiedAt = null;
    this.isReauthRequired = false;

    this.store.setSession(session);
    if (this.stateManager.canTransitionTo('AUTHENTICATED')) {
      this.stateManager.transitionTo('AUTHENTICATED', 'User session imported');
    } else {
      this.stateManager.reset('AUTHENTICATED', 'User session imported');
    }
    this.logger.info('User session successfully imported and initialized', { generation });
  }

  /**
   * Returns the current session lifecycle generation counter.
   */
  getSessionGeneration(): number {
    const session = this.store.getSession();
    return session?.generation ?? this.currentGeneration;
  }

  /**
   * Marks the current session as remotely verified after a successful validated bank API call.
   * Verifies both token equality and monotonic lifecycle generation match (Findings M-1, L-2).
   */
  markRemotelyVerified(token: string, generation?: number): void {
    const session = this.store.getSession();
    const currentGen = session?.generation ?? this.currentGeneration;
    const genMatches = generation === undefined || (generation === currentGen && generation === this.currentGeneration);

    if (session && session.token === token && genMatches) {
      this.verifiedSessionToken = token;
      this.verifiedGeneration = currentGen;
      this.lastVerifiedAt = Date.now();
      this.isReauthRequired = false;
      this.logger.info('Session successfully verified against remote bank server', { generation: currentGen });
    } else {
      this.logger.warn('Ignoring verification for mismatched or superseded session token/generation', {
        targetGeneration: generation,
        currentGeneration: this.currentGeneration,
      });
    }
  }

  /**
   * Records a confirmed authentication rejection from an ordinary read query.
   * Resets remote verification state and transitions status to REAUTHENTICATION_REQUIRED
   * without deleting local session data, while preventing stale responses from affecting
   * replacement sessions (Finding L-1).
   */
  markRemoteAuthFailure(token: string, generation?: number): void {
    const session = this.store.getSession();
    const currentGen = session?.generation ?? this.currentGeneration;
    const genMatches = generation === undefined || (generation === currentGen && generation === this.currentGeneration);

    if (session && session.token === token && genMatches) {
      this.verifiedSessionToken = null;
      this.verifiedGeneration = null;
      this.lastVerifiedAt = null;
      this.isReauthRequired = true;
      if (this.stateManager.canTransitionTo('EXPIRED')) {
        this.stateManager.transitionTo('EXPIRED', 'Remote authentication failure');
      }
      this.logger.warn('Remote authentication failure recorded for session; re-authentication required', {
        generation: currentGen,
      });
    } else {
      this.logger.warn('Ignoring remote auth failure for mismatched or superseded session token/generation', {
        targetGeneration: generation,
        currentGeneration: this.currentGeneration,
      });
    }
  }

  /**
   * Evaluates current authentication status without leaking sensitive material.
   */
  getStatus(): SessionStatusResponse {
    const session = this.store.getSession();
    const validation = this.validator.validateLocal(session);

    let status: AuthStatus = 'UNAUTHENTICATED';
    let isAuthenticated = false;

    const hasLocalSession = Boolean(session && validation === 'VALID');
    const isRemotelyVerified = Boolean(
      hasLocalSession &&
      session &&
      this.verifiedSessionToken &&
      this.verifiedSessionToken === session.token &&
      (this.verifiedGeneration === null || this.verifiedGeneration === session.generation)
    );

    if (validation === 'VALID' && session) {
      if (isRemotelyVerified) {
        status = 'VERIFIED';
        isAuthenticated = true;
      } else if (this.isReauthRequired) {
        status = 'REAUTHENTICATION_REQUIRED';
        isAuthenticated = false;
      } else {
        status = 'LOCAL_ACTIVE';
        isAuthenticated = true;
      }
    } else if (validation === 'EXPIRED_LOCALLY') {
      status = 'EXPIRED';
      isAuthenticated = false;
    } else if (validation === 'NO_SESSION' || !session) {
      status = 'UNAUTHENTICATED';
      isAuthenticated = false;
    }

    return {
      status,
      authenticationState: this.stateManager.getState(),
      isAuthenticated,
      hasLocalSession,
      isRemotelyVerified,
      expiresAt: session ? new Date(session.expiresAt).toISOString() : null,
      lastActivityAt: session ? new Date(session.lastActivityAt).toISOString() : null,
      lastVerifiedAt: (isRemotelyVerified && this.lastVerifiedAt) ? new Date(this.lastVerifiedAt).toISOString() : null,
      idleTimeoutSeconds: Math.round(this.idleTimeoutMs / 1000),
      hasPersistedSession: this.store.hasPersisted(),
      hasSavedCredentials: this.hasRenewalCredentials(),
      hasRegisteredDevice: Boolean(this.store.getDeviceToken()),
      credentialsStorage: this.getCredentialsStorageType(),
    };
  }

  /**
   * Returns the current state from the formal authentication state machine.
   */
  getAuthenticationState(): AuthenticationState {
    return this.stateManager.getState();
  }

  /**
   * Exposes the formal authentication state manager.
   */
  getStateManager(): AuthStateManager {
    return this.stateManager;
  }

  /**
   * Retrieves any pre-registered device token (mobileUserToken) stored in the session vault.
   */
  getRegisteredDeviceToken(): string | undefined {
    return this.store.getDeviceToken();
  }

  /**
   * Stores a pre-registered device token (mobileUserToken) in the session vault.
   */
  setRegisteredDeviceToken(deviceToken?: string): void {
    this.store.setDeviceToken(deviceToken);
  }

  /**
   * Sets the user credentials for session renewal (in-memory, and optionally AES-256-GCM encrypted on disk).
   */
  setCredentials(cifOrUsername: string, password: string, persist: boolean = false): void {
    const cleanCif = cifOrUsername.trim();
    if (!cleanCif || !password) return;

    this.memoryCredentials = { cifOrUsername: cleanCif, password };
    this.isCredentialsPersisted = persist;

    const session = this.store.getSession();
    if (session) {
      if (persist) {
        const encrypted = this.store.encryptSecret(password);
        session.savedCredentials = {
          cifOrUsername: cleanCif,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          tag: encrypted.tag,
        };
        this.store.setSession(session);
        this.logger.info('Encrypted credentials saved for automatic session renewal');
      } else if (session.savedCredentials) {
        delete session.savedCredentials;
        this.store.setSession(session);
      }
    }
  }

  /**
   * Returns whether renewal credentials are currently available in memory.
   */
  hasRenewalCredentials(): boolean {
    return Boolean(this.memoryCredentials?.cifOrUsername && this.memoryCredentials?.password);
  }

  /**
   * Returns the credential storage mode ('MEMORY', 'PERSISTED_ENCRYPTED', or 'NONE').
   */
  getCredentialsStorageType(): 'MEMORY' | 'PERSISTED_ENCRYPTED' | 'NONE' {
    if (!this.memoryCredentials) return 'NONE';
    return this.isCredentialsPersisted ? 'PERSISTED_ENCRYPTED' : 'MEMORY';
  }

  /**
   * Clears saved renewal credentials from memory and disk.
   */
  clearCredentials(): void {
    this.memoryCredentials = null;
    this.isCredentialsPersisted = false;
    const session = this.store.getSession();
    if (session && session.savedCredentials) {
      delete session.savedCredentials;
      this.store.setSession(session);
    }
  }

  /**
   * Attempts automatic background renewal using stored credentials with single-flight request coalescing.
   * If multiple concurrent queries hit Code 3071, only a single renewal request is dispatched to the bank.
   * All requests that initiate or await this single-flight renewal have their active request context attributed.
   */
  async attemptAutoRenewal(
    authClient: BankAuthClient,
    explicitTrigger?: 'local' | 'remote',
    explicitContext?: RequestContext
  ): Promise<boolean> {
    if (!this.hasRenewalCredentials()) {
      return false;
    }

    if (this.renewalPromise) {
      this.logger.info('Awaiting existing in-flight session renewal');
      const result = await this.renewalPromise;
      if (result.renewed) {
        recordRequestContextRenewal(result.expiredLocally, explicitContext);
      }
      return result.renewed;
    }

    const isExpiredLocally = explicitTrigger !== undefined
      ? explicitTrigger === 'local'
      : this.validator.validateLocal(this.store.getSession()) !== 'VALID';

    if (this.stateManager.canTransitionTo('REFRESHING')) {
      this.stateManager.transitionTo('REFRESHING', 'Executing auto-renewal');
    }

    this.renewalPromise = (async () => {
      try {
        const renewed = await this.executeRenewal(authClient, isExpiredLocally);
        return { renewed, expiredLocally: isExpiredLocally };
      } finally {
        this.renewalPromise = null;
      }
    })();

    const result = await this.renewalPromise;
    if (result.renewed) {
      if (this.stateManager.canTransitionTo('AUTHENTICATED')) {
        this.stateManager.transitionTo('AUTHENTICATED', 'Renewal succeeded');
      }
      recordRequestContextRenewal(result.expiredLocally, explicitContext);
    } else {
      if (this.stateManager.canTransitionTo('EXPIRED')) {
        this.stateManager.transitionTo('EXPIRED', 'Renewal failed');
      }
    }
    return result.renewed;
  }

  private async executeRenewal(authClient: BankAuthClient, isExpiredLocally: boolean): Promise<boolean> {
    const creds = this.memoryCredentials;
    if (!creds) return false;

    // Ensure registered device token is attached if available in store
    const storedDeviceToken = this.store.getDeviceToken();
    if (storedDeviceToken && !authClient.hasConfiguredDeviceToken()) {
      authClient.setDeviceToken(storedDeviceToken);
    }

    this.logger.info('Executing automatic session renewal with Bank Eghtesad Novin...');
    const outcome = await authClient.login({
      cifOrUsername: creds.cifOrUsername,
      password: creds.password,
      deviceToken: storedDeviceToken || authClient.getConfiguredDeviceToken(),
    });

    if (outcome.kind === 'success' && isValidToken(outcome.token)) {
      this.importSession(outcome.token, outcome.yaghootToken, undefined, outcome.cifOrUsername);
      // Replacement session starts in LOCAL_ACTIVE; it is marked verified ONLY after an explicit read query succeeds
      this.setCredentials(creds.cifOrUsername, creds.password, this.isCredentialsPersisted);
      this.lastRenewalTimestamp = Date.now();
      this.lastRenewalExpiredLocally = isExpiredLocally;
      this.logger.info('Automatic session renewal successful', { generation: this.currentGeneration, isExpiredLocally });
      return true;
    }

    this.logger.warn('Automatic session renewal could not complete silently', { outcomeKind: outcome.kind });
    const currentSession = this.store.getSession();
    if (currentSession) {
      this.markRemoteAuthFailure(currentSession.token, this.currentGeneration);
    }
    return false;
  }

  /**
   * Returns the epoch millisecond timestamp of the most recent successful automatic session renewal.
   */
  getLastRenewalTimestamp(): number {
    return this.lastRenewalTimestamp;
  }

  /**
   * Returns whether the most recent successful renewal was triggered by a local session expiration.
   */
  wasLastRenewalExpiredLocally(): boolean {
    return this.lastRenewalExpiredLocally;
  }

  /**
   * Retrieves the current session data (if any) directly from the underlying store.
   */
  getSession(): SessionData | null {
    return this.store.getSession();
  }

  /**
   * Returns the active valid token or throws ReauthenticationRequiredError.
   */
  getValidToken(): string {
    const session = this.store.getSession();
    const validation = this.validator.validateLocal(session);

    if (validation !== 'VALID' || !session) {
      this.logger.warn('Token request rejected: session is expired or uninitialized', { validation });
      const detail = validation === 'EXPIRED_LOCALLY'
        ? 'Local session idle timeout has expired (5m). Run "npm run cli -- verify" to check/refresh with bank, or "npm run cli -- login" to re-authenticate.'
        : 'Bank session has expired or is invalid. Interactive re-authentication is required.';
      throw new ReauthenticationRequiredError(detail);
    }

    if (this.isReauthRequired) {
      this.logger.warn('Token request rejected: session requires re-authentication following remote bank rejection');
      throw new ReauthenticationRequiredError(
        'Bank session was rejected by the bank server (e.g. Code 3071). Interactive re-authentication is required. Run "npm run cli -- login" or "npm run cli -- login --browser".'
      );
    }

    return session.token;
  }

  /**
   * Records user activity on a successful API request, resetting the local idle window.
   * NOTE: Local activity alone does NOT mark a session as remotely verified (Fix D).
   */
  recordActivity(): void {
    const session = this.store.getSession();
    if (session) {
      this.store.touchActivity(Date.now() + this.idleTimeoutMs);
    }
  }

  /**
   * Explicitly invalidates the active session due to remote rejection, logout, or security event.
   * Increments the generation to orphan any in-flight requests (Finding L-2).
   */
  invalidateSession(reason: string = 'Session explicitly invalidated'): void {
    this.clearCredentials();
    this.store.clear();
    this.currentGeneration += 1;
    this.verifiedSessionToken = null;
    this.verifiedGeneration = null;
    this.lastVerifiedAt = null;
    this.isReauthRequired = false;
    this.pendingHandoff = null;
    if (this.stateManager.canTransitionTo('LOGGED_OUT')) {
      this.stateManager.transitionTo('LOGGED_OUT', reason);
    } else {
      this.stateManager.reset('LOGGED_OUT', reason);
    }
    this.logger.warn(`Local session invalidated: ${reason}`);
  }

  /**
   * Clears the active session on explicit user logout, optionally calling bankLogout.
   */
  async logout(authClient?: BankAuthClient): Promise<void> {
    const session = this.store.getSession();
    if (authClient && session && session.token) {
      try {
        await authClient.logout(session.token);
      } catch (err) {
        this.logger.warn('Remote bank logout failed or timed out', err);
      }
    }
    this.invalidateSession('User explicitly logged out');
  }

  /**
   * Performs a keep-alive extension using the provided client.
   */
  async touchSession(client: KeepAliveClient): Promise<boolean> {
    return this.refreshManager.touchOrExtend(client);
  }
}
