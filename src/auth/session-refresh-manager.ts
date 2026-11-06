import { RedactingLogger } from '../logger.ts';
import type { SessionStore } from './session-store.ts';
import type { SessionValidator } from './session-validator.ts';

export type KeepAliveOutcome =
  | { kind: 'success' }
  | { kind: 'auth_rejected'; statusCode?: number; bankCode?: number; message?: string }
  | { kind: 'rate_limited'; statusCode?: number }
  | { kind: 'network_error'; error: Error }
  | { kind: 'server_error'; statusCode?: number }
  | { kind: 'unexpected_response'; statusCode?: number; message?: string };

export interface KeepAliveClient {
  executeKeepAlive(token: string): Promise<KeepAliveOutcome>;
}

export class SessionRefreshManager {
  private inFlightRefresh: Promise<boolean> | null = null;
  private logger = new RedactingLogger('SessionRefreshManager');
  private store: SessionStore;
  private validator: SessionValidator;
  private idleTimeoutMs: number;

  constructor(
    store: SessionStore,
    validator: SessionValidator,
    idleTimeoutMs: number
  ) {
    this.store = store;
    this.validator = validator;
    this.idleTimeoutMs = idleTimeoutMs;
  }

  /**
   * Refreshes / extends the session sliding-window via keep-alive.
   *
   * IMPORTANT EVIDENCE-BASED CONSTRAINT:
   * The bank Web application (neobank.enbank.ir) does NOT expose an OAuth2 refresh token endpoint.
   * Session lifetime is extended purely by server-side sliding-window activity before expiration.
   * Once invalidated by the server, silent renewal is impossible; human re-authentication is mandatory.
   */
  async touchOrExtend(client: KeepAliveClient): Promise<boolean> {
    const session = this.store.getSession();
    const localValidation = this.validator.validateLocal(session);

    if (localValidation !== 'VALID') {
      this.logger.warn('Cannot extend session: session is invalid or already expired locally', {
        reason: localValidation,
      });
      return false;
    }

    // Coalesce concurrent refresh/keep-alive calls
    if (this.inFlightRefresh) {
      this.logger.info('Awaiting existing in-flight keep-alive operation');
      return this.inFlightRefresh;
    }

    const targetToken = session!.token;
    const targetGeneration = session!.generation;

    this.inFlightRefresh = (async () => {
      try {
        const outcome = await client.executeKeepAlive(targetToken);

        // Verify session identity immediately before any store mutation (Finding M-1)
        const currentSession = this.store.getSession();
        const isStillCurrent = Boolean(
          currentSession &&
          currentSession.token === targetToken &&
          (targetGeneration === undefined || currentSession.generation === targetGeneration)
        );

        if (!isStillCurrent) {
          this.logger.warn('Ignoring Keep-Alive outcome for superseded or invalidated session', {
            targetGeneration,
            currentGeneration: currentSession?.generation,
            outcomeKind: outcome.kind,
          });
          return false;
        }

        if (outcome.kind === 'success') {
          const now = Date.now();
          this.store.touchActivity(now + this.idleTimeoutMs);
          this.logger.info('Session sliding window successfully extended via keep-alive');
          return true;
        } else if (outcome.kind === 'auth_rejected') {
          this.logger.warn('Server rejected keep-alive; clearing invalidated local session', outcome);
          this.store.clear();
          return false;
        } else {
          // Transient issues: network_error, rate_limited, server_error, unexpected_response
          // Session is PRESERVED in memory/store; do NOT clear store; do NOT touch activity/expiry
          this.logger.warn(`Keep-alive encountered transient issue (${outcome.kind}); preserving local session`, outcome);
          return false;
        }
      } catch (err) {
        this.logger.error('Keep-alive execution failed; preserving local session', err);
        return false;
      } finally {
        this.inFlightRefresh = null;
      }
    })();

    return this.inFlightRefresh;
  }

  /**
   * Explicitly documents the absence of a silent refresh token grant.
   */
  supportsSilentRefreshToken(): boolean {
    return false;
  }
}
