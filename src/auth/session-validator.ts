import type { SessionData } from '../types.ts';

export type ValidationOutcome = 
  | 'VALID' 
  | 'EXPIRED_LOCALLY' 
  | 'NO_SESSION' 
  | 'AUTH_FAILED_REMOTE' 
  | 'RATE_LIMITED' 
  | 'NETWORK_ERROR' 
  | 'SERVER_ERROR'
  | 'CLIENT_ERROR'
  | 'INVALID_RESPONSE';

export interface HttpResponseLike {
  status: number;
  body?: unknown;
}

export class SessionValidator {
  private idleTimeoutMs: number;

  constructor(idleTimeoutMs: number) {
    this.idleTimeoutMs = idleTimeoutMs;
  }

  /**
   * Performs local temporal validation on the session state.
   */
  validateLocal(session: SessionData | null): ValidationOutcome {
    if (!session || !session.token) {
      return 'NO_SESSION';
    }

    const now = Date.now();
    // Check if idle threshold has elapsed since last recorded activity
    if (now - session.lastActivityAt > this.idleTimeoutMs) {
      return 'EXPIRED_LOCALLY';
    }

    // Check if absolute expiry has elapsed
    if (session.expiresAt && now > session.expiresAt) {
      return 'EXPIRED_LOCALLY';
    }

    return 'VALID';
  }

  /**
   * Classifies an HTTP or Network response to distinguish auth failure, rate limiting,
   * client errors, server errors, and malformed envelopes.
   */
  classifyResponse(res: HttpResponseLike): ValidationOutcome {
    // 1. HTTP 401 & 403: remote authentication failure
    if (res.status === 401 || res.status === 403) {
      return 'AUTH_FAILED_REMOTE';
    }

    // 2. HTTP 429: rate limited
    if (res.status === 429) {
      return 'RATE_LIMITED';
    }

    // 3. HTTP 500-599: server errors
    if (res.status >= 500 && res.status <= 599) {
      return 'SERVER_ERROR';
    }

    // 4. Other HTTP 400-499: client/request errors (must NOT fall through to VALID)
    if (res.status >= 400 && res.status <= 499) {
      return 'CLIENT_ERROR';
    }

    // 5. Non-2xx responses (e.g. 1xx, 3xx redirects) are not valid API responses
    if (res.status < 200 || res.status >= 300) {
      return 'INVALID_RESPONSE';
    }

    // 6. 2xx HTTP Success: validate response envelope
    // Body must be a non-null, non-array object
    if (!res.body || typeof res.body !== 'object' || Array.isArray(res.body)) {
      return 'INVALID_RESPONSE';
    }

    // Must have a numeric `code` property
    const bankBody = res.body as { code?: unknown; message?: unknown };
    if (typeof bankBody.code !== 'number') {
      return 'INVALID_RESPONSE';
    }

    // Inspect Farazpardazan / Yaghut application-level error codes
    if (bankBody.code !== 0) {
      const msg = typeof bankBody.message === 'string' ? bankBody.message.toLowerCase() : '';
      if (
        bankBody.code === 401 ||
        bankBody.code === 102 ||
        bankBody.code === 104 ||
        bankBody.code === 105 ||
        bankBody.code === 1002 ||
        bankBody.code === 3071 ||
        msg.includes('token') ||
        msg.includes('توکن') ||
        msg.includes('ابطال') ||
        msg.includes('منقضی') ||
        msg.includes('نشست') ||
        msg.includes('unauthorized')
      ) {
        return 'AUTH_FAILED_REMOTE';
      }
    }

    return 'VALID';
  }

  /**
   * Distinguishes a network-level transport exception from an authentication failure.
   */
  classifyNetworkError(error: Error): ValidationOutcome {
    const msg = error.message.toLowerCase();
    if (
      msg.includes('econnrefused') ||
      msg.includes('econnreset') ||
      msg.includes('econnaborted') ||
      msg.includes('etimedout') ||
      msg.includes('enotfound') ||
      msg.includes('timeout') ||
      msg.includes('network') ||
      msg.includes('connection reset') ||
      msg.includes('socket hang up')
    ) {
      return 'NETWORK_ERROR';
    }
    return 'SERVER_ERROR';
  }
}
