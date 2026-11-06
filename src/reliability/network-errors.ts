/**
 * Base client error representing any error originating from bank communication or contract violations.
 */
export class BankClientError extends Error {
  public statusCode?: number;
  public bankCode?: number;
  public isAuthError: boolean;
  public isNetworkError: boolean;
  public isRateLimited: boolean;

  constructor(
    message: string,
    statusCode?: number,
    bankCode?: number,
    isAuthError: boolean = false,
    isNetworkError: boolean = false,
    isRateLimited: boolean = false
  ) {
    super(message);
    this.name = 'BankClientError';
    this.statusCode = statusCode;
    this.bankCode = bankCode;
    this.isAuthError = isAuthError;
    this.isNetworkError = isNetworkError;
    this.isRateLimited = isRateLimited;
  }
}

/**
 * Specialized error thrown when a remote banking network error occurs (DNS, connection reset, unreachable host).
 * Crucially, network errors do NOT invalidate or expire local authentication credentials.
 */
export class BankNetworkError extends BankClientError {
  public readonly code?: string;
  public readonly isTransient: boolean;

  constructor(message: string, code?: string, isTransient: boolean = true) {
    super(message, undefined, undefined, false, true, false);
    this.name = 'BankNetworkError';
    this.code = code;
    this.isTransient = isTransient;
  }
}

/**
 * Specialized error thrown when a request or connection exceeds its designated timeout threshold.
 */
export class BankTimeoutError extends BankClientError {
  public readonly timeoutMs: number;

  constructor(message: string, timeoutMs: number) {
    super(message, 408, undefined, false, true, false);
    this.name = 'BankTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Specialized error thrown when a bank response indicates rate limiting (HTTP 429).
 */
export class BankRateLimitError extends BankClientError {
  public readonly retryAfterSeconds?: number;

  constructor(message: string, retryAfterSeconds?: number) {
    super(message, 429, undefined, false, false, true);
    this.name = 'BankRateLimitError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Specialized error thrown when an entity or resource is not found (HTTP 404).
 */
export class BankNotFoundError extends BankClientError {
  constructor(message: string) {
    super(message, 404, undefined, false, false, false);
    this.name = 'BankNotFoundError';
  }
}

/**
 * Known transient network error codes from Node.js runtime and undici/fetch.
 */
const TRANSIENT_NETWORK_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
]);

/**
 * Inspects an unknown error and categorizes whether it is a transient network failure.
 */
export function classifyNetworkError(err: unknown): {
  isNetwork: boolean;
  isTransient: boolean;
  isTimeout: boolean;
  code?: string;
  message: string;
} {
  if (!err) {
    return { isNetwork: false, isTransient: false, isTimeout: false, message: 'Unknown error' };
  }

  const error = err instanceof Error ? err : new Error(String(err));
  const errWithCode = err as { code?: string; name?: string; status?: number };
  const code = errWithCode.code || (errWithCode.name === 'AbortError' ? 'ETIMEDOUT' : undefined);
  const msgLower = error.message.toLowerCase();

  const isTimeout =
    code === 'ETIMEDOUT' ||
    code === 'UND_ERR_CONNECT_TIMEOUT' ||
    code === 'UND_ERR_HEADERS_TIMEOUT' ||
    error.name === 'AbortError' ||
    msgLower.includes('timeout') ||
    msgLower.includes('timed out') ||
    msgLower.includes('aborted');

  const isTransient =
    isTimeout ||
    (code !== undefined && TRANSIENT_NETWORK_CODES.has(code)) ||
    msgLower.includes('socket hang up') ||
    msgLower.includes('econnreset') ||
    msgLower.includes('network error') ||
    msgLower.includes('connection refused') ||
    msgLower.includes('fetch failed');

  const isNetwork = isTransient || code !== undefined;

  return {
    isNetwork,
    isTransient,
    isTimeout,
    code,
    message: error.message,
  };
}
