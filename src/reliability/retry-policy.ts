import { BankClientError } from '../client/bank-read-only-client.ts';
import { classifyNetworkError } from './network-errors.ts';

export interface RetryPolicyConfig {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  jitter: boolean;
}

export const DEFAULT_RETRY_CONFIG: RetryPolicyConfig = {
  maxAttempts: 3,
  baseDelayMs: 200,
  maxDelayMs: 2000,
  backoffMultiplier: 2,
  jitter: true,
};

/**
 * Calculates exponential backoff delay with jitter.
 * Delay formula: min(maxDelayMs, baseDelayMs * multiplier^attempt) + jitter
 */
export function calculateBackoff(
  attempt: number,
  config: RetryPolicyConfig = DEFAULT_RETRY_CONFIG,
  retryAfterHeader?: string | number
): number {
  if (retryAfterHeader !== undefined && retryAfterHeader !== '') {
    const sec = typeof retryAfterHeader === 'number' ? retryAfterHeader : Number(retryAfterHeader);
    if (!isNaN(sec) && sec > 0) {
      return Math.min(sec * 1000, 10000);
    }
  }

  const expDelay = config.baseDelayMs * Math.pow(config.backoffMultiplier, attempt);
  const boundedDelay = Math.min(expDelay, config.maxDelayMs);

  if (config.jitter) {
    // Full jitter between 0 and boundedDelay
    const jitterAmount = Math.floor(Math.random() * (boundedDelay * 0.3));
    return boundedDelay + jitterAmount;
  }

  return boundedDelay;
}

/**
 * Evaluates whether an error should be retried under read-only safe guarantees.
 * NEVER retries client semantic errors: 400 (Bad Request), 401 (Unauthorized),
 * 403 (Forbidden), 404 (Not Found), 422 (Unprocessable Entity).
 * ONLY retries transient network errors or gateway/proxy errors (502, 503, 504).
 */
export function isRetryableError(err: unknown, isIdempotent: boolean = true): boolean {
  if (!isIdempotent) {
    return false;
  }

  if (err instanceof BankClientError) {
    // Never retry auth errors (handled separately by auth renewal), client errors, or not-found
    if (err.isAuthError || err.statusCode === 400 || err.statusCode === 401 || err.statusCode === 403 || err.statusCode === 404 || err.statusCode === 422) {
      return false;
    }

    if (err.isNetworkError) {
      return true;
    }

    if (err.statusCode && [502, 503, 504].includes(err.statusCode)) {
      return true;
    }

    return false;
  }

  const classification = classifyNetworkError(err);
  return classification.isTransient;
}

/**
 * Executes an async operation with bounded exponential backoff and jitter.
 */
export async function executeWithRetry<T>(
  operation: (attempt: number) => Promise<T>,
  options: Partial<RetryPolicyConfig> & {
    isIdempotent?: boolean;
    onRetry?: (err: unknown, attempt: number, delayMs: number) => void;
    sleepFn?: (ms: number) => Promise<void>;
  } = {}
): Promise<T> {
  const config: RetryPolicyConfig = { ...DEFAULT_RETRY_CONFIG, ...options };
  const isIdempotent = options.isIdempotent ?? true;
  const sleep = options.sleepFn ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));

  let lastError: unknown;

  for (let attempt = 0; attempt < config.maxAttempts; attempt++) {
    try {
      return await operation(attempt);
    } catch (err: unknown) {
      lastError = err;

      const isLastAttempt = attempt >= config.maxAttempts - 1;
      if (isLastAttempt || !isRetryableError(err, isIdempotent)) {
        throw err;
      }

      const delayMs = calculateBackoff(attempt, config);
      if (options.onRetry) {
        options.onRetry(err, attempt + 1, delayMs);
      }

      await sleep(delayMs);
    }
  }

  throw lastError;
}

