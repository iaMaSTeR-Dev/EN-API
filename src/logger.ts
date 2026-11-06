/**
 * Centralized Redacting Logger.
 * Ensures zero secrets (passwords, tokens, cookies, PANs, CVVs, OTPs) are emitted to stdout or log files,
 * while preserving complete error diagnostics (name, message, stack, nested cause, custom properties).
 */

const SENSITIVE_KEYS = new Set([
  'authorization',
  'cookie',
  'cookiesession1',
  'token',
  'currenttoken',
  'yaghoottoken',
  'refreshtoken',
  'devicetoken',
  'mobileusertoken',
  'validationcode',
  'password',
  'customerpassword',
  'otp',
  'activationcode',
  'cvv',
  'cvv2',
  'pan',
  'cardnumber',
  'cif',
  'secret',
  'vaultsecret',
  'localapikey',
  'apikey',
  'x-local-api-key',
]);

/**
 * Redacts sensitive tokens, PANs, and credentials embedded within strings.
 */
function redactString(str: string): string {
  return str
    // Bearer tokens
    .replace(/Bearer\s+[a-zA-Z0-9_\-\.]+/gi, 'Bearer [REDACTED_TOKEN]')
    // JWT / long bearer-like tokens
    .replace(/\bey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9._-]{15,}\b/g, '[REDACTED_TOKEN]')
    // 16-19 digit card PANs
    .replace(/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4,7}\b/g, '[REDACTED_PAN]')
    // Credential key-value pairs in URLs, query parameters, or form data
    .replace(/((?:password|customerpassword|token|currenttoken|yaghoottoken|refreshtoken|devicetoken|mobileusertoken|validationcode|activationcode|otp|code|secret|vaultsecret|localapikey|apikey|cookiesession1|cvv|cvv2|pan|cardnumber|cif)=)[^&\s;]+/gi, '$1[REDACTED]');
}

/**
 * Robust, centralized, recursive, cycle-safe error serializer.
 * Preserves Error.name, Error.message, Error.stack, nested Error.cause,
 * and custom diagnostics (statusCode, bankCode, code, etc.) without leaking credentials.
 */
export function serializeError(err: unknown, seen = new WeakSet()): unknown {
  if (err === null || err === undefined) {
    return err;
  }

  if (typeof err === 'string') {
    return redactString(err);
  }

  if (typeof err === 'number' || typeof err === 'boolean') {
    return err;
  }

  if (typeof err === 'bigint' || typeof err === 'symbol') {
    return String(err);
  }

  if (typeof err === 'object') {
    if (seen.has(err)) {
      return '[CIRCULAR]';
    }
    seen.add(err);

    if (Array.isArray(err)) {
      return err.map((item) => serializeError(item, seen));
    }

    const isError =
      err instanceof Error ||
      (typeof (err as Record<string, unknown>).message === 'string' &&
        typeof (err as Record<string, unknown>).name === 'string');

    const result: Record<string, unknown> = {};

    if (isError) {
      const errObj = err as Error;
      result.name = redactString(errObj.name || 'Error');
      result.message = redactString(errObj.message || '');
      if (errObj.stack) {
        result.stack = redactString(errObj.stack);
      }
      if (errObj.cause !== undefined) {
        result.cause = serializeError(errObj.cause, seen);
      }
    }

    // Inspect both own property names (including non-enumerable) and enumerable keys
    const propNames = new Set([
      ...Object.getOwnPropertyNames(err),
      ...Object.keys(err),
    ]);

    for (const prop of propNames) {
      if (isError && (prop === 'name' || prop === 'message' || prop === 'stack' || prop === 'cause')) {
        continue;
      }
      if (SENSITIVE_KEYS.has(prop.toLowerCase())) {
        result[prop] = '[REDACTED]';
      } else {
        result[prop] = serializeError((err as Record<string, unknown>)[prop], seen);
      }
    }

    return result;
  }

  return err;
}

/**
 * Recursively redacts sensitive keys and values from arbitrary data payloads.
 * Cycle-safe and preserves native Error properties via serializeError.
 */
export function redactSensitiveData(data: unknown, seen = new WeakSet()): unknown {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === 'string') {
    return redactString(data);
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return data;
  }

  if (typeof data === 'bigint' || typeof data === 'symbol') {
    return String(data);
  }

  if (data instanceof Error) {
    return serializeError(data, seen);
  }

  if (typeof data === 'object') {
    if (seen.has(data)) {
      return '[CIRCULAR]';
    }
    seen.add(data);

    if (Array.isArray(data)) {
      return data.map((item) => redactSensitiveData(item, seen));
    }

    const redactedObj: Record<string, unknown> = {};
    const propNames = new Set([
      ...Object.getOwnPropertyNames(data),
      ...Object.keys(data),
    ]);

    for (const prop of propNames) {
      if (SENSITIVE_KEYS.has(prop.toLowerCase())) {
        redactedObj[prop] = '[REDACTED]';
      } else {
        redactedObj[prop] = redactSensitiveData((data as Record<string, unknown>)[prop], seen);
      }
    }
    return redactedObj;
  }

  return data;
}

export class RedactingLogger {
  private context: string;

  constructor(context: string = 'App') {
    this.context = context;
  }

  info(message: string, meta?: unknown): void {
    const payload = meta !== undefined ? ` | ${JSON.stringify(redactSensitiveData(meta))}` : '';
    console.log(`[INFO] [${this.context}] ${redactSensitiveData(message)}${payload}`);
  }

  warn(message: string, meta?: unknown): void {
    const payload = meta !== undefined ? ` | ${JSON.stringify(redactSensitiveData(meta))}` : '';
    console.warn(`[WARN] [${this.context}] ${redactSensitiveData(message)}${payload}`);
  }

  error(message: string, error?: unknown): void {
    const payload = error !== undefined ? ` | ${JSON.stringify(serializeError(error))}` : '';
    console.error(`[ERROR] [${this.context}] ${redactSensitiveData(message)}${payload}`);
  }
}
