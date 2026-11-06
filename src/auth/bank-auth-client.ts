import type { TransportFn, TransportResponse } from '../client/bank-read-only-client.ts';
import type { SessionValidator } from './session-validator.ts';
import type { DeviceRegistrationOutcome, DeviceValidationOutcome } from '../types.ts';
import { RedactingLogger } from '../logger.ts';

/**
 * Strictly validates that an access/bearer token is non-empty, non-sentinel string.
 * Rejects undefined, null, "null", "undefined", "[object Object]", empty strings, and whitespace.
 */
export function isValidToken(token: unknown): token is string {
  if (typeof token !== 'string') return false;
  const trimmed = token.trim();
  if (trimmed.length < 5) return false;
  const lower = trimmed.toLowerCase();
  if (
    lower === 'null' ||
    lower === 'undefined' ||
    lower === '[object object]' ||
    lower === 'none' ||
    lower === 'false' ||
    lower === 'true' ||
    lower === '0'
  ) {
    return false;
  }
  return true;
}

export type LoginOutcome =
  | { kind: 'success'; token: string; yaghootToken?: string; cifOrUsername: string }
  | { kind: 'invalid_credentials'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'otp_required'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'captcha_required'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'device_token_required'; message: string; statusCode?: number; bankCode?: number }
  | { kind: 'rate_limited'; statusCode: number; message?: string }
  | { kind: 'auth_rejected'; statusCode: number; message?: string; bankCode?: number }
  | { kind: 'server_error'; statusCode: number; message?: string }
  | { kind: 'network_error'; error: Error; message?: string }
  | { kind: 'unexpected_response'; statusCode?: number; message?: string; bankCode?: number };

export class BankAuthClient {
  private logger = new RedactingLogger('BankAuthClient');
  private baseUrl: string;
  private transport: TransportFn;
  private validator: SessionValidator;
  private requestTimeoutMs: number;
  private configuredDeviceToken?: string;
  private requireDeviceToken: boolean;

  constructor(
    baseUrl: string,
    transport: TransportFn,
    validator: SessionValidator,
    requestTimeoutMs: number = 15000,
    configuredDeviceToken?: string,
    requireDeviceToken: boolean = false
  ) {
    this.baseUrl = baseUrl;
    this.transport = transport;
    this.validator = validator;
    this.requestTimeoutMs = requestTimeoutMs;
    this.configuredDeviceToken = (configuredDeviceToken && isValidToken(configuredDeviceToken))
      ? configuredDeviceToken.trim()
      : undefined;
    this.requireDeviceToken = requireDeviceToken;
  }

  setRequireDeviceToken(require: boolean): void {
    this.requireDeviceToken = require;
  }

  hasConfiguredDeviceToken(): boolean {
    return Boolean(this.configuredDeviceToken && isValidToken(this.configuredDeviceToken));
  }

  getConfiguredDeviceToken(): string | undefined {
    return this.configuredDeviceToken;
  }

  setDeviceToken(token?: string): void {
    this.configuredDeviceToken = (token && isValidToken(token)) ? token.trim() : undefined;
  }

  /**
   * Submits mobile number to initiate device registration via SMS OTP.
   * Evidence: chunk 7.js @ 11090 (POST /en/api/user/signup with { mobileNo, captcha }).
   */
  async requestDeviceRegistration(mobileNo: string, captcha?: string): Promise<DeviceRegistrationOutcome> {
    const cleanMobile = mobileNo.trim();
    const url = `${this.baseUrl}/en/api/user/signup`;
    const payload: Record<string, unknown> = { mobileNo: cleanMobile };
    if (captcha) {
      payload.captcha = captcha.trim();
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/plain, */*',
      'X-Platform': 'PWA',
      'X-Version': '2.8.4',
      'X-BuildNo': '284',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    };

    try {
      const res = await this.transport(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeoutMs: this.requestTimeoutMs,
      });

      if (res.status === 429) {
        return { kind: 'rate_limited', message: 'Too many requests. Please wait before retrying registration.', statusCode: 429 };
      }

      const body = (res.data || {}) as Record<string, unknown>;
      if (body.code === 0) {
        return {
          kind: 'otp_sent',
          message: typeof body.message === 'string' ? body.message : 'کد فعال‌سازی به شماره شما پیامک شد.',
        };
      }

      if (body.code === 107 || (typeof body.message === 'string' && /کپچا|captcha/i.test(body.message))) {
        return {
          kind: 'captcha_required',
          message: 'Bank gateway requires Google reCAPTCHA for registration. Please complete device registration once in your browser.',
        };
      }

      return {
        kind: 'bank_error',
        message: typeof body.message === 'string' ? body.message : `Bank returned error code ${body.code}`,
        statusCode: res.status,
        bankCode: typeof body.code === 'number' ? body.code : undefined,
      };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.logger.error('Device registration request transport error', error);
      return { kind: 'network_error', error };
    }
  }

  /**
   * Validates SMS OTP activation code to acquire mobileUserToken.
   * Evidence: chunk 7.js @ 11090 & 64270 (POST /en/api/user/validate with { activationCode, mobileNo, deviceId, deviceInfo, platform }).
   */
  async validateDeviceRegistration(mobileNo: string, activationCode: string): Promise<DeviceValidationOutcome> {
    const cleanMobile = mobileNo.trim();
    const cleanCode = activationCode.trim();
    const url = `${this.baseUrl}/en/api/user/validate`;
    const payload = {
      activationCode: cleanCode,
      deviceId: 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36',
      deviceInfo: 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36',
      mobileNo: cleanMobile,
      platform: 'PWA',
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/plain, */*',
      'X-Platform': 'PWA',
      'X-Version': '2.8.4',
      'X-BuildNo': '284',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    };

    try {
      const res = await this.transport(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeoutMs: this.requestTimeoutMs,
      });

      const body = (res.data || {}) as Record<string, unknown>;
      const content = (body.content || {}) as Record<string, unknown>;
      const receivedToken = typeof content.token === 'string' ? content.token.trim() : undefined;

      if (body.code === 0 && receivedToken && isValidToken(receivedToken)) {
        this.configuredDeviceToken = receivedToken;
        this.logger.info('Device successfully registered and device token (mobileUserToken) acquired');
        return {
          kind: 'success',
          deviceToken: receivedToken,
          message: typeof body.message === 'string' ? body.message : 'دستگاه با موفقیت ثبت شد.',
        };
      }

      if (body.code === 101 || body.code === 106 || (typeof body.message === 'string' && /نامعتبر|اشتباه|منقضی/.test(body.message))) {
        return {
          kind: 'invalid_code',
          message: typeof body.message === 'string' ? body.message : 'کد فعال‌سازی نامعتبر یا منقضی شده است.',
          bankCode: typeof body.code === 'number' ? body.code : undefined,
        };
      }

      return {
        kind: 'bank_error',
        message: typeof body.message === 'string' ? body.message : `Bank returned error code ${body.code}`,
        statusCode: res.status,
        bankCode: typeof body.code === 'number' ? body.code : undefined,
      };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.logger.error('Device validation transport error', error);
      return { kind: 'network_error', error };
    }
  }

  /**
   * Submits credentials directly to Bank Eghtesad Novin's official bankLogin endpoint.
   * Evidence: chunk 7.js (POST /en/api/user/bankLogin with { password, cif/username, deviceId, deviceInfo, platform: 'PWA' }).
   * Attaches Authorization bearer header if deviceToken or configuredDeviceToken is present.
   */
  async login(credentials: {
    cifOrUsername: string;
    password: string;
    otp?: string;
    deviceToken?: string;
  }): Promise<LoginOutcome> {
    const trimmedInput = credentials.cifOrUsername.trim();
    const isCif = /^\d+$/.test(trimmedInput);

    const payload: Record<string, unknown> = {
      password: credentials.password,
      deviceId: 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36',
      deviceInfo: 'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36',
      platform: 'PWA',
    };

    if (isCif) {
      payload.cif = trimmedInput;
    } else {
      payload.username = trimmedInput;
    }

    if (credentials.otp) {
      payload.otp = credentials.otp.trim();
      payload.activationCode = credentials.otp.trim();
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/plain, */*',
      'X-Platform': 'PWA',
      'X-Version': '2.8.4',
      'X-BuildNo': '284',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    };

    const rawDeviceToken = credentials.deviceToken ?? this.configuredDeviceToken;
    const effectiveDeviceToken = typeof rawDeviceToken === 'string' ? rawDeviceToken.trim() : undefined;

    // 1. If device token is required (production/daemon default) and missing:
    if (this.requireDeviceToken && !effectiveDeviceToken) {
      this.logger.warn('Direct bank login requires a pre-registered device token (mobileUserToken). Network request aborted.');
      return {
        kind: 'device_token_required',
        message: 'A pre-registered device token (mobileUserToken) is required in the Authorization header to authenticate directly with Bank Eghtesad Novin API gateway. No network request was sent.',
        bankCode: 102,
      };
    }

    // 2. If a device token is provided, ensure it is NOT a sentinel or placeholder string ("null", "undefined", etc.)
    if (effectiveDeviceToken !== undefined) {
      if (!isValidToken(effectiveDeviceToken)) {
        this.logger.warn('Direct bank login aborted: configured or provided device token is invalid or sentinel string');
        return {
          kind: 'device_token_required',
          message: 'Configured or provided device token is invalid (cannot be empty, "null", or sentinel string). No network request was sent.',
          bankCode: 102,
        };
      }
      headers['Authorization'] = `bearer ${effectiveDeviceToken}`;
    }

    const url = `${this.baseUrl}/en/api/user/bankLogin`;

    let response: TransportResponse;
    try {
      response = await this.transport(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        timeoutMs: this.requestTimeoutMs,
      });
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      this.logger.error('Login transport error', { message: error.message });
      return { kind: 'network_error', error };
    }

    // Inspect HTTP status
    if (response.status === 429) {
      return { kind: 'rate_limited', statusCode: 429 };
    }
    if (response.status >= 500) {
      return { kind: 'server_error', statusCode: response.status };
    }
    if (response.status === 401 || response.status === 403) {
      return { kind: 'auth_rejected', statusCode: response.status };
    }
    if (response.status < 200 || response.status >= 300) {
      return { kind: 'unexpected_response', statusCode: response.status };
    }

    // Validate envelope shape
    if (!response.data || typeof response.data !== 'object' || Array.isArray(response.data)) {
      return { kind: 'unexpected_response', statusCode: response.status, message: 'Invalid envelope format' };
    }

    const bankBody = response.data as {
      code?: unknown;
      message?: string;
      content?: Record<string, unknown> | null;
      token?: unknown;
    };

    if (typeof bankBody.code !== 'number') {
      return { kind: 'unexpected_response', statusCode: response.status, message: 'Missing response code' };
    }

    // Proven token extraction: Farazpardazan PWA bundle evidence (chunk 7.js) strictly accesses bankBody.content.token
    let extractedToken: string | null = null;
    if (bankBody.content && typeof bankBody.content === 'object' && bankBody.content !== null) {
      if (isValidToken(bankBody.content.token)) {
        extractedToken = (bankBody.content.token as string).trim();
      }
    }

    // Success requires a confirmed, non-empty session token from bankBody.content.token
    if (bankBody.code === 0 && extractedToken) {
      // Ensure a device token cannot accidentally be accepted as a new session token
      if (effectiveDeviceToken && extractedToken === effectiveDeviceToken.trim()) {
        return {
          kind: 'unexpected_response',
          statusCode: response.status,
          bankCode: bankBody.code,
          message: 'Bank returned pre-configured device token instead of an authenticated user session token.',
        };
      }
      return {
        kind: 'success',
        token: extractedToken,
        yaghootToken: extractedToken,
        cifOrUsername: trimmedInput,
      };
    }

    // Unicode-safe regex patterns for Persian / Arabic / English error classification
    // \u06A9 (Persian ک), \u0643 (Arabic ك), \u06cc (Persian ی), \u064a (Arabic ي)
    const PATTERNS = {
      // "کد تایید", "رمز یکبار مصرف", "فعالسازی", "otp", "activation"
      OTP_REQUIRED: /(?:[\u06A9\u0643]\u062f\s*\u062a\u0627[\u06cc\u064a\u0623\u0621][\u06cc\u064a]\u062f|[\u06cc\u064a][\u06A9\u0643]\s*\u0628\u0627\u0631|\u0645\u0635\u0631\u0641|\u0641\u0639\u0627\u0644\u0633\u0627\u0632[\u06cc\u064a]|otp|activation)/i,
      // "کپچا", "کد امنیتی", "captcha"
      CAPTCHA_REQUIRED: /(?:[\u06A9\u0643]\u067e\u0686\u0627|[\u06A9\u0643]\u062f\s*\u0627\u0645\u0646[\u06cc\u064a]\u062a[\u06cc\u064a]|captcha)/i,
      // "توکن", "دسترسی", "یافت نشد", "token", "access token", "null"
      TOKEN_OR_GATEWAY_ERROR: /(?:[\u062a\u062a]\u0648[\u06A9\u0643]\u0646|\u062f\u0633\u062a\u0631\u0633[\u06cc\u064a]|\u06cc\u0627\u0641\u062a\s*\u0646\u0634\u062f|token|access\s*token|null)/i,
      // "رمز", "کاربری", "اشتباه", "password", "username", "invalid"
      INVALID_CREDS: /(?:\u0631\u0645\u0632|[\u06A9\u0643]\u0627\u0631\u0628\u0631[\u06cc\u064a]|\u0627\u0634\u062a\u0628\u0627\u0647|password|username|invalid\s*credentials)/i,
    };

    const rawMessage = typeof bankBody.message === 'string' ? bankBody.message : '';
    const message = rawMessage.trim();

    // 1. OTP Challenge Detection (Code 106 or message match)
    if (bankBody.code === 106 || PATTERNS.OTP_REQUIRED.test(message)) {
      return {
        kind: 'otp_required',
        message: message || 'ورود نیازمند کد تایید یکبار مصرف (OTP) است.',
        statusCode: response.status,
        bankCode: bankBody.code,
      };
    }

    // 2. CAPTCHA Challenge Detection (Code 107 or message match)
    if (bankBody.code === 107 || PATTERNS.CAPTCHA_REQUIRED.test(message)) {
      return {
        kind: 'captcha_required',
        message: message || 'چالش کپچا فعال است. لطفا از ورود مرورگر استفاده کنید.',
        statusCode: response.status,
        bankCode: bankBody.code,
      };
    }

    // 3. Bank Gateway Token Error (Code 102/104/105/3071 or "توکن دسترسی null یافت نشد")
    if (
      bankBody.code === 102 ||
      bankBody.code === 104 ||
      bankBody.code === 105 ||
      bankBody.code === 3071 ||
      (PATTERNS.TOKEN_OR_GATEWAY_ERROR.test(message) && message.toLowerCase().includes('null'))
    ) {
      return {
        kind: 'device_token_required',
        message: message || 'توکن دسترسی "null" یافت نشد',
        statusCode: response.status,
        bankCode: bankBody.code,
      };
    }

    // 4. Invalid Credentials (Code 103/401 or message match)
    if (bankBody.code === 103 || bankBody.code === 401 || PATTERNS.INVALID_CREDS.test(message)) {
      return {
        kind: 'invalid_credentials',
        message: message || 'نام کاربری یا کلمه عبور اشتباه است.',
        statusCode: response.status,
        bankCode: bankBody.code,
      };
    }

    // 5. Code 0 but no valid token and no recognized challenge
    if (bankBody.code === 0) {
      return {
        kind: 'unexpected_response',
        statusCode: response.status,
        bankCode: bankBody.code,
        message: 'Bank returned success code 0, but access token was null, empty, or missing in the response envelope.',
      };
    }

    // 5. Unclassified Bank Error
    return {
      kind: 'unexpected_response',
      message: message || `Bank returned error code ${bankBody.code}`,
      statusCode: response.status,
      bankCode: bankBody.code,
    };
  }

  /**
   * Dispatches server-side session termination to the bank.
   */
  async logout(token: string): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/en/api/user/bankLogout`;
      const res = await this.transport(url, {
        method: 'POST',
        headers: {
          'Authorization': `bearer ${token}`,
          'X-Platform': 'PWA',
          'X-Version': '2.8.4',
          'X-BuildNo': '284',
        },
        timeoutMs: 5000,
      });
      return res.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * Checks whether reCAPTCHA challenge is currently enforced by the bank.
   */
  async checkCaptchaStatus(): Promise<boolean> {
    try {
      const url = `${this.baseUrl}/en/api/v2/baseInfo/captchaStatus`;
      const res = await this.transport(url, {
        method: 'GET',
        headers: {
          'X-Platform': 'PWA',
          'X-Version': '2.8.4',
          'X-BuildNo': '284',
        },
        timeoutMs: 5000,
      });
      if (res.status === 200 && res.data && typeof res.data === 'object') {
        const body = res.data as { code?: number; content?: { enable?: boolean } };
        return Boolean(body.content?.enable);
      }
      return false;
    } catch {
      return false;
    }
  }
}
