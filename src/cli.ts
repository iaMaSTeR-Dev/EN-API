import http from 'node:http';
import readline from 'node:readline';
import { loadConfig, type AppConfig } from './config.ts';
import { isValidToken } from './auth/bank-auth-client.ts';
import type {
  SessionStatusResponse,
  BankAccount,
  BankCard,
  TransactionRecord,
  CombinedBalance,
  UserProfile,
  BankInfo,
  DestinationContact,
  ScheduledTransfer,
  ChequeItem,
  LoanFacility,
  LoanInstallment,
  UtilityBill,
  AdvertisementBanner,
  IbanInquiryResult,
  OwnerInquiryResult,
  TopupItem,
  PackageItem,
} from './types.ts';

interface CliArgs {
  command: string;
  subcommand?: string;
  flags: Record<string, string>;
  positionals: string[];
}

function parseCliArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  const flags: Record<string, string> = {};
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = 'true';
      }
    } else {
      positionals.push(arg);
    }
  }

  return {
    command: positionals[0] || 'help',
    subcommand: positionals[1],
    flags,
    positionals,
  };
}

function formatCurrency(amount?: number, currency: string = 'IRR'): string {
  if (typeof amount !== 'number') return '0 ' + currency;
  return amount.toLocaleString('en-US') + ' ' + currency;
}

export function wrapText(text: string, maxWidth: number = 45): string[] {
  if (!text || text.length <= maxWidth) return [text || '-'];
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';
  for (const w of words) {
    if (!current) {
      current = w;
    } else if (current.length + 1 + w.length <= maxWidth) {
      current += ' ' + w;
    } else {
      lines.push(current);
      current = w;
    }
  }
  if (current) lines.push(current);
  return lines.length > 0 ? lines : [text];
}

/**
 * Prompts the user for normal text input (e.g. username/CIF).
 * Supports both interactive TTY and automated/piped streams.
 */
export function readPlainInput(
  promptText: string,
  inStream: NodeJS.ReadStream = process.stdin,
  outStream: NodeJS.WriteStream = process.stdout
): Promise<string> {
  if (!inStream.isTTY) {
    return new Promise((resolve) => {
      outStream.write(promptText);
      let input = '';
      inStream.setEncoding('utf8');
      const onData = (chunk: string) => {
        input += chunk;
      };
      inStream.once('end', () => {
        resolve(input.trim());
      });
      inStream.on('data', onData);
    });
  }

  const rl = readline.createInterface({
    input: inStream,
    output: outStream,
  });

  return new Promise((resolve) => {
    rl.question(promptText, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export interface SanitizedInputResult {
  value: string;
  length: number;
  isEmpty: boolean;
  wasTruncated: boolean;
  hadSurroundingQuotes: boolean;
  hadBracketedPaste: boolean;
  extractedFromFormat?: 'raw' | 'json' | 'cookie';
  yaghootToken?: string;
  mobileUserToken?: string;
  isDeviceTokenMatch?: boolean;
}

/**
 * Sanitizes sensitive token input:
 * - Strips ANSI escape sequences and bracketed paste mode wrappers (\u001b[200~ ... \u001b[201~)
 * - Strips accidental surrounding quotes (single or double) from browser console copy-paste
 * - Strips any carriage return / line feed artifacts
 * - Trims leading/trailing whitespace
 * - Intelligently parses browser console JSON dumps ({ yaghootToken, currentToken, mobileUserToken })
 * - Detects if currentToken matches mobileUserToken (device registration token)
 * - Strips cookie prefixes (e.g. "token=...; path=/")
 * - Enforces maximum length bounds without leaking characters
 */
export function sanitizeTokenInput(raw: string, maxLength: number = 4096): SanitizedInputResult {
  let value = (raw || '').trim();
  let hadBracketedPaste = false;
  let hadSurroundingQuotes = false;
  let wasTruncated = false;
  let extractedFromFormat: 'raw' | 'json' | 'cookie' = 'raw';
  let yaghootToken: string | undefined = undefined;
  let mobileUserToken: string | undefined = undefined;
  let isDeviceTokenMatch = false;

  // Check and strip bracketed paste wrappers (\u001b[200~ ... \u001b[201~)
  if (value.includes('\u001b[200~') || value.includes('\u001b[201~')) {
    hadBracketedPaste = true;
    value = value.replace(/\u001b\[20[01]~/g, '');
  }

  // Strip generic ANSI escape codes if present
  value = value.replace(/\u001b\[[0-9;]*[a-zA-Z]/g, '');

  // Strip newlines / carriage returns that might have been embedded
  value = value.replace(/[\r\n]/g, '').trim();

  // Check and strip matching surrounding quotes (e.g. from Chrome console)
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
    (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
  ) {
    hadSurroundingQuotes = true;
    value = value.slice(1, -1).trim();
  }

  // Check if input is a cookie string (e.g. "token=4df16c...; path=/")
  if (value.startsWith('token=')) {
    const cookieVal = value.slice('token='.length).split(';')[0].trim();
    if (cookieVal.length >= 20) {
      value = cookieVal;
      extractedFromFormat = 'cookie';
    }
  }

  // Check if input is a JSON object dump from browser console
  if (value.startsWith('{') && value.endsWith('}')) {
    try {
      const parsed = JSON.parse(value) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object') {
        const yToken = typeof parsed.yaghootToken === 'string' && parsed.yaghootToken.trim().length >= 20 ? parsed.yaghootToken.trim() : undefined;
        const cToken = typeof parsed.currentToken === 'string' && parsed.currentToken.trim().length >= 20 ? parsed.currentToken.trim() : undefined;
        const mToken = typeof parsed.mobileUserToken === 'string' && parsed.mobileUserToken.trim().length >= 20 ? parsed.mobileUserToken.trim() : undefined;

        if (mToken && cToken && mToken.toLowerCase() === cToken.toLowerCase()) {
          isDeviceTokenMatch = true;
        }

        // Prefer authenticated yaghootToken, otherwise currentToken (if not matching device token)
        let selected: string | undefined = undefined;
        if (yToken && yToken.toLowerCase() !== 'null' && yToken.toLowerCase() !== 'undefined') {
          selected = yToken;
        } else if (cToken && !isDeviceTokenMatch) {
          selected = cToken;
        } else if (cToken) {
          selected = cToken;
        }

        if (selected) {
          value = selected;
          extractedFromFormat = 'json';
          yaghootToken = yToken;
          mobileUserToken = mToken;
        }
      }
    } catch {
      // Not JSON, proceed with string token
    }
  }

  // Truncate if exceeding maximum allowed length
  if (value.length > maxLength) {
    value = value.slice(0, maxLength);
    wasTruncated = true;
  }

  return {
    value,
    length: value.length,
    isEmpty: value.length === 0,
    wasTruncated,
    hadSurroundingQuotes,
    hadBracketedPaste,
    extractedFromFormat,
    yaghootToken,
    mobileUserToken,
    isDeviceTokenMatch,
  };
}

/**
 * Prompts the user for sensitive input via stdin with masking/hidden input.
 * Correctly handles chunked paste on Windows/POSIX terminals by iterating through
 * incoming bytes/characters so that each character outputs an asterisk '*'
 * and trailing newlines/carriage-returns submit immediately.
 */
export function readHiddenInput(
  promptText: string,
  inStream: NodeJS.ReadStream = process.stdin,
  outStream: NodeJS.WriteStream = process.stdout
): Promise<string> {
  return new Promise((resolve) => {
    outStream.write(promptText);
    let input = '';

    if (!inStream.isTTY) {
      inStream.setEncoding('utf8');
      const onData = (chunk: string) => {
        input += chunk;
      };
      inStream.once('end', () => {
        resolve(input.trim());
      });
      inStream.on('data', onData);
      return;
    }

    const wasRaw = inStream.isRaw;
    inStream.setRawMode(true);
    inStream.resume();
    inStream.setEncoding('utf8');

    const cleanup = () => {
      inStream.setRawMode(wasRaw);
      inStream.pause();
      inStream.removeListener('data', onData);
    };

    const onData = (chunk: string) => {
      for (let i = 0; i < chunk.length; i++) {
        const ch = chunk[i];

        // Ctrl+C (0x03) or Ctrl+D (0x04)
        if (ch === '\u0003' || ch === '\u0004') {
          cleanup();
          outStream.write('\n[INPUT CANCELLED]\n');
          process.exit(1);
        }

        // Enter (\r or \n)
        if (ch === '\r' || ch === '\n') {
          // If Windows CRLF \r\n, skip the following \n if it immediately follows in this chunk
          if (ch === '\r' && i + 1 < chunk.length && chunk[i + 1] === '\n') {
            i++;
          }
          cleanup();
          outStream.write('\n');
          resolve(input);
          return;
        }

        // Backspace (\u0008 or \u007f)
        if (ch === '\u0008' || ch === '\u007f') {
          if (input.length > 0) {
            input = input.slice(0, -1);
            outStream.write('\b \b');
          }
          continue;
        }

        // Ignore control characters (< 32)
        if (ch.charCodeAt(0) < 32) {
          continue;
        }

        // Normal printable character: record and output masking asterisk
        input += ch;
        outStream.write('*');
      }
    };

    inStream.on('data', onData);
  });
}

export interface CliResponse<T> {
  status: number;
  data: T;
  renewed: boolean;
  expiredLocally: boolean;
  headers: http.IncomingHttpHeaders;
}

let hasNotifiedRenewal = false;

export function resetRenewalNotification(): void {
  hasNotifiedRenewal = false;
}

export function notifyRenewalIfOccurred(res: { renewed?: boolean; expiredLocally?: boolean; status?: number }): void {
  // Only display success notifications if the renewal occurred, the operation succeeded (2xx), and not already notified
  if (
    res?.renewed &&
    (res.status === undefined || (res.status >= 200 && res.status < 300)) &&
    !hasNotifiedRenewal
  ) {
    hasNotifiedRenewal = true;
    if (res.expiredLocally) {
      console.log('\n[NOTICE] Local session expired.');
    } else {
      console.log('\n[NOTICE] Bank session expired.');
    }
    console.log('[NOTICE] Automatic re-authentication completed successfully.');
    console.log('[NOTICE] Original request completed successfully.\n');
  }
}

export class BankCliClient {
  private host: string;
  private port: number;
  private apiKey: string;

  constructor(host: string = '127.0.0.1', port: number = 8080, apiKey: string = '') {
    this.host = host;
    this.port = port;
    this.apiKey = apiKey;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<CliResponse<T>> {
    return new Promise((resolve, reject) => {
      const payload = body ? JSON.stringify(body) : undefined;
      const req = http.request(
        {
          hostname: this.host,
          port: this.port,
          path,
          method,
          headers: {
            'Host': `${this.host}:${this.port}`,
            'X-Local-API-Key': this.apiKey,
            ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
          },
          timeout: 30000,
        },
        (res) => {
          let raw = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => {
            raw += chunk;
          });
          res.on('end', () => {
            let data: unknown;
            try {
              data = JSON.parse(raw);
            } catch {
              data = raw;
            }
            const renewed = res.headers['x-session-renewed'] === 'true';
            const expiredLocally = res.headers['x-session-expired-locally'] === 'true';
            resolve({
              status: res.statusCode || 200,
              data: data as T,
              renewed,
              expiredLocally,
              headers: res.headers,
            });
          });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Daemon request timed out after 30000ms.'));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (payload) {
        req.write(payload);
      }
      req.end();
    });
  }
}

function printHelp(): void {
  console.log(`
================================================================================
Bank Eghtesad Novin (Hamrah Novin) — Read-Only Personal CLI
================================================================================
Usage:
  npm run cli -- <command> [options]

Core Authentication & Session:
  login [--browser]                      Authenticate with bank credentials (CIF/Username & Password)
  enroll [--mobile <09...>]              Register/approve new device via SMS OTP (mobileUserToken)
  status                                 Check local daemon health and session status
  verify                                 Safely verify active session against bank server (read-only)
  import [token]                         Import an authenticated session token
  logout                                 Clear the active local session and persistent storage

Account & Balances:
  accounts                               List all owned bank accounts and balances
  balance [depositNumber]                Show combined total balance, or balance for a specific deposit
  balances                               Alias to list all owned accounts and balances
  statement <depositNumber> [options]    View paginated transaction statement
  transaction-find <code> [options]      Search transaction by receipt/reference code across pages

Cards & Directory:
  cards [--destination]                  List registered cards (or saved destination cards)
  owner <cardPan|iban|depositNumber>     Unified owner name inquiry (auto-detects PAN, IBAN, Deposit)
  inquire-card <pan>                     Inquire cardholder name by PAN
  inquire-iban <iban>                    Inquire IBAN owner information and bank
  card-balance <cardId>                  Show real-time balance for an owned card
  banks [search]                         Search Iranian bank directory and card BINs

Transfers & General Services (Read-Only):
  transfers-recent                       List saved destination accounts and transfer history
  transfers-scheduled [--type <ACH>]     List scheduled / recurring auto-transfers
  ach-reports [--page <n>] [--limit <n>] List ACH (Paya / Satna) transfer reports
  contacts                               List aggregated banking contacts
  topups                                 List saved mobile top-up phone numbers
  packages                               List saved mobile internet package numbers
  cheques [--page <n>] [--limit <n>]     List Sayad cheques in cartable
  cheque-books <depositNumber>           List cheque books for a deposit account
  loans                                  List customer loan facilities and remaining balances
  loan-installments <loanId>             List installment payment schedule for a loan
  bills                                  List saved utility bills
  banners                                List active announcements and promotions
  messages [--limit <n>]                 List customer messages and notifications
  sessions                               List active client devices and login sessions
  interbank-rules                        Show Paya/Satna interbank transfer rules & ceilings
  profile                                Display customer profile and identity summary
  help                                   Show this help message

General Options:
  --json                                 Output machine-readable JSON
  --from <YYYY/MM/DD>                    Filter transactions from date
  --to   <YYYY/MM/DD>                    Filter transactions to date
  --page <number>                        Statement/cheque page index (default: 0)
  --limit <number>                       Records per page (default: 20)
  --pages <number>                       Max pages to scan for transaction-find (default: 10)
  --deposit <depositNumber>              Specify deposit number for transaction search

Security Note:
  All banking operations are strictly read-only. Mutation requests (transfers,
  payments, card blocking) are structurally prohibited.
  Credentials and tokens are input with masking and securely encrypted on disk.
================================================================================
`);
}

async function executeBrowserLogin(client: BankCliClient, config: AppConfig): Promise<number> {
  console.log('\n[BROWSER LOGIN] Initiating browser-assisted authentication...');
  const handoffInit = await client.request<{
    handoffId: string;
    handoffSecret: string;
    loginUrl: string;
    expiresAt: string;
  }>('POST', '/api/v1/session/handoff/init');

  if (handoffInit.status !== 200) {
    console.error('\n[ERROR] Failed to initialize browser handoff: ' + JSON.stringify(handoffInit.data) + '\n');
    return 1;
  }

  console.log('\n============================================================');
  console.log('Browser-Assisted Authentication Handoff');
  console.log('============================================================');
  console.log('1. Open your browser and navigate to:');
  console.log(`   ${handoffInit.data.loginUrl}`);
  console.log('2. Log in using your Bank Eghtesad Novin credentials and complete any OTP/CAPTCHA.');
  console.log('   IMPORTANT: Stay on an authenticated page (Deposits or Cards).');
  console.log('   Do NOT navigate back to the login screen or close the tab, as');
  console.log('   Bank Eghtesad Novin PWA resets currentToken to mobileUserToken when on /#/login!');
  console.log('3. In your browser DevTools Console (press F12 -> Console tab), run:');
  console.log('\n   copy(sessionStorage.getItem("yaghootToken") || (localStorage.getItem("currentToken") !== localStorage.getItem("mobileUserToken") ? localStorage.getItem("currentToken") : ""))');
  console.log('\n   (This copies the authenticated banking session token straight to your clipboard.)');
  console.log('   Or copy the diagnostic JSON bundle:');
  console.log('   copy(JSON.stringify({ yaghootToken: sessionStorage.getItem("yaghootToken"), currentToken: localStorage.getItem("currentToken"), mobileUserToken: localStorage.getItem("mobileUserToken") }))');
  console.log('4. Paste the token or JSON below (input will be masked).');
  console.log('============================================================\n');

  const rawToken = await readHiddenInput('Paste session token: ');
  const sanitized = sanitizeTokenInput(rawToken);

  console.log('\n[TOKEN INPUT DIAGNOSTIC]');
  console.log(`  Input empty        : ${sanitized.isEmpty ? 'YES' : 'NO'}`);
  console.log(`  Captured length    : ${sanitized.length} characters`);
  console.log(`  Extracted format   : ${sanitized.extractedFromFormat?.toUpperCase() || 'RAW'}`);
  console.log(`  Surrounding quotes : ${sanitized.hadSurroundingQuotes ? 'STRIPPED' : 'NONE'}`);
  console.log(`  Bracketed paste    : ${sanitized.hadBracketedPaste ? 'STRIPPED' : 'NONE'}`);
  console.log(`  Device token match : ${sanitized.isDeviceTokenMatch ? 'YES (WARNING: matches mobileUserToken)' : 'NO'}`);
  console.log(`  Validation status  : ${sanitized.length >= 20 ? 'ACCEPTED (VALID LENGTH)' : 'REJECTED (TOO SHORT)'}\n`);

  if (sanitized.isEmpty) {
    console.error('[ERROR] No token entered. Handoff aborted.\n');
    return 1;
  }

  if (sanitized.isDeviceTokenMatch && !sanitized.yaghootToken) {
    console.error('\n[ERROR] The entered token matches your device registration token (mobileUserToken), not an active banking session token.');
    console.error('Evidence: In Bank Eghtesad Novin PWA, visiting /#/login resets currentToken to mobileUserToken.');
    console.error('Resolution: Please complete login in your browser, remain on Deposits or Cards, and run:');
    console.error('  copy(sessionStorage.getItem("yaghootToken"))\n');
    return 1;
  }

  const cleanToken = sanitized.value;
  const lower = cleanToken.toLowerCase();
  if (
    cleanToken.length < 20 ||
    cleanToken.length > 4096 ||
    lower === 'null' ||
    lower === 'undefined' ||
    lower === '[object object]'
  ) {
    console.error('\n[ERROR] Invalid token format. Session token must be a valid bearer token between 20 and 4096 characters (captured: ' + sanitized.length + ').\n');
    return 1;
  }

  if (config.security.deviceToken && cleanToken.toLowerCase() === config.security.deviceToken.toLowerCase()) {
    console.error('\n[ERROR] The entered token is your configured device registration token (mobileUserToken), not an authenticated banking session token (yaghootToken/currentToken). Please log into the portal and paste the session token.\n');
    return 1;
  }

  const completeRes = await client.request<{ message: string; status: SessionStatusResponse }>(
    'POST',
    '/api/v1/session/handoff/complete',
    {
      handoffSecret: handoffInit.data.handoffSecret,
      token: cleanToken,
      yaghootToken: sanitized.yaghootToken,
      mobileUserToken: sanitized.mobileUserToken,
    }
  );

  if (completeRes.status !== 200) {
    console.error('\n[HANDOFF FAILED] ' + JSON.stringify(completeRes.data) + '\n');
    return 1;
  }

  console.log('\n[SUCCESS] ' + completeRes.data.message);
  console.log('Local Session       : ACTIVE');
  console.log('Local Idle Expiry   : ' + (completeRes.data.status.expiresAt || 'N/A') + ' (daemon sliding window: ' + completeRes.data.status.idleTimeoutSeconds + 's)');
  console.log('\nVerifying session against Bank Eghtesad Novin server...');

  // Immediately verify against remote bank server
  const verifyRes = await client.request<{ verified: boolean; status: SessionStatusResponse; message: string }>(
    'POST',
    '/api/v1/session/verify'
  );

  if (verifyRes.status === 200 && verifyRes.data.verified) {
    console.log('\n============================================================');
    console.log('[VERIFICATION SUCCESS] Session successfully accepted and verified by Bank Eghtesad Novin!');
    console.log('Remote Verification : VERIFIED');
    console.log('Last Verified       : ' + (verifyRes.data.status.lastVerifiedAt || new Date().toISOString()));
    console.log('Authenticated       : YES (Remotely Verified)');
    console.log('============================================================\n');
    console.log('[TIP] You can now safely query banking data:');
    console.log('  npm run cli -- accounts');
    console.log('  npm run cli -- balance\n');
    return 0;
  } else {
    const errData = verifyRes.data as { error?: string; message?: string; bankCode?: number };
    console.warn('\n============================================================');
    console.warn('[REMOTE VERIFICATION FAILED]');
    if (errData?.bankCode === 3071) {
      console.error('Bank Error Code 3071: دسترسی کاربر منقضی شده است (User access has expired / token revoked).');
      console.error('\nRoot Cause & Diagnostic:');
      console.error('1. The copied token is not an active banking session token (e.g. was mobileUserToken).');
      console.error('2. Or the browser tab was refreshed or navigated to /#/login, which revokes yaghootToken.');
      console.error('3. Or the bank server session timed out on the bank side.');
      console.error('\nResolution:');
      console.error('1. Return to the browser tab where you are logged in (on Deposits or Cards).');
      console.error('2. In F12 Console, run: copy(sessionStorage.getItem("yaghootToken"))');
      console.error('3. Run "npm run cli -- login --browser" and paste the token.\n');
    } else {
      console.error(`Reason: ${errData?.message || 'Remote bank rejection'}${errData?.bankCode ? ` (Bank Code: ${errData.bankCode})` : ''}\n`);
    }
    console.warn('============================================================\n');
    return 1;
  }
}

export async function runCli(argv: string[] = process.argv): Promise<number> {
  resetRenewalNotification();
  const args = parseCliArgs(argv);

  if (args.command === 'help' || args.flags['help']) {
    printHelp();
    return 0;
  }

  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error(`\n[CONFIG ERROR] ${(err as Error).message}\n`);
    return 1;
  }

  const client = new BankCliClient(config.server.host, config.server.port, config.security.localApiKey);

  try {
    switch (args.command) {
      case 'enroll':
      case 'register-device': {
        console.log('\n============================================================');
        console.log('Bank Eghtesad Novin — Device Enrollment (mobileUserToken)');
        console.log('============================================================');
        console.log('Enroll this device to enable direct username/password login.\n');
        const mobileNo = await readPlainInput('Enter your registered Mobile Number (e.g. 0912xxxxxxx): ');
        if (!mobileNo || !/^09\d{9}$/.test(mobileNo.trim())) {
          console.error('\n[ERROR] Invalid Iranian mobile number format (must be 11 digits starting with 09).\n');
          return 1;
        }

        console.log('Requesting SMS activation code from Bank Eghtesad Novin...');
        const regRes = await client.request<{
          success?: boolean;
          message?: string;
          error?: string;
          validationCode?: string;
        }>('POST', '/api/v1/session/device/register', { mobileNo: mobileNo.trim() });

        if (regRes.status === 400 && regRes.data?.error === 'CAPTCHA_REQUIRED') {
          console.warn('\n[CAPTCHA REQUIRED] Bank gateway currently requires Google reCAPTCHA for new device registration.');
          console.log('Falling back to official Browser-Assisted Login...');
          return await executeBrowserLogin(client, config);
        }

        if (regRes.status !== 200 || !regRes.data?.success) {
          console.error('\n[REGISTRATION FAILED] ' + (regRes.data?.message || regRes.data?.error || 'Unknown bank error') + '\n');
          return 1;
        }

        console.log(`\n[SMS SENT] ${regRes.data.message}`);
        const activationCode = await readHiddenInput('Enter 5-digit SMS Activation Code: ');
        if (!activationCode) {
          console.error('\n[ERROR] Activation code is required to complete device registration.\n');
          return 1;
        }

        console.log('Validating activation code with Bank Eghtesad Novin...');
        const valRes = await client.request<{
          success?: boolean;
          message?: string;
          error?: string;
        }>('POST', '/api/v1/session/device/validate', {
          mobileNo: mobileNo.trim(),
          activationCode: activationCode.trim(),
        });

        if (valRes.status !== 200 || !valRes.data?.success) {
          console.error('\n[ACTIVATION FAILED] ' + (valRes.data?.message || valRes.data?.error || 'Validation error') + '\n');
          return 1;
        }

        console.log('\n[SUCCESS] Device successfully enrolled! Device registration token acquired and saved.');
        console.log('You can now log in directly using your credentials:');
        console.log('  npm run cli -- login\n');
        return 0;
      }

      case 'login': {
        const useBrowser = args.flags['browser'] === 'true';

        if (useBrowser) {
          return await executeBrowserLogin(client, config);
        }

        // Direct Bank Login with Credentials
        console.log('\n============================================================');
        console.log('Bank Eghtesad Novin — Secure Credential Authentication');
        console.log('============================================================');

        // Check if device token is provided via flag, env, or already enrolled in daemon session vault
        const rawDeviceToken = args.flags['device-token'] || config.security.deviceToken;
        let effectiveDeviceToken = (rawDeviceToken && isValidToken(rawDeviceToken)) ? rawDeviceToken.trim() : undefined;

        if (!effectiveDeviceToken) {
          const statusRes = await client.request<SessionStatusResponse>('GET', '/api/v1/session/status');
          if (statusRes.status === 200 && statusRes.data?.hasRegisteredDevice) {
            // Daemon already has the registered device token in session vault
          } else {
            console.log('\n============================================================');
            console.log('Bank Eghtesad Novin — Device Enrollment Required');
            console.log('============================================================');
            console.log('The bank API gateway enforces channel security: a pre-registered');
            console.log('device token (mobileUserToken) is required for credential login.');
            console.log('No registered device token was found.\n');
            console.log('Please choose an enrollment option:');
            console.log('  1. Register device directly via SMS OTP (Enter mobile number)');
            console.log('  2. Browser-Assisted Login (Official handoff from active browser session)');
            console.log('  3. Enter an existing device token (mobileUserToken) manually');
            console.log('============================================================\n');

            const choice = await readPlainInput('Select option [1/2/3, default=1]: ');
            const selected = choice.trim() || '1';

            if (selected === '2') {
              return await executeBrowserLogin(client, config);
            } else if (selected === '3') {
              const manualToken = await readHiddenInput('Paste device token (mobileUserToken): ');
              const sanitized = sanitizeTokenInput(manualToken);
              if (!sanitized.value || !isValidToken(sanitized.value)) {
                console.error('\n[ERROR] Invalid device token format.\n');
                return 1;
              }
              effectiveDeviceToken = sanitized.value;
            } else {
              // Option 1: Direct device registration via SMS OTP
              console.log('\n--- Direct Device Registration ---');
              const mobileNo = await readPlainInput('Enter your registered Mobile Number (e.g. 0912xxxxxxx): ');
              if (!mobileNo || !/^09\d{9}$/.test(mobileNo.trim())) {
                console.error('\n[ERROR] Invalid Iranian mobile number format (must be 11 digits starting with 09).\n');
                return 1;
              }

              console.log('Requesting SMS activation code from Bank Eghtesad Novin...');
              const regRes = await client.request<{
                success?: boolean;
                message?: string;
                error?: string;
                validationCode?: string;
              }>('POST', '/api/v1/session/device/register', { mobileNo: mobileNo.trim() });

              if (regRes.status === 400 && regRes.data?.error === 'CAPTCHA_REQUIRED') {
                console.warn('\n[CAPTCHA REQUIRED] Bank gateway currently requires Google reCAPTCHA for new device registration.');
                console.log('Falling back to official Browser-Assisted Login...');
                return await executeBrowserLogin(client, config);
              }

              if (regRes.status !== 200 || !regRes.data?.success) {
                console.error('\n[REGISTRATION FAILED] ' + (regRes.data?.message || regRes.data?.error || 'Unknown bank error') + '\n');
                return 1;
              }

              console.log(`\n[SMS SENT] ${regRes.data.message}`);
              const activationCode = await readHiddenInput('Enter 5-digit SMS Activation Code: ');
              if (!activationCode) {
                console.error('\n[ERROR] Activation code is required to complete device registration.\n');
                return 1;
              }

              console.log('Validating activation code with Bank Eghtesad Novin...');
              const valRes = await client.request<{
                success?: boolean;
                message?: string;
                error?: string;
              }>('POST', '/api/v1/session/device/validate', {
                mobileNo: mobileNo.trim(),
                activationCode: activationCode.trim(),
              });

              if (valRes.status !== 200 || !valRes.data?.success) {
                console.error('\n[ACTIVATION FAILED] ' + (valRes.data?.message || valRes.data?.error || 'Validation error') + '\n');
                return 1;
              }

              console.log('\n[DEVICE ENROLLED] Device successfully registered! Device token acquired and stored.\n');
            }
          }
        }

        let usernameOrCif = args.flags['username'] || args.flags['cif'] || args.subcommand || args.positionals[1];
        if (!usernameOrCif || usernameOrCif.startsWith('--')) {
          usernameOrCif = await readPlainInput('Enter Username or CIF (Customer Number): ');
        }

        if (!usernameOrCif) {
          console.error('\n[ERROR] Username or CIF cannot be empty.\n');
          return 1;
        }

        let password = args.flags['password'];
        if (!password) {
          password = await readHiddenInput('Enter Bank Password (input masked): ');
        }
        if (!password) {
          console.error('\n[ERROR] Password cannot be empty.\n');
          return 1;
        }

        let saveCredentials = false;
        if (args.flags['save-credentials'] === 'true') {
          saveCredentials = true;
        } else if (args.flags['save-credentials'] === 'false') {
          saveCredentials = false;
        } else {
          console.log('\n[CREDENTIAL STORAGE DISCLOSURE]');
          console.log('Credentials will be encrypted with AES-256-GCM using an OS-bound master key (Windows DPAPI / per-user vault).');
          console.log('Plaintext passwords are never stored on disk or logged.');
          console.log('You can revoke stored credentials at any time by running:');
          console.log('  npm run cli -- logout');
          const saveChoice = await readPlainInput('Save credentials for automatic session renewal? [y/N]: ');
          saveCredentials = saveChoice.trim().toLowerCase() === 'y' || saveChoice.trim().toLowerCase() === 'yes';
        }

        console.log('\nAuthenticating with Bank Eghtesad Novin...');
        const loginRes = await client.request<{
          message: string;
          status: SessionStatusResponse;
          requiresOtp?: boolean;
          requiresCaptcha?: boolean;
          requiresDeviceToken?: boolean;
          error?: string;
        }>('POST', '/api/v1/session/login', {
          cifOrUsername: usernameOrCif,
          password,
          deviceToken: effectiveDeviceToken,
          saveCredentials,
        });

        // Handle OTP Challenge
        if (loginRes.data && loginRes.data.requiresOtp) {
          console.log('\n[OTP REQUIRED] ' + loginRes.data.message);
          const otp = await readHiddenInput('Enter OTP / Activation Code: ');
          if (!otp) {
            console.error('\n[ERROR] OTP is required to complete authentication.\n');
            return 1;
          }

          console.log('\nSubmitting OTP verification...');
          const otpRes = await client.request<{
            message: string;
            status: SessionStatusResponse;
            error?: string;
          }>('POST', '/api/v1/session/login', {
            cifOrUsername: usernameOrCif,
            password,
            deviceToken: effectiveDeviceToken,
            otp,
            saveCredentials,
          });

          if (otpRes.status === 200) {
            console.log('\n[SUCCESS] ' + otpRes.data.message);
            console.log('Verifying session against Bank Eghtesad Novin server...');
            const verifyRes = await client.request<{ verified: boolean; status: SessionStatusResponse; message: string }>(
              'POST',
              '/api/v1/session/verify'
            );
            if (verifyRes.status === 200 && verifyRes.data.verified) {
              console.log('\n============================================================');
              console.log('[VERIFICATION SUCCESS] Session successfully accepted and verified by Bank Eghtesad Novin!');
              console.log('Auth Status         : ' + verifyRes.data.status.status);
              console.log('Remote Verification : VERIFIED');
              console.log('Last Verified       : ' + (verifyRes.data.status.lastVerifiedAt || new Date().toISOString()));
              console.log('Credentials Renewal : ' + (saveCredentials ? 'ENABLED (Encrypted on disk)' : 'ENABLED (In-Memory only)'));
              console.log('Expires At          : ' + (verifyRes.data.status.expiresAt || 'N/A'));
              console.log('============================================================\n');
              console.log('[TIP] You can now safely query banking data:');
              console.log('  npm run cli -- accounts');
              console.log('  npm run cli -- balance\n');
              return 0;
            } else {
              console.warn('\n[WARNING] Login succeeded locally but bank verification failed: ' + JSON.stringify(verifyRes.data) + '\n');
              return 1;
            }
          } else {
            console.error('\n[LOGIN FAILED] ' + (otpRes.data.message || otpRes.data.error || 'Authentication error') + '\n');
            return 1;
          }
        }

        // Handle CAPTCHA Challenge
        if (loginRes.data && loginRes.data.requiresCaptcha) {
          console.warn('\n[CAPTCHA ACTIVE] Bank server enforced CAPTCHA challenge on login.');
          console.log('Please use browser-assisted login flow:');
          console.log('  npm run cli -- login --browser\n');
          return 1;
        }

        // Handle Device Token / Gateway Rejection (e.g. "توکن دسترسی null یافت نشد")
        if (
          loginRes.data &&
          (loginRes.data.requiresDeviceToken ||
            (typeof loginRes.data.message === 'string' &&
              (loginRes.data.message.includes('توکن') || loginRes.data.message.toLowerCase().includes('null'))))
        ) {
          console.error('\n[LOGIN FAILED] ' + loginRes.data.message);
          console.log('\n[DIAGNOSTIC] Bank Eghtesad Novin API gateway rejected the request because the access token was "null".');
          console.log('The bank\'s Farazpardazan PWA gateway enforces pre-registered device tokens on /en/api/user/bankLogin.');
          console.log('To authenticate successfully:');
          console.log('  1. Use Browser-Assisted Login (Recommended):');
          console.log('     npm run cli -- login --browser');
          console.log('  2. Or import an active browser session token:');
          console.log('     npm run cli -- import');
          console.log('  3. Or configure a pre-registered device token in your .env:');
          console.log('     ENBANK_DEVICE_TOKEN=<your-mobile-user-token>\n');
          return 1;
        }

        if (loginRes.status === 200) {
          console.log('\n[SUCCESS] ' + loginRes.data.message);
          console.log('Verifying session against Bank Eghtesad Novin server...');
          const verifyRes = await client.request<{ verified: boolean; status: SessionStatusResponse; message: string }>(
            'POST',
            '/api/v1/session/verify'
          );
          if (verifyRes.status === 200 && verifyRes.data.verified) {
            console.log('\n============================================================');
            console.log('[VERIFICATION SUCCESS] Session successfully accepted and verified by Bank Eghtesad Novin!');
            console.log('Auth Status         : ' + verifyRes.data.status.status);
            console.log('Remote Verification : VERIFIED');
            console.log('Last Verified       : ' + (verifyRes.data.status.lastVerifiedAt || new Date().toISOString()));
            console.log('Credentials Renewal : ' + (saveCredentials ? 'ENABLED (Encrypted on disk)' : 'ENABLED (In-Memory only)'));
            console.log('Expires At          : ' + (verifyRes.data.status.expiresAt || 'N/A'));
            console.log('============================================================\n');
            console.log('[TIP] You can now safely query banking data:');
            console.log('  npm run cli -- accounts');
            console.log('  npm run cli -- balance\n');
            return 0;
          } else {
            console.warn('\n[WARNING] Login succeeded locally but bank verification failed: ' + JSON.stringify(verifyRes.data) + '\n');
            return 1;
          }
        } else {
          console.error('\n[LOGIN FAILED] ' + (loginRes.data.message || loginRes.data.error || JSON.stringify(loginRes.data)) + '\n');
          return 1;
        }
      }

      case 'status': {
        console.log('\nQuerying local daemon status...');
        const healthRes = await client.request<{ status: string; mode: string }>('GET', '/api/v1/health');
        const sessionRes = await client.request<SessionStatusResponse>('GET', '/api/v1/session/status');

        const isVerified = Boolean(sessionRes.data.isRemotelyVerified);
        const authStatus = sessionRes.data.status;
        let authLabel = 'NO';
        if (isVerified) {
          authLabel = 'YES (Remotely Verified)';
        } else if (authStatus === 'LOCAL_ACTIVE') {
          authLabel = 'LOCAL ONLY (Unverified with bank — run: npm run cli -- verify)';
        } else if (authStatus === 'REAUTHENTICATION_REQUIRED') {
          authLabel = 'NO (Re-authentication required: bank rejected token)';
        } else if (authStatus === 'EXPIRED') {
          authLabel = 'NO (Session expired)';
        }

        const credMode = sessionRes.data.credentialsStorage === 'PERSISTED_ENCRYPTED'
          ? 'STORED (Encrypted on disk)'
          : sessionRes.data.credentialsStorage === 'MEMORY'
          ? 'STORED (In-Memory only)'
          : 'NONE';

        console.log('\n============================================================');
        console.log('Daemon Status       : RUNNING (127.0.0.1:' + config.server.port + ')');
        console.log('Mode                : ' + (healthRes.data?.mode || 'READ_ONLY_FOUNDATION'));
        console.log('Auth Status         : ' + authStatus);
        console.log('Local Session       : ' + (sessionRes.data.hasLocalSession ? 'ACTIVE' : 'INACTIVE'));
        console.log('Device Enrollment   : ' + (sessionRes.data.hasRegisteredDevice ? 'ENROLLED (mobileUserToken active)' : 'NOT ENROLLED'));
        console.log('Remote Verification : ' + (isVerified ? 'VERIFIED' : 'UNVERIFIED'));
        console.log('Auto-Renewal Creds  : ' + credMode);
        console.log('Persistent Storage  : ' + (sessionRes.data.hasPersistedSession ? 'STORED (Encrypted on disk)' : 'NONE'));
        console.log('Last Verified       : ' + (sessionRes.data.lastVerifiedAt || 'Never'));
        console.log('Authenticated       : ' + authLabel);
        console.log('Local Idle Expiry   : ' + (sessionRes.data.expiresAt || 'N/A') + ' (sliding window: ' + sessionRes.data.idleTimeoutSeconds + 's)');
        console.log('Last Activity       : ' + (sessionRes.data.lastActivityAt || 'N/A'));
        console.log('Idle Window         : ' + sessionRes.data.idleTimeoutSeconds + ' seconds');
        console.log('============================================================\n');

        if (sessionRes.data.status === 'REAUTHENTICATION_REQUIRED') {
          console.log('[ACTION REQUIRED] Remote authentication rejection detected. Run:');
          console.log('  npm run cli -- login\n');
        } else if (!isVerified && sessionRes.data.hasLocalSession) {
          console.log('[TIP] Session is loaded locally but not yet verified with the bank server. Run:');
          console.log('  npm run cli -- verify\n');
        } else if (!sessionRes.data.isAuthenticated) {
          console.log('[TIP] To log in with your credentials, run:');
          console.log('  npm run cli -- login\n');
        }
        return 0;
      }

      case 'import': {
        let token = args.subcommand || args.positionals[1];
        if (token && token.trim().length > 0) {
          console.warn(
            '\n[SECURITY WARNING] Passing tokens as CLI arguments exposes credentials in shell history and process lists.\n' +
            'Prefer the interactive hidden prompt: run "npm run cli -- import" without arguments.\n'
          );
        } else {
          token = await readHiddenInput('Enter Banking Bearer Token (input will be masked): ');
        }

        const rawToken = token || '';
        const sanitized = sanitizeTokenInput(rawToken);

        console.log('\n[TOKEN INPUT DIAGNOSTIC]');
        console.log(`  Input empty        : ${sanitized.isEmpty ? 'YES' : 'NO'}`);
        console.log(`  Captured length    : ${sanitized.length} characters`);
        console.log(`  Extracted format   : ${sanitized.extractedFromFormat?.toUpperCase() || 'RAW'}`);
        console.log(`  Surrounding quotes : ${sanitized.hadSurroundingQuotes ? 'STRIPPED' : 'NONE'}`);
        console.log(`  Bracketed paste    : ${sanitized.hadBracketedPaste ? 'STRIPPED' : 'NONE'}`);
        console.log(`  Device token match : ${sanitized.isDeviceTokenMatch ? 'YES (WARNING: matches mobileUserToken)' : 'NO'}`);
        console.log(`  Validation status  : ${sanitized.length >= 20 ? 'ACCEPTED (VALID LENGTH)' : 'REJECTED (TOO SHORT)'}\n`);

        if (sanitized.isEmpty) {
          console.error('[ERROR] No token entered. Session import aborted.\n');
          return 1;
        }

        if (sanitized.isDeviceTokenMatch && !sanitized.yaghootToken) {
          console.error('\n[ERROR] The entered token matches your device registration token (mobileUserToken), not an active banking session token.');
          console.error('Evidence: In Bank Eghtesad Novin PWA, visiting /#/login resets currentToken to mobileUserToken.');
          console.error('Resolution: Please complete login in your browser, remain on Deposits or Cards, and run:');
          console.error('  copy(sessionStorage.getItem("yaghootToken"))\n');
          return 1;
        }

        const cleanToken = sanitized.value;
        const lower = cleanToken.toLowerCase();
        if (
          cleanToken.length < 20 ||
          cleanToken.length > 4096 ||
          lower === 'null' ||
          lower === 'undefined' ||
          lower === '[object object]'
        ) {
          console.error('\n[ERROR] Invalid token format. Token must be a valid, non-empty bearer token between 20 and 4096 characters (captured: ' + sanitized.length + ').\n');
          return 1;
        }

        if (config.security.deviceToken && cleanToken.toLowerCase() === config.security.deviceToken.toLowerCase()) {
          console.error('\n[ERROR] The entered token is your configured device registration token (mobileUserToken), not an authenticated banking session token (currentToken/yaghootToken). Please log into the portal and paste the session token.\n');
          return 1;
        }

        const res = await client.request<{ message: string; status: SessionStatusResponse }>(
          'POST',
          '/api/v1/session/import',
          { token: cleanToken }
        );

        if (res.status === 200) {
          console.log('\n[SUCCESS] ' + res.data.message);
          console.log('Auth Status : ' + res.data.status.status);
          console.log('Local Idle Expiry : ' + (res.data.status.expiresAt || 'N/A') + '\n');
          return 0;
        } else {
          console.error('\n[IMPORT FAILED] ' + JSON.stringify(res.data) + '\n');
          return 1;
        }
      }

      case 'verify': {
        console.log('\nVerifying session against Bank Eghtesad Novin server...');
        // Invoke dedicated remote verification endpoint
        const verifyRes = await client.request<{ verified: boolean; status: SessionStatusResponse; message: string }>(
          'POST',
          '/api/v1/session/verify'
        );

        if (verifyRes.status === 404) {
          console.error('\n[STALE DAEMON DETECTED] The background daemon (on port 8080) does not support /api/v1/session/verify.');
          console.error('The daemon is running an older process instance and must be restarted.');
          console.error('Please restart the daemon to load the latest routes:\n  npm start\n');
          return 1;
        }

        if (verifyRes.status !== 200) {
          const errData = verifyRes.data as { error?: string; message?: string; bankCode?: number };
          const errType = errData?.error;
          const msg = errData?.message || JSON.stringify(verifyRes.data);

          switch (errType) {
            case 'NO_SESSION':
              console.error('\n[VERIFICATION FAILED] No active session found.');
              console.error('Reason: ' + msg);
              console.error('Run: npm run cli -- login --browser  (or npm run cli -- import)\n');
              break;

            case 'BANK_AUTH_FAILED':
              console.error('\n[VERIFICATION FAILED] Bank server explicitly rejected the session token.');
              console.error(`Reason: ${msg}${errData.bankCode !== undefined ? ` (Bank Code: ${errData.bankCode})` : ''}`);
              if (errData.bankCode === 3071) {
                console.error('\n[DIAGNOSTIC - BANK CODE 3071]');
                console.error('Bank message: دسترسی کاربر منقضی شده است (User access has expired / token revoked).');
                console.error('This error indicates that the bank server does not recognize this token as an active banking session.');
                console.error('Causes:');
                console.error('  - You copied mobileUserToken (device registration token) instead of yaghootToken.');
                console.error('  - You were on /#/login or refreshed the page (which resets currentToken to mobileUserToken).');
                console.error('  - The session expired on the bank server.');
                console.error('Fix: Keep the browser tab open on an authenticated page (e.g. Deposits/Cards),');
                console.error('     run in Console: copy(sessionStorage.getItem("yaghootToken")),');
                console.error('     then run: npm run cli -- login --browser\n');
              } else {
                console.error('Run: npm run cli -- login --browser\n');
              }
              break;

            case 'LOCAL_SESSION_EXPIRED':
            case 'REAUTHENTICATION_REQUIRED':
              console.error('\n[SESSION INACTIVE] Session expired or re-authentication required.');
              console.error('Reason: ' + msg);
              console.error('Run: npm run cli -- login --browser  (or npm run cli -- import)\n');
              break;

            case 'UNAUTHORIZED':
              console.error('\n[DAEMON AUTH ERROR] Local daemon rejected request (invalid X-Local-API-Key).');
              console.error('Reason: ' + msg);
              console.error('Check LOCAL_API_KEY in your .env file.\n');
              break;

            case 'BANK_UNREACHABLE':
              console.error('\n[GATEWAY UNREACHABLE] Could not establish connection to Bank Eghtesad Novin server.');
              console.error('Reason: ' + msg);
              console.error('Check your internet connection and VPN/DNS settings.\n');
              break;

            case 'BANK_ERROR':
              console.error('\n[BANK APPLICATION ERROR] Bank returned an application-level error.');
              console.error(`Reason: ${msg}${errData.bankCode !== undefined ? ` (Bank Code: ${errData.bankCode})` : ''}\n`);
              break;

            case 'INVALID_RESPONSE':
              console.error('\n[RESPONSE ERROR] Bank returned an unexpected response format.');
              console.error('Reason: ' + msg + '\n');
              break;

            default:
              console.error('\n[VERIFICATION ERROR] ' + msg + '\n');
              break;
          }
          return 1;
        }

        // Verification succeeded! Now fetch deposit list
        const accountsRes = await client.request<{ count: number; accounts: BankAccount[] }>('GET', '/api/v1/accounts');
        const sessionRes = await client.request<SessionStatusResponse>('GET', '/api/v1/session/status');

        console.log('\n============================================================');
        console.log('Session Remote Verification Report');
        console.log('============================================================');
        console.log('Bank Gateway Status : CONFIRMED (HTTP 200)');
        console.log('Auth Status         : ' + sessionRes.data.status);
        console.log('Remote Verification : ' + (sessionRes.data.isRemotelyVerified ? 'VERIFIED' : 'UNVERIFIED'));
        console.log('Last Verified At    : ' + (sessionRes.data.lastVerifiedAt || new Date().toISOString()));
        console.log('Accessible Deposits : ' + (accountsRes.status === 200 ? accountsRes.data.count : 'Verified (Data ready)'));
        console.log('Session Expiry      : ' + (sessionRes.data.expiresAt || 'N/A'));
        console.log('============================================================\n');
        return 0;
      }

      case 'balances':
      case 'accounts': {
        const res = await client.request<{ count: number; accounts: BankAccount[] }>('GET', '/api/v1/accounts');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[SESSION INACTIVE] ' + (errData.message || 'Session expired or requires re-authentication.'));
            console.error('Run: npm run cli -- verify  (to check if browser session is still active on the bank)');
            console.error(' Or: npm run cli -- import  (to import a fresh browser token)');
            console.error(' Or: npm run cli -- login   (to log in again)\n');
          } else {
            console.error('\n[ERROR] ' + JSON.stringify(res.data) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nOwned Deposits (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Deposit Number     | Title                | Balance             | Available');
        console.log('--------------------------------------------------------------------------------');
        res.data.accounts.forEach((acc, idx) => {
          const num = acc.depositNumber.padEnd(18, ' ');
          const title = (acc.title || 'N/A').slice(0, 20).padEnd(20, ' ');
          const bal = formatCurrency(acc.balance, acc.currency).padStart(19, ' ');
          const avail = formatCurrency(acc.availableBalance, acc.currency).padStart(19, ' ');
          console.log(` ${idx + 1} | ${num} | ${title} | ${bal} | ${avail}`);
          if (acc.iban) {
            console.log(`   └─ IBAN: ${acc.iban}`);
          }
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'balance': {
        const deposit = (args.subcommand || args.positionals[1] || '').trim();
        // If no deposit number provided, show combined balance across all accounts
        if (!deposit) {
          const res = await client.request<CombinedBalance>('GET', '/api/v1/balance');
          if (res.status !== 200) {
            const errData = res.data as { error?: string; message?: string };
            if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
              console.error('\n[SESSION INACTIVE] Bank session has expired or requires re-authentication.');
              console.error('Run: npm run cli -- login --browser\n');
            } else {
              console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
            }
            return 1;
          }

          notifyRenewalIfOccurred(res);

          if (args.flags['json']) {
            console.log(JSON.stringify(res.data, null, 2));
            return 0;
          }

          const data = res.data;
          console.log('\n============================================================');
          console.log('Combined Account Balances Report');
          console.log('============================================================');
          console.log('Total Available Balance : ' + (data.totalAvailableFormatted || formatCurrency(data.totalAvailableBalance, data.currency)));
          console.log('Total Current Balance   : ' + (data.totalCurrentFormatted || formatCurrency(data.totalCurrentBalance, data.currency)));
          console.log('Currency                : ' + (data.currency || 'IRR'));
          console.log('Accessible Accounts     : ' + (data.accountCount || data.accounts.length));
          console.log('------------------------------------------------------------');
          console.log(' # | Deposit Number     | Available Balance   | Account Title');
          console.log('------------------------------------------------------------');
          data.accounts.forEach((acc, idx) => {
            const num = acc.depositNumber.padEnd(18, ' ');
            const avail = formatCurrency(acc.availableBalance, data.currency).padStart(19, ' ');
            const title = acc.title || 'N/A';
            console.log(` ${idx + 1} | ${num} | ${avail} | ${title}`);
          });
          console.log('============================================================\n');
          return 0;
        }

        const res = await client.request<Partial<BankAccount>>('GET', `/api/v1/accounts/${encodeURIComponent(deposit)}/balance`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && errData.error === 'ACCOUNT_NOT_FOUND') {
            console.error(`\n[ERROR] Account with deposit number "${deposit}" was not found.`);
            console.error('Run: npm run cli -- accounts  (to list all owned deposits)\n');
          } else if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[SESSION INACTIVE] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login --browser\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const data = res.data || {};
        let depositNumber = data.depositNumber ? String(data.depositNumber).trim() : deposit;
        let title = data.title ? String(data.title).trim() : '';
        let iban = data.iban ? String(data.iban).trim() : undefined;

        if (!title) {
          try {
            const accountsRes = await client.request<{ count: number; accounts: BankAccount[] }>('GET', '/api/v1/accounts');
            if (accountsRes.status === 200 && Array.isArray(accountsRes.data?.accounts)) {
              const match = accountsRes.data.accounts.find((a) => a.depositNumber === deposit);
              if (match) {
                if (match.title && match.title.trim()) title = match.title.trim();
                if (!iban && match.iban) iban = match.iban.trim();
                if (!depositNumber && match.depositNumber) depositNumber = match.depositNumber.trim();
              }
            }
          } catch {
            // Best-effort lookup
          }
        }

        const displayDepositNumber = depositNumber || deposit || 'N/A';
        const displayTitle = title || 'N/A';
        const rawBalance = typeof data.balance === 'number' && !isNaN(data.balance) ? data.balance : 0;
        const rawAvail = typeof data.availableBalance === 'number' && !isNaN(data.availableBalance)
          ? data.availableBalance
          : rawBalance;
        const currency = (data.currency ? String(data.currency).trim() : 'IRR') || 'IRR';

        console.log('\n============================================================');
        console.log('Deposit Balance Report');
        console.log('============================================================');
        console.log('Deposit Number    : ' + displayDepositNumber);
        console.log('Account Title     : ' + displayTitle);
        console.log('Real-Time Balance : ' + formatCurrency(rawBalance, currency));
        console.log('Available Balance : ' + formatCurrency(rawAvail, currency));
        if (iban) {
          console.log('Sheba / IBAN      : ' + iban);
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'statement': {
        const deposit = args.subcommand || args.positionals[1];
        if (!deposit) {
          console.error('\n[ERROR] Missing deposit number. Usage: npm run cli -- statement <depositNumber>\n');
          return 1;
        }

        const queryParams = new URLSearchParams();
        if (args.flags['from']) queryParams.set('fromDate', args.flags['from']);
        if (args.flags['to']) queryParams.set('toDate', args.flags['to']);
        if (args.flags['page']) queryParams.set('page', args.flags['page']);
        if (args.flags['limit']) queryParams.set('limit', args.flags['limit']);

        const queryString = queryParams.toString() ? '?' + queryParams.toString() : '';
        const res = await client.request<{ transactions?: TransactionRecord[]; totalCount?: number }>(
          'GET',
          `/api/v1/accounts/${encodeURIComponent(deposit)}/statement${queryString}`
        );
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && errData.error === 'ACCOUNT_NOT_FOUND') {
            console.error(`\n[ERROR] Account with deposit number "${deposit}" was not found in your owned accounts.`);
            console.error('Run: npm run cli -- accounts  (to list all owned deposits)\n');
          } else if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login --browser\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const statementData = res.data;
        const txList = Array.isArray(statementData?.transactions) ? statementData.transactions : [];

        if (args.flags['detail'] === 'true') {
          console.log('\n================================================================================');
          console.log(`Deposit Transaction Statement (Detailed) : ${deposit} (${txList.length} records)`);
          console.log('================================================================================');
          if (txList.length === 0) {
            console.log('No transactions found for the specified period or parameters.\n');
            return 0;
          }
          txList.forEach((tx, idx) => {
            const num = idx + 1;
            const type = tx.isDebit ? 'DEBIT (برداشت)' : 'CREDIT (واریز)';
            const jalali = (tx.jalaliDate ? `${tx.jalaliDate} ${tx.jalaliTime || ''}` : '') || tx.transactionDate || '-';
            const greg = (tx.gregorianDate ? `${tx.gregorianDate} ${tx.gregorianTime || ''}` : '') || tx.transactionDate || '-';
            console.log(`\n[Transaction #${num}]`);
            console.log(`  Amount       : ${formatCurrency(tx.amount, 'IRR')} [${type}]`);
            if (tx.balance !== undefined) {
              console.log(`  Balance      : ${formatCurrency(tx.balance, 'IRR')}`);
            }
            console.log(`  Jalali Date  : ${jalali}`);
            console.log(`  Gregorian    : ${greg}`);
            if (tx.trackingNumber) {
              console.log(`  Tracking No  : ${tx.trackingNumber}`);
            }
            if (tx.referenceId && tx.referenceId !== tx.trackingNumber) {
              console.log(`  Reference ID : ${tx.referenceId}`);
            }
            console.log(`  Description  : ${tx.description || tx.type || '-'}`);
          });
          console.log('\n================================================================================');
          console.log('* Note: Bank Eghtesad Novin core banking API does not provide per-transaction running balance.\n');
          return 0;
        }

        console.log('\n========================================================================================================');
        console.log(`Deposit Transaction Statement : ${deposit} (${txList.length} records)`);
        console.log('========================================================================================================');
        if (txList.length === 0) {
          console.log('No transactions found for the specified period or parameters.\n');
          return 0;
        }

        const hasAnyBalance = txList.some((tx) => tx.balance !== undefined);

        if (hasAnyBalance) {
          console.log(' # | Jalali Date/Time     | Gregorian   | Type   | Amount (IRR)        | Balance (IRR)       | Description');
          console.log('---+----------------------+-------------+--------+---------------------+---------------------+---------------------------------');
          txList.forEach((tx, idx) => {
            const num = String(idx + 1).padStart(2, ' ');
            const jalali = ((tx.jalaliDate ? `${tx.jalaliDate} ${tx.jalaliTime || ''}` : '') || tx.transactionDate || '-').slice(0, 20).padEnd(20, ' ');
            const greg = (tx.gregorianDate || tx.transactionDate || '-').slice(0, 11).padEnd(11, ' ');
            const type = tx.isDebit ? 'DEBIT ' : 'CREDIT';
            const amt = formatCurrency(tx.amount, 'IRR').padStart(19, ' ');
            const bal = (tx.balance !== undefined ? formatCurrency(tx.balance, 'IRR') : '-').padStart(19, ' ');
            const descLines = wrapText(tx.description || tx.type || '-', 40);
            console.log(` ${num} | ${jalali} | ${greg} | ${type} | ${amt} | ${bal} | ${descLines[0]}`);
            for (let l = 1; l < descLines.length; l++) {
              console.log(`    |                      |             |        |                     |                     | ${descLines[l]}`);
            }
            if (tx.trackingNumber && tx.trackingNumber !== tx.referenceId) {
              console.log(`    └─ Tracking: ${tx.trackingNumber} | Ref: ${tx.referenceId}`);
            } else if (tx.referenceId) {
              console.log(`    └─ Ref: ${tx.referenceId}`);
            }
          });
        } else {
          console.log(' # | Jalali Date/Time     | Gregorian   | Type   | Amount (IRR)        | Description');
          console.log('---+----------------------+-------------+--------+---------------------+--------------------------------------------------');
          txList.forEach((tx, idx) => {
            const num = String(idx + 1).padStart(2, ' ');
            const jalali = ((tx.jalaliDate ? `${tx.jalaliDate} ${tx.jalaliTime || ''}` : '') || tx.transactionDate || '-').slice(0, 20).padEnd(20, ' ');
            const greg = (tx.gregorianDate || tx.transactionDate || '-').slice(0, 11).padEnd(11, ' ');
            const type = tx.isDebit ? 'DEBIT ' : 'CREDIT';
            const amt = formatCurrency(tx.amount, 'IRR').padStart(19, ' ');
            const descLines = wrapText(tx.description || tx.type || '-', 50);
            console.log(` ${num} | ${jalali} | ${greg} | ${type} | ${amt} | ${descLines[0]}`);
            for (let l = 1; l < descLines.length; l++) {
              console.log(`    |                      |             |        |                     | ${descLines[l]}`);
            }
            if (tx.trackingNumber && tx.trackingNumber !== tx.referenceId) {
              console.log(`    └─ Tracking: ${tx.trackingNumber} | Ref: ${tx.referenceId}`);
            } else if (tx.referenceId) {
              console.log(`    └─ Ref: ${tx.referenceId}`);
            }
          });
        }
        console.log('========================================================================================================');
        console.log('* Note: Bank Eghtesad Novin core banking API does not provide per-transaction running balance.');
        console.log('* Tip: Use "--detail" for full expanded view or "--json" for raw structured output.\n');
        return 0;
      }

      case 'cards': {
        const isDestination = args.flags['destination'] === 'true' || args.flags['dest'] === 'true' || args.subcommand === 'destination';
        if (isDestination) {
          const res = await client.request<{ count: number; cards: BankCard[] }>('GET', '/api/v1/cards/destination');
          if (res.status !== 200) {
            const errData = res.data as { error?: string; message?: string };
            if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
              console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
              console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
              console.error('Run: npm run cli -- login\n');
            } else {
              console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
            }
            return 1;
          }

          notifyRenewalIfOccurred(res);

          if (args.flags['json']) {
            console.log(JSON.stringify(res.data, null, 2));
            return 0;
          }

          if (!res.data.cards || res.data.cards.length === 0) {
            console.log('\n[INFO] No saved destination cards found.\n');
            return 0;
          }

          console.log(`\nSaved Destination Cards (${res.data.count}):`);
          console.log('--------------------------------------------------------------------------------');
          console.log(' # | Card PAN / Masked   | Title                | Bank Name       | Owner');
          console.log('--------------------------------------------------------------------------------');
          res.data.cards.forEach((card, idx) => {
            const pan = (card.maskedPan || (card as any).pan || 'N/A').padEnd(20, ' ');
            const title = (card.title || 'Card').slice(0, 20).padEnd(20, ' ');
            const bank = (card.bankName || 'N/A').slice(0, 15).padEnd(15, ' ');
            const owner = card.cardHolderName || card.linkedIban || 'N/A';
            console.log(` ${idx + 1} | ${pan} | ${title} | ${bank} | ${owner}`);
          });
          console.log('--------------------------------------------------------------------------------\n');
          return 0;
        }

        const res = await client.request<{ count: number; cards: BankCard[] }>('GET', '/api/v1/cards');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + JSON.stringify(res.data) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nRegistered Cards (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Masked PAN           | Title                | Status   | Default');
        console.log('--------------------------------------------------------------------------------');
        res.data.cards.forEach((card, idx) => {
          const pan = card.maskedPan.padEnd(20, ' ');
          const title = (card.title || 'Card').slice(0, 20).padEnd(20, ' ');
          const status = (card.cardStatus || 'ACTIVE').padEnd(8, ' ');
          const def = card.isDefault ? 'YES' : 'NO';
          console.log(` ${idx + 1} | ${pan} | ${title} | ${status} | ${def}`);
          if (card.linkedIban) {
            console.log(`   └─ Linked IBAN: ${card.linkedIban}`);
          }
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'inquire-card': {
        const pan = args.subcommand || args.positionals[1];
        if (!pan) {
          console.error('\n[ERROR] Missing card PAN. Usage: npm run cli -- inquire-card <PAN>\n');
          return 1;
        }

        const res = await client.request<unknown>('GET', `/api/v1/cards/inquiry?pan=${encodeURIComponent(pan)}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const inq = res.data as { recipientName?: string; bankName?: string; depositNumber?: string; linkedIban?: string };
        console.log('\n============================================================');
        console.log('Card Recipient Inquiry');
        console.log('============================================================');
        console.log('Card PAN       : ' + pan);
        if (inq.recipientName) {
          console.log('Recipient Name : ' + inq.recipientName);
        } else {
          console.log('Recipient Name : UNRESOLVED (Remote bank gateway was unable to query recipient name for this card)');
        }
        if (inq.bankName) {
          console.log('Issuing Bank   : ' + inq.bankName);
        }
        if (inq.depositNumber) {
          console.log('Linked Deposit : ' + inq.depositNumber);
        }
        if (inq.linkedIban) {
          console.log('Linked IBAN    : ' + inq.linkedIban);
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'inquire-iban': {
        const iban = (args.subcommand || args.positionals[1] || '').trim();
        if (!iban) {
          console.error('\n[ERROR] Missing IBAN. Usage: npm run cli -- inquire-iban <IR...>\n');
          return 1;
        }

        const res = await client.request<IbanInquiryResult>('GET', `/api/v1/iban/inquiry?iban=${encodeURIComponent(iban)}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const info = res.data;
        console.log('\n============================================================');
        console.log('IBAN Account & Owner Inquiry');
        console.log('============================================================');
        console.log('IBAN            : ' + info.iban);
        console.log('Account Owner   : ' + (info.ownerName || 'N/A'));
        console.log('Bank Name       : ' + (info.bankName || 'N/A'));
        if (info.depositNumber) {
          console.log('Deposit Number  : ' + info.depositNumber);
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'profile': {
        const res = await client.request<UserProfile>('GET', '/api/v1/profile');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const profile = res.data;
        console.log('\n============================================================');
        console.log('Customer Profile & Identity (Hamrah Novin)');
        console.log('============================================================');
        console.log('Full Name       : ' + (profile.fullName || 'N/A'));
        if (profile.cif) {
          console.log('Customer CIF    : ' + profile.cif);
        }
        if (profile.username) {
          console.log('Username        : ' + profile.username);
        }
        if (profile.nationalCode) {
          console.log('National Code   : ' + profile.nationalCode);
        }
        if (profile.mobileNumber) {
          console.log('Mobile Number   : ' + profile.mobileNumber);
        }
        if (profile.lastLoginDate) {
          console.log('Last Login Date : ' + profile.lastLoginDate);
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'transaction-find': {
        const code = (args.subcommand || args.positionals[1] || '').trim();
        if (!code) {
          console.error('\n[ERROR] Missing transaction receipt or reference code. Usage: npm run cli -- transaction-find <code>\n');
          return 1;
        }

        const queryParams = new URLSearchParams();
        if (args.flags['pages']) queryParams.set('pages', args.flags['pages']);
        if (args.flags['deposit']) queryParams.set('deposit', args.flags['deposit']);
        const queryString = queryParams.toString() ? '?' + queryParams.toString() : '';

        const res = await client.request<TransactionRecord>('GET', `/api/v1/transactions/find/${encodeURIComponent(code)}${queryString}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && errData.error === 'TRANSACTION_NOT_FOUND') {
            console.error(`\n[NOT FOUND] No transaction found matching reference/tracking code "${code}".\n`);
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const tx = res.data;
        const refDisplay = tx.referenceId || tx.trackingNumber || 'N/A';
        console.log('\n============================================================');
        console.log('Transaction Details');
        console.log('============================================================');
        console.log('Reference ID     : ' + refDisplay);
        if (tx.trackingNumber && tx.trackingNumber !== refDisplay) {
          console.log('Tracking Number  : ' + tx.trackingNumber);
        }
        console.log('Direction / Type : ' + (tx.isDebit ? 'DEBIT (-)' : 'CREDIT (+)'));
        console.log('Amount           : ' + (tx.amountFormatted || formatCurrency(tx.amount, 'IRR')));
        if (tx.balanceFormatted || tx.balance !== undefined) {
          console.log('Running Balance  : ' + (tx.balanceFormatted || formatCurrency(tx.balance, 'IRR')));
        }
        console.log('Jalali Date/Time : ' + ((tx.jalaliDate ? `${tx.jalaliDate} ${tx.jalaliTime || ''}` : '') || 'N/A'));
        console.log('Gregorian Date   : ' + (tx.gregorianDate || tx.transactionDate || 'N/A'));
        console.log('Description      : ' + (tx.description || tx.type || 'N/A'));
        console.log('============================================================\n');
        return 0;
      }

      case 'banks': {
        const query = (args.subcommand || args.positionals[1] || '').trim();
        const queryString = query ? `?q=${encodeURIComponent(query)}` : '';
        const res = await client.request<{ count: number; banks: BankInfo[] }>('GET', `/api/v1/banks${queryString}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nIranian Bank Directory (${res.data.count} banks):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Code | Persian Bank Name       | English Name             | BIN Prefixes');
        console.log('--------------------------------------------------------------------------------');
        res.data.banks.forEach((b, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const code = (b.bankCode || 'N/A').padEnd(4, ' ');
          const fa = (b.persianName || 'N/A').slice(0, 22).padEnd(22, ' ');
          const en = (b.bankName || 'N/A').slice(0, 24).padEnd(24, ' ');
          const bins = b.bins && b.bins.length > 0 ? b.bins.slice(0, 3).join(', ') : 'N/A';
          console.log(` ${num} | ${code} | ${fa} | ${en} | ${bins}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'transfers-recent': {
        const res = await client.request<{ count: number; transfers: Array<{
          referenceId?: string;
          trackingNumber?: string;
          amount?: number;
          status?: string;
          destinationIban?: string;
          destinationOwnerName?: string;
          description?: string;
          jalaliDate?: string;
          jalaliTime?: string;
        }> }>('GET', '/api/v1/transfers/recent');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        if (!res.data.transfers || res.data.transfers.length === 0) {
          console.log('\n[INFO] No recent transfer records found.\n');
          return 0;
        }

        console.log(`\nRecent Transfers (Paya / ACH Transfer History) (${res.data.count} records):`);
        console.log('--------------------------------------------------------------------------------------------------------');
        console.log(' # | Tracking / Ref ID    | Date (Jalali) | Amount (IRR)        | Status     | Destination / Owner');
        console.log('--------------------------------------------------------------------------------------------------------');
        res.data.transfers.forEach((tx, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const ref = (tx.trackingNumber || tx.referenceId || 'N/A').slice(0, 20).padEnd(20, ' ');
          const date = (tx.jalaliDate ? `${tx.jalaliDate} ${tx.jalaliTime || ''}` : 'N/A').slice(0, 13).padEnd(13, ' ');
          const amt = formatCurrency(tx.amount || 0, 'IRR').padStart(19, ' ');
          const status = (tx.status || 'UNKNOWN').slice(0, 10).padEnd(10, ' ');
          const dest = tx.destinationOwnerName
            ? `${tx.destinationOwnerName} (${tx.destinationIban ? tx.destinationIban.slice(-8) : ''})`
            : tx.destinationIban || 'N/A';
          console.log(` ${num} | ${ref} | ${date} | ${amt} | ${status} | ${dest}`);
        });
        console.log('--------------------------------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'transfers-scheduled': {
        const type = args.flags['type']?.toUpperCase() === 'ACH' ? 'ACH' : 'NORMAL';
        const res = await client.request<{ count: number; scheduledTransfers: ScheduledTransfer[] }>(
          'GET',
          `/api/v1/transfers/scheduled?type=${type}`
        );
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nScheduled Auto-Transfers (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Type   | Source Deposit     | Destination          | Amount (IRR)        | Status');
        console.log('--------------------------------------------------------------------------------');
        res.data.scheduledTransfers.forEach((s, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const stype = s.autoTransferType.padEnd(6, ' ');
          const src = s.sourceDepositNumber.slice(0, 18).padEnd(18, ' ');
          const dst = s.destinationNumber.slice(0, 20).padEnd(20, ' ');
          const amt = formatCurrency(s.amount, 'IRR').padStart(19, ' ');
          const status = s.status || 'ACTIVE';
          console.log(` ${num} | ${stype} | ${src} | ${dst} | ${amt} | ${status}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'cheques': {
        const queryParams = new URLSearchParams();
        if (args.flags['page']) queryParams.set('page', args.flags['page']);
        if (args.flags['limit']) queryParams.set('limit', args.flags['limit']);
        if (args.flags['status']) queryParams.set('status', args.flags['status']);
        const queryString = queryParams.toString() ? '?' + queryParams.toString() : '';

        const res = await client.request<{ count: number; cheques: ChequeItem[] }>('GET', `/api/v1/cheques${queryString}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nSayad Cheques Cartable (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Sayad ID             | Due Date     | Amount (IRR)        | Status     | Bank');
        console.log('--------------------------------------------------------------------------------');
        res.data.cheques.forEach((c, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const id = (c.sayadId || c.chequeBookNumber || 'N/A').slice(0, 20).padEnd(20, ' ');
          const due = (c.jalaliDueDate || c.dueDate || 'N/A').slice(0, 12).padEnd(12, ' ');
          const amt = (c.amount !== undefined ? formatCurrency(c.amount, 'IRR') : 'N/A').padStart(19, ' ');
          const status = (c.statusTitle || c.status || 'PENDING').slice(0, 10).padEnd(10, ' ');
          const bank = c.bankName || 'N/A';
          console.log(` ${num} | ${id} | ${due} | ${amt} | ${status} | ${bank}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'loans': {
        const res = await client.request<{ count: number; loans: LoanFacility[] }>('GET', '/api/v1/loans');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nCustomer Loan Facilities (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Loan Number    | Title                | Total Amount        | Remaining Amount');
        console.log('--------------------------------------------------------------------------------');
        res.data.loans.forEach((l, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const lnum = l.loanNumber.slice(0, 14).padEnd(14, ' ');
          const title = (l.loanTitle || 'Loan').slice(0, 20).padEnd(20, ' ');
          const total = (l.totalAmountFormatted || formatCurrency(l.totalAmount, 'IRR')).padStart(19, ' ');
          const remain = (l.remainAmountFormatted || formatCurrency(l.remainAmount, 'IRR')).padStart(19, ' ');
          console.log(` ${num} | ${lnum} | ${title} | ${total} | ${remain}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'loan-installments': {
        const loanId = (args.subcommand || args.positionals[1] || '').trim();
        if (!loanId) {
          console.error('\n[ERROR] Missing loan identifier. Usage: npm run cli -- loan-installments <loanId>\n');
          return 1;
        }

        const res = await client.request<{ loanId: string; count: number; installments: LoanInstallment[] }>(
          'GET',
          `/api/v1/loans/${encodeURIComponent(loanId)}/installments`
        );
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nLoan Installments Schedule (${res.data.count} installments):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Due Date (Jalali) | Amount (IRR)        | Status');
        console.log('--------------------------------------------------------------------------------');
        res.data.installments.forEach((inst) => {
          const num = String(inst.installmentNumber).padStart(2, ' ');
          const due = (inst.jalaliDueDate || inst.dueDate || 'N/A').slice(0, 18).padEnd(18, ' ');
          const amt = (inst.amountFormatted || formatCurrency(inst.amount, 'IRR')).padStart(19, ' ');
          const status = inst.isPaid ? 'PAID' : 'UNPAID';
          console.log(` ${num} | ${due} | ${amt} | ${status}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'contacts': {
        const res = await client.request<{ count: number; contacts: DestinationContact[] }>('GET', '/api/v1/contacts');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        if (!res.data.contacts || res.data.contacts.length === 0) {
          console.log('\n[INFO] No saved contacts found.\n');
          return 0;
        }

        console.log(`\nAggregated Banking Contacts (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Type    | Title                | Destination Value    | Owner / Bank');
        console.log('--------------------------------------------------------------------------------');
        res.data.contacts.forEach((c, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const type = c.type.toUpperCase().padEnd(7, ' ');
          const title = (c.title || 'Contact').slice(0, 20).padEnd(20, ' ');
          const val = (c.value || '').slice(0, 22).padEnd(22, ' ');
          const ownerDisplay = c.ownerName ? (c.bankName ? `${c.ownerName} (${c.bankName})` : c.ownerName) : (c.bankName || c.title || 'N/A');
          console.log(` ${num} | ${type} | ${title} | ${val} | ${ownerDisplay}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'bills': {
        const res = await client.request<{ count: number; bills: UtilityBill[] }>('GET', '/api/v1/bills');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        if (!res.data.bills || res.data.bills.length === 0) {
          console.log('\n[INFO] No saved utility bills found.\n');
          return 0;
        }

        console.log(`\nSaved Utility Bills (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Title                | Bill ID              | Pay ID');
        console.log('--------------------------------------------------------------------------------');
        res.data.bills.forEach((b, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const title = (b.title || 'Bill').slice(0, 20).padEnd(20, ' ');
          const bid = b.billId.slice(0, 20).padEnd(20, ' ');
          const pid = b.payId || 'N/A';
          console.log(` ${num} | ${title} | ${bid} | ${pid}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'banners': {
        const res = await client.request<{ count: number; banners: AdvertisementBanner[] }>('GET', '/api/v1/banners');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nActive Bank Announcements & Banners (${res.data.count}):`);
        console.log('================================================================================');
        res.data.banners.forEach((b, idx) => {
          console.log(`[${idx + 1}] ${b.title}`);
          if (b.body) {
            console.log(`    ${b.body}`);
          }
          if (b.linkUrl) {
            console.log(`    Link: ${b.linkUrl}`);
          }
          console.log('--------------------------------------------------------------------------------');
        });
        console.log();
        return 0;
      }

      case 'owner': {
        const identifier = (args.subcommand || args.positionals[1] || '').trim();
        if (!identifier) {
          console.error('\n[ERROR] Missing card PAN, IBAN, or deposit number. Usage: npm run cli -- owner <identifier>\n');
          return 1;
        }

        const res = await client.request<OwnerInquiryResult>('GET', `/api/v1/owner/${encodeURIComponent(identifier)}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        const info = res.data;
        console.log('\n============================================================');
        console.log('Account / Card Owner Inquiry');
        console.log('============================================================');
        console.log('Identifier      : ' + info.identifier);
        console.log('Type            : ' + ((info as any).identifierType || (info as any).type || 'IDENTIFIER').toUpperCase());
        console.log('Owner Name      : ' + (info.ownerName || 'N/A'));
        if (info.bankName) {
          console.log('Bank Name       : ' + info.bankName);
        }
        if (info.depositNumber) {
          console.log('Deposit Number  : ' + info.depositNumber);
        }
        if (info.iban) {
          console.log('IBAN / Sheba    : ' + info.iban);
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'topups':
      case 'charge-recent': {
        const res = await client.request<{ count: number; topups: TopupItem[] }>('GET', '/api/v1/topups');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        if (!res.data.topups || res.data.topups.length === 0) {
          console.log('\n[INFO] No saved mobile top-up records found.\n');
          return 0;
        }

        console.log(`\nSaved Mobile Top-Up Records (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Mobile Number     | Operator        | Title                | Date');
        console.log('--------------------------------------------------------------------------------');
        res.data.topups.forEach((t, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const mobile = (t.phoneNumber || (t as any).mobileNumber || 'N/A').padEnd(17, ' ');
          const op = (t.operator || (t as any).operatorName || 'N/A').slice(0, 15).padEnd(15, ' ');
          const title = (t.title || 'N/A').slice(0, 20).padEnd(20, ' ');
          const date = t.date || 'N/A';
          console.log(` ${num} | ${mobile} | ${op} | ${title} | ${date}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'packages':
      case 'internet-recent': {
        const res = await client.request<{ count: number; packages: PackageItem[] }>('GET', '/api/v1/packages');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          if (errData && (errData.error === 'REAUTHENTICATION_REQUIRED' || errData.error === 'BANK_AUTH_FAILED')) {
            console.error('\n[REAUTHENTICATION REQUIRED] Bank session has expired or requires re-authentication.');
            console.error('Reason: ' + (errData.message || 'Token expired or rejected'));
            console.error('Run: npm run cli -- login\n');
          } else {
            console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          }
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        if (!res.data.packages || res.data.packages.length === 0) {
          console.log('\n[INFO] No saved internet package records found.\n');
          return 0;
        }

        console.log(`\nSaved Internet Package Records (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Mobile Number     | Operator        | Title                | Date');
        console.log('--------------------------------------------------------------------------------');
        res.data.packages.forEach((p, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const mobile = (p.phoneNumber || (p as any).mobileNumber || 'N/A').padEnd(17, ' ');
          const op = (p.operator || (p as any).operatorName || 'N/A').slice(0, 15).padEnd(15, ' ');
          const title = (p.packageTitle || p.title || 'N/A').slice(0, 20).padEnd(20, ' ');
          const date = p.date || 'N/A';
          console.log(` ${num} | ${mobile} | ${op} | ${title} | ${date}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'ach-reports': {
        const queryParams = new URLSearchParams();
        if (args.flags['page']) queryParams.set('page', args.flags['page']);
        if (args.flags['limit']) queryParams.set('limit', args.flags['limit']);
        const queryString = queryParams.toString() ? '?' + queryParams.toString() : '';

        const res = await client.request<{ count: number; reports: Array<{ reportId?: string; trackingNumber?: string; status?: string; amount?: number; jalaliDate?: string; iban?: string }> }>('GET', `/api/v1/ach/reports${queryString}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nACH Transfer Reports (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Tracking / ID        | Date (Jalali) | Amount (IRR)        | Status');
        console.log('--------------------------------------------------------------------------------');
        res.data.reports.forEach((r, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const id = (r.trackingNumber || r.reportId || 'N/A').slice(0, 20).padEnd(20, ' ');
          const date = (r.jalaliDate || 'N/A').slice(0, 13).padEnd(13, ' ');
          const amt = (r.amount !== undefined ? formatCurrency(r.amount, 'IRR') : 'N/A').padStart(19, ' ');
          const status = r.status || 'PROCESSED';
          console.log(` ${num} | ${id} | ${date} | ${amt} | ${status}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'sessions':
      case 'devices': {
        const res = await client.request<{ count: number; sessions: Array<{ id?: string; deviceName?: string; os?: string; browser?: string; ip?: string; lastActivity?: string; isCurrent?: boolean }> }>('GET', '/api/v1/sessions/active');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nActive Client Sessions / Devices (${res.data.count}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Device Name       | Platform / OS   | Last Activity        | Current');
        console.log('--------------------------------------------------------------------------------');
        res.data.sessions.forEach((s, idx) => {
          const num = String(idx + 1).padStart(2, ' ');
          const dev = (s.deviceName || 'N/A').slice(0, 17).padEnd(17, ' ');
          const os = (s.os || 'N/A').slice(0, 15).padEnd(15, ' ');
          const act = (s.lastActivity || 'N/A').slice(0, 20).padEnd(20, ' ');
          const cur = s.isCurrent ? 'YES (*)' : 'NO';
          console.log(` ${num} | ${dev} | ${os} | ${act} | ${cur}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'messages':
      case 'notifications': {
        const queryParams = new URLSearchParams();
        if (args.flags['limit']) queryParams.set('pageSize', args.flags['limit']);
        const queryString = queryParams.toString() ? '?' + queryParams.toString() : '';

        const res = await client.request<{ count: number; messages: Array<{ id: string; title: string; body?: string; date?: string; isUnread?: boolean }> }>('GET', `/api/v1/messages${queryString}`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nCustomer Messages & Notifications (${res.data.count}):`);
        console.log('================================================================================');
        res.data.messages.forEach((m, idx) => {
          const unreadTag = m.isUnread ? ' [UNREAD]' : '';
          console.log(`[${idx + 1}] ${m.title}${unreadTag} (${m.date || 'N/A'})`);
          if (m.body) {
            console.log(`    ${m.body}`);
          }
          console.log('--------------------------------------------------------------------------------');
        });
        console.log();
        return 0;
      }

      case 'cheque-books': {
        const depositNumber = (args.subcommand || args.positionals[1] || '').trim();
        if (!depositNumber) {
          console.error('\n[ERROR] Deposit number is required. Usage: npm run cli -- cheque-books <depositNumber>\n');
          return 1;
        }

        const res = await client.request<{ chequeBooks: any[]; totalRecord?: number }>('GET', `/api/v1/accounts/${encodeURIComponent(depositNumber)}/cheque-books`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log(`\nCheque Books for Deposit ${depositNumber} (${res.data.chequeBooks.length}):`);
        console.log('--------------------------------------------------------------------------------');
        console.log(' # | Cheque Book Number   | Total Sheets | Status');
        console.log('--------------------------------------------------------------------------------');
        res.data.chequeBooks.forEach((b: any, idx: number) => {
          const num = String(idx + 1).padStart(2, ' ');
          const bookNum = String(b.chequeBookNumber || b.number || 'N/A').padEnd(20, ' ');
          const count = String(b.count || b.sheetCount || 'N/A').padEnd(12, ' ');
          const status = String(b.statusTitle || b.status || 'ACTIVE');
          console.log(` ${num} | ${bookNum} | ${count} | ${status}`);
        });
        console.log('--------------------------------------------------------------------------------\n');
        return 0;
      }

      case 'card-balance': {
        const cardId = (args.subcommand || args.positionals[1] || '').trim();
        if (!cardId) {
          console.error('\n[ERROR] Card ID or PAN is required. Usage: npm run cli -- card-balance <cardId>\n');
          return 1;
        }

        const res = await client.request<{ cardUniqueId: string; balance: number; availableBalance: number; currency: string; balanceFormatted: string; availableBalanceFormatted: string }>('GET', `/api/v1/cards/${encodeURIComponent(cardId)}/balance`);
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log('\n============================================================');
        console.log(`Card Balance for Card ${res.data.cardUniqueId}`);
        console.log('============================================================');
        console.log('Current Balance   : ' + res.data.balanceFormatted);
        console.log('Available Balance : ' + res.data.availableBalanceFormatted);
        console.log('Currency          : ' + res.data.currency);
        console.log('============================================================\n');
        return 0;
      }

      case 'interbank-rules': {
        const res = await client.request<any>('GET', '/api/v1/interbank/rules');
        if (res.status !== 200) {
          const errData = res.data as { error?: string; message?: string };
          console.error('\n[ERROR] ' + (errData?.message || JSON.stringify(res.data)) + '\n');
          return 1;
        }

        notifyRenewalIfOccurred(res);

        if (args.flags['json']) {
          console.log(JSON.stringify(res.data, null, 2));
          return 0;
        }

        console.log('\n============================================================');
        console.log('Interbank Transfer Rules & Limits (Paya / Satna)');
        console.log('============================================================');
        let printedAny = false;
        if (res.data.payaCeiling !== undefined) {
          console.log('Paya Ceiling     : ' + formatCurrency(res.data.payaCeiling, 'IRR'));
          printedAny = true;
        }
        if (res.data.satnaFloor !== undefined) {
          console.log('Satna Floor      : ' + formatCurrency(res.data.satnaFloor, 'IRR'));
          printedAny = true;
        }
        if (res.data.satnaCeiling !== undefined) {
          console.log('Satna Ceiling    : ' + formatCurrency(res.data.satnaCeiling, 'IRR'));
          printedAny = true;
        }
        if (res.data.cardTransferCeiling !== undefined) {
          console.log('Card Transfer Max: ' + formatCurrency(res.data.cardTransferCeiling, 'IRR'));
          printedAny = true;
        }

        if (Array.isArray(res.data.rules) && res.data.rules.length > 0) {
          if (printedAny) {
            console.log('------------------------------------------------------------');
          }
          res.data.rules.forEach((rule: any, idx: number) => {
            const typeLabel = rule.type || `Rule #${idx + 1}`;
            console.log(`\n[${typeLabel}]`);
            if (rule.floor !== undefined) console.log(`  Minimum Limit  : ${formatCurrency(rule.floor, 'IRR')}`);
            if (rule.ceiling !== undefined) console.log(`  Maximum Limit  : ${formatCurrency(rule.ceiling, 'IRR')}`);
            if (rule.description) {
              const lines = String(rule.description).split('\n');
              lines.forEach((l) => {
                if (l.trim()) console.log(`  ${l.trim()}`);
              });
            }
          });
          printedAny = true;
        }

        if (!printedAny) {
          console.log('No transfer limit thresholds currently advertised by bank server.');
        }
        console.log('============================================================\n');
        return 0;
      }

      case 'logout': {
        const res = await client.request<{ message: string }>('POST', '/api/v1/session/logout');
        console.log('\n[SUCCESS] ' + res.data.message + '\n');
        return 0;
      }

      default: {
        console.error(`\n[ERROR] Unknown command: "${args.command}"`);
        printHelp();
        return 1;
      }
    }
  } catch (err: unknown) {
    const error = err as Error & { code?: string };
    if (error.code === 'ECONNREFUSED') {
      console.error(
        `\n[ERROR] Local daemon is not reachable at 127.0.0.1:${config.server.port}.\n` +
        `Start the daemon first with:\n` +
        `  npm start\n`
      );
    } else {
      console.error(`\n[CLI ERROR] ${error.message}\n`);
    }
    return 1;
  }
}

// Start CLI if executed directly
if (process.argv[1] && process.argv[1].endsWith('cli.ts')) {
  runCli().then((exitCode) => {
    if (exitCode !== 0) process.exit(exitCode);
  });
}
