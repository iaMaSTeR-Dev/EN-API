import cp from 'node:child_process';
import os from 'node:os';
import crypto from 'node:crypto';
import { RedactingLogger } from '../logger.ts';

const logger = new RedactingLogger('OSVault');

/**
 * Derives a machine-unique and user-account-bound salt to ensure the master key
 * is tied to the current OS user and cannot be decrypted if copied to another machine or account.
 */
export function getMachineUserBoundSalt(): Buffer {
  let userIdentifier: string;
  try {
    userIdentifier = `${os.userInfo().username}:${os.homedir()}:${os.hostname()}`;
  } catch {
    userIdentifier = `${os.homedir()}:${os.hostname()}`;
  }
  return crypto.createHash('sha256').update(userIdentifier).digest();
}

/**
 * Checks whether Windows Data Protection API (DPAPI) is available on the current host.
 */
export function isWindowsDPAPIAvailable(): boolean {
  return process.platform === 'win32' && process.env.NODE_ENV !== 'test' && process.env.npm_lifecycle_event !== 'test';
}

/**
 * Encrypts a secret string using Windows DPAPI (System.Security.Cryptography.ProtectedData)
 * bound to the CurrentUser scope.
 * Transmits plaintext via standard input (stdin) so it never appears in command-line arguments.
 */
export function protectSecretWithDPAPI(plaintext: string): string {
  if (process.platform !== 'win32') {
    throw new Error('DPAPI is only available on Windows platforms.');
  }

  const script = `
    Add-Type -AssemblyName System.Security
    $raw = [Console]::In.ReadToEnd()
    $b = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $e = [System.Security.Cryptography.ProtectedData]::Protect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.Convert]::ToBase64String($e)
  `;

  try {
    const output = cp.execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', `& { ${script} }`],
      { input: plaintext, encoding: 'utf8', timeout: 5000 }
    );
    return output.trim();
  } catch (err) {
    logger.error('Failed to protect secret with Windows DPAPI', err);
    throw new Error('Windows DPAPI protection failed.');
  }
}

/**
 * Decrypts a DPAPI-protected base64 string using Windows DPAPI bound to CurrentUser scope.
 * Transmits ciphertext via standard input (stdin) to prevent argument exposure.
 */
export function unprotectSecretWithDPAPI(ciphertextB64: string): string {
  if (process.platform !== 'win32') {
    throw new Error('DPAPI is only available on Windows platforms.');
  }

  const script = `
    Add-Type -AssemblyName System.Security
    $raw = [Console]::In.ReadToEnd().Trim()
    $e = [System.Convert]::FromBase64String($raw)
    $d = [System.Security.Cryptography.ProtectedData]::Unprotect($e, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.Text.Encoding]::UTF8.GetString($d)
  `;

  try {
    const output = cp.execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', `& { ${script} }`],
      { input: ciphertextB64, encoding: 'utf8', timeout: 5000 }
    );
    return output.trim();
  } catch (err) {
    logger.error('Failed to unprotect secret with Windows DPAPI', err);
    throw new Error('Windows DPAPI decryption failed: data cannot be decrypted by this user account.');
  }
}

