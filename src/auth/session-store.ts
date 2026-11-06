import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { SessionData } from '../types.ts';
import { RedactingLogger } from '../logger.ts';
import {
  isWindowsDPAPIAvailable,
  protectSecretWithDPAPI,
  unprotectSecretWithDPAPI,
  getMachineUserBoundSalt,
} from './os-vault.ts';

/**
 * Validates the structure and field types of session data before importing or persisting.
 */
export function isValidSessionData(data: unknown): data is SessionData {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return false;
  }
  const s = data as Record<string, unknown>;
  if (typeof s.token !== 'string' || !s.token.trim()) {
    return false;
  }
  if (typeof s.createdAt !== 'number' || isNaN(s.createdAt) || s.createdAt <= 0) {
    return false;
  }
  if (typeof s.expiresAt !== 'number' || isNaN(s.expiresAt) || s.expiresAt <= 0) {
    return false;
  }
  return true;
}

/**
 * Computes the canonical, per-user persistent encrypted session storage path.
 * Supports multiple independent user profiles via optional profileName parameter or ENBANK_PROFILE env.
 */
export function getDefaultSessionFilePath(profileName?: string): string {
  const effectiveProfile = (profileName || process.env.ENBANK_PROFILE || '').trim();
  const filename = effectiveProfile && effectiveProfile !== 'default'
    ? `session.${effectiveProfile.replace(/[^a-zA-Z0-9_-]/g, '_')}.enc`
    : 'session.enc';

  if (process.env.ENBANK_SESSION_FILE && process.env.ENBANK_SESSION_FILE.trim().length > 0) {
    if (effectiveProfile && effectiveProfile !== 'default') {
      const baseDir = path.dirname(path.resolve(process.env.ENBANK_SESSION_FILE.trim()));
      return path.join(baseDir, filename);
    }
    return path.resolve(process.env.ENBANK_SESSION_FILE.trim());
  }

  // Windows per-user local app data
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'EghtesadNovin', filename);
  }

  // POSIX (Linux / macOS)
  const base = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(base, 'eghtesadnovin', filename);
}

export class SessionStore {
  private activeSession: SessionData | null = null;
  private savedDeviceToken?: string;
  private logger = new RedactingLogger('SessionStore');
  private vaultKey: string;
  private persistenceFilePath: string | null = null;
  private profileName: string = 'default';

  constructor(vaultKey: string, persistenceFilePath?: string | null, profileName?: string) {
    if (!vaultKey || vaultKey.length < 16) {
      throw new Error('SessionStore requires a secure vault key of at least 16 characters.');
    }
    this.vaultKey = vaultKey;
    if (profileName && profileName.trim().length > 0) {
      this.profileName = profileName.trim();
    }

    if (persistenceFilePath !== undefined) {
      this.persistenceFilePath = persistenceFilePath;
    } else if (process.env.NODE_ENV !== 'test' && process.env.npm_lifecycle_event !== 'test') {
      this.persistenceFilePath = getDefaultSessionFilePath(this.profileName);
    }
  }

  /**
   * Returns the current profile name for this session store.
   */
  getProfileName(): string {
    return this.profileName;
  }

  /**
   * Retrieves the configured or saved device registration token (mobileUserToken).
   */
  getDeviceToken(): string | undefined {
    return this.savedDeviceToken || this.activeSession?.deviceToken;
  }

  /**
   * Stores and preserves the device registration token across sessions.
   */
  setDeviceToken(token?: string): void {
    this.savedDeviceToken = token?.trim();
    if (this.activeSession) {
      this.activeSession.deviceToken = this.savedDeviceToken;
      this.persist();
    }
  }

  /**
   * Sets the active in-memory session and persists encrypted payload if configured.
   */
  setSession(session: SessionData): void {
    const deviceToken = session.deviceToken || this.savedDeviceToken;
    this.activeSession = { ...session, deviceToken };
    if (deviceToken) {
      this.savedDeviceToken = deviceToken;
    }
    this.logger.info('Active session stored in memory', {
      createdAt: session.createdAt,
      expiresAt: session.expiresAt,
    });
    this.persist();
  }

  /**
   * Retrieves the active in-memory session.
   */
  getSession(): SessionData | null {
    if (!this.activeSession) {
      return null;
    }
    return { ...this.activeSession };
  }

  /**
   * Updates the last activity timestamp and refreshes persisted storage.
   */
  touchActivity(newExpiresAt?: number): void {
    if (this.activeSession) {
      this.activeSession.lastActivityAt = Date.now();
      if (newExpiresAt) {
        this.activeSession.expiresAt = newExpiresAt;
      }
      this.persist();
    }
  }

  /**
   * Invalidate and clear the active session from memory and persistent disk.
   */
  clear(): void {
    this.activeSession = null;
    this.deletePersisted();
    this.logger.info('Active session cleared');
  }

  /**
   * Persists the active session encrypted to disk atomically.
   */
  persist(): void {
    if (!this.persistenceFilePath) return;

    const encrypted = this.exportEncrypted();
    if (!encrypted) {
      this.deletePersisted();
      return;
    }

    let tmpFile: string | null = null;
    try {
      const dir = path.dirname(this.persistenceFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      tmpFile = `${this.persistenceFilePath}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tmpFile, encrypted, { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmpFile, this.persistenceFilePath);
      tmpFile = null;
      this.logger.info('Encrypted session successfully persisted to storage');
    } catch (err) {
      if (tmpFile && fs.existsSync(tmpFile)) {
        try {
          fs.unlinkSync(tmpFile);
        } catch {
          // Ignore secondary cleanup error
        }
      }
      this.logger.error('Failed to persist encrypted session', err);
    }
  }

  /**
   * Loads and decrypts the persisted session from disk.
   */
  loadPersisted(): boolean {
    if (!this.persistenceFilePath || !fs.existsSync(this.persistenceFilePath)) {
      return false;
    }

    try {
      const data = fs.readFileSync(this.persistenceFilePath, 'utf8');
      if (!data || data.trim().length === 0) {
        return false;
      }
      this.importEncrypted(data);
      this.logger.info('Persisted session successfully restored and decrypted');
      return true;
    } catch (err) {
      this.logger.warn('Failed to restore persisted session (corrupted or invalid key); resetting file', err);
      this.deletePersisted();
      return false;
    }
  }

  /**
   * Deletes the persisted session file.
   */
  deletePersisted(): void {
    if (!this.persistenceFilePath) return;
    try {
      if (fs.existsSync(this.persistenceFilePath)) {
        fs.unlinkSync(this.persistenceFilePath);
        this.logger.info('Persisted encrypted session file removed');
      }
    } catch (err) {
      this.logger.error('Failed to delete persisted session file', err);
    }
  }

  /**
   * Derives a machine-and-user-bound AES-256 key from the configured vault secret.
   */
  deriveVaultKey(): Buffer {
    const salt = getMachineUserBoundSalt();
    return crypto.pbkdf2Sync(this.vaultKey, salt, 10000, 32, 'sha256');
  }

  /**
   * Encrypts arbitrary secret text (e.g. password) with AES-256-GCM using the vault key
   * or Windows DPAPI when running on Windows.
   */
  encryptSecret(secret: string): { ciphertext: string; iv: string; tag: string } {
    if (isWindowsDPAPIAvailable()) {
      try {
        const dpapiB64 = protectSecretWithDPAPI(secret);
        return {
          ciphertext: dpapiB64,
          iv: 'dpapi',
          tag: 'dpapi',
        };
      } catch (err) {
        this.logger.warn('Windows DPAPI protection fallback to user-bound AES-256-GCM', err);
      }
    }

    const iv = crypto.randomBytes(12);
    const key = this.deriveVaultKey();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
      ciphertext: encrypted,
      iv: iv.toString('hex'),
      tag: authTag,
    };
  }

  /**
   * Decrypts ciphertext with AES-256-GCM or Windows DPAPI.
   */
  decryptSecret(encrypted: { ciphertext: string; iv: string; tag: string }): string {
    if (encrypted.iv === 'dpapi') {
      return unprotectSecretWithDPAPI(encrypted.ciphertext);
    }
    const iv = Buffer.from(encrypted.iv, 'hex');
    const tag = Buffer.from(encrypted.tag, 'hex');
    const key = this.deriveVaultKey();
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  /**
   * Returns whether a persistent encrypted session file currently exists on disk.
   */
  hasPersisted(): boolean {
    return Boolean(this.persistenceFilePath && fs.existsSync(this.persistenceFilePath));
  }

  /**
   * Returns the configured persistence file path.
   */
  getPersistencePath(): string | null {
    return this.persistenceFilePath;
  }

  /**
   * Encrypts the active session data into an AES-256-GCM ciphertext payload.
   */
  exportEncrypted(): string | null {
    if (!this.activeSession) {
      return null;
    }
    const iv = crypto.randomBytes(12);
    const key = this.deriveVaultKey();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const plaintext = JSON.stringify(this.activeSession);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return JSON.stringify({
      iv: iv.toString('hex'),
      tag: authTag,
      ciphertext: encrypted,
    });
  }

  /**
   * Decrypts and restores an encrypted session payload.
   */
  importEncrypted(encryptedPayload: string): void {
    try {
      const parsed = JSON.parse(encryptedPayload);
      if (!parsed || typeof parsed !== 'object' || !parsed.iv || !parsed.tag || !parsed.ciphertext) {
        throw new Error('Encrypted payload missing mandatory cryptographic fields (iv, tag, ciphertext).');
      }
      const iv = Buffer.from(parsed.iv, 'hex');
      const tag = Buffer.from(parsed.tag, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.deriveVaultKey(), iv);
      decipher.setAuthTag(tag);

      let decrypted = decipher.update(parsed.ciphertext, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      const session: unknown = JSON.parse(decrypted);
      if (!isValidSessionData(session)) {
        throw new Error('Decrypted session data is corrupted or does not conform to required session schema.');
      }
      this.setSession(session);
    } catch (err) {
      this.logger.error('Failed to decrypt session payload', err);
      throw new Error('Session decryption failed: invalid vault key or corrupted payload.');
    }
  }
}
