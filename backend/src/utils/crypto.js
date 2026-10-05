const crypto = require('crypto');

/**
 * AES-256-GCM encryption for RECOVERABLE sensitive fields only
 * (student date of birth / address / mobile / guardian contact).
 *
 * NEVER use this for passwords — passwords stay one-way hashed with
 * bcrypt (see routes/auth.js, routes/admin.js). This module exists so a
 * small set of legitimately-recoverable PII fields can be stored
 * encrypted at rest instead of as plaintext, with decryption gated
 * behind admin auth + a separate passkey (see middleware/adminPasskey.js)
 * and every attempt written to the audit log (see utils/auditLog.js).
 *
 * Payload format stored in the DB column (plain string, fits existing
 * VARCHAR columns): `v1:<ivBase64>:<authTagBase64>:<ciphertextBase64>`
 *   - v1            — format version, so a future algorithm change can
 *                     be detected and handled explicitly instead of
 *                     silently mis-decrypting old rows.
 *   - iv            — random 12-byte nonce, unique per encryption call.
 *   - authTag       — GCM's 16-byte integrity tag; decryption fails
 *                     loudly (safely) if ciphertext or tag were altered.
 *   - ciphertext    — the encrypted value.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // recommended nonce size for GCM
const VERSION = 'v1';

let cachedKey = null;

function getKey() {
  if (cachedKey) return cachedKey;

  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      'ENCRYPTION_KEY is not set. Generate one with: ' +
      `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" ` +
      'and add it to backend/.env — never commit it or expose it to the frontend.'
    );
  }

  const key = Buffer.from(raw, 'hex');
  if (key.length !== 32) {
    throw new Error(
      'ENCRYPTION_KEY must decode to exactly 32 bytes (a 64-character hex string) for AES-256.'
    );
  }

  cachedKey = key;
  return cachedKey;
}

/**
 * Encrypts a plaintext string. Returns null for null/undefined/empty
 * input (so optional fields stay NULL in the DB instead of becoming an
 * encrypted empty string). Never throws on empty input.
 */
function encryptField(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') {
    return null;
  }

  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return [
    VERSION,
    iv.toString('base64'),
    authTag.toString('base64'),
    ciphertext.toString('base64')
  ].join(':');
}

/**
 * Returns true if the given DB value looks like a payload this module
 * produced (used by migrations to avoid double-encrypting, and by
 * decryptField to tell "already plaintext / legacy row" apart from
 * "encrypted" without throwing).
 */
function isEncryptedPayload(value) {
  return typeof value === 'string' && value.startsWith(VERSION + ':');
}

/**
 * Decrypts a payload produced by encryptField. Returns null for
 * null/undefined/empty input. Throws a generic Error (never leaking
 * cipher internals) if the payload is malformed, the key is wrong, or
 * the auth tag doesn't match (tampered/corrupted ciphertext) — callers
 * must catch this and respond with a generic message, never forwarding
 * err.message to the frontend.
 */
function decryptField(payload) {
  if (payload === null || payload === undefined || payload === '') {
    return null;
  }

  if (!isEncryptedPayload(payload)) {
    // Legacy/plaintext row that hasn't been migrated yet, or a caller
    // error. Treat as a hard failure rather than silently returning the
    // raw (unencrypted) value — callers decide how to handle this.
    throw new Error('Value is not a recognized encrypted payload.');
  }

  const parts = payload.split(':');
  if (parts.length !== 4) {
    throw new Error('Malformed encrypted payload.');
  }
  const [, ivB64, tagB64, dataB64] = parts;

  try {
    const key = getKey();
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const ciphertext = Buffer.from(dataB64, 'base64');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch (err) {
    // Wrong key, corrupted ciphertext, or tampered auth tag all land
    // here. Never rethrow err directly to an HTTP response.
    throw new Error('Could not decrypt value.');
  }
}

module.exports = { encryptField, decryptField, isEncryptedPayload };
