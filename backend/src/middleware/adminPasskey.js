const bcrypt = require('bcryptjs');

/**
 * requireAdminPasskey
 * Second factor required (on top of requireAuth + requireAdmin) before an
 * admin can view decrypted sensitive fields (student DOB / address /
 * mobile / guardian contact). Must be mounted AFTER requireAuth and
 * requireAdmin so req.user is already populated and verified.
 *
 * The passkey itself is never stored in plaintext — only its bcrypt hash
 * lives in ADMIN_PASSKEY_HASH (backend/.env). This is intentionally
 * separate from the admin's login password: a stolen/leaked login
 * session alone is not enough to reveal sensitive PII.
 *
 * Every call — success or failure — is logged by the caller via
 * utils/auditLog.js; this middleware only decides pass/fail so the
 * route handler can log a single consistent audit entry either way.
 */
async function requireAdminPasskey(req, res, next) {
  const hash = process.env.ADMIN_PASSKEY_HASH;
  if (!hash) {
    console.error('[adminPasskey] ADMIN_PASSKEY_HASH is not configured — refusing all reveal requests.');
    return res.status(503).json({ message: 'Sensitive data recovery is not configured on this server.' });
  }

  const passkey = String((req.body && req.body.passkey) || '');
  if (!passkey) {
    req.passkeyValid = false;
    return res.status(400).json({ message: 'Administrator passkey is required.' });
  }

  try {
    const ok = await bcrypt.compare(passkey, hash);
    req.passkeyValid = ok;
    if (!ok) {
      return res.status(401).json({ message: 'Invalid administrator passkey.' });
    }
    return next();
  } catch (err) {
    console.error('[adminPasskey] Passkey verification failed:', err.message);
    req.passkeyValid = false;
    return res.status(500).json({ message: 'Could not verify administrator passkey.' });
  }
}

module.exports = { requireAdminPasskey };
