const pool = require('../db');

/**
 * Records one sensitive-data access attempt (student PII decryption).
 * NEVER pass the actual field values (plaintext or encrypted) into this
 * — only metadata about the attempt. Failures to write the audit log
 * itself are logged to the console but never block or fail the request,
 * since availability of the underlying feature shouldn't hinge on the
 * audit table.
 *
 * @param {object} entry
 * @param {number} entry.adminId
 * @param {string} entry.adminEmail
 * @param {string} entry.targetType   e.g. 'student_profile'
 * @param {number} entry.targetId
 * @param {string} entry.fieldsRequested  comma-separated field names, e.g. 'address,mobile'
 * @param {boolean} entry.success
 * @param {string} [entry.reason]  short machine-readable reason on failure, e.g. 'invalid_passkey'
 * @param {string} [entry.ip]
 */
async function logSensitiveAccess(entry) {
  try {
    await pool.query(
      `INSERT INTO sensitive_data_access_log
        (admin_id, admin_email, target_type, target_id, fields_requested, success, reason, ip_address)
       VALUES (?,?,?,?,?,?,?,?)`,
      [
        entry.adminId || null,
        entry.adminEmail || null,
        entry.targetType || null,
        entry.targetId || null,
        entry.fieldsRequested || null,
        entry.success ? 1 : 0,
        entry.reason || null,
        entry.ip || null
      ]
    );
  } catch (err) {
    console.error('[auditLog] Could not write sensitive_data_access_log entry:', err.message);
  }
}

module.exports = { logSensitiveAccess };
