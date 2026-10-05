const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin, requireRole } = require('../middleware/auth');
const { encryptField, decryptField } = require('../utils/crypto');

const router = express.Router();

/**
 * Student "personal information" change requests.
 *
 * The Personal information card on a student's Profile tab (date of birth,
 * sex, civil status, nationality, religion) is registrar-managed: a student
 * can NOT edit it directly (PUT /api/profiles/me ignores those fields on
 * purpose). This router adds the missing path — a student files a change
 * REQUEST, and nothing on their profile changes until an admin approves it.
 *
 *   Student:  GET  /mine           own requests, newest first
 *             POST /               file a new request
 *             POST /:id/cancel     withdraw their own still-pending request
 *   Admin:    GET  /               every request
 *             POST /:id/approve    apply the changes to student_profiles
 *             POST /:id/reject     decline (reason required)
 *
 * Nothing here touches routes/profiles.js — the existing profile endpoints
 * behave exactly as before.
 */

// Whitelist of fields a request may touch. `column` comes from THIS table,
// never from client-supplied or stored keys, so a crafted request can't
// point an UPDATE at any other column.
const FIELDS = {
  dateOfBirth: { column: 'date_of_birth', label: 'Date of birth', sensitive: true },
  sex: { column: 'sex', label: 'Sex' },
  civilStatus: { column: 'civil_status', label: 'Civil status' },
  nationality: { column: 'nationality', label: 'Nationality' },
  religion: { column: 'religion', label: 'Religion' }
};
const FIELD_KEYS = Object.keys(FIELDS);

const SEX_OPTIONS = ['Male', 'Female'];
const CIVIL_STATUS_OPTIONS = ['Single', 'Married', 'Widowed', 'Separated', 'Annulled'];
const TEXT_PATTERN = /^[\p{L}\p{M}0-9 .,'()\-/]+$/u;
const MASK = '\u2022\u2022\u2022\u2022\u2022\u2022';

const MAX_REQUESTS_PER_DAY = 5;

function matchOption(value, options) {
  const v = String(value).trim().toLowerCase();
  return options.find((o) => o.toLowerCase() === v) || null;
}

/**
 * Validates + normalizes one submitted field value.
 * Returns { value } on success or { error } with a student-facing message.
 */
function normalizeField(key, raw) {
  const text = String(raw).replace(/\s+/g, ' ').trim();

  if (key === 'dateOfBirth') {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
    if (!m) return { error: 'Date of birth must be a valid date.' };
    const y = Number(m[1]); const mo = Number(m[2]); const d = Number(m[3]);
    const dt = new Date(Date.UTC(y, mo - 1, d));
    if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) {
      return { error: 'Date of birth must be a valid date.' };
    }
    if (y < 1900 || dt.getTime() > Date.now()) {
      return { error: 'Date of birth must be between 1900 and today.' };
    }
    return { value: text };
  }

  if (key === 'sex') {
    const opt = matchOption(text, SEX_OPTIONS);
    return opt ? { value: opt } : { error: 'Sex must be Male or Female.' };
  }

  if (key === 'civilStatus') {
    const opt = matchOption(text, CIVIL_STATUS_OPTIONS);
    return opt ? { value: opt } : { error: 'Civil status must be one of: ' + CIVIL_STATUS_OPTIONS.join(', ') + '.' };
  }

  // nationality / religion — short free text
  if (text.length > 80 || !TEXT_PATTERN.test(text)) {
    return { error: FIELDS[key].label + ' contains invalid characters or is too long (max 80).' };
  }
  return { value: text };
}

/** Current plaintext value of a field on a student_profiles row ('' if unset). */
function currentValue(key, profileRow) {
  const f = FIELDS[key];
  const raw = profileRow[f.column];
  if (!raw) return '';
  if (!f.sensitive) return String(raw);
  try { return decryptField(raw) || ''; } catch (err) { return ''; }
}

function readChanges(row) {
  try {
    const parsed = JSON.parse(decryptField(row.changes));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (err) {
    console.error('Could not read profile_change_requests.changes for #' + row.id + ':', err.message);
    return null;
  }
}

/**
 * view: 'student' (own data — everything visible) or 'admin'.
 * For admins the CURRENT date of birth stays masked, same as the roster
 * (routes/profiles.js): only the passkey-gated reveal endpoint ever shows
 * an admin a stored DOB. The REQUESTED value is what the student submitted,
 * and has to be visible or there would be nothing to approve.
 */
function serialize(row, view) {
  const changes = readChanges(row) || {};
  const list = FIELD_KEYS.filter((k) => changes[k]).map((k) => {
    const from = changes[k].from || '';
    return {
      field: k,
      label: FIELDS[k].label,
      from: view === 'admin' && FIELDS[k].sensitive ? (from ? MASK : '') : from,
      to: changes[k].to || ''
    };
  });
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    changes: list,
    reason: row.reason || '',
    status: row.status,
    adminNote: row.admin_note || '',
    reviewedBy: row.reviewed_by || '',
    reviewedAt: row.reviewed_at,
    createdAt: row.created_at
  };
}

function audit(db, action, req, profileId) {
  return db.query(
    `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
    [action, req.user.id, req.user.email, 'student', profileId]
  ).catch((err) => console.error('[profile_audit_log]', err.message));
}

function notifyStudent(db, email, title, message) {
  return db.query(
    `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at)
     VALUES (?, ?, 'specific', ?, 'sent', NOW())`,
    [title, message, email]
  );
}

function labelList(changes) {
  return FIELD_KEYS.filter((k) => changes[k]).map((k) => FIELDS[k].label.toLowerCase()).join(', ');
}

/* ------------------------------------------------------------------ */
/* Student                                                            */
/* ------------------------------------------------------------------ */

// GET /api/profile-change-requests/mine
router.get('/mine', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [rows] = await pool.query(
      'SELECT * FROM profile_change_requests WHERE student_email = ? ORDER BY id DESC LIMIT 50',
      [email]
    );
    return res.json({ requests: rows.map((r) => serialize(r, 'student')) });
  } catch (err) {
    console.error('GET /api/profile-change-requests/mine failed:', err);
    return res.status(500).json({ message: 'Could not load your change requests.' });
  }
});

// POST /api/profile-change-requests
router.post('/', requireAuth, requireRole('student'), async (req, res) => {
  const email = String(req.user.email || '').trim().toLowerCase();
  const b = req.body || {};

  // Reason is required so the reviewing admin knows why.
  const reason = String(b.reason || '').replace(/\s+/g, ' ').trim();
  if (reason.length < 5) return res.status(400).json({ message: 'Please give a short reason for the change (at least 5 characters).' });
  if (reason.length > 500) return res.status(400).json({ message: 'Reason is too long (max 500 characters).' });

  // Validate everything sent before touching the DB.
  const submitted = {};
  for (const key of FIELD_KEYS) {
    if (b[key] === undefined || b[key] === null || String(b[key]).trim() === '') continue;
    if (typeof b[key] !== 'string') return res.status(400).json({ message: FIELDS[key].label + ' is invalid.' });
    const result = normalizeField(key, b[key]);
    if (result.error) return res.status(400).json({ message: result.error });
    submitted[key] = result.value;
  }
  if (!Object.keys(submitted).length) {
    return res.status(400).json({ message: 'Enter the new value for at least one field.' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Lock the student's profile row so two simultaneous submissions can't
    // both slip past the "one pending request" check below.
    const [profiles] = await conn.query(
      'SELECT * FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1 FOR UPDATE',
      [email]
    );
    if (!profiles.length) {
      await conn.rollback();
      return res.status(404).json({ message: 'Your profile record isn\u2019t set up yet \u2014 ask the registrar/admin to add you to the roster first.' });
    }
    const profile = profiles[0];

    const [pending] = await conn.query(
      `SELECT id FROM profile_change_requests WHERE profile_id = ? AND status = 'pending' LIMIT 1`,
      [profile.id]
    );
    if (pending.length) {
      await conn.rollback();
      return res.status(409).json({ message: 'You already have a request waiting for review. Wait for the decision, or cancel it first.' });
    }

    const [recent] = await conn.query(
      `SELECT COUNT(*) AS n FROM profile_change_requests WHERE profile_id = ? AND created_at > (NOW() - INTERVAL 1 DAY)`,
      [profile.id]
    );
    if (recent[0].n >= MAX_REQUESTS_PER_DAY) {
      await conn.rollback();
      return res.status(429).json({ message: 'You have sent too many requests today. Please try again tomorrow.' });
    }

    // Keep only fields that actually differ from what's on file.
    const changes = {};
    for (const key of Object.keys(submitted)) {
      const from = currentValue(key, profile);
      if (from !== submitted[key]) changes[key] = { from, to: submitted[key] };
    }
    if (!Object.keys(changes).length) {
      await conn.rollback();
      return res.status(400).json({ message: 'Nothing to change \u2014 those values are already on your profile.' });
    }

    // The whole payload is encrypted at rest (it can hold a date of birth),
    // the same AES-256-GCM scheme used for the profile columns themselves.
    const [result] = await conn.query(
      `INSERT INTO profile_change_requests (profile_id, student_email, student_name, changes, reason)
       VALUES (?,?,?,?,?)`,
      [profile.id, email, profile.name, encryptField(JSON.stringify(changes)), reason]
    );
    await audit(conn, 'PROFILE_CHANGE_REQUESTED', req, profile.id);
    await conn.commit();

    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [result.insertId]);
    return res.status(201).json({ request: serialize(rows[0], 'student') });
  } catch (err) {
    try { await conn.rollback(); } catch (e) { /* connection already gone */ }
    console.error('POST /api/profile-change-requests failed:', err);
    return res.status(500).json({ message: 'Could not submit your request.' });
  } finally {
    conn.release();
  }
});

// POST /api/profile-change-requests/:id/cancel
router.post('/:id/cancel', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid request id.' });
    const email = String(req.user.email || '').trim().toLowerCase();

    // Scoped by the JWT email, and only while still pending.
    const [result] = await pool.query(
      `UPDATE profile_change_requests SET status = 'cancelled', reviewed_at = NOW()
       WHERE id = ? AND student_email = ? AND status = 'pending'`,
      [id, email]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ message: 'That request can\u2019t be cancelled \u2014 it may already have been reviewed.' });
    }
    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    await audit(pool, 'PROFILE_CHANGE_CANCELLED', req, rows[0].profile_id);
    return res.json({ request: serialize(rows[0], 'student') });
  } catch (err) {
    console.error('POST /api/profile-change-requests/:id/cancel failed:', err);
    return res.status(500).json({ message: 'Could not cancel the request.' });
  }
});

/* ------------------------------------------------------------------ */
/* Admin                                                              */
/* ------------------------------------------------------------------ */

// GET /api/profile-change-requests
router.get('/', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM profile_change_requests ORDER BY id DESC LIMIT 500');
    return res.json({ requests: rows.map((r) => serialize(r, 'admin')) });
  } catch (err) {
    console.error('GET /api/profile-change-requests failed:', err);
    return res.status(500).json({ message: 'Could not load change requests.' });
  }
});

/**
 * Shared approve/reject flow: lock the request row, make sure it is still
 * pending (so two admins can't both act on it), do the work, notify the
 * student and write the audit entry — all in one transaction.
 */
async function review(req, res, decision) {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid request id.' });

  const note = String((req.body && req.body.note) || '').replace(/\s+/g, ' ').trim().slice(0, 500);
  if (decision === 'rejected' && !note) {
    return res.status(400).json({ message: 'A reason is required so the student knows why.' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [found] = await conn.query('SELECT * FROM profile_change_requests WHERE id = ? FOR UPDATE', [id]);
    if (!found.length) {
      await conn.rollback();
      return res.status(404).json({ message: 'Change request not found.' });
    }
    const row = found[0];
    if (row.status !== 'pending') {
      await conn.rollback();
      return res.status(409).json({ message: 'That request has already been ' + row.status + '.' });
    }
    const changes = readChanges(row);
    if (!changes) {
      await conn.rollback();
      return res.status(500).json({ message: 'Could not read that request.' });
    }

    if (decision === 'approved') {
      const [profiles] = await conn.query('SELECT id FROM student_profiles WHERE id = ? FOR UPDATE', [row.profile_id]);
      if (!profiles.length) {
        await conn.rollback();
        return res.status(409).json({ message: 'This student\u2019s profile no longer exists.' });
      }

      const sets = [];
      const values = [];
      for (const key of FIELD_KEYS) {
        if (!changes[key]) continue;
        // Re-validate what's about to be written, even though it was
        // validated at submit time.
        const result = normalizeField(key, changes[key].to);
        if (result.error) {
          await conn.rollback();
          return res.status(500).json({ message: 'That request contains an invalid value.' });
        }
        sets.push(FIELDS[key].column + ' = ?');
        values.push(FIELDS[key].sensitive ? encryptField(result.value) : result.value);
      }
      if (!sets.length) {
        await conn.rollback();
        return res.status(500).json({ message: 'That request has nothing to apply.' });
      }
      await conn.query('UPDATE student_profiles SET ' + sets.join(', ') + ' WHERE id = ?', values.concat([row.profile_id]));
    }

    await conn.query(
      `UPDATE profile_change_requests
       SET status = ?, admin_note = ?, reviewed_by = ?, reviewed_at = NOW()
       WHERE id = ?`,
      [decision, note || null, req.user.email, id]
    );

    // Notification text names the fields only — never the values — since
    // notifications are not encrypted.
    const what = labelList(changes);
    if (decision === 'approved') {
      await notifyStudent(conn, row.student_email, 'Profile change approved',
        'Your request to update your ' + what + ' was approved. Your profile now shows the updated details.' +
        (note ? ' Note from the admin office: ' + note : ''));
    } else {
      await notifyStudent(conn, row.student_email, 'Profile change not approved',
        'Your request to update your ' + what + ' was not approved. Reason: ' + note);
    }
    await audit(conn, decision === 'approved' ? 'PROFILE_CHANGE_APPROVED' : 'PROFILE_CHANGE_REJECTED', req, row.profile_id);

    await conn.commit();

    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    return res.json({ request: serialize(rows[0], 'admin') });
  } catch (err) {
    try { await conn.rollback(); } catch (e) { /* connection already gone */ }
    console.error('POST /api/profile-change-requests/:id/' + decision + ' failed:', err);
    return res.status(500).json({ message: 'Could not save that decision.' });
  } finally {
    conn.release();
  }
}

router.post('/:id/approve', requireAuth, requireAdmin, (req, res) => review(req, res, 'approved'));
router.post('/:id/reject', requireAuth, requireAdmin, (req, res) => review(req, res, 'rejected'));

module.exports = router;
