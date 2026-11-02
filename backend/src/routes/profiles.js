const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin, requireRole } = require('../middleware/auth');
const { requireAdminPasskey } = require('../middleware/adminPasskey');
const { sensitiveDataLimiter } = require('../middleware/rateLimiters');
const { logSensitiveAccess } = require('../utils/auditLog');
const { encryptField, decryptField } = require('../utils/crypto');
const { upload, saveValidatedImage, deleteStoredImage } = require('../utils/secureUpload');

function logProfileAudit(action, req, targetId) {
  return pool.query(
    `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
    [action, req.user.id, req.user.email, 'student', targetId]
  ).catch((err) => console.error('[profile_audit_log]', err.message));
}

const router = express.Router();

// Fields stored AES-256-GCM encrypted at rest (see utils/crypto.js).
// Passwords are never in this list — they stay one-way hashed with
// bcrypt (routes/auth.js, routes/admin.js) and are never decryptable.
const SENSITIVE_FIELDS = ['date_of_birth', 'address', 'mobile', 'guardian_contact'];
const SENSITIVE_MASK = '••••••';

/**
 * serialize(row, { reveal })
 * reveal=false (default): used for admin bulk/list views. Sensitive
 * fields are masked, never decrypted, so browsing the roster never pulls
 * PII into memory or the response body.
 * reveal=true: used only for (a) a student viewing their own /me record,
 * and (b) the passkey-gated /:id/reveal-sensitive endpoint below.
 */
function serialize(row, { reveal = false } = {}) {
  const sensitive = {};
  for (const col of SENSITIVE_FIELDS) {
    const camel = col.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    if (!reveal) {
      sensitive[camel] = row[col] ? SENSITIVE_MASK : '';
      continue;
    }
    try {
      sensitive[camel] = decryptField(row[col]) || '';
    } catch (err) {
      // Corrupted ciphertext / wrong key — fail closed on that one field
      // rather than leaking a crypto error or blank-but-wrong value.
      console.error(`Could not decrypt ${col} for profile ${row.id}:`, err.message);
      sensitive[camel] = null;
    }
  }

  return {
    id: String(row.id),
    name: row.name,
    email: row.email,
    studentId: row.student_id || '',
    program: row.program || '',
    yearLevel: row.year_level || '',
    section: row.section || '',
    status: row.status,
    dateOfBirth: sensitive.dateOfBirth,
    sex: row.sex || '',
    civilStatus: row.civil_status || '',
    nationality: row.nationality || '',
    religion: row.religion || '',
    address: sensitive.address,
    mobile: sensitive.mobile,
    guardianName: row.guardian_name || '',
    guardianContact: sensitive.guardianContact,
    adviser: row.adviser || '',
    dateAdmitted: row.date_admitted || '',
    profilePicture: row.profile_picture ? `/uploads/profile-pictures/${row.profile_picture}` : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

/**
 * GET /api/profiles/me
 * The signed-in student's own profile record — read-only self-service.
 * Placed above the blanket `requireAdmin` gate below and scoped with its
 * own requireRole('student') instead, since a student may only ever see
 * their own record (identity comes from the verified JWT, never a
 * client-supplied id/email) and every other route on this router is
 * admin-only roster management.
 *
 * Falls back to the bare account details (name/email/Student ID/program,
 * with section and year level blank) when this student doesn't have an
 * admin-maintained student_profiles row yet — e.g. a freshly-approved
 * signup an admin hasn't assigned a section to. Used by
 * student-dashboard.html's Profile tab.
 */
router.get('/me', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [rows] = await pool.query(
      'SELECT * FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1',
      [email]
    );
    if (rows.length) {
      // A student viewing their own record always sees it in full —
      // the passkey gate exists for an ADMIN viewing someone else's PII,
      // not for people viewing their own.
      return res.json({ profile: serialize(rows[0], { reveal: true }) });
    }

    const [userRows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const u = userRows[0];
    return res.json({
      profile: {
        id: '',
        name: u ? u.name : (req.user.name || ''),
        email: u ? u.email : email,
        studentId: u ? (u.student_id || '') : '',
        program: u ? (u.detail || '') : '',
        yearLevel: '',
        section: '',
        status: 'Regular',
        dateOfBirth: '', sex: '', civilStatus: '', nationality: '', religion: '',
        address: '', mobile: '', guardianName: '', guardianContact: '', adviser: '', dateAdmitted: '',
        profilePicture: null,
        createdAt: u ? u.created_at : null,
        updatedAt: null
      }
    });
  } catch (err) {
    console.error('GET /api/profiles/me failed:', err);
    return res.status(500).json({ message: 'Could not load your profile.' });
  }
});

/**
 * PUT /api/profiles/me
 * The signed-in student's own SELF-SERVICE edit — deliberately a narrow
 * whitelist. A student may update only their own contact details:
 * address, mobile number, guardian name, guardian contact number.
 *
 * Everything else a student might send in the request body is silently
 * ignored server-side, INCLUDING studentId, program, yearLevel, section,
 * status, dateOfBirth, sex, civilStatus, nationality, religion, adviser,
 * dateAdmitted, and profilePicture — this is enforced here, not by
 * hiding fields in the UI, so a hand-crafted request can't change them
 * either. Only an admin (PUT /api/profiles/:id below) may change those.
 *
 * Identity is taken from the verified JWT (req.user.email), never from
 * any id/email the client could put in the request body or URL — a
 * student can only ever update the row that already matches their own
 * account email.
 */
router.put('/me', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [existing] = await pool.query(
      'SELECT * FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1',
      [email]
    );
    if (!existing.length) {
      return res.status(404).json({ message: 'Your profile record isn\u2019t set up yet \u2014 ask the registrar/admin to add you to the roster first.' });
    }
    const cur = existing[0];
    const b = req.body || {};

    // Whitelist only — anything else in b is ignored, not just unused.
    const address = b.address !== undefined ? String(b.address).trim().slice(0, 250) : null;
    const mobile = b.mobile !== undefined ? String(b.mobile).trim().slice(0, 40) : null;
    const guardianName = b.guardianName !== undefined ? String(b.guardianName).trim().slice(0, 150) : undefined;
    const guardianContact = b.guardianContact !== undefined ? String(b.guardianContact).trim().slice(0, 40) : null;

    // Basic sanity validation on the two contact-number-shaped fields —
    // reject obviously-invalid input rather than silently storing junk.
    const PHONE_PATTERN = /^[0-9+()\-.\s]{7,20}$/;
    if (b.mobile !== undefined && mobile && !PHONE_PATTERN.test(mobile)) {
      return res.status(400).json({ message: 'Mobile number looks invalid.' });
    }
    if (b.guardianContact !== undefined && guardianContact && !PHONE_PATTERN.test(guardianContact)) {
      return res.status(400).json({ message: 'Guardian contact number looks invalid.' });
    }

    await pool.query(
      `UPDATE student_profiles SET
        address = ?, mobile = ?, guardian_name = ?, guardian_contact = ?
       WHERE id = ?`,
      [
        b.address !== undefined ? encryptField(address) : cur.address,
        b.mobile !== undefined ? encryptField(mobile) : cur.mobile,
        guardianName !== undefined ? guardianName : cur.guardian_name,
        b.guardianContact !== undefined ? encryptField(guardianContact) : cur.guardian_contact,
        cur.id
      ]
    );

    const [rows] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [cur.id]);
    return res.json({ profile: serialize(rows[0], { reveal: true }) });
  } catch (err) {
    console.error('PUT /api/profiles/me failed:', err);
    return res.status(500).json({ message: 'Could not update your profile.' });
  }
});


/* =========================================================================
   Personal-information change requests (student -> admin approval)

   A student may NOT edit date of birth / sex / civil status / nationality /
   religion directly (PUT /me above ignores them). Instead they submit a
   request here; it sits as 'pending' and changes nothing until an admin
   approves it (admin routes further below). Identity always comes from the
   verified JWT, never from the request body.
   ========================================================================= */
const SEX_VALUES = ['Male', 'Female'];
const CIVIL_VALUES = ['Single', 'Married', 'Widowed', 'Separated'];
const CHANGE_LABELS = {
  dateOfBirth: 'Date of birth', sex: 'Sex', civilStatus: 'Civil status',
  nationality: 'Nationality', religion: 'Religion'
};
// request key -> student_profiles column
const CHANGE_COLUMNS = {
  dateOfBirth: 'date_of_birth', sex: 'sex', civilStatus: 'civil_status',
  nationality: 'nationality', religion: 'religion'
};

function cleanText(v, max) {
  // Trim, collapse whitespace, drop control characters and angle brackets.
  return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** Returns { value } or { error } for one requested field. */
function validateChange(key, raw) {
  const v = cleanText(raw, 80);
  if (!v) return { error: CHANGE_LABELS[key] + ' can\u2019t be blank.' };
  if (key === 'sex') {
    const hit = SEX_VALUES.find((x) => x.toLowerCase() === v.toLowerCase());
    return hit ? { value: hit } : { error: 'Sex must be Male or Female.' };
  }
  if (key === 'civilStatus') {
    const hit = CIVIL_VALUES.find((x) => x.toLowerCase() === v.toLowerCase());
    return hit ? { value: hit } : { error: 'Civil status must be one of: ' + CIVIL_VALUES.join(', ') + '.' };
  }
  if (key === 'dateOfBirth') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return { error: 'Date of birth must be a valid date.' };
    const d = new Date(v + 'T00:00:00Z');
    if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) return { error: 'Date of birth must be a valid date.' };
    if (d.getTime() > Date.now()) return { error: 'Date of birth can\u2019t be in the future.' };
    if (Number(v.slice(0, 4)) < 1900) return { error: 'Date of birth looks invalid.' };
    return { value: v };
  }
  return { value: v }; // nationality / religion: free text, already cleaned
}

function safeParseJson(text) {
  try { const o = JSON.parse(text); return o && typeof o === 'object' ? o : {}; } catch (e) { return {}; }
}

/** Decrypts the stored DOB (if any) so the requester / reviewing admin can read it. */
function readChanges(row) {
  const raw = safeParseJson(row.changes);
  const out = {};
  for (const key of Object.keys(CHANGE_LABELS)) {
    if (raw[key] === undefined) continue;
    if (key === 'dateOfBirth') {
      try { out[key] = decryptField(raw[key]) || ''; } catch (e) { out[key] = ''; }
    } else {
      out[key] = raw[key];
    }
  }
  return out;
}

function serializeRequest(row) {
  return {
    id: String(row.id),
    status: row.status,
    changes: readChanges(row),
    adminNote: row.admin_note || '',
    reviewedBy: row.reviewed_by || '',
    reviewedAt: row.reviewed_at,
    createdAt: row.created_at
  };
}

// GET /api/profiles/me/change-requests — my pending request + recent decisions
router.get('/me/change-requests', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [rows] = await pool.query(
      `SELECT * FROM profile_change_requests WHERE LOWER(student_email) = ? ORDER BY id DESC LIMIT 5`,
      [email]
    );
    const requests = rows.map(serializeRequest);
    return res.json({
      pending: requests.find((r) => r.status === 'pending') || null,
      recent: requests.filter((r) => r.status !== 'pending').slice(0, 1)[0] || null
    });
  } catch (err) {
    console.error('GET /api/profiles/me/change-requests failed:', err);
    return res.status(500).json({ message: 'Could not load your change requests.' });
  }
});

// POST /api/profiles/me/change-request — submit (or replace my pending) request
router.post('/me/change-request', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [profRows] = await pool.query(
      'SELECT * FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1', [email]
    );
    if (!profRows.length) {
      return res.status(404).json({ message: 'Your profile record isn\u2019t set up yet \u2014 ask the registrar/admin to add you to the roster first.' });
    }
    const cur = profRows[0];
    const b = req.body || {};

    // Current values, for "did anything actually change?"
    let curDob = '';
    try { curDob = decryptField(cur.date_of_birth) || ''; } catch (e) { curDob = ''; }
    const current = {
      dateOfBirth: curDob, sex: cur.sex || '', civilStatus: cur.civil_status || '',
      nationality: cur.nationality || '', religion: cur.religion || ''
    };

    const changes = {};
    for (const key of Object.keys(CHANGE_LABELS)) {
      if (b[key] === undefined || b[key] === null || String(b[key]).trim() === '') continue; // untouched
      const result = validateChange(key, b[key]);
      if (result.error) return res.status(400).json({ message: result.error });
      if (String(result.value).toLowerCase() === String(current[key]).toLowerCase()) continue; // same as on file
      changes[key] = key === 'dateOfBirth' ? encryptField(result.value) : result.value;
    }
    if (!Object.keys(changes).length) {
      return res.status(400).json({ message: 'You haven\u2019t changed anything from what\u2019s on file.' });
    }

    const json = JSON.stringify(changes);
    const [pending] = await pool.query(
      `SELECT id FROM profile_change_requests WHERE profile_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
      [cur.id]
    );
    let requestId;
    if (pending.length) {
      requestId = pending[0].id; // a newer request replaces the one still waiting
      await pool.query(
        `UPDATE profile_change_requests SET changes = ?, student_name = ?, created_at = NOW() WHERE id = ?`,
        [json, cur.name, requestId]
      );
    } else {
      const [ins] = await pool.query(
        `INSERT INTO profile_change_requests (profile_id, student_email, student_name, changes) VALUES (?,?,?,?)`,
        [cur.id, email, cur.name, json]
      );
      requestId = ins.insertId;
    }
    await logProfileAudit('STUDENT_PROFILE_CHANGE_REQUESTED', req, cur.id);

    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [requestId]);
    return res.status(201).json({ request: serializeRequest(rows[0]) });
  } catch (err) {
    console.error('POST /api/profiles/me/change-request failed:', err);
    return res.status(500).json({ message: 'Could not submit your change request.' });
  }
});

// DELETE /api/profiles/me/change-request — withdraw my own pending request
router.delete('/me/change-request', requireAuth, requireRole('student'), async (req, res) => {
  try {
    const email = String(req.user.email || '').trim().toLowerCase();
    const [result] = await pool.query(
      `DELETE FROM profile_change_requests WHERE LOWER(student_email) = ? AND status = 'pending'`, [email]
    );
    return res.json({ withdrawn: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/profiles/me/change-request failed:', err);
    return res.status(500).json({ message: 'Could not withdraw your request.' });
  }
});

// All student-profile routes are admin-only (roster management screen).
router.use(requireAuth, requireAdmin);

/* ----- Admin review of student change requests ----- */

// GET /api/profiles/change-requests?status=pending|all
router.get('/change-requests', async (req, res) => {
  try {
    const all = String(req.query.status || 'pending') === 'all';
    const [rows] = await pool.query(
      `SELECT r.*, p.sex AS cur_sex, p.civil_status AS cur_civil, p.nationality AS cur_nat,
              p.religion AS cur_rel, p.student_id AS cur_student_id
       FROM profile_change_requests r
       LEFT JOIN student_profiles p ON p.id = r.profile_id
       ${all ? '' : "WHERE r.status = 'pending'"}
       ORDER BY (r.status = 'pending') DESC, r.created_at DESC
       LIMIT 100`
    );
    const requests = rows.map((r) => {
      const changes = readChanges(r);
      const current = { sex: r.cur_sex || '', civilStatus: r.cur_civil || '', nationality: r.cur_nat || '', religion: r.cur_rel || '' };
      return {
        ...serializeRequest(r),
        profileId: String(r.profile_id),
        studentName: r.student_name,
        studentEmail: r.student_email,
        studentId: r.cur_student_id || '',
        fields: Object.keys(changes).map((key) => ({
          key,
          label: CHANGE_LABELS[key],
          requested: changes[key],
          // Date of birth on file stays masked here (passkey-gated elsewhere).
          current: key === 'dateOfBirth' ? null : (current[key] || '')
        }))
      };
    });
    return res.json({ requests });
  } catch (err) {
    console.error('GET /api/profiles/change-requests failed:', err);
    return res.status(500).json({ message: 'Could not load change requests.' });
  }
});

async function notifyStudent(email, title, message) {
  try {
    await pool.query(
      `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at)
       VALUES (?,?, 'specific', ?, 'sent', NOW())`,
      [title, message, email]
    );
  } catch (err) { console.error('[profile change notify]', err.message); }
}

// POST /api/profiles/change-requests/:id/approve — applies the change
router.post('/change-requests/:id/approve', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid request id.' });
    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ message: 'Change request not found.' });
    const reqRow = rows[0];
    if (reqRow.status !== 'pending') return res.status(409).json({ message: 'This request was already reviewed.' });

    const [profs] = await pool.query('SELECT id, email FROM student_profiles WHERE id = ?', [reqRow.profile_id]);
    if (!profs.length) return res.status(404).json({ message: 'The student profile no longer exists.' });

    // Re-validate stored values before writing them (defence in depth).
    const raw = safeParseJson(reqRow.changes);
    const sets = []; const vals = []; const plain = {};
    for (const key of Object.keys(CHANGE_COLUMNS)) {
      if (raw[key] === undefined) continue;
      if (key === 'dateOfBirth') {
        sets.push('date_of_birth = ?'); vals.push(raw[key]); // already ciphertext
      } else {
        const check = validateChange(key, raw[key]);
        if (check.error) return res.status(400).json({ message: check.error });
        sets.push(CHANGE_COLUMNS[key] + ' = ?'); vals.push(check.value); plain[CHANGE_COLUMNS[key]] = check.value;
      }
    }
    if (!sets.length) return res.status(400).json({ message: 'This request has nothing to apply.' });

    await pool.query(`UPDATE student_profiles SET ${sets.join(', ')} WHERE id = ?`, [...vals, reqRow.profile_id]);

    // Keep the normalized `students` table (same columns) in step; best-effort.
    try {
      await pool.query(
        `UPDATE students s JOIN users u ON u.id = s.user_id SET ${sets.map((x) => 's.' + x).join(', ')}
         WHERE LOWER(u.email) = ?`,
        [...vals, String(profs[0].email || '').toLowerCase()]
      );
    } catch (syncErr) { console.error('[profile change sync students]', syncErr.message); }

    await pool.query(
      `UPDATE profile_change_requests SET status = 'approved', reviewed_by = ?, reviewed_at = NOW(), admin_note = NULL
       WHERE id = ? AND status = 'pending'`,
      [req.user.email, id]
    );
    await logProfileAudit('STUDENT_PROFILE_CHANGE_APPROVED', req, reqRow.profile_id);
    await notifyStudent(
      reqRow.student_email, 'Profile change approved',
      'Your requested changes to your personal information were approved and are now on your profile.'
    );
    return res.json({ approved: true });
  } catch (err) {
    console.error('POST /api/profiles/change-requests/:id/approve failed:', err);
    return res.status(500).json({ message: 'Could not approve this request.' });
  }
});

// POST /api/profiles/change-requests/:id/reject — { note? }
router.post('/change-requests/:id/reject', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid request id.' });
    const note = cleanText((req.body || {}).note, 300);
    const [rows] = await pool.query('SELECT * FROM profile_change_requests WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ message: 'Change request not found.' });
    if (rows[0].status !== 'pending') return res.status(409).json({ message: 'This request was already reviewed.' });

    await pool.query(
      `UPDATE profile_change_requests SET status = 'rejected', reviewed_by = ?, reviewed_at = NOW(), admin_note = ?
       WHERE id = ? AND status = 'pending'`,
      [req.user.email, note || null, id]
    );
    await logProfileAudit('STUDENT_PROFILE_CHANGE_REJECTED', req, rows[0].profile_id);
    await notifyStudent(
      rows[0].student_email, 'Profile change not approved',
      'Your requested changes to your personal information were not approved.' + (note ? ' Reason: ' + note : '')
    );
    return res.json({ rejected: true });
  } catch (err) {
    console.error('POST /api/profiles/change-requests/:id/reject failed:', err);
    return res.status(500).json({ message: 'Could not reject this request.' });
  }
});

// GET /api/profiles
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM student_profiles ORDER BY name ASC');
    return res.json({ profiles: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/profiles failed:', err);
    return res.status(500).json({ message: 'Could not load student profiles.' });
  }
});

// POST /api/profiles
router.post('/', async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const email = String(b.email || '').trim().toLowerCase();
    if (!name || !email) {
      return res.status(400).json({ message: 'Name and email are required.' });
    }

    const [result] = await pool.query(
      `INSERT INTO student_profiles
        (name, email, student_id, program, year_level, section, status,
         date_of_birth, sex, civil_status, nationality, religion, address, mobile,
         guardian_name, guardian_contact, adviser, date_admitted)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        name, email, b.studentId || null, b.program || null, b.yearLevel || null, b.section || null,
        b.status || 'Regular', encryptField(b.dateOfBirth), b.sex || null, b.civilStatus || null,
        b.nationality || null, b.religion || null, encryptField(b.address), encryptField(b.mobile),
        b.guardianName || null, encryptField(b.guardianContact), b.adviser || null, b.dateAdmitted || null
      ]
    );
    const [rows] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [result.insertId]);
    return res.status(201).json({ profile: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/profiles failed:', err);
    return res.status(500).json({ message: 'Could not create the student profile.' });
  }
});

// PUT /api/profiles/:id
router.put('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid profile id.' });

    const [existing] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Student profile not found.' });

    const b = req.body || {};
    const cur = existing[0];

    // Sensitive columns hold ciphertext in `cur` — only re-encrypt when
    // the caller actually sent a new plaintext value; otherwise keep the
    // existing encrypted value as-is (never re-encrypt/pass through a
    // ciphertext value we didn't just produce ourselves).
    const dateOfBirth = b.dateOfBirth !== undefined ? encryptField(b.dateOfBirth) : cur.date_of_birth;
    const address = b.address !== undefined ? encryptField(b.address) : cur.address;
    const mobile = b.mobile !== undefined ? encryptField(b.mobile) : cur.mobile;
    const guardianContact = b.guardianContact !== undefined ? encryptField(b.guardianContact) : cur.guardian_contact;

    await pool.query(
      `UPDATE student_profiles SET
        name=?, email=?, student_id=?, program=?, year_level=?, section=?, status=?,
        date_of_birth=?, sex=?, civil_status=?, nationality=?, religion=?, address=?, mobile=?,
        guardian_name=?, guardian_contact=?, adviser=?, date_admitted=?
       WHERE id=?`,
      [
        b.name ?? cur.name, (b.email ?? cur.email).toLowerCase?.() || cur.email,
        b.studentId ?? cur.student_id, b.program ?? cur.program, b.yearLevel ?? cur.year_level,
        b.section ?? cur.section, b.status ?? cur.status, dateOfBirth,
        b.sex ?? cur.sex, b.civilStatus ?? cur.civil_status, b.nationality ?? cur.nationality,
        b.religion ?? cur.religion, address, mobile,
        b.guardianName ?? cur.guardian_name, guardianContact,
        b.adviser ?? cur.adviser, b.dateAdmitted ?? cur.date_admitted, id
      ]
    );
    const [rows] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [id]);
    return res.json({ profile: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/profiles/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the student profile.' });
  }
});

/**
 * POST /api/profiles/:id/reveal-sensitive
 * Decrypts and returns a single student's DOB / address / mobile /
 * guardian contact — the only path in the app that ever returns these
 * fields unmasked to an admin viewing someone else's record.
 *
 * Requires, in order: admin JWT (router-level requireAuth+requireAdmin
 * above already ran), rate limiting, and the separate administrator
 * passkey (ADMIN_PASSKEY_HASH) in the request body. Every attempt —
 * success or failure — is written to sensitive_data_access_log, but the
 * decrypted values themselves are never logged, only returned in this
 * one response.
 */
router.post('/:id/reveal-sensitive', sensitiveDataLimiter, requireAdminPasskey, async (req, res) => {
  const id = Number(req.params.id);
  const ip = req.ip;

  if (!Number.isInteger(id)) {
    return res.status(400).json({ message: 'Invalid profile id.' });
  }

  try {
    const [rows] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [id]);
    if (!rows.length) {
      await logSensitiveAccess({
        adminId: req.user.id, adminEmail: req.user.email, targetType: 'student_profile',
        targetId: id, fieldsRequested: SENSITIVE_FIELDS.join(','), success: false,
        reason: 'not_found', ip
      });
      return res.status(404).json({ message: 'Student profile not found.' });
    }

    const full = serialize(rows[0], { reveal: true });
    await logSensitiveAccess({
      adminId: req.user.id, adminEmail: req.user.email, targetType: 'student_profile',
      targetId: id, fieldsRequested: SENSITIVE_FIELDS.join(','), success: true, ip
    });

    return res.json({
      profileId: String(id),
      dateOfBirth: full.dateOfBirth,
      address: full.address,
      mobile: full.mobile,
      guardianContact: full.guardianContact
    });
  } catch (err) {
    console.error('POST /api/profiles/:id/reveal-sensitive failed:', err.message);
    await logSensitiveAccess({
      adminId: req.user.id, adminEmail: req.user.email, targetType: 'student_profile',
      targetId: id, fieldsRequested: SENSITIVE_FIELDS.join(','), success: false,
      reason: 'server_error', ip
    });
    return res.status(500).json({ message: 'Could not retrieve sensitive data.' });
  }
});

/** Wraps multer's single-file middleware so its own errors (oversized
 * file, malformed multipart body, etc.) come back as the same clean JSON
 * shape as every other error here, instead of an unhandled exception. */
function handleUpload(req, res, next) {
  upload(req, res, (err) => {
    if (err) {
      const message = err.code === 'LIMIT_FILE_SIZE'
        ? 'Image is too large (max 2MB).'
        : 'Could not process the uploaded file.';
      return res.status(400).json({ message });
    }
    next();
  });
}

/**
 * POST /api/profiles/:id/picture — ADMIN ONLY (this whole router is
 * admin-gated above via router.use(requireAuth, requireAdmin), so no
 * student or teacher token can ever reach this route regardless of what
 * id they pass — there is no student-facing upload/replace endpoint at
 * all, by design).
 *
 * Uploads or replaces this student's profile picture. The file's actual
 * bytes are validated (magic-number check, not filename/MIME) and stored
 * under a fresh server-generated filename by utils/secureUpload.js — see
 * that file for the full security rationale. The previous picture file
 * (if any) is deleted after the new one is successfully saved, so a
 * failed upload never destroys the existing picture.
 */
router.post('/:id/picture', handleUpload, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid profile id.' });

    const [rows] = await pool.query('SELECT id, profile_picture FROM student_profiles WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ message: 'Student profile not found.' });

    let filename;
    try {
      filename = saveValidatedImage(req.file ? req.file.buffer : null);
    } catch (validationErr) {
      // Message here is already user-safe (see secureUpload.js) — no
      // internal error detail is ever forwarded to the client.
      return res.status(400).json({ message: validationErr.message });
    }

    const previousFile = rows[0].profile_picture;
    const isReplace = !!previousFile;
    await pool.query('UPDATE student_profiles SET profile_picture = ? WHERE id = ?', [filename, id]);
    if (previousFile) deleteStoredImage(previousFile);

    await logProfileAudit(
      isReplace ? 'STUDENT_PROFILE_PICTURE_REPLACED' : 'STUDENT_PROFILE_PICTURE_UPLOADED',
      req, id
    );

    return res.status(201).json({ profilePicture: `/uploads/profile-pictures/${filename}` });
  } catch (err) {
    console.error('POST /api/profiles/:id/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not upload the profile picture.' });
  }
});

/**
 * DELETE /api/profiles/:id/picture — ADMIN ONLY, same gating as above.
 * Removes the stored file and clears the DB field, reverting the student
 * to the default avatar the frontend already shows for a null picture.
 */
router.delete('/:id/picture', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid profile id.' });

    const [rows] = await pool.query('SELECT id, profile_picture FROM student_profiles WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ message: 'Student profile not found.' });
    if (!rows[0].profile_picture) return res.json({ removed: false });

    deleteStoredImage(rows[0].profile_picture);
    await pool.query('UPDATE student_profiles SET profile_picture = NULL WHERE id = ?', [id]);
    await logProfileAudit('STUDENT_PROFILE_PICTURE_REMOVED', req, id);

    return res.json({ removed: true });
  } catch (err) {
    console.error('DELETE /api/profiles/:id/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not remove the profile picture.' });
  }
});

// DELETE /api/profiles/:id
router.delete('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid profile id.' });
    const [existing] = await pool.query('SELECT profile_picture FROM student_profiles WHERE id = ?', [id]);
    const [result] = await pool.query('DELETE FROM student_profiles WHERE id = ?', [id]);
    if (existing.length && existing[0].profile_picture) deleteStoredImage(existing[0].profile_picture);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/profiles/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the student profile.' });
  }
});

module.exports = router;
