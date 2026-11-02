const express = require('express');
const pool = require('../db');
const { requireAuth, requireTeacher } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');
const { getTeacherStudents } = require('../utils/teacherStudents');
const { encryptField } = require('../utils/crypto');
const { upload, saveValidatedImage, deleteStoredImage } = require('../utils/secureUpload');

const router = express.Router();

// Every route below requires a valid teacher JWT — a student or admin
// token is rejected by requireTeacher, and a teacher only ever sees their
// own notifications / master lists (never another teacher's), enforced
// per-route below by matching req.user.email.
router.use(requireAuth, requireTeacher);

function serializeTeacherProfile(userRow, teacherRow) {
  return {
    id: String(userRow.id),
    name: userRow.name,
    email: userRow.email,
    department: teacherRow ? (teacherRow.department || '') : '',
    subjects: teacherRow ? (teacherRow.subjects || '') : '',
    phone: teacherRow ? (teacherRow.phone || '') : '',
    address: teacherRow ? (teacherRow.address || '') : '',
    position: teacherRow ? (teacherRow.position || '') : '',
    specialization: teacherRow ? (teacherRow.specialization || '') : '',
    employmentStatus: teacherRow ? (teacherRow.employment_status || 'Full-time') : 'Full-time',
    profilePicture: teacherRow && teacherRow.profile_picture ? `/uploads/profile-pictures/${teacherRow.profile_picture}` : null,
    accountStatus: userRow.status,
    updatedAt: teacherRow ? teacherRow.updated_at : null
  };
}

/**
 * GET /api/teacher/me
 * The signed-in teacher's own profile — personal/contact fields plus the
 * admin-controlled professional fields (department, position,
 * specialization, employment status, assigned subjects), all read-only
 * here except via PUT below. Identity always comes from req.user, never
 * a client-supplied id.
 */
router.get('/me', async (req, res) => {
  try {
    const [userRows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!userRows.length) return res.status(404).json({ message: 'Account not found.' });
    const [teacherRows] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [req.user.id]);
    return res.json({ profile: serializeTeacherProfile(userRows[0], teacherRows[0] || null) });
  } catch (err) {
    console.error('GET /api/teacher/me failed:', err);
    return res.status(500).json({ message: 'Could not load your profile.' });
  }
});

/**
 * PUT /api/teacher/me
 * Self-service edit — deliberately narrow. A teacher may update only
 * their own contact details: phone and address.
 *
 * Everything else (department, position, specialization,
 * employment status, assigned subjects/sections, account status) is
 * silently ignored here even if sent — those are admin-only, enforced
 * server-side via the separate admin-only routes in routes/admin.js, not
 * by hiding fields in the UI.
 */
router.put('/me', async (req, res) => {
  try {
    const b = req.body || {};
    const phone = b.phone !== undefined ? String(b.phone).trim().slice(0, 40) : undefined;
    const address = b.address !== undefined ? String(b.address).trim().slice(0, 250) : undefined;

    const PHONE_PATTERN = /^[0-9+()\-.\s]{7,20}$/;
    if (phone !== undefined && phone && !PHONE_PATTERN.test(phone)) {
      return res.status(400).json({ message: 'Phone number looks invalid.' });
    }

    // Ensure a teachers row exists (mirrors sections.js's ensureTeacherRow
    // pattern — a teacher approved after the last migration run may not
    // have one yet).
    const [existing] = await pool.query('SELECT id FROM teachers WHERE user_id = ?', [req.user.id]);
    if (!existing.length) {
      await pool.query('INSERT INTO teachers (user_id) VALUES (?)', [req.user.id]);
    }

    const sets = [];
    const values = [];
    if (phone !== undefined) { sets.push('phone = ?'); values.push(phone); }
    if (address !== undefined) { sets.push('address = ?'); values.push(address); }
    if (sets.length) {
      values.push(req.user.id);
      await pool.query(`UPDATE teachers SET ${sets.join(', ')} WHERE user_id = ?`, values);
    }

    const [userRows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const [teacherRows] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [req.user.id]);
    return res.json({ profile: serializeTeacherProfile(userRows[0], teacherRows[0] || null) });
  } catch (err) {
    console.error('PUT /api/teacher/me failed:', err);
    return res.status(500).json({ message: 'Could not update your profile.' });
  }
});

function serializeNotification(row) {
  return {
    id: String(row.id),
    title: row.title,
    message: row.message,
    createdAt: row.created_at,
    sentAt: row.sent_at,
    relatedMasterlistId: row.related_masterlist_id ? String(row.related_masterlist_id) : null,
    masterlistViewed: row.masterlist_viewed_at ? true : false
  };
}

/**
 * GET /api/teacher/notifications
 * This teacher's own notification feed: anything broadcast to 'all',
 * broadcast to 'teacher', or sent 'specific'-ally to their email —
 * mirrors the recipient-matching that frontend/js/modules/notifications.js
 * forRecipient() already does client-side, just enforced server-side too
 * (the general GET /api/notifications is admin-only, so teachers/students
 * never had a way to fetch their own feed before this route existed).
 */
router.get('/notifications', async (req, res) => {
  try {
    const email = req.user.email;
    const [rows] = await pool.query(
      `SELECT n.*, m.viewed_at AS masterlist_viewed_at
       FROM notifications n
       LEFT JOIN masterlist_shares m ON m.id = n.related_masterlist_id
       WHERE n.status = 'sent'
         AND (n.recipient_type = 'all' OR n.recipient_type = 'teacher'
              OR (n.recipient_type = 'specific' AND n.recipient_email = ?))
       ORDER BY n.sent_at DESC, n.created_at DESC`,
      [email]
    );
    return res.json({ notifications: rows.map(serializeNotification) });
  } catch (err) {
    console.error('GET /api/teacher/notifications failed:', err);
    return res.status(500).json({ message: 'Could not load your notifications.' });
  }
});

/**
 * GET /api/teacher/master-list/:shareId
 * A single master-list share — Student ID, Name, and Section for the
 * section (or sections) an admin sent this teacher. Authorization: the
 * share's teacher_email must match the signed-in teacher's own email, or
 * this 404s exactly the way a nonexistent id would (so a teacher probing
 * ids can't tell "not yours" apart from "doesn't exist"). Marks the share
 * viewed on first open.
 */
router.get('/master-list/:shareId', async (req, res) => {
  try {
    const shareId = Number(req.params.shareId);
    if (!Number.isInteger(shareId) || shareId <= 0) {
      return res.status(400).json({ message: 'Invalid master list id.' });
    }

    const [rows] = await pool.query('SELECT * FROM masterlist_shares WHERE id = ?', [shareId]);
    const share = rows[0];
    if (!share || String(share.teacher_email).toLowerCase() !== String(req.user.email).toLowerCase()) {
      return res.status(404).json({ message: 'Master list not found.' });
    }

    if (!share.viewed_at) {
      await pool.query('UPDATE masterlist_shares SET viewed_at = NOW() WHERE id = ?', [shareId]);
    }

    let students = share.students;
    if (typeof students === 'string') {
      try { students = JSON.parse(students); } catch (e) { students = []; }
    }

    const term = await getActiveTerm();

    return res.json({
      id: String(share.id),
      section: share.section || '',
      sentByName: share.sent_by_name,
      sentAt: share.sent_at,
      term: term ? { id: term.id, schoolYear: term.school_year, semester: term.semester, label: term.label } : null,
      students: Array.isArray(students) ? students : []
    });
  } catch (err) {
    console.error('GET /api/teacher/master-list/:shareId failed:', err);
    return res.status(500).json({ message: 'Could not load that master list.' });
  }
});

/**
 * GET /api/teacher/sections
 * Sections this teacher is currently the assigned adviser/teacher for —
 * i.e. sections.adviser_teacher_id points at this teacher's row. Purely a
 * live read of the current assignment, so if admin reassigns a section to
 * someone else, it simply stops showing up here on next load (and starts
 * showing up on the new teacher's) — no extra bookkeeping needed.
 * Each section includes its full active roster inline (name, email,
 * student ID, program, year level) plus a student count, per spec.
 */
router.get('/sections', async (req, res) => {
  try {
    const [teacherRows] = await pool.query(`SELECT id FROM teachers WHERE user_id = ?`, [req.user.id]);
    if (!teacherRows.length) return res.json({ sections: [] });
    const teacherId = teacherRows[0].id;

    const [sections] = await pool.query(
      `SELECT * FROM sections WHERE adviser_teacher_id = ? ORDER BY term DESC, section_code ASC`,
      [teacherId]
    );
    if (!sections.length) return res.json({ sections: [] });

    const sectionIds = sections.map((s) => s.id);
    const [studentRows] = await pool.query(
      `SELECT ssa.section_id, u.id AS user_id, u.name, u.email, s.student_id, s.program, s.year_level
       FROM student_section_assignments ssa
       JOIN students s ON s.id = ssa.student_id
       JOIN users u ON u.id = s.user_id
       WHERE ssa.section_id IN (?) AND ssa.status = 'active'
       ORDER BY u.name ASC`,
      [sectionIds]
    );

    const studentsBySection = {};
    studentRows.forEach((r) => {
      if (!studentsBySection[r.section_id]) studentsBySection[r.section_id] = [];
      studentsBySection[r.section_id].push({
        id: r.user_id,
        studentId: r.student_id || '',
        name: r.name,
        email: r.email,
        program: r.program || '',
        yearLevel: r.year_level || ''
      });
    });

    return res.json({
      sections: sections.map((s) => {
        const students = studentsBySection[s.id] || [];
        return {
          id: s.id,
          sectionCode: s.section_code,
          program: s.program || '',
          yearLevel: s.year_level || '',
          term: s.term,
          students: students,
          studentCount: students.length
        };
      })
    });
  } catch (err) {
    console.error('GET /api/teacher/sections failed:', err);
    return res.status(500).json({ message: 'Could not load your sections.' });
  }
});

/* =========================================================================
   Teacher editing a student's profile (own students only)

   A teacher may update personal + contact details of a student on THEIR OWN
   roster (graded by them / on their schedule / admin-assigned — the same
   getTeacherStudents() link used by GET /api/roster). That covers personal and
   contact details AND academic details (name, student ID, program, year level,
   section, status, adviser, date admitted) plus the profile picture. Only the
   account email stays admin-only (it is the login / record-linking key).

   Encrypted fields (date of birth, address, mobile, guardian contact) are
   WRITE-ONLY here: the teacher never receives their current values, and a
   blank field means "leave unchanged". Every edit is audit-logged and the
   student is notified (field labels only, never values).
   ========================================================================= */
const TS_LABELS = {
  dateOfBirth: 'Date of birth', sex: 'Sex', civilStatus: 'Civil status',
  nationality: 'Nationality', religion: 'Religion', address: 'Address',
  mobile: 'Mobile number', guardianName: 'Guardian name', guardianContact: 'Guardian contact number',
  name: 'Name', studentId: 'Student ID', program: 'Program', yearLevel: 'Year level',
  section: 'Section', status: 'Status', adviser: 'Adviser', dateAdmitted: 'Date admitted'
};
const TS_COLUMNS = {
  dateOfBirth: 'date_of_birth', sex: 'sex', civilStatus: 'civil_status',
  nationality: 'nationality', religion: 'religion', address: 'address',
  mobile: 'mobile', guardianName: 'guardian_name', guardianContact: 'guardian_contact',
  name: 'name', studentId: 'student_id', program: 'program', yearLevel: 'year_level',
  section: 'section', status: 'status', adviser: 'adviser', dateAdmitted: 'date_admitted'
};
// Columns that also exist on the normalized `students` table (it has no name/section/adviser).
const TS_STUDENTS_SYNC = ['student_id', 'program', 'year_level', 'status', 'date_admitted',
  'date_of_birth', 'sex', 'civil_status', 'nationality', 'religion', 'address', 'mobile',
  'guardian_name', 'guardian_contact'];
const TS_ENCRYPTED = ['dateOfBirth', 'address', 'mobile', 'guardianContact'];
const TS_MAX = {
  nationality: 80, religion: 80, address: 250, mobile: 40, guardianName: 150, guardianContact: 40,
  name: 150, studentId: 50, program: 150, yearLevel: 50, section: 50, adviser: 150, dateAdmitted: 50
};
const TS_STATUS = ['Regular', 'Irregular', 'Inactive'];
const TS_SEX = ['Male', 'Female'];
const TS_CIVIL = ['Single', 'Married', 'Widowed', 'Separated'];
const TS_PHONE = /^[0-9+()\-.\s]{7,20}$/;

function tsClean(v, max) {
  return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** Returns { value } or { error } for one non-blank field. */
function tsValidate(key, raw) {
  const v = tsClean(raw, TS_MAX[key] || 80);
  if (key === 'sex') {
    const hit = TS_SEX.find((x) => x.toLowerCase() === v.toLowerCase());
    return hit ? { value: hit } : { error: 'Sex must be Male or Female.' };
  }
  if (key === 'civilStatus') {
    const hit = TS_CIVIL.find((x) => x.toLowerCase() === v.toLowerCase());
    return hit ? { value: hit } : { error: 'Civil status must be one of: ' + TS_CIVIL.join(', ') + '.' };
  }
  if (key === 'status') {
    const hit = TS_STATUS.find((x) => x.toLowerCase() === v.toLowerCase());
    return hit ? { value: hit } : { error: 'Status must be one of: ' + TS_STATUS.join(', ') + '.' };
  }
  if (key === 'dateAdmitted') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || isNaN(new Date(v + 'T00:00:00Z').getTime())) {
      return { error: 'Date admitted must be a valid date.' };
    }
    return { value: v };
  }
  if (key === 'dateOfBirth') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return { error: 'Date of birth must be a valid date.' };
    const d = new Date(v + 'T00:00:00Z');
    if (isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) return { error: 'Date of birth must be a valid date.' };
    if (d.getTime() > Date.now() || Number(v.slice(0, 4)) < 1900) return { error: 'Date of birth looks invalid.' };
    return { value: v };
  }
  if ((key === 'mobile' || key === 'guardianContact') && !TS_PHONE.test(v)) {
    return { error: TS_LABELS[key] + ' looks invalid.' };
  }
  return { value: v };
}

/** Resolves :email to a profile row, only if that student is on this teacher's roster. */
async function loadOwnStudentProfile(req, res) {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!email) { res.status(400).json({ message: 'Student email is required.' }); return null; }
  const roster = await getTeacherStudents(req.user.email, req.user.name);
  if (!roster.has(email)) {
    res.status(403).json({ message: 'You can only edit the profiles of your own students.' });
    return null;
  }
  const [rows] = await pool.query(
    'SELECT * FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1', [email]
  );
  if (rows.length) return rows[0];

  // No admin-created profile row yet (e.g. a freshly approved student). Build one
  // from the student's account so the teacher can still fill it in.
  const [users] = await pool.query(
    `SELECT * FROM users WHERE LOWER(email) = ? AND role = 'student' ORDER BY id DESC LIMIT 1`, [email]
  );
  if (!users.length) {
    res.status(404).json({ message: 'This student has no account in the system yet, so there is no profile to edit.' });
    return null;
  }
  const u = users[0];
  const [ins] = await pool.query(
    `INSERT INTO student_profiles (name, email, student_id, program, status) VALUES (?,?,?,?, 'Regular')`,
    [u.name, String(u.email || email).toLowerCase(), u.student_id || null, u.detail || null]
  );
  const [created] = await pool.query('SELECT * FROM student_profiles WHERE id = ?', [ins.insertId]);
  return created[0];
}

// GET /api/teacher/students/:email/profile — non-sensitive current values only.
router.get('/students/:email/profile', async (req, res) => {
  try {
    const cur = await loadOwnStudentProfile(req, res);
    if (!cur) return;
    return res.json({
      profile: {
        name: cur.name, email: cur.email, studentId: cur.student_id || '',
        program: cur.program || '', yearLevel: cur.year_level || '', section: cur.section || '',
        status: cur.status || 'Regular', adviser: cur.adviser || '', dateAdmitted: cur.date_admitted || '',
        profilePicture: cur.profile_picture ? `/uploads/profile-pictures/${cur.profile_picture}` : null,
        sex: cur.sex || '', civilStatus: cur.civil_status || '',
        nationality: cur.nationality || '', religion: cur.religion || '',
        guardianName: cur.guardian_name || '',
        // Encrypted fields: only whether a value is on file, never the value.
        onFile: {
          dateOfBirth: !!cur.date_of_birth, address: !!cur.address,
          mobile: !!cur.mobile, guardianContact: !!cur.guardian_contact
        }
      }
    });
  } catch (err) {
    console.error('GET /api/teacher/students/:email/profile failed:', err);
    return res.status(500).json({ message: 'Could not load this student\u2019s profile.' });
  }
});

// PUT /api/teacher/students/:email/profile — blank/omitted field = unchanged.
router.put('/students/:email/profile', async (req, res) => {
  try {
    const cur = await loadOwnStudentProfile(req, res);
    if (!cur) return;
    const b = req.body || {};

    const sets = []; const vals = []; const changed = [];
    for (const key of Object.keys(TS_COLUMNS)) {
      if (b[key] === undefined || b[key] === null || String(b[key]).trim() === '') continue;
      const result = tsValidate(key, b[key]);
      if (result.error) return res.status(400).json({ message: result.error });
      sets.push(TS_COLUMNS[key] + ' = ?');
      vals.push(TS_ENCRYPTED.indexOf(key) !== -1 ? encryptField(result.value) : result.value);
      changed.push(key);
    }
    if (!sets.length) return res.status(400).json({ message: 'You haven\u2019t entered any changes.' });

    await pool.query(`UPDATE student_profiles SET ${sets.join(', ')} WHERE id = ?`, [...vals, cur.id]);

    // Keep the normalized `students` table in step (same column names); best-effort.
    try {
      const syncIdx = sets.map((x, i) => i).filter((i) => TS_STUDENTS_SYNC.indexOf(sets[i].split(' = ')[0]) !== -1);
      if (syncIdx.length) {
        await pool.query(
          `UPDATE students s JOIN users u ON u.id = s.user_id SET ${syncIdx.map((i) => 's.' + sets[i]).join(', ')}
           WHERE LOWER(u.email) = ?`,
          [...syncIdx.map((i) => vals[i]), String(cur.email || '').toLowerCase()]
        );
      }
    } catch (syncErr) { console.error('[teacher profile edit sync students]', syncErr.message); }

    await pool.query(
      `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
      ['TEACHER_STUDENT_PROFILE_UPDATED', req.user.id, req.user.email, 'student', cur.id]
    ).catch((e) => console.error('[profile_audit_log]', e.message));

    await pool.query(
      `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at)
       VALUES (?,?, 'specific', ?, 'sent', NOW())`,
      [
        'Profile updated by your teacher',
        (req.user.name || 'Your teacher') + ' updated your profile: ' + changed.map((k) => TS_LABELS[k]).join(', ') + '.',
        String(cur.email || '').toLowerCase()
      ]
    ).catch((e) => console.error('[teacher profile edit notify]', e.message));

    return res.json({ updated: true, fields: changed.map((k) => TS_LABELS[k]) });
  } catch (err) {
    console.error('PUT /api/teacher/students/:email/profile failed:', err);
    return res.status(500).json({ message: 'Could not update this student\u2019s profile.' });
  }
});

function tsHandleUpload(req, res, next) {
  upload(req, res, (err) => {
    if (err) {
      const message = err.code === 'LIMIT_FILE_SIZE' ? 'Image is too large (max 2MB).' : 'Could not process the uploaded file.';
      return res.status(400).json({ message });
    }
    next();
  });
}

async function tsAuditAndNotify(req, cur, action, what) {
  await pool.query(
    `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
    [action, req.user.id, req.user.email, 'student', cur.id]
  ).catch((e) => console.error('[profile_audit_log]', e.message));
  await pool.query(
    `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at)
     VALUES (?,?, 'specific', ?, 'sent', NOW())`,
    ['Profile updated by your teacher', (req.user.name || 'Your teacher') + ' ' + what + '.', String(cur.email || '').toLowerCase()]
  ).catch((e) => console.error('[teacher profile edit notify]', e.message));
}

// POST /api/teacher/students/:email/picture — upload / replace (same validation as admin).
router.post('/students/:email/picture', tsHandleUpload, async (req, res) => {
  try {
    const cur = await loadOwnStudentProfile(req, res);
    if (!cur) return;
    let filename;
    try { filename = saveValidatedImage(req.file ? req.file.buffer : null); }
    catch (validationErr) { return res.status(400).json({ message: validationErr.message }); }
    const previous = cur.profile_picture;
    await pool.query('UPDATE student_profiles SET profile_picture = ? WHERE id = ?', [filename, cur.id]);
    try {
      await pool.query(
        `UPDATE students s JOIN users u ON u.id = s.user_id SET s.profile_picture = ? WHERE LOWER(u.email) = ?`,
        [filename, String(cur.email || '').toLowerCase()]
      );
    } catch (syncErr) { console.error('[teacher picture sync students]', syncErr.message); }
    if (previous) deleteStoredImage(previous);
    await tsAuditAndNotify(req, cur, previous ? 'TEACHER_STUDENT_PICTURE_REPLACED' : 'TEACHER_STUDENT_PICTURE_UPLOADED', 'changed your profile picture');
    return res.status(201).json({ profilePicture: `/uploads/profile-pictures/${filename}` });
  } catch (err) {
    console.error('POST /api/teacher/students/:email/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not upload the profile picture.' });
  }
});

// DELETE /api/teacher/students/:email/picture — revert to the default avatar.
router.delete('/students/:email/picture', async (req, res) => {
  try {
    const cur = await loadOwnStudentProfile(req, res);
    if (!cur) return;
    if (!cur.profile_picture) return res.json({ removed: false });
    deleteStoredImage(cur.profile_picture);
    await pool.query('UPDATE student_profiles SET profile_picture = NULL WHERE id = ?', [cur.id]);
    try {
      await pool.query(
        `UPDATE students s JOIN users u ON u.id = s.user_id SET s.profile_picture = NULL WHERE LOWER(u.email) = ?`,
        [String(cur.email || '').toLowerCase()]
      );
    } catch (syncErr) { console.error('[teacher picture sync students]', syncErr.message); }
    await tsAuditAndNotify(req, cur, 'TEACHER_STUDENT_PICTURE_REMOVED', 'removed your profile picture');
    return res.json({ removed: true });
  } catch (err) {
    console.error('DELETE /api/teacher/students/:email/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not remove the profile picture.' });
  }
});

module.exports = router;
