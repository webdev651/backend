const express = require('express');
const bcrypt = require('bcryptjs');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { getTeacherStudents, getAllTeacherStudentLinks } = require('../utils/teacherStudents');
const { getActiveTerm } = require('../utils/academicTerm');
const { loadUnitsByEmail, serializeTerm } = require('../utils/officialList');
const { checkPasswordStrength } = require('../utils/passwordPolicy');
const { upload, saveValidatedImage, deleteStoredImage } = require('../utils/secureUpload');

/** Same wrapper pattern as routes/profiles.js — turns multer's own
 * errors (oversized file, malformed multipart body) into the same clean
 * JSON error shape as everything else here. */
function handleTeacherPictureUpload(req, res, next) {
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

const router = express.Router();
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 10);

function serializeRequest(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    detail: row.detail || '',
    studentId: row.student_id || '',
    status: row.status,
    requestedAt: row.requested_at,
    decidedAt: row.decided_at
  };
}

// Every route below requires a valid admin JWT.
router.use(requireAuth, requireAdmin);

/**
 * GET /api/admin/requests
 * All student/teacher account requests (any status), newest first —
 * matches the old accounts.js `all()` used by the Approvals table.
 */
router.get('/requests', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM users WHERE role IN ('student', 'teacher') ORDER BY requested_at DESC`
    );
    return res.json({ requests: rows.map(serializeRequest) });
  } catch (err) {
    console.error('GET /api/admin/requests failed:', err);
    return res.status(500).json({ message: 'Could not load account requests.' });
  }
});

async function decide(req, res, newStatus) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid request id.' });

    const [rows] = await pool.query(
      `SELECT * FROM users WHERE id = ? AND role IN ('student', 'teacher')`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ message: 'Account request not found.' });

    await pool.query(
      `UPDATE users SET status = ?, decided_at = NOW() WHERE id = ?`,
      [newStatus, id]
    );
    const [updated] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    return res.json({ request: serializeRequest(updated[0]) });
  } catch (err) {
    console.error('POST /api/admin/requests/:id/' + newStatus + ' failed:', err);
    return res.status(500).json({ message: 'Could not update the account request.' });
  }
}

// POST /api/admin/requests/:id/approve
router.post('/requests/:id/approve', (req, res) => decide(req, res, 'approved'));

// POST /api/admin/requests/:id/reject
router.post('/requests/:id/reject', (req, res) => decide(req, res, 'rejected'));

/**
 * POST /api/admin/users/:id/reset-password
 * Sets a new password for the given user, chosen by the admin (typed into
 * the inline form on the Approvals row) rather than auto-generated. Hashed
 * the same way signup does and overwrites password_hash. There is no way
 * to recover a user's actual password — only to replace it — so this is
 * the one supported way for an admin to help someone who's locked out.
 * The admin should relay the new password to the user, who should sign in
 * and change it.
 */
router.post('/users/:id/reset-password', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid user id.' });

    const newPassword = String(req.body.newPassword || '');
    const strength = checkPasswordStrength(newPassword);
    if (!strength.valid) {
      return res.status(400).json({ message: strength.message });
    }

    const [rows] = await pool.query('SELECT id, name, email FROM users WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ message: 'User not found.' });

    const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, id]);

    return res.json({ name: rows[0].name, email: rows[0].email, newPassword });
  } catch (err) {
    console.error('POST /api/admin/users/:id/reset-password failed:', err);
    return res.status(500).json({ message: "Could not reset this user's password." });
  }
});

/* =========================================================================
   Admin — Teacher Master List & All Student Accounts
   (Admin Dashboard → Students → "Teacher Master List" / "All Student
   Accounts" cards, frontend/js/admin/admin-roster.js and
   admin-all-students.js.)

   Reuses the existing `users` (accounts), `student_profiles` (admin
   roster detail), and the teacher<->student relationship already derived
   by src/utils/teacherStudents.js from grades / schedules+enrollments /
   teacher_students — no new tables. Every route on this router already
   requires a valid admin JWT (router.use(requireAuth, requireAdmin)
   above), so teachers/students cannot reach any of this.
   ========================================================================= */

function serializeTeacherAccount(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    department: row.detail || '',
    status: row.status,
    createdAt: row.created_at
  };
}

/**
 * GET /api/admin/teachers?q=partial+name
 * All approved teacher accounts, optionally filtered by a partial,
 * case-insensitive name match (?q=). Backs the Teacher Master List
 * search box.
 */
router.get('/teachers', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().slice(0, 150);
    const params = ['teacher', 'approved'];
    let sql = `SELECT id, name, email, detail, status, created_at FROM users WHERE role = ? AND status = ?`;
    if (q) {
      sql += ` AND name LIKE ?`;
      params.push('%' + q.replace(/[%_]/g, '\\$&') + '%');
    }
    sql += ` ORDER BY name ASC`;
    const [rows] = await pool.query(sql, params);
    return res.json({ teachers: rows.map(serializeTeacherAccount) });
  } catch (err) {
    console.error('GET /api/admin/teachers failed:', err);
    return res.status(500).json({ message: 'Could not load teacher accounts.' });
  }
});

/**
 * GET /api/admin/teachers/:id
 * A single teacher's full professional profile for the admin's
 * "Manage teacher" view — personal, contact, and professional fields
 * plus current picture. :id is a users.id.
 */
router.get('/teachers/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid teacher id.' });
    const [userRows] = await pool.query(`SELECT * FROM users WHERE id = ? AND role = 'teacher'`, [id]);
    if (!userRows.length) return res.status(404).json({ message: 'Teacher not found.' });
    const [teacherRows] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [id]);
    const t = teacherRows[0] || null;
    const u = userRows[0];
    return res.json({
      profile: {
        id: String(u.id),
        name: u.name,
        email: u.email,
        accountStatus: u.status,
        department: t ? (t.department || '') : '',
        subjects: t ? (t.subjects || '') : '',
        phone: t ? (t.phone || '') : '',
        address: t ? (t.address || '') : '',
        position: t ? (t.position || '') : '',
        specialization: t ? (t.specialization || '') : '',
        employmentStatus: t ? (t.employment_status || 'Full-time') : 'Full-time',
        profilePicture: t && t.profile_picture ? `/uploads/profile-pictures/${t.profile_picture}` : null,
        updatedAt: t ? t.updated_at : null
      }
    });
  } catch (err) {
    console.error('GET /api/admin/teachers/:id failed:', err);
    return res.status(500).json({ message: 'Could not load this teacher\u2019s profile.' });
  }
});

/**
 * PUT /api/admin/teachers/:id
 * Admin-only edit of a teacher's administrative/professional fields —
 * department, position, specialization, employment status, assigned
 * subjects. (Contact fields like phone/address are also editable here
 * since an admin may legitimately need to correct them, but a teacher's
 * OWN self-edit — PUT /api/teacher/me — is restricted to just those two;
 * this route is the admin-privileged counterpart with no such limit.)
 */
router.put('/teachers/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid teacher id.' });
    const [userRows] = await pool.query(`SELECT * FROM users WHERE id = ? AND role = 'teacher'`, [id]);
    if (!userRows.length) return res.status(404).json({ message: 'Teacher not found.' });

    const [existing] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [id]);
    if (!existing.length) {
      await pool.query('INSERT INTO teachers (user_id) VALUES (?)', [id]);
    }
    const [rows] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [id]);
    const cur = rows[0];
    const b = req.body || {};

    await pool.query(
      `UPDATE teachers SET department=?, subjects=?, phone=?, address=?, position=?, specialization=?, employment_status=? WHERE user_id=?`,
      [
        b.department !== undefined ? String(b.department).trim().slice(0, 150) : cur.department,
        b.subjects !== undefined ? String(b.subjects).trim().slice(0, 255) : cur.subjects,
        b.phone !== undefined ? String(b.phone).trim().slice(0, 50) : cur.phone,
        b.address !== undefined ? String(b.address).trim().slice(0, 255) : cur.address,
        b.position !== undefined ? String(b.position).trim().slice(0, 150) : cur.position,
        b.specialization !== undefined ? String(b.specialization).trim().slice(0, 150) : cur.specialization,
        b.employmentStatus !== undefined ? String(b.employmentStatus).trim().slice(0, 50) : cur.employment_status,
        id
      ]
    );

    const [updated] = await pool.query('SELECT * FROM teachers WHERE user_id = ?', [id]);
    return res.json({
      profile: {
        id: String(id),
        department: updated[0].department || '',
        subjects: updated[0].subjects || '',
        phone: updated[0].phone || '',
        address: updated[0].address || '',
        position: updated[0].position || '',
        specialization: updated[0].specialization || '',
        employmentStatus: updated[0].employment_status || 'Full-time',
        updatedAt: updated[0].updated_at
      }
    });
  } catch (err) {
    console.error('PUT /api/admin/teachers/:id failed:', err);
    return res.status(500).json({ message: 'Could not update this teacher\u2019s profile.' });
  }
});

/**
 * POST /api/admin/teachers/:id/picture — ADMIN ONLY (entire router is
 * admin-gated; no teacher self-upload endpoint exists at all, by design
 * — see routes/teacher.js, which never exposes a picture-upload route).
 * Same magic-byte validation / server-generated filename approach as the
 * student picture endpoint (routes/profiles.js) — see utils/secureUpload.js.
 */
router.post('/teachers/:id/picture', handleTeacherPictureUpload, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid teacher id.' });
    const [userRows] = await pool.query(`SELECT id FROM users WHERE id = ? AND role = 'teacher'`, [id]);
    if (!userRows.length) return res.status(404).json({ message: 'Teacher not found.' });

    const [existing] = await pool.query('SELECT profile_picture FROM teachers WHERE user_id = ?', [id]);
    if (!existing.length) await pool.query('INSERT INTO teachers (user_id) VALUES (?)', [id]);

    let filename;
    try {
      filename = saveValidatedImage(req.file ? req.file.buffer : null);
    } catch (validationErr) {
      return res.status(400).json({ message: validationErr.message });
    }

    const previousFile = existing.length ? existing[0].profile_picture : null;
    await pool.query('UPDATE teachers SET profile_picture = ? WHERE user_id = ?', [filename, id]);
    if (previousFile) deleteStoredImage(previousFile);

    await pool.query(
      `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
      [previousFile ? 'TEACHER_PROFILE_PICTURE_REPLACED' : 'TEACHER_PROFILE_PICTURE_UPLOADED', req.user.id, req.user.email, 'teacher', id]
    ).catch((e) => console.error('[profile_audit_log]', e.message));

    return res.status(201).json({ profilePicture: `/uploads/profile-pictures/${filename}` });
  } catch (err) {
    console.error('POST /api/admin/teachers/:id/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not upload the profile picture.' });
  }
});

/**
 * DELETE /api/admin/teachers/:id/picture — ADMIN ONLY.
 */
router.delete('/teachers/:id/picture', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid teacher id.' });
    const [existing] = await pool.query('SELECT profile_picture FROM teachers WHERE user_id = ?', [id]);
    if (!existing.length || !existing[0].profile_picture) return res.json({ removed: false });

    deleteStoredImage(existing[0].profile_picture);
    await pool.query('UPDATE teachers SET profile_picture = NULL WHERE user_id = ?', [id]);
    await pool.query(
      `INSERT INTO profile_audit_log (action, actor_id, actor_email, target_type, target_id) VALUES (?,?,?,?,?)`,
      ['TEACHER_PROFILE_PICTURE_REMOVED', req.user.id, req.user.email, 'teacher', id]
    ).catch((e) => console.error('[profile_audit_log]', e.message));

    return res.json({ removed: true });
  } catch (err) {
    console.error('DELETE /api/admin/teachers/:id/picture failed:', err.message);
    return res.status(500).json({ message: 'Could not remove the profile picture.' });
  }
});


/**
 * A single teacher's complete master list of students — the same
 * grades/schedule/admin-assignment matching used for that teacher's own
 * "My students" tab (getTeacherStudents), enriched with the admin roster
 * detail (student ID, year level, section, status) from student_profiles
 * where a profile exists.
 */
router.get('/master-list', async (req, res) => {
  try {
    const teacherId = Number(req.query.teacher_id);
    if (!Number.isInteger(teacherId) || teacherId <= 0) {
      return res.status(400).json({ message: 'A valid teacher_id is required.' });
    }

    const [teacherRows] = await pool.query(
      `SELECT id, name, email, detail, status FROM users WHERE id = ? AND role = 'teacher'`,
      [teacherId]
    );
    if (!teacherRows.length) return res.status(404).json({ message: 'Teacher not found.' });
    const teacher = teacherRows[0];

    const map = await getTeacherStudents(teacher.email, teacher.name);
    const emails = Array.from(map.keys());

    let profileByEmail = {};
    if (emails.length) {
      const [profileRows] = await pool.query(
        `SELECT * FROM student_profiles WHERE LOWER(email) IN (?)`,
        [emails]
      );
      profileRows.forEach((p) => { profileByEmail[String(p.email).toLowerCase()] = p; });
    }

    const term = await getActiveTerm();
    const unitsByEmail = await loadUnitsByEmail(emails, term);

    const students = Array.from(map.values()).map((s) => {
      const key = String(s.email).toLowerCase();
      const p = profileByEmail[key] || {};
      return {
        studentId: p.student_id || '',
        name: s.name,
        email: s.email,
        gradeLevel: p.year_level || '',
        section: p.section || '',
        status: p.status || '',
        // Extra fields for the printable Official List (PDF download).
        sex: p.sex || '',
        program: p.program || '',
        units: Object.prototype.hasOwnProperty.call(unitsByEmail, key) ? unitsByEmail[key] : null,
        subjects: Array.from(s.subjects)
      };
    }).sort((a, b) => a.name.localeCompare(b.name));

    // Subjects this teacher teaches — the union of every subject that
    // links them to any of the students above (schedules + grades
    // entries), same source getTeacherStudents() already used per-student.
    const teacherSubjects = Array.from(
      students.reduce((set, s) => { s.subjects.forEach((subj) => set.add(subj)); return set; }, new Set())
    ).sort();

    return res.json({
      teacher: {
        id: teacher.id,
        name: teacher.name,
        email: teacher.email,
        department: teacher.detail || '',
        status: teacher.status,
        subjects: teacherSubjects
      },
      term: serializeTerm(term),
      totalStudents: students.length,
      students: students
    });
  } catch (err) {
    console.error('GET /api/admin/master-list failed:', err);
    return res.status(500).json({ message: "Could not load this teacher's master list." });
  }
});

/**
 * POST /api/admin/master-list/send
 * Body: { teacherId, section? }
 * Shares a snapshot of a teacher's master list with that teacher: a
 * masterlist_shares row (Student ID / Name / Section only, per spec) plus
 * a linked notification (recipient_type='specific', recipient_email=the
 * teacher) so it shows up under Notifications on their own dashboard.
 * Reuses the exact same getTeacherStudents() + student_profiles matching
 * as GET /master-list above; if `section` is given, the snapshot is
 * narrowed to just that section (case-insensitive exact match) so admin
 * can send one of a multi-section teacher's sections at a time.
 */
router.post('/master-list/send', async (req, res) => {
  try {
    const teacherId = Number(req.body.teacherId);
    if (!Number.isInteger(teacherId) || teacherId <= 0) {
      return res.status(400).json({ message: 'A valid teacherId is required.' });
    }
    const section = String(req.body.section || '').trim();

    const [teacherRows] = await pool.query(
      `SELECT id, name, email, status FROM users WHERE id = ? AND role = 'teacher'`,
      [teacherId]
    );
    if (!teacherRows.length) return res.status(404).json({ message: 'Teacher not found.' });
    const teacher = teacherRows[0];

    const map = await getTeacherStudents(teacher.email, teacher.name);
    const emails = Array.from(map.keys());

    let profileByEmail = {};
    if (emails.length) {
      const [profileRows] = await pool.query(
        `SELECT email, student_id, section, sex, status, program, year_level FROM student_profiles WHERE LOWER(email) IN (?)`,
        [emails]
      );
      profileRows.forEach((p) => { profileByEmail[String(p.email).toLowerCase()] = p; });
    }

    const term = await getActiveTerm();
    const unitsByEmail = await loadUnitsByEmail(emails, term);

    let students = Array.from(map.values()).map((s) => {
      const key = String(s.email).toLowerCase();
      const p = profileByEmail[key] || {};
      return {
        studentId: p.student_id || '',
        name: s.name,
        section: p.section || '',
        // Kept in the snapshot so the teacher can download the same
        // Official List PDF (male/female groups, irregular highlight, units).
        sex: p.sex || '',
        status: p.status || '',
        program: p.program || '',
        gradeLevel: p.year_level || '',
        units: Object.prototype.hasOwnProperty.call(unitsByEmail, key) ? unitsByEmail[key] : null
      };
    });
    if (section) {
      students = students.filter((s) => s.section.toLowerCase() === section.toLowerCase());
    }
    students.sort((a, b) => a.name.localeCompare(b.name));

    if (!students.length) {
      return res.status(400).json({
        message: section
          ? `${teacher.name} has no students on file for section "${section}".`
          : `${teacher.name} has no students on file yet.`
      });
    }

    const [shareResult] = await pool.query(
      `INSERT INTO masterlist_shares (teacher_email, teacher_name, section, students, sent_by_name, sent_by_email)
       VALUES (?,?,?,?,?,?)`,
      [teacher.email, teacher.name, section || null, JSON.stringify(students), req.user.name || 'Admin', req.user.email || null]
    );
    const shareId = shareResult.insertId;

    const sectionLabel = section || 'all their sections';
    const title = 'Master list shared: ' + (section || 'All sections');
    const message = (req.user.name || 'Admin') + ' shared the master list for ' + sectionLabel +
      ' with you (' + students.length + (students.length === 1 ? ' student' : ' students') + ').';

    await pool.query(
      `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at, related_masterlist_id)
       VALUES (?,?, 'specific', ?, 'sent', NOW(), ?)`,
      [title, message, teacher.email, shareId]
    );

    return res.status(201).json({
      share: { id: shareId, teacherId: teacher.id, teacherName: teacher.name, section: section || '', totalStudents: students.length }
    });
  } catch (err) {
    console.error('POST /api/admin/master-list/send failed:', err);
    return res.status(500).json({ message: 'Could not send the master list.' });
  }
});

/**
 * GET /api/admin/students?q=&yearLevel=&section=&teacherId=
 * Every approved student account, enriched with student_profiles detail
 * (student ID, program, year level, section) and the teacher(s) each
 * student is linked to (via getAllTeacherStudentLinks — same three link
 * types as a teacher's own roster, computed once for everyone instead of
 * per-teacher). All filters are optional and combine with AND.
 */
router.get('/students', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().toLowerCase().slice(0, 150);
    const yearLevel = String(req.query.yearLevel || '').trim();
    const section = String(req.query.section || '').trim();
    const teacherIdParam = req.query.teacherId != null ? Number(req.query.teacherId) : null;
    if (req.query.teacherId != null && (!Number.isInteger(teacherIdParam) || teacherIdParam <= 0)) {
      return res.status(400).json({ message: 'Invalid teacherId.' });
    }

    const [userRows] = await pool.query(
      `SELECT id, name, email, detail, student_id, status, created_at FROM users WHERE role = 'student' AND status = 'approved' ORDER BY name ASC`
    );

    const emails = userRows.map((u) => String(u.email).toLowerCase());
    let profileByEmail = {};
    if (emails.length) {
      const [profileRows] = await pool.query(
        `SELECT * FROM student_profiles WHERE LOWER(email) IN (?)`,
        [emails]
      );
      profileRows.forEach((p) => { profileByEmail[String(p.email).toLowerCase()] = p; });
    }

    const links = await getAllTeacherStudentLinks();
    const teachersByStudent = {}; // studentEmail (lower) -> Map(teacherKey -> {id/email/name})
    links.forEach((l) => {
      const studentKey = String(l.studentEmail || '').trim().toLowerCase();
      if (!studentKey) return;
      const teacherKey = (l.teacherEmail || ('name:' + String(l.teacherName || '').toLowerCase())).toLowerCase();
      if (!teachersByStudent[studentKey]) teachersByStudent[studentKey] = new Map();
      teachersByStudent[studentKey].set(teacherKey, {
        email: l.teacherEmail || '',
        name: l.teacherName || l.teacherEmail || ''
      });
    });

    // Resolve a requested ?teacherId= to the email/name key used above.
    let teacherFilterKey = null;
    if (teacherIdParam) {
      const [tRows] = await pool.query(`SELECT email FROM users WHERE id = ? AND role = 'teacher'`, [teacherIdParam]);
      teacherFilterKey = tRows.length ? String(tRows[0].email).toLowerCase() : '__no_such_teacher__';
    }

    let students = userRows.map((u) => {
      const key = String(u.email).toLowerCase();
      const p = profileByEmail[key] || {};
      const teacherMap = teachersByStudent[key];
      const teachers = teacherMap ? Array.from(teacherMap.values()) : [];
      return {
        id: u.id,
        // Prefer the Student ID captured at signup (authoritative, unique);
        // fall back to the admin roster's value for older accounts created
        // before this field existed.
        studentId: u.student_id || p.student_id || '',
        name: u.name,
        email: u.email,
        program: p.program || u.detail || '',
        yearLevel: p.year_level || '',
        section: p.section || '',
        assignedTeachers: teachers.map((t) => t.name),
        status: p.status || 'Regular',
        createdAt: u.created_at,
        _teacherKeys: teachers.map((t) => t.email.toLowerCase())
      };
    });

    if (q) {
      students = students.filter((s) =>
        s.name.toLowerCase().indexOf(q) !== -1 ||
        s.email.toLowerCase().indexOf(q) !== -1 ||
        s.studentId.toLowerCase().indexOf(q) !== -1
      );
    }
    if (yearLevel) students = students.filter((s) => s.yearLevel.toLowerCase() === yearLevel.toLowerCase());
    if (section) students = students.filter((s) => s.section.toLowerCase() === section.toLowerCase());
    if (teacherFilterKey) students = students.filter((s) => s._teacherKeys.indexOf(teacherFilterKey) !== -1);

    students.forEach((s) => { delete s._teacherKeys; });

    return res.json({ students: students, total: students.length });
  } catch (err) {
    console.error('GET /api/admin/students failed:', err);
    return res.status(500).json({ message: 'Could not load student accounts.' });
  }
});

/* =========================================================================
   Admin — Section Assignment
   (Admin Dashboard → Students → "All Student Accounts" → Section column.)

   Reuses student_profiles.section — the same field the manually-edited
   roster (src/routes/profiles.js) already exposes — so a section set here
   shows up everywhere that already reads it (this list, the Teacher
   Master List, and the student's own Profile via GET /api/profiles/me).
   ========================================================================= */

/**
 * GET /api/admin/sections
 * Distinct, non-empty section values already on file. Populates the
 * Section Assignment picker with sections in current use so admins pick
 * from a known list instead of retyping one from scratch — a soft
 * convenience, not an enforced whitelist (see the PUT route below for the
 * actual validation), so a school can still start a brand-new section.
 */
router.get('/sections', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT DISTINCT section FROM student_profiles
       WHERE section IS NOT NULL AND section <> '' ORDER BY section ASC`
    );
    return res.json({ sections: rows.map((r) => r.section) });
  } catch (err) {
    console.error('GET /api/admin/sections failed:', err);
    return res.status(500).json({ message: 'Could not load sections.' });
  }
});

// Letters, digits, spaces, hyphens, and periods only, 2–30 characters after
// trimming — e.g. "BSCS-2A", "BSIT 1B", "Sec. A". Rejects empty/whitespace-
// only values and stray symbols without locking sections to a fixed enum.
const SECTION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 .-]{1,29}$/;

/**
 * PUT /api/admin/students/:id/section
 * Assigns or changes the section for one approved student account. :id is
 * the account's users.id — the same id already returned by GET /students,
 * so the frontend table can call this directly per row.
 *
 * Invalid assignments are rejected outright:
 *  - :id must belong to an approved student account (never a teacher/
 *    admin, and never a pending or rejected request).
 *  - section is required and must match SECTION_PATTERN above.
 */
router.put('/students/:id/section', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid student id.' });
    }

    const section = String((req.body || {}).section || '').trim().replace(/\s+/g, ' ');
    if (!section) {
      return res.status(400).json({ message: 'Section is required.' });
    }
    if (!SECTION_PATTERN.test(section)) {
      return res.status(400).json({
        message: 'Section must be 2–30 characters: letters, numbers, spaces, hyphens, or periods only.'
      });
    }

    const [userRows] = await pool.query(
      `SELECT id, name, email, detail, student_id FROM users
       WHERE id = ? AND role = 'student' AND status = 'approved'`,
      [id]
    );
    if (!userRows.length) {
      return res.status(404).json({ message: 'No approved student account with that id.' });
    }
    const student = userRows[0];
    const email = String(student.email).toLowerCase();

    const [existingProfile] = await pool.query(
      `SELECT id FROM student_profiles WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1`,
      [email]
    );

    if (existingProfile.length) {
      await pool.query(`UPDATE student_profiles SET section = ? WHERE id = ?`, [section, existingProfile[0].id]);
    } else {
      // First roster record for this student (e.g. a self-registered
      // account an admin never added to the roster manually) — seed it
      // with what the account already knows so the rest of the roster
      // screen has something sensible to show too.
      await pool.query(
        `INSERT INTO student_profiles (name, email, student_id, program, section, status)
         VALUES (?, ?, ?, ?, ?, 'Regular')`,
        [student.name, student.email, student.student_id || null, student.detail || null, section]
      );
    }

    return res.json({ id: student.id, studentId: student.student_id || '', section: section });
  } catch (err) {
    console.error('PUT /api/admin/students/:id/section failed:', err);
    return res.status(500).json({ message: "Could not update this student's section." });
  }
});

module.exports = router;
