const express = require('express');
const pool = require('../db');
const { requireAuth, requireTeacher } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

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

module.exports = router;
