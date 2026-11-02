const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

// Admin-only — everything here is section management (Admin → Sections).
router.use(requireAuth, requireAdmin);

const DEFAULT_TERM = 'Current Term';
// Same shape as the free-text section validation already used in
// src/routes/admin.js (PUT /students/:id/section) — letters, numbers,
// spaces, hyphens, periods only, 2–30 chars.
const SECTION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 .-]{1,29}$/;

function serializeSection(row) {
  // "Sent" means the current adviser is the same teacher admin last sent
  // this section to. Reassigning to someone else (adviser_teacher_id
  // changes) makes these stop matching, so the badge flips back to "Not
  // sent" for the new teacher on its own — no reset needed on the PUT
  // route above.
  const isSent = !!(row.sent_to_teacher_id && row.adviser_teacher_id && row.sent_to_teacher_id === row.adviser_teacher_id);
  // dateStrings:true (see db.js) means these are 'YYYY-MM-DD HH:MM:SS'
  // strings, which compare correctly with plain string comparison.
  const changedSinceSent = isSent && !!row.sent_at && row.updated_at > row.sent_at;
  return {
    id: row.id,
    sectionCode: row.section_code,
    program: row.program || '',
    yearLevel: row.year_level || '',
    term: row.term,
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    teacherId: row.teacher_user_id || null,      // users.id, not the internal teachers.id
    teacherName: row.teacher_name || '',
    teacherEmail: row.teacher_email || '',
    studentCount: Number(row.student_count || 0),
    isSent: isSent,
    sentAt: isSent ? row.sent_at : null,
    changedSinceSent: changedSinceSent,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function serializeRosterStudent(row) {
  return {
    id: row.user_id,          // users.id — what the frontend selects/removes by
    studentId: row.student_id || '',
    name: row.name,
    email: row.email,
    program: row.program || '',
    yearLevel: row.year_level || ''
  };
}

const SECTION_SELECT = `
  SELECT sec.*, tu.id AS teacher_user_id, tu.name AS teacher_name, tu.email AS teacher_email,
    (SELECT COUNT(*) FROM student_section_assignments ssa
      WHERE ssa.section_id = sec.id AND ssa.status = 'active') AS student_count
  FROM sections sec
  LEFT JOIN teachers t ON sec.adviser_teacher_id = t.id
  LEFT JOIN users tu ON t.user_id = tu.id
`;

async function getSectionOr404(id, res) {
  const [rows] = await pool.query(SECTION_SELECT + ' WHERE sec.id = ?', [id]);
  if (!rows.length) {
    res.status(404).json({ message: 'Section not found.' });
    return null;
  }
  return rows[0];
}

/* =========================================================================
   syncSectionTeacherLinks(sectionId)
   The connective piece Enrollment Workflow Integration needed: makes "the
   teacher automatically sees students assigned to their section" actually
   true, by keeping `teacher_students` (what getTeacherStudents() reads for
   the teacher's Students tab, and for attendance/grade-entry authorization
   — see src/utils/teacherStudents.js) in sync with this section's adviser
   + roster (`student_section_assignments`, what the Sections admin screen
   and the teacher's My Sections tab already read live).

   Called after anything that can change either half of that link: adding/
   removing a roster student, or reassigning the adviser. Always removes
   every teacher_students row this function previously created for this
   section (source_section_id = sectionId) and rebuilds it from the
   section's current, live state — so a student removed from the roster,
   or an adviser who got reassigned, stops seeing each other automatically.

   Never touches a link with source_section_id IS NULL — those are manual
   links created directly via /api/roster/assignments (roster.js), which
   this function must not delete or repurpose.
   ========================================================================= */
async function syncSectionTeacherLinks(sectionId) {
  const [secRows] = await pool.query(SECTION_SELECT + ' WHERE sec.id = ?', [sectionId]);
  const section = secRows[0];
  if (!section) return;

  await pool.query('DELETE FROM teacher_students WHERE source_section_id = ?', [sectionId]);
  if (!section.teacher_email) return; // no adviser assigned — nothing to link

  const [roster] = await pool.query(
    `SELECT u.email, u.name
     FROM student_section_assignments ssa
     JOIN students s ON s.id = ssa.student_id
     JOIN users u ON u.id = s.user_id
     WHERE ssa.section_id = ? AND ssa.status = 'active'`,
    [sectionId]
  );
  for (const student of roster) {
    await pool.query(
      `INSERT INTO teacher_students (teacher_email, teacher_name, student_email, student_name, source_section_id)
       VALUES (?,?,?,?,?)
       ON DUPLICATE KEY UPDATE teacher_name = VALUES(teacher_name)`,
      [section.teacher_email, section.teacher_name || section.teacher_email, student.email, student.name, sectionId]
    );
  }
}

/* Ensures a Phase 3 `teachers` row exists for an approved teacher account
   and returns its id (teachers.id, used as sections.adviser_teacher_id).
   Self-healing the same way src/migrate.js's backfill is — a teacher
   approved after the last server restart may not have a row yet. */
async function ensureTeacherRow(userId) {
  const [u] = await pool.query(
    `SELECT id, detail FROM users WHERE id = ? AND role = 'teacher' AND status = 'approved'`,
    [userId]
  );
  if (!u.length) return null;
  await pool.query(`INSERT IGNORE INTO teachers (user_id, department) VALUES (?, ?)`, [userId, u[0].detail || null]);
  const [t] = await pool.query(`SELECT id FROM teachers WHERE user_id = ?`, [userId]);
  return t.length ? t[0].id : null;
}

/* Same idea for the `students` row (needs a non-null student_id, which
   every approved student account has). */
async function ensureStudentRow(userId) {
  const [u] = await pool.query(
    `SELECT id, student_id, detail FROM users WHERE id = ? AND role = 'student' AND status = 'approved'`,
    [userId]
  );
  if (!u.length || !u[0].student_id) return null;
  await pool.query(
    `INSERT IGNORE INTO students (user_id, student_id, program) VALUES (?, ?, ?)`,
    [userId, u[0].student_id, u[0].detail || null]
  );
  const [s] = await pool.query(`SELECT id FROM students WHERE user_id = ?`, [userId]);
  return s.length ? s[0].id : null;
}

/**
 * GET /api/sections
 * Every section, newest term first, with its adviser (if any) and a live
 * count of actively-assigned students.
 */
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query(SECTION_SELECT + ' ORDER BY sec.term DESC, sec.section_code ASC');
    return res.json({ sections: rows.map(serializeSection) });
  } catch (err) {
    console.error('GET /api/sections failed:', err);
    return res.status(500).json({ message: 'Could not load sections.' });
  }
});

/**
 * POST /api/sections
 * Body: { sectionCode, program?, yearLevel?, term?, teacherId? }
 * teacherId is a users.id (an approved teacher account) — optional, a
 * section can be created without an adviser and assigned one later.
 */
router.post('/', async (req, res) => {
  try {
    const b = req.body || {};
    const sectionCode = String(b.sectionCode || '').trim().replace(/\s+/g, ' ');
    // Defaults to the active academic term's label when the admin leaves
    // Term blank, so a new section lines up with the current term out of
    // the box — admin can still type any other term by hand (e.g. to set
    // up next semester's sections ahead of activating it).
    const activeTerm = await getActiveTerm();
    const term = String(b.term || '').trim() || (activeTerm ? activeTerm.label : DEFAULT_TERM);

    if (!sectionCode) return res.status(400).json({ message: 'Section name is required.' });
    if (!SECTION_PATTERN.test(sectionCode)) {
      return res.status(400).json({ message: 'Section name must be 2–30 characters: letters, numbers, spaces, hyphens, or periods only.' });
    }

    let teacherRowId = null;
    if (b.teacherId != null && b.teacherId !== '') {
      const teacherUserId = Number(b.teacherId);
      if (!Number.isInteger(teacherUserId)) return res.status(400).json({ message: 'Invalid teacher.' });
      teacherRowId = await ensureTeacherRow(teacherUserId);
      if (!teacherRowId) return res.status(400).json({ message: 'That teacher account could not be found.' });
    }

    // Matched against academic_terms.label rather than always using
    // activeTerm.id, since the term text above may have been hand-typed
    // for a different (e.g. future, not-yet-active) term.
    const [termMatch] = await pool.query('SELECT id FROM academic_terms WHERE label = ?', [term]);
    const academicTermId = termMatch[0] ? termMatch[0].id : null;

    const [result] = await pool.query(
      `INSERT INTO sections (section_code, program, year_level, term, academic_term_id, adviser_teacher_id) VALUES (?,?,?,?,?,?)`,
      [sectionCode, b.program || null, b.yearLevel || null, term, academicTermId, teacherRowId]
    );
    const row = await getSectionOr404(result.insertId, res);
    if (!row) return;
    return res.status(201).json({ section: serializeSection(row) });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'A section with that name already exists for that term.' });
    }
    console.error('POST /api/sections failed:', err);
    return res.status(500).json({ message: 'Could not create the section.' });
  }
});

/**
 * PUT /api/sections/:id
 * Body: any of { sectionCode, program, yearLevel, term, teacherId }.
 * teacherId: '' or null clears the adviser.
 */
router.put('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid section id.' });
    const existing = await getSectionOr404(id, res);
    if (!existing) return;

    const b = req.body || {};
    const sectionCode = b.sectionCode != null ? String(b.sectionCode).trim().replace(/\s+/g, ' ') : existing.section_code;
    if (!sectionCode) return res.status(400).json({ message: 'Section name is required.' });
    if (!SECTION_PATTERN.test(sectionCode)) {
      return res.status(400).json({ message: 'Section name must be 2–30 characters: letters, numbers, spaces, hyphens, or periods only.' });
    }
    const term = b.term != null ? (String(b.term).trim() || DEFAULT_TERM) : existing.term;
    // Re-matched against academic_terms whenever term text changes, same
    // lookup as POST above; left untouched if term wasn't part of this edit.
    let academicTermId = existing.academic_term_id;
    if (b.term != null) {
      const [termMatch] = await pool.query('SELECT id FROM academic_terms WHERE label = ?', [term]);
      academicTermId = termMatch[0] ? termMatch[0].id : null;
    }

    let teacherRowId = existing.adviser_teacher_id;
    if (Object.prototype.hasOwnProperty.call(b, 'teacherId')) {
      if (b.teacherId == null || b.teacherId === '') {
        teacherRowId = null;
      } else {
        const teacherUserId = Number(b.teacherId);
        if (!Number.isInteger(teacherUserId)) return res.status(400).json({ message: 'Invalid teacher.' });
        teacherRowId = await ensureTeacherRow(teacherUserId);
        if (!teacherRowId) return res.status(400).json({ message: 'That teacher account could not be found.' });
      }
    }

    await pool.query(
      `UPDATE sections SET section_code=?, program=?, year_level=?, term=?, academic_term_id=?, adviser_teacher_id=? WHERE id=?`,
      [
        sectionCode,
        b.program != null ? (b.program || null) : existing.program,
        b.yearLevel != null ? (b.yearLevel || null) : existing.year_level,
        term,
        academicTermId,
        teacherRowId,
        id
      ]
    );
    // Adviser may have just changed (or been cleared) — resync so the new
    // adviser sees this section's roster and the old one stops seeing it.
    await syncSectionTeacherLinks(id);
    const row = await getSectionOr404(id, res);
    if (!row) return;
    return res.json({ section: serializeSection(row) });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'A section with that name already exists for that term.' });
    }
    console.error('PUT /api/sections/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the section.' });
  }
});

/**
 * DELETE /api/sections/:id
 * Cascades to student_section_assignments and masterlists (see schema.sql
 * FK ON DELETE CASCADE) — removing a section clears its roster with it.
 */
router.delete('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid section id.' });
    // No FK from teacher_students to sections (see schema.sql comment on
    // that column), so this cleanup has to happen explicitly here —
    // otherwise a deleted section would leave its auto-created roster
    // links pointing at a section id that no longer exists.
    await pool.query('DELETE FROM teacher_students WHERE source_section_id = ?', [id]);
    const [result] = await pool.query('DELETE FROM sections WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/sections/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the section.' });
  }
});

/**
 * GET /api/sections/:id/students
 * The section's current roster (active assignments only), alphabetical.
 */
router.get('/:id/students', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid section id.' });
    const section = await getSectionOr404(id, res);
    if (!section) return;

    const [rows] = await pool.query(
      `SELECT u.id AS user_id, u.name, u.email, s.student_id, s.program, s.year_level
       FROM student_section_assignments ssa
       JOIN students s ON s.id = ssa.student_id
       JOIN users u ON u.id = s.user_id
       WHERE ssa.section_id = ? AND ssa.status = 'active'
       ORDER BY u.name ASC`,
      [id]
    );
    return res.json({ students: rows.map(serializeRosterStudent) });
  } catch (err) {
    console.error('GET /api/sections/:id/students failed:', err);
    return res.status(500).json({ message: 'Could not load this section\u2019s roster.' });
  }
});

/**
 * POST /api/sections/:id/students
 * Body: { studentId } — a users.id for an approved student account.
 * Re-adding a previously-removed student reactivates their assignment
 * instead of creating a duplicate row.
 */
router.post('/:id/students', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid section id.' });
    const section = await getSectionOr404(id, res);
    if (!section) return;

    const studentUserId = Number((req.body || {}).studentId);
    if (!Number.isInteger(studentUserId)) return res.status(400).json({ message: 'Select a student to add.' });

    const studentRowId = await ensureStudentRow(studentUserId);
    if (!studentRowId) return res.status(400).json({ message: 'That student account could not be found.' });

    await pool.query(
      `INSERT INTO student_section_assignments (student_id, section_id, status)
       VALUES (?, ?, 'active')
       ON DUPLICATE KEY UPDATE status = 'active'`,
      [studentRowId, id]
    );
    // The connective fix for Enrollment Workflow Integration: this student
    // now automatically shows up for the section's adviser (if any).
    await syncSectionTeacherLinks(id);
    // Touch the section row so serializeSection() can flag "changed since
    // last sent" (compares updated_at against sent_at) — lets admin see
    // when a previously-sent section's roster has since moved.
    await pool.query(`UPDATE sections SET updated_at = NOW() WHERE id = ?`, [id]);

    const [rows] = await pool.query(
      `SELECT u.id AS user_id, u.name, u.email, s.student_id, s.program, s.year_level
       FROM students s JOIN users u ON u.id = s.user_id WHERE s.id = ?`,
      [studentRowId]
    );
    return res.status(201).json({ student: serializeRosterStudent(rows[0]) });
  } catch (err) {
    console.error('POST /api/sections/:id/students failed:', err);
    return res.status(500).json({ message: 'Could not add this student to the section.' });
  }
});

/**
 * DELETE /api/sections/:id/students/:studentUserId
 * Removes the student from this section's roster.
 */
router.delete('/:id/students/:studentUserId', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const studentUserId = Number(req.params.studentUserId);
    if (!Number.isInteger(id) || !Number.isInteger(studentUserId)) {
      return res.status(400).json({ message: 'Invalid section or student id.' });
    }
    const [result] = await pool.query(
      `DELETE ssa FROM student_section_assignments ssa
       JOIN students s ON s.id = ssa.student_id
       WHERE ssa.section_id = ? AND s.user_id = ?`,
      [id, studentUserId]
    );
    if (result.affectedRows > 0) {
      await pool.query(`UPDATE sections SET updated_at = NOW() WHERE id = ?`, [id]);
      // Remove this student from the section's automatic teacher link too.
      await syncSectionTeacherLinks(id);
    }
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/sections/:id/students/:studentUserId failed:', err);
    return res.status(500).json({ message: 'Could not remove this student from the section.' });
  }
});

/**
 * POST /api/sections/:id/send
 * "Send to Teacher" — confirms the section's current adviser and current
 * roster, then:
 *   1. Notifies that teacher (a `notifications` row, recipient_type=
 *      'specific' — the exact same mechanism teacher.js already reads
 *      for GET /api/teacher/notifications, so it just shows up there,
 *      no new teacher-facing endpoint needed).
 *   2. Stamps sections.sent_to_teacher_id/sent_at so the admin UI can
 *      show a Sent/Not sent status (see serializeSection() above).
 * Does NOT touch adviser_teacher_id or student_section_assignments —
 * those stay exactly as-is, so /api/teacher/sections keeps working the
 * same way it already does (a live read of the current assignment).
 * That also means roster/teacher changes after sending don't need any
 * special handling here: the teacher's My Sections view is always live,
 * and a reassignment simply makes isSent recompute to false above.
 */
router.post('/:id/send', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid section id.' });
    const section = await getSectionOr404(id, res);
    if (!section) return;

    if (!section.adviser_teacher_id || !section.teacher_email) {
      return res.status(400).json({ message: 'Assign a teacher to this section before sending it.' });
    }

    const [rows] = await pool.query(
      `SELECT u.name
       FROM student_section_assignments ssa
       JOIN students s ON s.id = ssa.student_id
       JOIN users u ON u.id = s.user_id
       WHERE ssa.section_id = ? AND ssa.status = 'active'
       ORDER BY u.name ASC`,
      [id]
    );
    const studentNames = rows.map((r) => r.name);

    const title = 'Section assigned: ' + section.section_code;
    const countLabel = studentNames.length + (studentNames.length === 1 ? ' student' : ' students');
    const message = (req.user.name || 'Admin') + ' assigned you as teacher for ' + section.section_code +
      ' (' + countLabel + ').' +
      (studentNames.length ? ' Students: ' + studentNames.join(', ') + '.' : '');

    await pool.query(
      `INSERT INTO notifications (title, message, recipient_type, recipient_email, status, sent_at)
       VALUES (?,?, 'specific', ?, 'sent', NOW())`,
      [title, message, section.teacher_email]
    );

    await pool.query(
      `UPDATE sections SET sent_to_teacher_id = ?, sent_at = NOW() WHERE id = ?`,
      [section.adviser_teacher_id, id]
    );

    const updated = await getSectionOr404(id, res);
    if (!updated) return;
    return res.status(201).json({ section: serializeSection(updated) });
  } catch (err) {
    console.error('POST /api/sections/:id/send failed:', err);
    return res.status(500).json({ message: 'Could not send this section to the teacher.' });
  }
});

module.exports = router;
