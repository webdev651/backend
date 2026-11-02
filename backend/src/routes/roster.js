const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getTeacherStudents } = require('../utils/teacherStudents');
const { getActiveTerm } = require('../utils/academicTerm');
const { loadUnitsByEmail, serializeTerm, loadProfilesByEmail } = require('../utils/officialList');

const router = express.Router();

router.use(requireAuth);

// GET /api/roster — the signed-in teacher's own students only (graded by
// you, enrolled in a subject on your Class Schedule, or hand-assigned by
// admin). Admins can pass ?teacherEmail= to preview any teacher's roster.
router.get('/', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const teacherEmail = req.user.role === 'teacher' ? req.user.email : String(req.query.teacherEmail || '');
    const teacherName = req.user.role === 'teacher' ? req.user.name : String(req.query.teacherName || '');
    if (!teacherEmail && !teacherName) return res.json({ students: [], term: null });

    const map = await getTeacherStudents(teacherEmail, teacherName);
    const emails = Array.from(map.keys());

    // Extra fields for the printable Official List (PDF download): student
    // ID, sex, section, status, program, year level and unit load. Students
    // with no profile row / no approved enrollment just come back blank/null.
    const profileByEmail = await loadProfilesByEmail(emails);
    const term = await getActiveTerm();
    const unitsByEmail = await loadUnitsByEmail(emails, term);

    const students = Array.from(map.values())
      .map((s) => {
        const key = String(s.email).toLowerCase();
        const p = profileByEmail[key] || {};
        return {
          email: s.email,
          name: s.name,
          subjects: Array.from(s.subjects),
          studentId: p.student_id || '',
          sex: p.sex || '',
          section: p.section || '',
          status: p.status || '',
          program: p.program || '',
          gradeLevel: p.year_level || '',
          units: Object.prototype.hasOwnProperty.call(unitsByEmail, key) ? unitsByEmail[key] : null
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));

    return res.json({ students: students, term: serializeTerm(term) });
  } catch (err) {
    console.error('GET /api/roster failed:', err);
    return res.status(500).json({ message: 'Could not load your students.' });
  }
});

function serializeAssignment(row) {
  return {
    id: String(row.id),
    teacherEmail: row.teacher_email,
    teacherName: row.teacher_name || '',
    studentEmail: row.student_email,
    studentName: row.student_name,
    assignedAt: row.assigned_at
  };
}

// GET /api/roster/assignments — admin only. All explicit teacher↔student
// assignments, optionally filtered by ?teacherEmail=.
router.get('/assignments', requireRole('admin'), async (req, res) => {
  try {
    const teacherEmail = String(req.query.teacherEmail || '').trim();
    const [rows] = teacherEmail
      ? await pool.query('SELECT * FROM teacher_students WHERE teacher_email = ? ORDER BY assigned_at DESC', [teacherEmail])
      : await pool.query('SELECT * FROM teacher_students ORDER BY assigned_at DESC');
    return res.json({ assignments: rows.map(serializeAssignment) });
  } catch (err) {
    console.error('GET /api/roster/assignments failed:', err);
    return res.status(500).json({ message: 'Could not load teacher-student assignments.' });
  }
});

// POST /api/roster/assignments — admin only. Assigns a student to a
// teacher directly (independent of grades/schedule matching). Re-posting
// the same pair just refreshes assigned_at instead of erroring.
router.post('/assignments', requireRole('admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const teacherEmail = String(b.teacherEmail || '').trim().toLowerCase();
    const teacherName = String(b.teacherName || '').trim();
    const studentEmail = String(b.studentEmail || '').trim().toLowerCase();
    const studentName = String(b.studentName || '').trim();
    if (!teacherEmail || !studentEmail || !studentName) {
      return res.status(400).json({ message: 'Teacher and student are required.' });
    }

    await pool.query(
      `INSERT INTO teacher_students (teacher_email, teacher_name, student_email, student_name)
       VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE teacher_name = VALUES(teacher_name), student_name = VALUES(student_name), assigned_at = NOW()`,
      [teacherEmail, teacherName || null, studentEmail, studentName]
    );
    const [rows] = await pool.query(
      'SELECT * FROM teacher_students WHERE teacher_email = ? AND student_email = ?',
      [teacherEmail, studentEmail]
    );
    return res.status(201).json({ assignment: serializeAssignment(rows[0]) });
  } catch (err) {
    console.error('POST /api/roster/assignments failed:', err);
    return res.status(500).json({ message: 'Could not assign this student to the teacher.' });
  }
});

// DELETE /api/roster/assignments/:id — admin only.
router.delete('/assignments/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid assignment id.' });
    const [result] = await pool.query('DELETE FROM teacher_students WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/roster/assignments/:id failed:', err);
    return res.status(500).json({ message: 'Could not remove this assignment.' });
  }
});

module.exports = router;
