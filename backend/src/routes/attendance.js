const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getTeacherStudents } = require('../utils/teacherStudents');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    subject: row.subject,
    date: row.date,
    status: row.status,
    remarks: row.remarks || '',
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    recordedAt: row.recorded_at
  };
}

router.use(requireAuth);

// GET /api/attendance — admin=all, teacher=own students only, student=own
router.get('/', async (req, res) => {
  try {
    const { role, email, name } = req.user;
    let rows;
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const termClause = termId ? ' AND academic_term_id = ?' : '';
    if (role === 'student') {
      [rows] = await pool.query(
        `SELECT * FROM attendance WHERE student_email = ?${termClause} ORDER BY date DESC`,
        termId ? [email, termId] : [email]
      );
    } else if (role === 'teacher') {
      const roster = await getTeacherStudents(email, name);
      const emails = Array.from(roster.keys());
      if (!emails.length) return res.json({ attendance: [] });
      [rows] = await pool.query(
        `SELECT * FROM attendance WHERE LOWER(student_email) IN (${emails.map(() => '?').join(',')})${termClause} ORDER BY date DESC`,
        termId ? [...emails, termId] : emails
      );
    } else {
      [rows] = await pool.query(
        `SELECT * FROM attendance ${termId ? 'WHERE academic_term_id = ?' : ''} ORDER BY date DESC`,
        termId ? [termId] : []
      );
    }
    return res.json({ attendance: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/attendance failed:', err);
    return res.status(500).json({ message: 'Could not load attendance.' });
  }
});

// POST /api/attendance/generate — bulk-create one record per student for
// a subject/date, skipping students who already have one. Admin generates
// for the whole roster (student_profiles); a teacher only for their own
// students (getTeacherStudents), so a subject they don't teach can't be
// used to sweep in students who aren't theirs.
// Registered before /:id-style routes below so 'generate' is never
// mistaken for a numeric id.
router.post('/generate', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const subject = String(b.subject || '').trim();
    const date = String(b.date || '').trim();
    if (!subject || !date) return res.status(400).json({ message: 'Subject and date are required.' });
    const status = b.status || 'Present';
    const remarks = b.remarks || null;

    let students;
    if (req.user.role === 'teacher') {
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      students = Array.from(roster.values()).map((s) => ({ name: s.name, email: s.email }));
    } else {
      [students] = await pool.query('SELECT name, email FROM student_profiles');
    }
    const [already] = await pool.query(
      'SELECT student_email FROM attendance WHERE subject = ? AND date = ?',
      [subject, date]
    );
    const covered = new Set(already.map((r) => r.student_email));

    const activeTerm = await getActiveTerm();
    const activeTermId = activeTerm ? activeTerm.id : null;
    let created = 0;
    for (const s of students) {
      if (covered.has(s.email)) continue;
      await pool.query(
        `INSERT INTO attendance (student_email, student_name, subject, date, status, remarks, academic_term_id)
         VALUES (?,?,?,?,?,?,?)`,
        [s.email, s.name, subject, date, status, remarks, activeTermId]
      );
      created += 1;
    }
    return res.json({ created });
  } catch (err) {
    console.error('POST /api/attendance/generate failed:', err);
    return res.status(500).json({ message: 'Could not generate attendance for this class.' });
  }
});

// POST /api/attendance — teacher (own students only) or admin (anyone)
router.post('/', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const studentEmail = String(b.studentEmail || '').trim().toLowerCase();
    const studentName = String(b.studentName || '').trim();
    const subject = String(b.subject || '').trim();
    const date = String(b.date || '').trim();
    if (!studentEmail || !studentName || !subject || !date) {
      return res.status(400).json({ message: 'Student, subject, and date are required.' });
    }
    if (req.user.role === 'teacher') {
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      if (!roster.has(studentEmail)) {
        return res.status(403).json({ message: 'That student isn\u2019t linked to you yet \u2014 check your Students tab.' });
      }
    }
    const activeTerm = await getActiveTerm();
    const [result] = await pool.query(
      `INSERT INTO attendance (student_email, student_name, subject, date, status, remarks, academic_term_id)
       VALUES (?,?,?,?,?,?,?)`,
      [studentEmail, studentName, subject, date, b.status || 'Present', b.remarks || null, activeTerm ? activeTerm.id : null]
    );
    const [rows] = await pool.query('SELECT * FROM attendance WHERE id = ?', [result.insertId]);
    return res.status(201).json({ attendance: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/attendance failed:', err);
    return res.status(500).json({ message: 'Could not record attendance.' });
  }
});

// PUT /api/attendance/:id — teacher (own students only) or admin
router.put('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid attendance id.' });
    const [existing] = await pool.query('SELECT * FROM attendance WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Attendance record not found.' });
    const cur = existing[0];

    if (req.user.role === 'teacher') {
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      if (!roster.has(String(cur.student_email).toLowerCase())) {
        return res.status(403).json({ message: 'This record isn\u2019t for one of your students.' });
      }
    }

    const b = req.body || {};
    await pool.query(
      'UPDATE attendance SET status=?, remarks=? WHERE id=?',
      [b.status ?? cur.status, b.remarks !== undefined ? b.remarks : cur.remarks, id]
    );
    const [rows] = await pool.query('SELECT * FROM attendance WHERE id = ?', [id]);
    return res.json({ attendance: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/attendance/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the attendance record.' });
  }
});

// DELETE /api/attendance/:id — teacher (own students only) or admin
router.delete('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid attendance id.' });

    if (req.user.role === 'teacher') {
      const [existing] = await pool.query('SELECT student_email FROM attendance WHERE id = ?', [id]);
      if (!existing.length) return res.status(404).json({ message: 'Attendance record not found.' });
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      if (!roster.has(String(existing[0].student_email).toLowerCase())) {
        return res.status(403).json({ message: 'This record isn\u2019t for one of your students.' });
      }
    }

    const [result] = await pool.query('DELETE FROM attendance WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/attendance/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the attendance record.' });
  }
});

module.exports = router;
