const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');
const { getTeacherStudents } = require('../utils/teacherStudents');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    subject: row.subject,
    term: row.term, // grading PERIOD ('Midterm'/'Final') — see academicTermLabel for the school year/semester
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    academicTermLabel: row.academic_term_label || null,
    teacherEmail: row.teacher_email || '',
    teacherName: row.teacher_name || '',
    midterm: row.midterm === null ? null : Number(row.midterm),
    final: row.final === null ? null : Number(row.final),
    remarks: row.remarks || '',
    adminStatus: row.admin_status,
    enteredAt: row.entered_at,
    updatedAt: row.updated_at
  };
}

router.use(requireAuth);

// GET /api/grades — admin=all, teacher=own, student=own. Optional
// ?termId= scopes to one academic term; omitted (the default) still
// returns every term, same as before Academic Term Management existed.
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const base = `SELECT g.*, at.label AS academic_term_label FROM grades g LEFT JOIN academic_terms at ON at.id = g.academic_term_id`;
    const clauses = [];
    const params = [];
    if (role === 'teacher') { clauses.push('g.teacher_email = ?'); params.push(email); }
    else if (role !== 'admin') { clauses.push('g.student_email = ?'); params.push(email); }
    if (termId) { clauses.push('g.academic_term_id = ?'); params.push(termId); }
    const where = clauses.length ? ' WHERE ' + clauses.join(' AND ') : '';
    const [rows] = await pool.query(`${base}${where} ORDER BY g.updated_at DESC`, params);
    return res.json({ grades: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/grades failed:', err);
    return res.status(500).json({ message: 'Could not load grades.' });
  }
});

// POST /api/grades — teacher or admin
router.post('/', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const studentEmail = String(b.studentEmail || '').trim().toLowerCase();
    const studentName = String(b.studentName || '').trim();
    const subject = String(b.subject || '').trim();
    if (!studentEmail || !studentName || !subject) {
      return res.status(400).json({ message: 'Student, and subject are required.' });
    }

    // SECURITY: a teacher may only create a grade for a student actually on
    // their roster — otherwise any authenticated teacher could POST a grade
    // for an arbitrary student email they don't teach. Admins are unrestricted.
    if (req.user.role === 'teacher') {
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      if (!roster.has(studentEmail)) {
        return res.status(403).json({ message: 'That student isn\u2019t linked to you yet \u2014 check your Students tab.' });
      }
    }

    const teacherEmail = req.user.role === 'teacher' ? req.user.email : (b.teacherEmail || null);
    const teacherName = req.user.role === 'teacher' ? req.user.name : (b.teacherName || null);
    const activeTerm = await getActiveTerm();

    const [result] = await pool.query(
      `INSERT INTO grades
        (student_email, student_name, subject, term, academic_term_id, teacher_email, teacher_name, midterm, final, remarks, admin_status)
       VALUES (?,?,?,?,?,?,?,?,?,?, 'pending')`,
      [
        studentEmail, studentName, subject, b.term || 'Midterm', activeTerm ? activeTerm.id : null,
        teacherEmail, teacherName,
        b.midterm ?? null, b.final ?? null, b.remarks || null
      ]
    );
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [result.insertId]);
    return res.status(201).json({ grade: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/grades failed:', err);
    return res.status(500).json({ message: 'Could not create the grade record.' });
  }
});

// PUT /api/grades/:id — teacher (own) or admin
router.put('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });

    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Grade record not found.' });
    const cur = existing[0];
    if (req.user.role === 'teacher' && cur.teacher_email !== req.user.email) {
      return res.status(403).json({ message: 'You can only edit grades you entered.' });
    }

    const b = req.body || {};
    await pool.query(
      `UPDATE grades SET subject=?, term=?, midterm=?, final=?, remarks=? WHERE id=?`,
      [
        b.subject ?? cur.subject, b.term ?? cur.term,
        b.midterm !== undefined ? b.midterm : cur.midterm,
        b.final !== undefined ? b.final : cur.final,
        b.remarks !== undefined ? b.remarks : cur.remarks,
        id
      ]
    );
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    return res.json({ grade: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/grades/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the grade record.' });
  }
});

// POST /api/grades/:id/verify — admin only
router.post('/:id/verify', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });
    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Grade record not found.' });

    await pool.query(`UPDATE grades SET admin_status = 'verified' WHERE id = ?`, [id]);
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    return res.json({ grade: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/grades/:id/verify failed:', err);
    return res.status(500).json({ message: 'Could not verify the grade record.' });
  }
});

// DELETE /api/grades/:id — teacher (own) or admin
router.delete('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });

    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.json({ deleted: false });
    if (req.user.role === 'teacher' && existing[0].teacher_email !== req.user.email) {
      return res.status(403).json({ message: 'You can only delete grades you entered.' });
    }

    const [result] = await pool.query('DELETE FROM grades WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/grades/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the grade record.' });
  }
});

module.exports = router;
