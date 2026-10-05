const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

function serialize(row) {
  let subjects = [];
  try { subjects = typeof row.subjects === 'string' ? JSON.parse(row.subjects) : (row.subjects || []); }
  catch (e) { subjects = []; }
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    term: row.term || '',
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    subjects,
    totalUnits: row.total_units,
    status: row.status, // 'pending' | 'approved' | 'rejected' | 'correction_requested'
    adminNote: row.admin_note || '',
    source: row.source,
    submittedAt: row.submitted_at,
    decidedAt: row.decided_at
  };
}

function computeUnits(subjects) {
  if (!Array.isArray(subjects)) return 0;
  return subjects.reduce((sum, s) => sum + (Number(s && s.units) || 0), 0);
}

router.use(requireAuth);

// GET /api/enrollments — admin=all, student=own. Optional ?termId= scopes
// to one academic term; omitted (the default) still returns every term,
// same as before Academic Term Management existed.
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const clauses = [];
    const params = [];
    if (role !== 'admin') { clauses.push('student_email = ?'); params.push(email); }
    if (termId) { clauses.push('academic_term_id = ?'); params.push(termId); }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const [rows] = await pool.query(`SELECT * FROM enrollments ${where} ORDER BY submitted_at DESC`, params);
    return res.json({ enrollments: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/enrollments failed:', err);
    return res.status(500).json({ message: 'Could not load enrollments.' });
  }
});

// POST /api/enrollments — student request
router.post('/', requireRole('student'), async (req, res) => {
  try {
    const b = req.body || {};
    const subjects = Array.isArray(b.subjects) ? b.subjects : [];
    const activeTerm = await getActiveTerm();
    const [result] = await pool.query(
      `INSERT INTO enrollments (student_email, student_name, term, academic_term_id, subjects, total_units, status, source)
       VALUES (?,?,?,?,?,?, 'pending', 'request')`,
      [req.user.email, req.user.name, b.term || null, activeTerm ? activeTerm.id : null, JSON.stringify(subjects), computeUnits(subjects)]
    );
    const [rows] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [result.insertId]);
    return res.status(201).json({ enrollment: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/enrollments failed:', err);
    return res.status(500).json({ message: 'Could not submit the enrollment request.' });
  }
});

// POST /api/enrollments/assign — admin assigns directly, pre-approved
router.post('/assign', requireRole('admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const studentEmail = String(b.studentEmail || '').trim().toLowerCase();
    const studentName = String(b.studentName || '').trim();
    if (!studentEmail || !studentName) {
      return res.status(400).json({ message: 'Student is required.' });
    }
    const subjects = Array.isArray(b.subjects) ? b.subjects : [];
    const activeTerm = await getActiveTerm();
    const [result] = await pool.query(
      `INSERT INTO enrollments (student_email, student_name, term, academic_term_id, subjects, total_units, status, source, decided_at)
       VALUES (?,?,?,?,?,?, 'approved', 'assigned', NOW())`,
      [studentEmail, studentName, b.term || null, activeTerm ? activeTerm.id : null, JSON.stringify(subjects), computeUnits(subjects)]
    );
    const [rows] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [result.insertId]);
    return res.status(201).json({ enrollment: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/enrollments/assign failed:', err);
    return res.status(500).json({ message: 'Could not assign the enrollment.' });
  }
});

async function decide(req, res, newStatus) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid enrollment id.' });
    const [existing] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Enrollment not found.' });

    const note = String((req.body || {}).note || '').trim() || null;
    await pool.query('UPDATE enrollments SET status=?, admin_note=?, decided_at=NOW() WHERE id=?', [newStatus, note, id]);
    const [rows] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [id]);
    return res.json({ enrollment: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/enrollments/:id/' + newStatus + ' failed:', err);
    return res.status(500).json({ message: 'Could not update the enrollment.' });
  }
}

// POST /api/enrollments/:id/approve — admin only
router.post('/:id/approve', requireRole('admin'), (req, res) => decide(req, res, 'approved'));
// POST /api/enrollments/:id/reject — admin only. Optional { note } explains why.
router.post('/:id/reject', requireRole('admin'), (req, res) => decide(req, res, 'rejected'));
// POST /api/enrollments/:id/request-correction — admin only. { note } is
// required — it tells the student what subjects/units to fix before
// resubmitting via PUT /:id below.
router.post('/:id/request-correction', requireRole('admin'), async (req, res) => {
  const note = String((req.body || {}).note || '').trim();
  if (!note) return res.status(400).json({ message: 'A note is required so the student knows what to fix.' });
  return decide(req, res, 'correction_requested');
});

// PUT /api/enrollments/:id — the student edits and resubmits their own
// enrollment request after a correction was requested (or while still
// pending). Same record moves pending → correction_requested → pending →
// approved/rejected instead of spawning a second, disconnected request.
router.put('/:id', requireRole('student'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid enrollment id.' });
    const [existing] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Enrollment not found.' });
    if (existing[0].student_email.toLowerCase() !== req.user.email.toLowerCase()) {
      return res.status(403).json({ message: 'You can only edit your own enrollment request.' });
    }
    if (existing[0].status !== 'pending' && existing[0].status !== 'correction_requested') {
      return res.status(409).json({ message: 'This enrollment has already been decided and can no longer be edited.' });
    }

    const b = req.body || {};
    const subjects = Array.isArray(b.subjects) ? b.subjects : JSON.parse(existing[0].subjects || '[]');
    await pool.query(
      `UPDATE enrollments SET term=?, subjects=?, total_units=?, status='pending', admin_note=NULL WHERE id=?`,
      [b.term != null ? b.term : existing[0].term, JSON.stringify(subjects), computeUnits(subjects), id]
    );
    const [rows] = await pool.query('SELECT * FROM enrollments WHERE id = ?', [id]);
    return res.json({ enrollment: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/enrollments/:id failed:', err);
    return res.status(500).json({ message: 'Could not resubmit the enrollment.' });
  }
});

module.exports = router;
