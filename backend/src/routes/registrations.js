const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    term: row.term,
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    yearLevel: row.year_level || '',
    type: row.type,
    status: row.status, // 'pending' | 'approved' | 'rejected' | 'correction_requested'
    adminNote: row.admin_note || '',
    submittedAt: row.submitted_at,
    decidedAt: row.decided_at
  };
}

router.use(requireAuth);

// GET /api/registrations — admin=all, student=own. Optional ?termId=
// scopes to one academic term; omitted (the default, and the only mode
// that existed before Academic Term Management) still returns every term.
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const clauses = [];
    const params = [];
    if (role !== 'admin') { clauses.push('student_email = ?'); params.push(email); }
    if (termId) { clauses.push('academic_term_id = ?'); params.push(termId); }
    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const [rows] = await pool.query(`SELECT * FROM registrations ${where} ORDER BY submitted_at DESC`, params);
    return res.json({ registrations: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/registrations failed:', err);
    return res.status(500).json({ message: 'Could not load registrations.' });
  }
});

// POST /api/registrations — student. Auto-stamped with whichever academic
// term is currently active (see src/utils/academicTerm.js) — the student
// still picks a display term string as before, but which *real* term the
// record belongs to is set by the admin's active-term setting, not by
// the student, so it can't end up filed under the wrong one.
router.post('/', requireRole('student'), async (req, res) => {
  try {
    const b = req.body || {};
    const term = String(b.term || '').trim();
    if (!term) return res.status(400).json({ message: 'Term is required.' });

    const activeTerm = await getActiveTerm();
    const [result] = await pool.query(
      `INSERT INTO registrations (student_email, student_name, term, academic_term_id, year_level, type, status)
       VALUES (?,?,?,?,?,?, 'pending')`,
      [req.user.email, req.user.name, term, activeTerm ? activeTerm.id : null, b.yearLevel || null, b.type || 'Regular']
    );
    const [rows] = await pool.query('SELECT * FROM registrations WHERE id = ?', [result.insertId]);
    return res.status(201).json({ registration: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/registrations failed:', err);
    return res.status(500).json({ message: 'Could not submit the registration.' });
  }
});

async function decide(req, res, newStatus) {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid registration id.' });
    const [existing] = await pool.query('SELECT * FROM registrations WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Registration not found.' });

    const note = String((req.body || {}).note || '').trim() || null;
    await pool.query('UPDATE registrations SET status=?, admin_note=?, decided_at=NOW() WHERE id=?', [newStatus, note, id]);
    const [rows] = await pool.query('SELECT * FROM registrations WHERE id = ?', [id]);
    return res.json({ registration: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/registrations/:id/' + newStatus + ' failed:', err);
    return res.status(500).json({ message: 'Could not update the registration.' });
  }
}

// POST /api/registrations/:id/approve — admin only
router.post('/:id/approve', requireRole('admin'), (req, res) => decide(req, res, 'approved'));
// POST /api/registrations/:id/reject — admin only. Optional { note } explains why.
router.post('/:id/reject', requireRole('admin'), (req, res) => decide(req, res, 'rejected'));
// POST /api/registrations/:id/request-correction — admin only. { note } is
// required — it's the whole point of this stage, telling the student what
// to fix (see PUT /:id below, where the student edits and resubmits it).
router.post('/:id/request-correction', requireRole('admin'), async (req, res) => {
  const note = String((req.body || {}).note || '').trim();
  if (!note) return res.status(400).json({ message: 'A note is required so the student knows what to fix.' });
  return decide(req, res, 'correction_requested');
});

// PUT /api/registrations/:id — the student edits and resubmits their own
// registration after a correction was requested (or while still pending).
// Resubmitting clears admin_note and returns the record to 'pending' so it
// re-enters admin's review queue — the same registration row moves through
// pending → correction_requested → pending → approved/rejected rather than
// spawning a second, disconnected request.
router.put('/:id', requireRole('student'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid registration id.' });
    const [existing] = await pool.query('SELECT * FROM registrations WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Registration not found.' });
    if (existing[0].student_email.toLowerCase() !== req.user.email.toLowerCase()) {
      return res.status(403).json({ message: 'You can only edit your own registration.' });
    }
    if (existing[0].status !== 'pending' && existing[0].status !== 'correction_requested') {
      return res.status(409).json({ message: 'This registration has already been decided and can no longer be edited.' });
    }

    const b = req.body || {};
    const term = String(b.term || existing[0].term || '').trim();
    if (!term) return res.status(400).json({ message: 'Term is required.' });

    await pool.query(
      `UPDATE registrations SET term=?, year_level=?, type=?, status='pending', admin_note=NULL WHERE id=?`,
      [term, b.yearLevel != null ? (b.yearLevel || null) : existing[0].year_level, b.type || existing[0].type, id]
    );
    const [rows] = await pool.query('SELECT * FROM registrations WHERE id = ?', [id]);
    return res.json({ registration: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/registrations/:id failed:', err);
    return res.status(500).json({ message: 'Could not resubmit the registration.' });
  }
});

module.exports = router;
