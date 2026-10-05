const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    name: row.name,
    email: row.email || '',
    role: row.role,
    category: row.category,
    subject: row.subject || '',
    message: row.message,
    status: row.status,
    response: row.response || '',
    submittedAt: row.submitted_at,
    respondedAt: row.responded_at
  };
}

router.use(requireAuth);

// GET /api/feedback — admin=all, else own
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    let rows;
    if (role === 'admin') {
      [rows] = await pool.query('SELECT * FROM feedback ORDER BY submitted_at DESC');
    } else {
      [rows] = await pool.query('SELECT * FROM feedback WHERE email = ? ORDER BY submitted_at DESC', [email]);
    }
    return res.json({ feedback: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/feedback failed:', err);
    return res.status(500).json({ message: 'Could not load feedback.' });
  }
});

// POST /api/feedback — student or teacher
router.post('/', requireRole('student', 'teacher'), async (req, res) => {
  try {
    const b = req.body || {};
    const message = String(b.message || '').trim();
    if (!message) return res.status(400).json({ message: 'Message is required.' });

    const [result] = await pool.query(
      `INSERT INTO feedback (name, email, role, category, subject, message, status)
       VALUES (?,?,?,?,?,?, 'new')`,
      [req.user.name, req.user.email, req.user.role, b.category || 'General', b.subject || null, message]
    );
    const [rows] = await pool.query('SELECT * FROM feedback WHERE id = ?', [result.insertId]);
    return res.status(201).json({ feedback: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/feedback failed:', err);
    return res.status(500).json({ message: 'Could not submit feedback.' });
  }
});

// POST /api/feedback/:id/respond — admin only
router.post('/:id/respond', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid feedback id.' });
    const [existing] = await pool.query('SELECT * FROM feedback WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Feedback not found.' });

    const response = String((req.body || {}).response || '').trim();
    await pool.query(
      `UPDATE feedback SET response=?, status='resolved', responded_at=NOW() WHERE id=?`,
      [response, id]
    );
    const [rows] = await pool.query('SELECT * FROM feedback WHERE id = ?', [id]);
    return res.json({ feedback: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/feedback/:id/respond failed:', err);
    return res.status(500).json({ message: 'Could not respond to this feedback.' });
  }
});

// DELETE /api/feedback/:id — admin only
router.delete('/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid feedback id.' });
    const [result] = await pool.query('DELETE FROM feedback WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/feedback/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete this feedback.' });
  }
});

module.exports = router;
