const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    name: row.name,
    email: row.email || '',
    department: row.department || '',
    subjects: row.subjects || '',
    load: row.load_sections || '',
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

// Admin-only staff directory management.
router.use(requireAuth, requireAdmin);

router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM staff ORDER BY name ASC');
    return res.json({ staff: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/staff failed:', err);
    return res.status(500).json({ message: 'Could not load staff.' });
  }
});

router.post('/', async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    if (!name) return res.status(400).json({ message: 'Name is required.' });

    const [result] = await pool.query(
      `INSERT INTO staff (name, email, department, subjects, load_sections) VALUES (?,?,?,?,?)`,
      [name, b.email || null, b.department || null, b.subjects || null, b.load || null]
    );
    const [rows] = await pool.query('SELECT * FROM staff WHERE id = ?', [result.insertId]);
    return res.status(201).json({ staff: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/staff failed:', err);
    return res.status(500).json({ message: 'Could not create the staff record.' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid staff id.' });
    const [existing] = await pool.query('SELECT * FROM staff WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Staff record not found.' });

    const b = req.body || {};
    const cur = existing[0];
    await pool.query(
      'UPDATE staff SET name=?, email=?, department=?, subjects=?, load_sections=? WHERE id=?',
      [
        b.name ?? cur.name, b.email ?? cur.email, b.department ?? cur.department,
        b.subjects ?? cur.subjects, b.load ?? cur.load_sections, id
      ]
    );
    const [rows] = await pool.query('SELECT * FROM staff WHERE id = ?', [id]);
    return res.json({ staff: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/staff/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the staff record.' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid staff id.' });
    const [result] = await pool.query('DELETE FROM staff WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/staff/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the staff record.' });
  }
});

module.exports = router;
