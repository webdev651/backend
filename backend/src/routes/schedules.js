const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

function serialize(row) {
  return {
    id: String(row.id),
    subject: row.subject,
    section: row.section,
    day: row.day,
    time: row.time,
    room: row.room || '',
    teacherName: row.teacher_name || '',
    teacherEmail: row.teacher_email || '',
    term: row.term || '',
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

// Any signed-in role can read the full schedule. Optional ?termId= scopes
// to one academic term; omitted (the default) still returns every term,
// same as before Academic Term Management existed.
router.get('/', requireAuth, async (req, res) => {
  try {
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const where = termId ? 'WHERE academic_term_id = ?' : '';
    const params = termId ? [termId] : [];
    const [rows] = await pool.query(`SELECT * FROM schedules ${where} ORDER BY subject ASC, section ASC`, params);
    return res.json({ schedules: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/schedules failed:', err);
    return res.status(500).json({ message: 'Could not load the schedule.' });
  }
});

// Only admin can add/update/remove.
router.use(requireAuth, requireAdmin);

router.post('/', async (req, res) => {
  try {
    const b = req.body || {};
    const subject = String(b.subject || '').trim();
    const day = String(b.day || '').trim();
    const time = String(b.time || '').trim();
    if (!subject || !day || !time) {
      return res.status(400).json({ message: 'Subject, day, and time are required.' });
    }
    const activeTerm = await getActiveTerm();
    const [result] = await pool.query(
      `INSERT INTO schedules (subject, section, day, time, room, teacher_name, teacher_email, term, academic_term_id)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [subject, b.section || 'Sec A', day, time, b.room || null, b.teacherName || null, b.teacherEmail || null, b.term || null, activeTerm ? activeTerm.id : null]
    );
    const [rows] = await pool.query('SELECT * FROM schedules WHERE id = ?', [result.insertId]);
    return res.status(201).json({ schedule: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/schedules failed:', err);
    return res.status(500).json({ message: 'Could not create the schedule entry.' });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid schedule id.' });
    const [existing] = await pool.query('SELECT * FROM schedules WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Schedule entry not found.' });

    const b = req.body || {};
    const cur = existing[0];
    await pool.query(
      `UPDATE schedules SET subject=?, section=?, day=?, time=?, room=?, teacher_name=?, teacher_email=?, term=? WHERE id=?`,
      [
        b.subject ?? cur.subject, b.section ?? cur.section, b.day ?? cur.day, b.time ?? cur.time,
        b.room ?? cur.room, b.teacherName ?? cur.teacher_name, b.teacherEmail ?? cur.teacher_email,
        b.term ?? cur.term, id
      ]
    );
    const [rows] = await pool.query('SELECT * FROM schedules WHERE id = ?', [id]);
    return res.json({ schedule: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/schedules/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the schedule entry.' });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid schedule id.' });
    const [result] = await pool.query('DELETE FROM schedules WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/schedules/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the schedule entry.' });
  }
});

module.exports = router;
