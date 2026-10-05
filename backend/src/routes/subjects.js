const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');

const router = express.Router();

function serialize(row, taken) {
  const slotsTotal = row.slots_total;
  const slotsLeft = Math.max(0, slotsTotal - (taken || 0));
  return {
    id: String(row.id),
    code: row.code,
    name: row.name,
    units: Number(row.units),
    teacherName: row.teacher_name || '',
    scheduleDay: row.schedule_day || '',
    scheduleTime: row.schedule_time || '',
    slotsTotal: slotsTotal,
    slotsLeft: slotsLeft,
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    createdAt: row.created_at
  };
}

router.use(requireAuth);

// GET /api/subjects — any signed-in role. This is what students' "Available
// subjects" list (Subject Enrollment page) reads live, instead of the
// hand-typed HTML checkboxes it used to ship with — an admin adding a
// subject here is what makes it show up there. Defaults to the active
// academic term; ?termId= overrides (e.g. admin reviewing another term).
router.get('/', async (req, res) => {
  try {
    let termId = req.query.termId ? Number(req.query.termId) : null;
    if (!req.query.termId) {
      const active = await getActiveTerm();
      termId = active ? active.id : null;
    }

    const [subjectRows] = termId
      ? await pool.query('SELECT * FROM subjects WHERE academic_term_id = ? ORDER BY code ASC', [termId])
      : await pool.query('SELECT * FROM subjects ORDER BY code ASC');

    // Slots taken = how many pending/approved enrollment requests already
    // include this subject's code, in the same term — tallied here rather
    // than in SQL since enrollments.subjects is a JSON array, not a join
    // table (see enrollments' schema.sql comment on that column).
    const [enrollRows] = termId
      ? await pool.query(
          `SELECT subjects FROM enrollments WHERE status IN ('pending','approved') AND academic_term_id = ?`,
          [termId]
        )
      : await pool.query(`SELECT subjects FROM enrollments WHERE status IN ('pending','approved')`);

    const taken = {};
    enrollRows.forEach((r) => {
      let subs = [];
      try { subs = JSON.parse(r.subjects || '[]'); } catch (e) { subs = []; }
      subs.forEach((s) => { if (s && s.code) taken[s.code] = (taken[s.code] || 0) + 1; });
    });

    return res.json({ subjects: subjectRows.map((row) => serialize(row, taken[row.code])) });
  } catch (err) {
    console.error('GET /api/subjects failed:', err);
    return res.status(500).json({ message: 'Could not load subjects.' });
  }
});

// POST /api/subjects — admin only. Defaults to the active academic term;
// admin can pass academicTermId to set up a future term's offerings ahead
// of activating it (same pattern as sections.js).
router.post('/', requireRole('admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const code = String(b.code || '').trim().toUpperCase();
    const name = String(b.name || '').trim();
    if (!code) return res.status(400).json({ message: 'Subject code is required.' });
    if (!name) return res.status(400).json({ message: 'Subject name is required.' });

    const units = Number(b.units);
    if (!Number.isFinite(units) || units <= 0 || units > 12) {
      return res.status(400).json({ message: 'Units must be a number between 0 and 12.' });
    }
    const slotsTotal = b.slotsTotal != null ? Number(b.slotsTotal) : 40;
    if (!Number.isInteger(slotsTotal) || slotsTotal < 0) {
      return res.status(400).json({ message: 'Slots must be a whole number.' });
    }

    let academicTermId = b.academicTermId ? Number(b.academicTermId) : null;
    if (!b.academicTermId) {
      const active = await getActiveTerm();
      academicTermId = active ? active.id : null;
    }

    const [result] = await pool.query(
      `INSERT INTO subjects (code, name, units, teacher_name, schedule_day, schedule_time, slots_total, academic_term_id)
       VALUES (?,?,?,?,?,?,?,?)`,
      [code, name, units, b.teacherName || null, b.scheduleDay || null, b.scheduleTime || null, slotsTotal, academicTermId]
    );
    const [rows] = await pool.query('SELECT * FROM subjects WHERE id = ?', [result.insertId]);
    return res.status(201).json({ subject: serialize(rows[0], 0) });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'That subject code already exists for this term.' });
    }
    console.error('POST /api/subjects failed:', err);
    return res.status(500).json({ message: 'Could not add the subject.' });
  }
});

// PUT /api/subjects/:id — admin only
router.put('/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid subject id.' });
    const [existing] = await pool.query('SELECT * FROM subjects WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Subject not found.' });

    const b = req.body || {};
    const code = b.code != null ? String(b.code).trim().toUpperCase() : existing[0].code;
    const name = b.name != null ? String(b.name).trim() : existing[0].name;
    if (!code) return res.status(400).json({ message: 'Subject code is required.' });
    if (!name) return res.status(400).json({ message: 'Subject name is required.' });

    let units = existing[0].units;
    if (b.units != null) {
      units = Number(b.units);
      if (!Number.isFinite(units) || units <= 0 || units > 12) {
        return res.status(400).json({ message: 'Units must be a number between 0 and 12.' });
      }
    }
    let slotsTotal = existing[0].slots_total;
    if (b.slotsTotal != null) {
      slotsTotal = Number(b.slotsTotal);
      if (!Number.isInteger(slotsTotal) || slotsTotal < 0) {
        return res.status(400).json({ message: 'Slots must be a whole number.' });
      }
    }

    await pool.query(
      `UPDATE subjects SET code=?, name=?, units=?, teacher_name=?, schedule_day=?, schedule_time=?, slots_total=? WHERE id=?`,
      [
        code, name, units,
        b.teacherName != null ? (b.teacherName || null) : existing[0].teacher_name,
        b.scheduleDay != null ? (b.scheduleDay || null) : existing[0].schedule_day,
        b.scheduleTime != null ? (b.scheduleTime || null) : existing[0].schedule_time,
        slotsTotal,
        id
      ]
    );
    const [rows] = await pool.query('SELECT * FROM subjects WHERE id = ?', [id]);
    return res.json({ subject: serialize(rows[0], 0) });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'That subject code already exists for this term.' });
    }
    console.error('PUT /api/subjects/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the subject.' });
  }
});

// DELETE /api/subjects/:id — admin only. Removes it from the catalog
// (future enrollment); existing enrollment requests keep their own JSON
// snapshot of {code,name,units} regardless, so past records are unaffected.
router.delete('/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid subject id.' });
    const [result] = await pool.query('DELETE FROM subjects WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/subjects/:id failed:', err);
    return res.status(500).json({ message: 'Could not remove the subject.' });
  }
});

module.exports = router;
