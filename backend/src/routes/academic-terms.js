const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

const SEMESTERS = ['1st Semester', '2nd Semester', 'Summer'];

// "2026-2027" -> "2026–2027" (en dash), matching the format already used
// everywhere in the frontend's free-text term strings ("1st Semester, SY
// 2026–2027") so labels generated here read identically to the existing
// demo copy instead of introducing a second, slightly-different format.
function buildLabel(schoolYear, semester) {
  return semester + ', SY ' + String(schoolYear).replace('-', '\u2013');
}

function serialize(row) {
  return {
    id: String(row.id),
    schoolYear: row.school_year,
    semester: row.semester,
    label: row.label,
    status: row.status, // 'upcoming' | 'active' | 'closed'
    startsOn: row.starts_on,
    endsOn: row.ends_on,
    activatedAt: row.activated_at,
    closedAt: row.closed_at,
    createdAt: row.created_at
  };
}

router.use(requireAuth);

// GET /api/academic-terms — everyone signed in (students/teachers need to
// know what terms exist for display; only admin can mutate them below).
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM academic_terms ORDER BY school_year DESC, semester ASC`
    );
    return res.json({ academicTerms: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/academic-terms failed:', err);
    return res.status(500).json({ message: 'Could not load academic terms.' });
  }
});

// GET /api/academic-terms/active — the single term every other module
// (registration, enrollment, sections, schedules, attendance, grades)
// auto-stamps new records with. Returns { academicTerm: null } if the
// admin hasn't activated one yet, rather than a 404 — "no active term" is
// an expected, valid state, not an error condition.
router.get('/active', async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM academic_terms WHERE status = 'active' LIMIT 1`);
    return res.json({ academicTerm: rows[0] ? serialize(rows[0]) : null });
  } catch (err) {
    console.error('GET /api/academic-terms/active failed:', err);
    return res.status(500).json({ message: 'Could not load the active academic term.' });
  }
});

// POST /api/academic-terms — admin only. Creates a term as 'upcoming';
// use /:id/activate to make it the active one.
router.post('/', requireRole('admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const schoolYear = String(b.schoolYear || '').trim();
    const semester = String(b.semester || '').trim();

    if (!/^\d{4}-\d{4}$/.test(schoolYear)) {
      return res.status(400).json({ message: 'School year must look like 2026-2027.' });
    }
    if (!SEMESTERS.includes(semester)) {
      return res.status(400).json({ message: 'Semester must be one of: ' + SEMESTERS.join(', ') + '.' });
    }
    const [startYear, endYear] = schoolYear.split('-').map(Number);
    if (endYear !== startYear + 1) {
      return res.status(400).json({ message: 'School year must be two consecutive years, e.g. 2026-2027.' });
    }

    const label = buildLabel(schoolYear, semester);
    const [result] = await pool.query(
      `INSERT INTO academic_terms (school_year, semester, label, status, starts_on, ends_on)
       VALUES (?,?,?, 'upcoming', ?, ?)`,
      [schoolYear, semester, label, b.startsOn || null, b.endsOn || null]
    );
    const [rows] = await pool.query('SELECT * FROM academic_terms WHERE id = ?', [result.insertId]);
    return res.status(201).json({ academicTerm: serialize(rows[0]) });
  } catch (err) {
    if (err.errno === 1062) {
      return res.status(409).json({ message: 'That school year and semester already exists.' });
    }
    console.error('POST /api/academic-terms failed:', err);
    return res.status(500).json({ message: 'Could not create the academic term.' });
  }
});

// POST /api/academic-terms/:id/activate — admin only. Exactly one term is
// 'active' at a time: activating this one demotes whichever term (if any)
// was previously active back to 'upcoming' — it isn't auto-closed, since
// "close/archive" is its own deliberate action (below), separate from
// switching which term is current.
router.post('/:id/activate', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid academic term id.' });

    const [existing] = await pool.query('SELECT * FROM academic_terms WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Academic term not found.' });

    await pool.query(`UPDATE academic_terms SET status = 'upcoming' WHERE status = 'active' AND id <> ?`, [id]);
    await pool.query(`UPDATE academic_terms SET status = 'active', activated_at = NOW() WHERE id = ?`, [id]);

    const [rows] = await pool.query('SELECT * FROM academic_terms WHERE id = ?', [id]);
    return res.json({ academicTerm: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/academic-terms/:id/activate failed:', err);
    return res.status(500).json({ message: 'Could not activate that academic term.' });
  }
});

// POST /api/academic-terms/:id/close — admin only. Archives a term
// (typically the currently active one, at the end of a semester). Leaves
// no term active until admin explicitly activates the next one — records
// created in that gap simply get academic_term_id = NULL, same as before
// Academic Term Management existed.
router.post('/:id/close', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid academic term id.' });

    const [existing] = await pool.query('SELECT * FROM academic_terms WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Academic term not found.' });

    await pool.query(`UPDATE academic_terms SET status = 'closed', closed_at = NOW() WHERE id = ?`, [id]);
    const [rows] = await pool.query('SELECT * FROM academic_terms WHERE id = ?', [id]);
    return res.json({ academicTerm: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/academic-terms/:id/close failed:', err);
    return res.status(500).json({ message: 'Could not close that academic term.' });
  }
});

module.exports = router;
