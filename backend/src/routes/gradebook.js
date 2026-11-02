const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth, requireRole('teacher'));

/* Spreadsheet gradebook layout, saved per teacher + subject + semester + grading term:
   how many item columns each part has and each item's perfect score.
   config = { items: { quizzes: [{max}], exam: [{max}], assignments: [{max}], attendance: [{max}] } } */
const GROUPS = ['quizzes', 'exam', 'assignments', 'attendance'];
const PERIODS = ['Prelim', 'Midterm', 'Pre-Final', 'Final'];

function normKey(v) { return String(v == null ? '' : v).trim().toLowerCase().slice(0, 150); }

function cleanConfig(c) {
  if (!c || typeof c !== 'object' || !c.items || typeof c.items !== 'object') return null;
  const out = { items: {} };
  for (const g of GROUPS) {
    const arr = c.items[g];
    if (!Array.isArray(arr) || arr.length < 1 || arr.length > 10) return null;
    out.items[g] = [];
    for (const it of arr) {
      const n = Number(it && typeof it === 'object' ? it.max : it);
      if (!Number.isFinite(n) || n <= 0 || n > 9999) return null;
      out.items[g].push({ max: Math.round(n * 100) / 100 });
    }
  }
  return out;
}

// GET /api/gradebook/config?subject=&academicTermId=  ->  { configs: { Prelim: {...}, Midterm: {...} } }  (only saved ones)
router.get('/config', async (req, res) => {
  try {
    const subject = normKey(req.query.subject);
    if (!subject) return res.status(400).json({ message: 'Subject is required.' });
    const termId = Number(req.query.academicTermId) || 0;
    const [rows] = await pool.query(
      'SELECT period, config FROM gradebook_configs WHERE teacher_email = ? AND subject_key = ? AND academic_term_id = ?',
      [req.user.email, subject, termId]
    );
    const configs = {};
    for (const r of rows) { try { const c = cleanConfig(JSON.parse(r.config)); if (c) configs[r.period] = c; } catch (e) { /* skip */ } }
    return res.json({ configs });
  } catch (err) {
    console.error('GET /api/gradebook/config failed:', err);
    return res.status(500).json({ message: 'Could not load the sheet layout.' });
  }
});

// PUT /api/gradebook/config  body: { subject, academicTermId, period, config }
router.put('/config', async (req, res) => {
  try {
    const b = req.body || {};
    const subject = normKey(b.subject);
    if (!subject) return res.status(400).json({ message: 'Subject is required.' });
    if (PERIODS.indexOf(b.period) < 0) return res.status(400).json({ message: 'Grading term must be one of: ' + PERIODS.join(', ') + '.' });
    const config = cleanConfig(b.config);
    if (!config) return res.status(400).json({ message: 'Each part needs 1 to 10 item columns, each with a perfect score above 0.' });
    const termId = Number(b.academicTermId) || 0;
    await pool.query(
      `INSERT INTO gradebook_configs (teacher_email, subject_key, academic_term_id, period, config)
       VALUES (?,?,?,?,?)
       ON DUPLICATE KEY UPDATE config = VALUES(config)`,
      [req.user.email, subject, termId, b.period, JSON.stringify(config)]
    );
    return res.json({ config });
  } catch (err) {
    console.error('PUT /api/gradebook/config failed:', err);
    return res.status(500).json({ message: 'Could not save the sheet layout.' });
  }
});

module.exports = router;
