const express = require('express');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getEnrollmentStatus, setEnrollmentOpen, getGradeWeights, setGradeWeights, resetGradeWeights, cleanWeights, cleanMaxScores, weightsTotal, weightsTotalIsExactly100 } = require('../utils/settings');

const router = express.Router();
router.use(requireAuth);

// GET /api/settings/enrollment — anyone signed in (students need to know
// whether they can enroll; admin needs it for the toggle).
router.get('/enrollment', async (req, res) => {
  try {
    return res.json(await getEnrollmentStatus());
  } catch (err) {
    console.error('GET /api/settings/enrollment failed:', err);
    return res.status(500).json({ message: 'Could not load the enrollment status.' });
  }
});

// PUT /api/settings/enrollment — admin only. Body: { open: true | false }
router.put('/enrollment', requireRole('admin'), async (req, res) => {
  try {
    const open = (req.body || {}).open;
    if (typeof open !== 'boolean') {
      return res.status(400).json({ message: 'Send { "open": true } or { "open": false }.' });
    }
    return res.json(await setEnrollmentOpen(open, req.user.email));
  } catch (err) {
    console.error('PUT /api/settings/enrollment failed:', err);
    return res.status(500).json({ message: 'Could not update the enrollment status.' });
  }
});

// ---- Grading settings (percentages) --------------------------------------
// RBAC, enforced here on the server for EVERY write, whatever the UI shows:
//   * GET  /api/settings/grade-weights        any signed-in user (teachers need
//                                             to SEE the percentages; read-only)
//   * every other method / sub-path           admin only -> 403 for anyone else
// This guard runs before the handlers, so a teacher (or student) gets 403 on
// PUT, POST, PATCH and DELETE alike, and no handler below can be reached.
router.use('/grade-weights', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (!req.user || req.user.role !== 'admin') {
    console.warn('[security] blocked grading-settings ' + req.method + ' from ' + (req.user && req.user.email) + ' (' + (req.user && req.user.role) + ')');
    return res.status(403).json({ message: 'Only an administrator can change the grading percentages.' });
  }
  return next();
});

// GET /api/settings/grade-weights — any signed-in user (read-only for teachers).
router.get('/grade-weights', async (req, res) => {
  try {
    return res.json(await getGradeWeights());
  } catch (err) {
    console.error('GET /api/settings/grade-weights failed:', err);
    return res.status(500).json({ message: 'Could not load the grade weights.' });
  }
});

// PUT /api/settings/grade-weights — admin only (re-checked by requireRole as well).
// Body: { weights: { quizzes (Participation), exam (Major Performance), assignments (Summative), attendance },
//         maxScores: { quizzes, assignments, attendance, exam }  (perfect scores, 1-999) }
// Every weight must be a number 0-100 and the total must be exactly 100.
// (A flat weights object without the wrapper is still accepted.)
router.put('/grade-weights', requireRole('admin'), async (req, res) => {
  try {
    const body = req.body || {};
    const weights = cleanWeights(body.weights || body);
    if (!weights) {
      return res.status(400).json({ message: 'Each percentage must be a number from 0 to 100.' });
    }
    if (!weightsTotalIsExactly100(weights)) {
      return res.status(400).json({ message: 'The percentages must add up to exactly 100% (currently ' + weightsTotal(weights) + '%).' });
    }
    let maxScores = null;
    if (body.maxScores !== undefined) {
      maxScores = cleanMaxScores(body.maxScores);
      if (!maxScores) return res.status(400).json({ message: 'Each perfect score must be a number greater than 0 and at most 999.' });
    }
    return res.json(await setGradeWeights(weights, maxScores, req.user.email));
  } catch (err) {
    console.error('PUT /api/settings/grade-weights failed:', err);
    return res.status(500).json({ message: 'Could not save the grade weights.' });
  }
});

// POST /api/settings/grade-weights/reset — admin only. Restores the default
// percentages (Participation 25, Major Performance 40, Summative 30, Attendance 5)
// and default perfect scores. Existing student grades are not touched.
router.post('/grade-weights/reset', requireRole('admin'), async (req, res) => {
  try {
    return res.json(await resetGradeWeights(req.user.email));
  } catch (err) {
    console.error('POST /api/settings/grade-weights/reset failed:', err);
    return res.status(500).json({ message: 'Could not reset the grade weights.' });
  }
});

module.exports = router;
