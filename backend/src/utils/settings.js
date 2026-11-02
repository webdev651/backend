const pool = require('../db');

/* Enrollment open/closed switch.
   Stored in app_settings as setting_key = 'enrollment_open' ('1' or '0').
   If there is no row yet, enrollment is OPEN — so nothing changes for an
   existing install until the admin closes it. */

async function getEnrollmentStatus() {
  const [rows] = await pool.query(
    `SELECT setting_value, updated_by, updated_at FROM app_settings WHERE setting_key = 'enrollment_open' LIMIT 1`
  );
  if (!rows.length) return { open: true, updatedBy: null, updatedAt: null };
  return {
    open: rows[0].setting_value !== '0',
    updatedBy: rows[0].updated_by || null,
    updatedAt: rows[0].updated_at || null
  };
}

async function setEnrollmentOpen(open, adminEmail) {
  await pool.query(
    `INSERT INTO app_settings (setting_key, setting_value, updated_by)
     VALUES ('enrollment_open', ?, ?)
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`,
    [open ? '1' : '0', adminEmail || null]
  );
  return getEnrollmentStatus();
}

/* Grading settings (admin-controlled, one set for the whole college).
   Stored in the existing app_settings table (the project's central settings
   table, which already records updated_by + updated_at) as
     setting_key = 'grade_weights'     -> the four grading percentages (JSON)
     setting_key = 'grade_max_scores'  -> the perfect score per component (JSON)
   so no duplicate "grading_settings" table is needed.

   Component keys (the keys match the existing grades-table columns, so no
   stored grade is touched; only the labels changed):
     quizzes     = Participation
     exam        = Major Performance
     assignments = Summative
     attendance  = Attendance
     activities  = retired: stays a valid key, always 0.
   If nothing has been saved yet the defaults below apply. */
const GRADE_WEIGHT_KEYS = ['quizzes', 'assignments', 'activities', 'attendance', 'exam'];
const DEFAULT_GRADE_WEIGHTS = { quizzes: 25, assignments: 30, activities: 0, attendance: 5, exam: 40 };

// A real number or a non-empty numeric string. Rejects null, '', booleans,
// arrays, objects, NaN and Infinity (Number() alone would turn several of
// those into 0 or 1 and let them through).
function strictNumber(raw) {
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : NaN;
  if (typeof raw === 'string' && /^\s*-?(\d+(\.\d+)?|\.\d+)\s*$/.test(raw)) return Number(raw);
  return NaN;
}

/* Returns the cleaned weights, or null if any weight is missing, non-numeric
   or outside 0-100. `activities` is retired and optional (defaults to 0). */
function cleanWeights(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const out = {};
  for (const k of GRADE_WEIGHT_KEYS) {
    const raw = obj[k];
    const blank = raw === undefined || raw === null || raw === '';
    const n = (k === 'activities' && blank) ? 0 : strictNumber(raw);
    if (!Number.isFinite(n) || n < 0 || n > 100) return null;
    out[k] = Math.round(n * 100) / 100;
  }
  return out;
}

/* Exact total check in whole hundredths, so 33.33 + 33.33 + 33.34 is exactly
   100 and floating-point noise can never let 99.99 or 100.01 through. */
function weightsTotalIsExactly100(weights) {
  const hundredths = GRADE_WEIGHT_KEYS.reduce((a, k) => a + Math.round(Number(weights[k]) * 100), 0);
  return hundredths === 10000;
}
function weightsTotal(weights) {
  return Math.round(GRADE_WEIGHT_KEYS.reduce((a, k) => a + Math.round(Number(weights[k]) * 100), 0)) / 100;
}

/* Perfect (highest possible) score per component. Every part is now out of 100
   (the per-item perfect scores live in each teacher's sheet layout, see
   routes/gradebook.js). Older meaning: Attendance 10 meant a teacher typed 8 for "8/10". Stored separately in app_settings as
   'grade_max_scores' (JSON). Exam is included too: the teacher sheet
   converts an exam score to a percentage (score / perfect x 100) before it is
   saved, so the Midterm/Final percentage the rest of the system reads is
   unaffected. `exam` is optional in the request (older clients) and defaults
   to 100. */
const MAX_SCORE_KEYS = ['quizzes', 'assignments', 'activities', 'attendance', 'exam'];
const DEFAULT_MAX_SCORES = { quizzes: 100, assignments: 100, activities: 100, attendance: 100, exam: 100 };

function cleanMaxScores(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const out = {};
  for (const k of MAX_SCORE_KEYS) {
    const raw = obj[k];
    if ((k === 'exam' || k === 'activities') && (raw === undefined || raw === null || raw === '')) { out[k] = 100; continue; }
    const n = strictNumber(raw);
    if (!Number.isFinite(n) || n <= 0 || n > 999) return null;
    out[k] = Math.round(n * 100) / 100;
  }
  return out;
}

async function getGradeWeights() {
  const [rows] = await pool.query(
    `SELECT setting_key, setting_value, updated_by, updated_at FROM app_settings WHERE setting_key IN ('grade_weights', 'grade_max_scores')`
  );
  const wRow = rows.find((r) => r.setting_key === 'grade_weights');
  const mRow = rows.find((r) => r.setting_key === 'grade_max_scores');
  let weights = { ...DEFAULT_GRADE_WEIGHTS };
  let maxScores = { ...DEFAULT_MAX_SCORES };
  // A stored set that is unreadable or does not total exactly 100 is ignored
  // (defaults apply) so a bad row can never skew every student's grade.
  if (wRow) { try { const p = cleanWeights(JSON.parse(wRow.setting_value)); if (p && weightsTotalIsExactly100(p)) weights = p; } catch (e) { /* defaults */ } }
  if (mRow) { try { const p = cleanMaxScores(JSON.parse(mRow.setting_value)); if (p) maxScores = p; } catch (e) { /* defaults */ } }
  const latest = [wRow, mRow].filter(Boolean).sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at))[0];
  return {
    weights,
    maxScores,
    defaults: { weights: { ...DEFAULT_GRADE_WEIGHTS }, maxScores: { ...DEFAULT_MAX_SCORES } },
    isDefault: !wRow && !mRow,
    updatedBy: latest ? latest.updated_by || null : null,
    updatedAt: latest ? latest.updated_at || null : null
  };
}

/* Both settings rows are written in ONE statement, so a teacher's gradebook
   can never read new percentages with old perfect scores (or the reverse). */
async function setGradeWeights(weights, maxScores, adminEmail) {
  const rows = [['grade_weights', JSON.stringify(weights), adminEmail || null]];
  if (maxScores) rows.push(['grade_max_scores', JSON.stringify(maxScores), adminEmail || null]);
  await pool.query(
    `INSERT INTO app_settings (setting_key, setting_value, updated_by) VALUES ${rows.map(() => '(?,?,?)').join(',')}
     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)`,
    rows.flat()
  );
  return getGradeWeights();
}

/* Admin "Reset to defaults": saves the default percentages AND perfect scores. */
async function resetGradeWeights(adminEmail) {
  return setGradeWeights({ ...DEFAULT_GRADE_WEIGHTS }, { ...DEFAULT_MAX_SCORES }, adminEmail);
}

/* Weighted term percentage for ONE saved grade row, using the given
   admin-configured settings ({ weights, maxScores } from getGradeWeights()).
     Final = sum( normalizedScore% x weight% )
   where normalizedScore% = score / perfectScore x 100 for Participation,
   Summative and Attendance. Major Performance is already stored as a
   percentage (it is saved as one so it also feeds the official Midterm/Final
   column), so it is not divided again. The Major Performance score is read
   from the column for the row's grading period (Midterm -> midterm,
   Final -> final, Prelim / Pre-Final -> exam).
   Returns a number (0-100, 2dp) or null when the weights do not total 100 or
   any weighted score is still missing (never treated as zero). */
const EXAM_FIELD_BY_PERIOD = { prelim: 'exam', midterm: 'midterm', 'pre-final': 'exam', final: 'final' };
function computeTermPercent(row, settings) {
  const weights = settings && settings.weights, maxScores = (settings && settings.maxScores) || DEFAULT_MAX_SCORES;
  if (!row || !weights || !weightsTotalIsExactly100(weights)) return null;
  const examCol = EXAM_FIELD_BY_PERIOD[String(row.term || '').trim().toLowerCase()] || 'exam';
  let sum = 0;
  for (const k of GRADE_WEIGHT_KEYS) {
    const w = Number(weights[k]) || 0;
    if (!w) continue;
    const raw = k === 'exam' ? row[examCol] : row[k];
    if (raw === null || raw === undefined || raw === '') return null;
    const score = Number(raw);
    if (!Number.isFinite(score)) return null;
    const pct = k === 'exam' ? score : (score / (Number(maxScores[k]) || 100)) * 100;
    sum += pct * w / 100;
  }
  return Math.round(sum * 100) / 100;
}

module.exports = {
  getEnrollmentStatus, setEnrollmentOpen,
  getGradeWeights, setGradeWeights, resetGradeWeights,
  cleanWeights, cleanMaxScores, weightsTotalIsExactly100, weightsTotal, computeTermPercent,
  DEFAULT_GRADE_WEIGHTS, DEFAULT_MAX_SCORES
};
