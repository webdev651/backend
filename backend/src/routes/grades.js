const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getActiveTerm } = require('../utils/academicTerm');
const { getTeacherStudents, getTeacherSubjectNames } = require('../utils/teacherStudents');
const { getGradeWeights, computeTermPercent } = require('../utils/settings');

const router = express.Router();

// Midterm / Final / Exam scores are percentages (the college-scale conversion
// in frontend/js/modules/grades.js is only defined for 0-100). Quizzes,
// Summative, Activities and Attendance are raw scores out of the perfect score
// the admin set (Admin > Grades > Grade weights); `max` is that perfect score.
// '' / null / undefined mean "not entered yet" and are stored as NULL.
function parseScore(value, label, max = 100) {
  if (value === undefined) return { value: undefined };
  if (value === null || value === '') return { value: null };
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > max) {
    return { error: label + ' must be a number from 0 to ' + max + '.' };
  }
  return { value: n };
}

function serialize(row, settings) {
  return {
    id: String(row.id),
    studentEmail: row.student_email,
    studentName: row.student_name,
    subject: row.subject,
    term: row.term, // grading PERIOD ('Midterm'/'Final') — see academicTermLabel for the school year/semester
    academicTermId: row.academic_term_id ? String(row.academic_term_id) : null,
    academicTermLabel: row.academic_term_label || null,
    teacherEmail: row.teacher_email || '',
    teacherName: row.teacher_name || '',
    quizzes: row.quizzes === null || row.quizzes === undefined ? null : Number(row.quizzes),
    assignments: row.assignments === null || row.assignments === undefined ? null : Number(row.assignments),
    activities: row.activities === null || row.activities === undefined ? null : Number(row.activities),
    attendance: row.attendance === null || row.attendance === undefined ? null : Number(row.attendance),
    exam: row.exam === null || row.exam === undefined ? null : Number(row.exam),
    midterm: row.midterm === null ? null : Number(row.midterm),
    final: row.final === null ? null : Number(row.final),
    remarks: row.remarks || '',
    details: parseDetailsOut(row.details),
    adminStatus: row.admin_status,
    locked: isLocked(row),
    // Weighted Term Grade (%) from the admin's CURRENT percentages, computed on read
    // (never stored), so a percentage change applies to every record immediately and
    // no saved score is altered. null = a weighted score is still missing.
    termPercent: settings ? computeTermPercent(row, settings) : undefined,
    enteredAt: row.entered_at,
    updatedAt: row.updated_at
  };
}

/* Per-item scores from the spreadsheet gradebook (e.g. Participation item 1 and 2),
   kept as JSON text in grades.details: { scores: { quizzes: [n|null, ...], exam: [...], assignments: [...], attendance: [...] } }.
   The existing percentage columns keep holding each part's %EQ, so every other screen is unaffected. */
const DETAIL_GROUPS = ['quizzes', 'assignments', 'attendance', 'exam'];
function parseDetailsOut(text) {
  if (!text) return null;
  try { const o = JSON.parse(text); return o && typeof o === 'object' ? o : null; } catch (e) { return null; }
}
function parseDetails(v) {
  if (v === undefined) return { value: undefined };
  if (v === null || v === '') return { value: null };
  let o = v;
  if (typeof v === 'string') { try { o = JSON.parse(v); } catch (e) { return { error: 'The item scores are not valid.' }; } }
  if (!o || typeof o !== 'object' || Array.isArray(o) || !o.scores || typeof o.scores !== 'object') return { error: 'The item scores are not valid.' };
  const clean = { scores: {} };
  for (const k of DETAIL_GROUPS) {
    const arr = o.scores[k];
    if (arr === undefined) continue;
    if (!Array.isArray(arr) || arr.length > 12) return { error: 'The item scores are not valid.' };
    const out = [];
    for (const x of arr) {
      if (x === null || x === '') { out.push(null); continue; }
      const n = Number(x);
      if (!Number.isFinite(n) || n < 0 || n > 99999) return { error: 'Each item score must be a number from 0 to 99999.' };
      out.push(Math.round(n * 100) / 100);
    }
    clean.scores[k] = out;
  }
  const text = JSON.stringify(clean);
  if (text.length > 2000) return { error: 'The item scores are too large.' };
  return { value: text };
}

const SCORE_FIELDS = ['quizzes', 'assignments', 'activities', 'attendance', 'exam', 'midterm', 'final', 'remarks'];
const VALID_PERIODS = ['Prelim', 'Midterm', 'Pre-Final', 'Final'];

function normKey(v) { return String(v == null ? '' : v).trim().toLowerCase(); }
function cleanReason(v) { const t = String(v == null ? '' : v).trim(); return t ? t.slice(0, 255) : ''; }

// Grades are LOCKED once an admin has verified them (admin_status = 'verified').
// Teachers can no longer edit or delete a locked grade; an admin must reopen it
// first (POST /api/grades/:id/reopen, which requires a reason and is logged).
function isLocked(row) { return row && row.admin_status === 'verified'; }

// Append-only history. A failure to write history must never be silent about
// the grade write that already happened, but also must not crash the request.
async function logAudit(user, row, action, changes, reason, conn) {
  try {
    await (conn || pool).query(
      `INSERT INTO grade_audit_log
        (grade_id, student_email, subject, term, action, changes, reason, changed_by_email, changed_by_name, changed_by_role)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        row.id, row.student_email || null, row.subject || null, row.term || null, action,
        changes && Object.keys(changes).length ? JSON.stringify(changes) : null,
        reason || null, user.email || null, user.name || null, user.role || null
      ]
    );
  } catch (err) {
    console.error('[grades] could not write grade_audit_log:', err.message);
  }
}

// { field: { from, to } } for every field that actually changed.
function diffRows(before, after) {
  const out = {};
  for (const f of ['subject', 'term', ...SCORE_FIELDS, 'details']) {
    const a = before[f] === undefined ? null : before[f];
    const b = after[f] === undefined ? null : after[f];
    const na = a === null ? null : (f === 'remarks' || f === 'subject' || f === 'term' || f === 'details' ? String(a) : Number(a));
    const nb = b === null ? null : (f === 'remarks' || f === 'subject' || f === 'term' || f === 'details' ? String(b) : Number(b));
    if (na !== nb && !(na === null && nb === '') && !(na === '' && nb === null)) out[f] = f === 'details' ? { from: na === null ? null : 'item scores', to: nb === null ? null : 'updated item scores' } : { from: na, to: nb };
  }
  return out;
}

// Same student + subject + grading period + semester must never exist twice.
async function findDuplicate(studentEmail, subject, term, academicTermId, excludeId) {
  const [rows] = await pool.query(
    `SELECT id FROM grades
     WHERE LOWER(student_email) = ? AND LOWER(subject) = ? AND LOWER(term) = ?
       AND (academic_term_id <=> ?) ${excludeId ? 'AND id <> ?' : ''} LIMIT 1`,
    excludeId
      ? [normKey(studentEmail), normKey(subject), normKey(term), academicTermId || null, excludeId]
      : [normKey(studentEmail), normKey(subject), normKey(term), academicTermId || null]
  );
  return rows.length ? rows[0].id : null;
}

// A teacher may only grade subjects they actually teach: a subject on their
// Class Schedule, or one they have already graded. (If the teacher has no
// schedule entries at all, the existing roster check remains the gate, so
// nothing that worked before is newly blocked.)
async function teacherMaySubject(user, subject) {
  const key = normKey(subject);
  const sched = await getTeacherSubjectNames(user.email, user.name);
  if (!sched.length) return true;
  if (sched.some((s) => s.key === key)) return true;
  const [rows] = await pool.query(
    'SELECT 1 FROM grades WHERE teacher_email = ? AND LOWER(subject) = ? LIMIT 1', [user.email, key]
  );
  return rows.length > 0;
}

function parseAll(b, maxScores) {
  const r = {
    midterm: parseScore(b.midterm, 'Midterm score'),
    final: parseScore(b.final, 'Final score'),
    quizzes: parseScore(b.quizzes, 'Participation score', maxScores.quizzes),
    assignments: parseScore(b.assignments, 'Summative score', maxScores.assignments),
    activities: parseScore(b.activities, 'Activities score', maxScores.activities),
    attendance: parseScore(b.attendance, 'Attendance score', maxScores.attendance),
    exam: parseScore(b.exam, 'Exam score'),
    details: parseDetails(b.details)
  };
  const bad = Object.values(r).map((x) => x.error).filter(Boolean)[0];
  return { r, bad };
}

router.use(requireAuth);

// GET /api/grades — admin=all, teacher=own, student=own PUBLISHED (verified)
// grades only. Optional ?termId= scopes to one academic term; omitted still
// returns every term, same as before Academic Term Management existed.
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    const termId = req.query.termId ? Number(req.query.termId) : null;
    const base = `SELECT g.*, at.label AS academic_term_label FROM grades g LEFT JOIN academic_terms at ON at.id = g.academic_term_id`;
    const clauses = [];
    const params = [];
    if (role === 'teacher') { clauses.push('g.teacher_email = ?'); params.push(email); }
    else if (role !== 'admin') {
      // PRIVACY: a student sees only their own grades, and only once an admin
      // has verified (published) them — never drafts / pending entries.
      clauses.push('LOWER(g.student_email) = ?'); params.push(normKey(email));
      clauses.push(`g.admin_status = 'verified'`);
    }
    if (termId) { clauses.push('g.academic_term_id = ?'); params.push(termId); }
    const where = clauses.length ? ' WHERE ' + clauses.join(' AND ') : '';
    const [rows] = await pool.query(`${base}${where} ORDER BY g.updated_at DESC`, params);
    const settings = await getGradeWeights();
    return res.json({ grades: rows.map((r) => serialize(r, settings)) });
  } catch (err) {
    console.error('GET /api/grades failed:', err);
    return res.status(500).json({ message: 'Could not load grades.' });
  }
});

// GET /api/grades/:id/history — audit trail. Admin: any grade. Teacher: only their own.
router.get('/:id/history', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });
    if (req.user.role === 'teacher') {
      const [g] = await pool.query('SELECT teacher_email FROM grades WHERE id = ?', [id]);
      // A deleted grade has no owner row left; fall back to who logged against it.
      let owns = g.length && g[0].teacher_email === req.user.email;
      if (!g.length) {
        const [a] = await pool.query(
          `SELECT 1 FROM grade_audit_log WHERE grade_id = ? AND changed_by_email = ? AND action = 'create' LIMIT 1`, [id, req.user.email]);
        owns = a.length > 0;
      }
      if (!owns) return res.status(403).json({ message: 'You can only view the history of grades you entered.' });
    }
    const [rows] = await pool.query(
      `SELECT id, action, changes, reason, changed_by_email, changed_by_name, changed_by_role, created_at
       FROM grade_audit_log WHERE grade_id = ? ORDER BY id DESC LIMIT 200`, [id]);
    return res.json({
      history: rows.map((r) => {
        let changes = r.changes;
        if (typeof changes === 'string') { try { changes = JSON.parse(changes); } catch (e) { changes = null; } }
        return {
          id: String(r.id), action: r.action, changes: changes || {}, reason: r.reason || '',
          by: r.changed_by_name || r.changed_by_email || '', byEmail: r.changed_by_email || '',
          role: r.changed_by_role || '', at: r.created_at
        };
      })
    });
  } catch (err) {
    console.error('GET /api/grades/:id/history failed:', err);
    return res.status(500).json({ message: 'Could not load the grade history.' });
  }
});

// POST /api/grades — teacher or admin
router.post('/', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const studentEmail = String(b.studentEmail || '').trim().toLowerCase();
    const studentName = String(b.studentName || '').trim();
    const subject = String(b.subject || '').trim();
    const term = String(b.term || 'Midterm').trim();
    if (!studentEmail || !studentName || !subject) {
      return res.status(400).json({ message: 'Student, and subject are required.' });
    }
    if (VALID_PERIODS.map(normKey).indexOf(normKey(term)) === -1) {
      return res.status(400).json({ message: 'Grading term must be one of: ' + VALID_PERIODS.join(', ') + '.' });
    }

    // SECURITY: a teacher may only create a grade for a student actually on
    // their roster AND for a subject they actually teach. Admins are unrestricted.
    if (req.user.role === 'teacher') {
      const roster = await getTeacherStudents(req.user.email, req.user.name);
      if (!roster.has(studentEmail)) {
        return res.status(403).json({ message: 'That student isn\u2019t linked to you yet \u2014 check your Students tab.' });
      }
      if (!(await teacherMaySubject(req.user, subject))) {
        return res.status(403).json({ message: 'You can only enter grades for subjects on your Class Schedule.' });
      }
    }

    const { maxScores } = await getGradeWeights();
    const { r, bad } = parseAll(b, maxScores);
    if (bad) return res.status(400).json({ message: bad });

    const teacherEmail = req.user.role === 'teacher' ? req.user.email : (b.teacherEmail || null);
    const teacherName = req.user.role === 'teacher' ? req.user.name : (b.teacherName || null);
    const activeTerm = await getActiveTerm();
    const termId = activeTerm ? activeTerm.id : null;

    // Never create a second record for the same student/subject/period/semester.
    const dupId = await findDuplicate(studentEmail, subject, term, termId, null);
    if (dupId) {
      return res.status(409).json({ message: 'A grade record for this student, subject and grading term already exists. Edit that record instead of creating a new one.', existingId: String(dupId) });
    }

    const [result] = await pool.query(
      `INSERT INTO grades
        (student_email, student_name, subject, term, academic_term_id, teacher_email, teacher_name, quizzes, assignments, activities, attendance, exam, midterm, final, remarks, details, admin_status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending')`,
      [
        studentEmail, studentName, subject, term, termId,
        teacherEmail, teacherName,
        r.quizzes.value ?? null, r.assignments.value ?? null, r.activities.value ?? null, r.attendance.value ?? null, r.exam.value ?? null,
        r.midterm.value ?? null, r.final.value ?? null, b.remarks || null, r.details.value ?? null
      ]
    );
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [result.insertId]);
    const blank = { subject: null, term: null };
    await logAudit(req.user, rows[0], 'create', diffRows(blank, rows[0]), cleanReason(b.reason));
    return res.status(201).json({ grade: serialize(rows[0], await getGradeWeights()) });
  } catch (err) {
    console.error('POST /api/grades failed:', err);
    return res.status(500).json({ message: 'Could not create the grade record.' });
  }
});

// PUT /api/grades/:id — teacher (own, not locked) or admin (reason required if locked)
router.put('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });

    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Grade record not found.' });
    const cur = existing[0];
    if (req.user.role === 'teacher' && cur.teacher_email !== req.user.email) {
      return res.status(403).json({ message: 'You can only edit grades you entered.' });
    }

    const b = req.body || {};
    const reason = cleanReason(b.reason);

    // LOCK: verified (published) grades cannot be changed by a teacher at all,
    // and an admin must say why — so nothing is overwritten silently.
    if (isLocked(cur)) {
      if (req.user.role === 'teacher') {
        return res.status(423).json({ message: 'This grade has been verified and is locked. Ask an administrator to reopen it before making changes.' });
      }
      if (!reason) {
        return res.status(400).json({ message: 'This grade is verified and locked. Enter a reason to change it.' });
      }
    }

    // Optimistic concurrency (optional): if the client says which version it
    // loaded and someone changed the record since, refuse instead of overwriting.
    if (b.expectedUpdatedAt) {
      const a = new Date(b.expectedUpdatedAt).getTime(), c = new Date(cur.updated_at).getTime();
      if (Number.isFinite(a) && Math.abs(a - c) > 1000) {
        return res.status(409).json({ message: 'This grade was changed by someone else after you loaded it. Reload the sheet and review it before saving.' });
      }
    }

    const { maxScores } = await getGradeWeights();
    const { r, bad } = parseAll(b, maxScores);
    if (bad) return res.status(400).json({ message: bad });

    const newSubject = b.subject !== undefined ? String(b.subject).trim() : cur.subject;
    const newTerm = b.term !== undefined ? String(b.term).trim() : cur.term;
    if (!newSubject) return res.status(400).json({ message: 'Subject cannot be empty.' });
    // Only validate the term when it is being changed, so older records that
    // carry a legacy free-text term can still have their scores edited.
    if (normKey(newTerm) !== normKey(cur.term) && VALID_PERIODS.map(normKey).indexOf(normKey(newTerm)) === -1) {
      return res.status(400).json({ message: 'Grading term must be one of: ' + VALID_PERIODS.join(', ') + '.' });
    }
    if (req.user.role === 'teacher' && normKey(newSubject) !== normKey(cur.subject) && !(await teacherMaySubject(req.user, newSubject))) {
      return res.status(403).json({ message: 'You can only enter grades for subjects on your Class Schedule.' });
    }
    if (normKey(newSubject) !== normKey(cur.subject) || normKey(newTerm) !== normKey(cur.term)) {
      const dupId = await findDuplicate(cur.student_email, newSubject, newTerm, cur.academic_term_id, id);
      if (dupId) return res.status(409).json({ message: 'Another grade record already exists for that student, subject and grading term.', existingId: String(dupId) });
    }

    const next = {
      subject: newSubject, term: newTerm,
      quizzes: r.quizzes.value !== undefined ? r.quizzes.value : cur.quizzes,
      assignments: r.assignments.value !== undefined ? r.assignments.value : cur.assignments,
      activities: r.activities.value !== undefined ? r.activities.value : cur.activities,
      attendance: r.attendance.value !== undefined ? r.attendance.value : cur.attendance,
      exam: r.exam.value !== undefined ? r.exam.value : cur.exam,
      midterm: r.midterm.value !== undefined ? r.midterm.value : cur.midterm,
      final: r.final.value !== undefined ? r.final.value : cur.final,
      remarks: b.remarks !== undefined ? b.remarks : cur.remarks,
      details: r.details.value !== undefined ? r.details.value : cur.details
    };
    const changes = diffRows(cur, next);
    if (!Object.keys(changes).length) {
      return res.json({ grade: serialize(cur, await getGradeWeights()), unchanged: true });
    }
    // An admin correcting a verified grade sends it back for re-verification
    // (the admin screen already tells the user so); it is hidden from the
    // student again until verified.
    const reopening = isLocked(cur);
    if (reopening) changes.adminStatus = { from: 'verified', to: 'pending' };

    await pool.query(
      `UPDATE grades SET subject=?, term=?, quizzes=?, assignments=?, activities=?, attendance=?, exam=?, midterm=?, final=?, remarks=?, details=?${reopening ? ", admin_status='pending'" : ''} WHERE id=?`,
      [next.subject, next.term, next.quizzes, next.assignments, next.activities, next.attendance, next.exam, next.midterm, next.final, next.remarks, next.details === undefined ? null : next.details, id]
    );
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    await logAudit(req.user, rows[0], 'update', changes, reason);
    return res.json({ grade: serialize(rows[0], await getGradeWeights()) });
  } catch (err) {
    console.error('PUT /api/grades/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the grade record.' });
  }
});

// POST /api/grades/:id/verify — admin only. Verifying publishes the grade to the
// student and locks it against teacher edits.
router.post('/:id/verify', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });
    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Grade record not found.' });
    if (isLocked(existing[0])) return res.json({ grade: serialize(existing[0], await getGradeWeights()), unchanged: true });

    await pool.query(`UPDATE grades SET admin_status = 'verified' WHERE id = ?`, [id]);
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    await logAudit(req.user, rows[0], 'verify', { adminStatus: { from: 'pending', to: 'verified' } }, cleanReason((req.body || {}).reason));
    return res.json({ grade: serialize(rows[0], await getGradeWeights()) });
  } catch (err) {
    console.error('POST /api/grades/:id/verify failed:', err);
    return res.status(500).json({ message: 'Could not verify the grade record.' });
  }
});

// POST /api/grades/:id/reopen — admin only. Unlocks a verified grade (it is
// hidden from the student again until re-verified). A reason is mandatory.
router.post('/:id/reopen', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });
    const reason = cleanReason((req.body || {}).reason);
    if (!reason) return res.status(400).json({ message: 'A reason is required to reopen a verified grade.' });
    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Grade record not found.' });
    if (!isLocked(existing[0])) return res.json({ grade: serialize(existing[0], await getGradeWeights()), unchanged: true });

    await pool.query(`UPDATE grades SET admin_status = 'pending' WHERE id = ?`, [id]);
    const [rows] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    await logAudit(req.user, rows[0], 'reopen', { adminStatus: { from: 'verified', to: 'pending' } }, reason);
    return res.json({ grade: serialize(rows[0], await getGradeWeights()) });
  } catch (err) {
    console.error('POST /api/grades/:id/reopen failed:', err);
    return res.status(500).json({ message: 'Could not reopen the grade record.' });
  }
});

// DELETE /api/grades/:id — teacher (own, not locked) or admin (reason required if locked)
router.delete('/:id', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid grade id.' });

    const [existing] = await pool.query('SELECT * FROM grades WHERE id = ?', [id]);
    if (!existing.length) return res.json({ deleted: false });
    const cur = existing[0];
    if (req.user.role === 'teacher' && cur.teacher_email !== req.user.email) {
      return res.status(403).json({ message: 'You can only delete grades you entered.' });
    }
    const reason = cleanReason((req.body && req.body.reason) || req.query.reason);
    if (isLocked(cur)) {
      if (req.user.role === 'teacher') {
        return res.status(423).json({ message: 'This grade has been verified and is locked. Ask an administrator to reopen it before deleting.' });
      }
      if (!reason) return res.status(400).json({ message: 'This grade is verified and locked. Enter a reason to delete it.' });
    }

    // Snapshot first so the deleted values are still recoverable from history.
    const snapshot = {};
    for (const f of ['subject', 'term', ...SCORE_FIELDS]) snapshot[f] = { from: cur[f] === undefined ? null : cur[f], to: null };
    await logAudit(req.user, cur, 'delete', snapshot, reason);
    const [result] = await pool.query('DELETE FROM grades WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/grades/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the grade record.' });
  }
});

module.exports = router;
