const pool = require('../db');

/* =========================================================================
   Shared helpers behind the printable "Official List" PDF (frontend
   js/core/official-list-pdf.js). Used by every endpoint that feeds that PDF:
   - routes/admin.js   GET /master-list, POST /master-list/send
   - routes/roster.js  GET /            (a teacher's "My students")
   ========================================================================= */

/** Approved-enrollment unit load per student (lowercased email -> units) —
 * what the "TOTAL NO. OF UNITS" column on the printed Official List shows.
 * Scoped to the active term; enrollments filed before terms existed
 * (academic_term_id IS NULL) still count so older data isn't dropped.
 * Students with no approved enrollment are simply absent from the result. */
async function loadUnitsByEmail(emails, term) {
  const out = {};
  if (!emails.length) return out;
  let sql = `SELECT LOWER(student_email) AS email, SUM(total_units) AS units
             FROM enrollments
             WHERE status = 'approved' AND LOWER(student_email) IN (?)`;
  const params = [emails];
  if (term) { sql += ' AND (academic_term_id = ? OR academic_term_id IS NULL)'; params.push(term.id); }
  sql += ' GROUP BY LOWER(student_email)';
  const [rows] = await pool.query(sql, params);
  rows.forEach((r) => { out[r.email] = Number(r.units) || 0; });
  return out;
}

function serializeTerm(term) {
  return term
    ? { id: term.id, schoolYear: term.school_year, semester: term.semester, label: term.label }
    : null;
}

/** Profile rows (student ID, sex, section, ...) keyed by lowercased email. */
async function loadProfilesByEmail(emails) {
  const out = {};
  if (!emails.length) return out;
  const [rows] = await pool.query(
    `SELECT email, student_id, section, sex, status, program, year_level
     FROM student_profiles WHERE LOWER(email) IN (?)`,
    [emails]
  );
  rows.forEach((p) => { out[String(p.email).toLowerCase()] = p; });
  return out;
}

module.exports = { loadUnitsByEmail, serializeTerm, loadProfilesByEmail };
