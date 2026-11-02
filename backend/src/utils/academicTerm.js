const pool = require('../db');

/* =========================================================================
   getActiveTerm()
   Returns the one academic_terms row with status='active' (or null if the
   admin hasn't activated one yet — e.g. right after a fresh install). Used
   by every route that creates a term-scoped record (registrations,
   enrollments, schedules, sections, attendance, grades) to auto-stamp
   academic_term_id, so students/teachers never have to pick a term
   themselves and can't accidentally file something under the wrong one.

   Returns null rather than throwing when there's no active term, so a
   fresh install (or one where admin hasn't set an active term yet) keeps
   working exactly as before Academic Term Management existed — every
   caller treats a null academicTermId as "not yet assigned to a term"
   rather than an error.
   ========================================================================= */
async function getActiveTerm() {
  const [rows] = await pool.query(`SELECT * FROM academic_terms WHERE status = 'active' LIMIT 1`);
  return rows[0] || null;
}

async function getActiveTermId() {
  const term = await getActiveTerm();
  return term ? term.id : null;
}

module.exports = { getActiveTerm, getActiveTermId };
