const pool = require('../db');

/* =========================================================================
   getTeacherStudents(teacherEmail, teacherName)
   The single source of truth for "who are this teacher's own students".
   Used by:
   - routes/roster.js      -> GET /api/roster (the teacher's Students tab)
   - routes/announcements.js -> scopes teacher-posted "student" announcements
                                  so they only reach that teacher's own
                                  students, not every student in the college.

   A student counts as "yours" if EITHER is true:
   1. You've entered at least one grade for them (grades.teacher_email) —
      the most explicit, already-existing link in the schema.
   2. They're approved-enrolled in a subject that appears on your Class
      Schedule (schedules.teacher_email / teacher_name), matched by
      subject name/code against enrollments.subjects (JSON array).

   Returns a Map keyed by lowercased email:
     { email, name, subjects: Set<string> }
   ========================================================================= */

async function getTeacherSubjectNames(teacherEmail, teacherName) {
  const [rows] = await pool.query(
    `SELECT DISTINCT subject FROM schedules
     WHERE (teacher_email IS NOT NULL AND teacher_email <> '' AND teacher_email = ?)
        OR (teacher_name = ? AND (teacher_email IS NULL OR teacher_email = ''))`,
    [teacherEmail || '', teacherName || '']
  );
  // Keep original casing (for display) alongside the lowercase match key.
  const seen = new Set();
  const out = [];
  rows.forEach((r) => {
    const original = String(r.subject || '').trim();
    const key = original.toLowerCase();
    if (!key || seen.has(key)) return;
    seen.add(key);
    out.push({ key: key, label: original });
  });
  return out;
}

function subjectNamesFromEnrollmentJson(raw) {
  // enrollments.subjects is a MySQL JSON column, which mysql2 already
  // parses into a JS array/object automatically — only fall back to
  // JSON.parse() if it ever comes back as a raw string (e.g. a
  // different driver/config).
  let list = raw;
  if (typeof raw === 'string') {
    try { list = JSON.parse(raw || '[]'); } catch (e) { list = []; }
  }
  if (!Array.isArray(list)) return [];
  return list
    .map((s) => String((s && (s.name || s.code)) || '').trim())
    .filter(Boolean);
}

async function getTeacherStudents(teacherEmail, teacherName) {
  const students = new Map();

  function upsert(email, name, subjectLabel) {
    if (!email) return;
    const key = String(email).trim().toLowerCase();
    if (!key) return;
    if (!students.has(key)) {
      students.set(key, { email: email, name: name || email, subjects: new Set() });
    }
    if (subjectLabel) students.get(key).subjects.add(subjectLabel);
  }

  // 1) Explicit link: grades you've entered for a student.
  const [gradeRows] = await pool.query(
    `SELECT DISTINCT student_email, student_name, subject FROM grades WHERE teacher_email = ?`,
    [teacherEmail || '']
  );
  gradeRows.forEach((r) => upsert(r.student_email, r.student_name, r.subject));

  // 2) Class-schedule link: students enrolled in a subject you teach.
  const subjectNames = await getTeacherSubjectNames(teacherEmail, teacherName);
  if (subjectNames.length) {
    const subjectKeys = subjectNames.map((s) => s.key);
    const [enrollRows] = await pool.query(
      `SELECT student_email, student_name, subjects FROM enrollments WHERE status = 'approved'`
    );
    enrollRows.forEach((r) => {
      const names = subjectNamesFromEnrollmentJson(r.subjects);
      const matchedName = names.find((n) => subjectKeys.indexOf(n.toLowerCase()) !== -1);
      if (matchedName) {
        const matchedEntry = subjectNames[subjectKeys.indexOf(matchedName.toLowerCase())];
        upsert(r.student_email, r.student_name, matchedEntry.label);
      }
    });
  }

  // 3) Explicit admin-assigned link (teacher_students table) — always
  // wins over the automatic matches above for showing up in "my students",
  // regardless of grades/schedule state. Tagged either with the section
  // name (auto-created by src/routes/sections.js when this student is on
  // a section this teacher advises) or 'Assigned by admin' for a link
  // made directly via /api/roster/assignments.
  const [assignedRows] = await pool.query(
    `SELECT ts.student_email, ts.student_name, sec.section_code
     FROM teacher_students ts
     LEFT JOIN sections sec ON sec.id = ts.source_section_id
     WHERE ts.teacher_email = ?`,
    [teacherEmail || '']
  );
  assignedRows.forEach((r) => upsert(r.student_email, r.student_name, r.section_code ? ('Section: ' + r.section_code) : 'Assigned by admin'));

  return students;
}

/* =========================================================================
   getAllTeacherStudentLinks()
   Same three link types as getTeacherStudents(), but computed for every
   teacher at once in a fixed number of queries (no N+1 over the teacher
   list). Used by GET /api/admin/students to show each student's assigned
   teacher(s) without calling getTeacherStudents() once per teacher.

   Returns an array of { studentEmail, studentName, teacherEmail,
   teacherName, subject }. A student can appear multiple times (one row
   per link) — callers group by student email themselves.
   ========================================================================= */
async function getAllTeacherStudentLinks() {
  const links = [];

  // 1) Grades entered by a teacher.
  const [gradeRows] = await pool.query(
    `SELECT DISTINCT student_email, student_name, teacher_email, teacher_name, subject
     FROM grades WHERE teacher_email IS NOT NULL AND teacher_email <> ''`
  );
  gradeRows.forEach((r) => links.push({
    studentEmail: r.student_email,
    studentName: r.student_name,
    teacherEmail: r.teacher_email,
    teacherName: r.teacher_name || r.teacher_email,
    subject: r.subject
  }));

  // 2) Class-schedule + approved-enrollment matches (subject name match,
  // same logic as getTeacherSubjectNames()/getTeacherStudents() above,
  // just done for every teacher in one pass instead of one query per
  // teacher).
  const [scheduleRows] = await pool.query(
    `SELECT DISTINCT subject, teacher_email, teacher_name FROM schedules
     WHERE (teacher_email IS NOT NULL AND teacher_email <> '')
        OR (teacher_name IS NOT NULL AND teacher_name <> '')`
  );
  if (scheduleRows.length) {
    const bySubject = new Map(); // subject (lowercase) -> [{teacherEmail, teacherName}]
    scheduleRows.forEach((r) => {
      const key = String(r.subject || '').trim().toLowerCase();
      if (!key) return;
      if (!bySubject.has(key)) bySubject.set(key, []);
      bySubject.get(key).push({
        teacherEmail: r.teacher_email || '',
        teacherName: r.teacher_name || r.teacher_email || ''
      });
    });

    const [enrollRows] = await pool.query(
      `SELECT student_email, student_name, subjects FROM enrollments WHERE status = 'approved'`
    );
    enrollRows.forEach((r) => {
      const names = subjectNamesFromEnrollmentJson(r.subjects);
      names.forEach((n) => {
        const teachers = bySubject.get(n.toLowerCase());
        if (!teachers) return;
        teachers.forEach((t) => links.push({
          studentEmail: r.student_email,
          studentName: r.student_name,
          teacherEmail: t.teacherEmail,
          teacherName: t.teacherName,
          subject: n
        }));
      });
    });
  }

  // 3) Explicit admin-assigned links, tagged the same way as
  // getTeacherStudents() above (section name when auto-created by
  // src/routes/sections.js, otherwise 'Assigned by admin').
  const [assignedRows] = await pool.query(
    `SELECT ts.student_email, ts.student_name, ts.teacher_email, ts.teacher_name, sec.section_code
     FROM teacher_students ts
     LEFT JOIN sections sec ON sec.id = ts.source_section_id`
  );
  assignedRows.forEach((r) => links.push({
    studentEmail: r.student_email,
    studentName: r.student_name,
    teacherEmail: r.teacher_email,
    teacherName: r.teacher_name || r.teacher_email,
    subject: r.section_code ? ('Section: ' + r.section_code) : 'Assigned by admin'
  }));

  return links;
}

module.exports = { getTeacherStudents, getTeacherSubjectNames, getAllTeacherStudentLinks };
