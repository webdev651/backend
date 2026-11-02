/* Grading Settings tests — run with:  node --test test/
   Uses the REAL express routers + middleware with an in-memory stand-in for the
   MySQL pool (no database needed). Covers: admin-only writes (HTTP 403 for
   teachers/students), validation, exact-100 total, reset, and that grade
   calculation follows the latest saved percentages without altering records. */
process.env.JWT_SECRET = 'test-secret-not-for-production-0123456789abcdef';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const express = require('express');

/* ---- in-memory pool, injected before any route module loads db.js ------- */
const store = { app_settings: new Map(), grades: [], gradeWrites: 0 };
const fakePool = {
  async query(sql, params = []) {
    const q = String(sql).replace(/\s+/g, ' ').trim();
    if (/^SELECT setting_key, setting_value, updated_by, updated_at FROM app_settings/i.test(q)) {
      return [[...store.app_settings.values()].filter((r) => ['grade_weights', 'grade_max_scores'].includes(r.setting_key)), []];
    }
    if (/^INSERT INTO app_settings/i.test(q)) {
      for (let i = 0; i < params.length; i += 3) {
        store.app_settings.set(params[i], { setting_key: params[i], setting_value: params[i + 1], updated_by: params[i + 2], updated_at: new Date() });
      }
      return [{ affectedRows: params.length / 3 }, []];
    }
    if (/^SELECT g\.\*, at\.label/i.test(q)) return [store.grades.map((g) => ({ ...g })), []];
    if (/^(INSERT INTO|UPDATE|DELETE FROM) grades/i.test(q)) { store.gradeWrites++; return [{ affectedRows: 0 }, []]; }
    throw new Error('Unexpected SQL in test: ' + q);
  }
};
const dbPath = require.resolve(path.join('..', 'src', 'db.js'));
require.cache[dbPath] = { id: dbPath, filename: dbPath, loaded: true, exports: fakePool };

const { signToken } = require('../src/utils/token');
const settingsRoutes = require('../src/routes/settings');
const gradesRoutes = require('../src/routes/grades');
const { DEFAULT_GRADE_WEIGHTS } = require('../src/utils/settings');

const app = express();
app.use(express.json());
app.use('/api/settings', settingsRoutes);
app.use('/api/grades', gradesRoutes);

let base, server;
const tok = {
  admin: signToken({ id: 1, email: 'admin@tcc.edu', role: 'admin', name: 'Admin' }),
  teacher: signToken({ id: 2, email: 'teacher@tcc.edu', role: 'teacher', name: 'Teacher' }),
  student: signToken({ id: 3, email: 'student@tcc.edu', role: 'student', name: 'Student' })
};
async function call(method, url, who, body) {
  const res = await fetch(base + url, {
    method,
    headers: { 'Content-Type': 'application/json', ...(who ? { Authorization: 'Bearer ' + tok[who] } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  let json = null; try { json = await res.json(); } catch (e) { /* no body */ }
  return { status: res.status, json };
}
const W = (q, e, s, a) => ({ weights: { quizzes: q, exam: e, assignments: s, attendance: a } });
const URL_W = '/api/settings/grade-weights';

test.before(() => new Promise((r) => { server = app.listen(0, () => { base = 'http://127.0.0.1:' + server.address().port; r(); }); }));
test.after(() => server.close());

test('defaults are Participation 25 / Major Performance 40 / Summative 30 / Attendance 5 (= 100)', async () => {
  const r = await call('GET', URL_W, 'teacher');
  assert.equal(r.status, 200);
  const w = r.json.weights;
  assert.deepEqual([w.quizzes, w.exam, w.assignments, w.attendance], [25, 40, 30, 5]);
  assert.equal(w.activities, 0);
  assert.equal(r.json.isDefault, true);
  assert.equal(Object.values(DEFAULT_GRADE_WEIGHTS).reduce((a, n) => a + n, 0), 100);
});

test('1. admin can change the percentages', async () => {
  const r = await call('PUT', URL_W, 'admin', W(20, 45, 25, 10));
  assert.equal(r.status, 200);
  const g = await call('GET', URL_W, 'admin');
  assert.deepEqual([g.json.weights.quizzes, g.json.weights.exam, g.json.weights.assignments, g.json.weights.attendance], [20, 45, 25, 10]);
  assert.equal(g.json.updatedBy, 'admin@tcc.edu');
  assert.equal(g.json.isDefault, false);
});

test('2. teacher (and student) can VIEW the percentages', async () => {
  for (const who of ['teacher', 'student']) {
    const r = await call('GET', URL_W, who);
    assert.equal(r.status, 200);
    assert.equal(r.json.weights.exam, 45);
  }
});

test('3. teacher cannot change them by direct API request — 403 on every write method', async () => {
  const before = (await call('GET', URL_W, 'admin')).json.weights;
  for (const who of ['teacher', 'student']) {
    for (const [m, u, b] of [
      ['PUT', URL_W, W(25, 40, 30, 5)], ['POST', URL_W, W(25, 40, 30, 5)], ['PATCH', URL_W, W(25, 40, 30, 5)],
      ['DELETE', URL_W, undefined], ['POST', URL_W + '/reset', {}], ['PUT', URL_W + '/anything', W(25, 40, 30, 5)]
    ]) {
      const r = await call(m, u, who, b);
      assert.equal(r.status, 403, who + ' ' + m + ' ' + u + ' should be 403, got ' + r.status);
    }
  }
  assert.deepEqual((await call('GET', URL_W, 'admin')).json.weights, before, 'nothing changed');
});

test('3b. unauthenticated and forged-token writes are rejected (401)', async () => {
  assert.equal((await call('PUT', URL_W, null, W(25, 40, 30, 5))).status, 401);
  const res = await fetch(base + URL_W, { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer forged.token.value' }, body: JSON.stringify(W(25, 40, 30, 5)) });
  assert.equal(res.status, 401);
});

test('3c. a teacher cannot escalate by putting role/admin fields in the body', async () => {
  const r = await call('PUT', URL_W, 'teacher', { ...W(25, 40, 30, 5), role: 'admin', user: { role: 'admin' } });
  assert.equal(r.status, 403);
});

test('4. invalid percentages are rejected (400) and nothing is saved', async () => {
  const before = (await call('GET', URL_W, 'admin')).json.weights;
  const bad = [
    W(-5, 55, 30, 20), W(101, 0, 0, -1), W('abc', 40, 30, 5), W(25, 40, 30, null), W(25, 40, 30, ''),
    W(25, 40, 30, true), W(25, 40, 30, [5]), W(25, 40, 30, NaN), W(25, 40, 30, undefined), W(25, 40, 30, {}),
    { weights: { quizzes: 25, exam: 40, assignments: 30 } },   // attendance missing
    { weights: 'nope' }, { weights: null }, {}
  ];
  for (const b of bad) {
    const r = await call('PUT', URL_W, 'admin', b);
    assert.equal(r.status, 400, 'should reject ' + JSON.stringify(b) + ' got ' + r.status);
  }
  assert.deepEqual((await call('GET', URL_W, 'admin')).json.weights, before);
});

test('5. totals below or above 100% are rejected; exactly 100 (incl. decimals) is accepted', async () => {
  for (const b of [W(25, 40, 30, 4), W(25, 40, 30, 6), W(0, 0, 0, 0), W(25, 40, 30, 5.01), W(33.33, 33.33, 33.33, 0)]) {
    const r = await call('PUT', URL_W, 'admin', b);
    assert.equal(r.status, 400, JSON.stringify(b));
    assert.match(r.json.message, /exactly 100%/);
  }
  assert.equal((await call('PUT', URL_W, 'admin', W(33.33, 33.33, 33.34, 0))).status, 200);   // floating-point-safe
  assert.equal((await call('PUT', URL_W, 'admin', W('25', '40', '30', '5'))).status, 200);    // numeric strings from a form
  assert.equal((await call('PUT', URL_W, 'admin', W(100, 0, 0, 0))).status, 200);
});

test('invalid perfect scores are rejected', async () => {
  for (const ms of [{ quizzes: 0 }, { quizzes: 100, assignments: 100, attendance: -1 }, { quizzes: 100, assignments: 100, attendance: 'x' }, { quizzes: 100, assignments: 1000, attendance: 10 }]) {
    assert.equal((await call('PUT', URL_W, 'admin', { ...W(25, 40, 30, 5), maxScores: ms })).status, 400, JSON.stringify(ms));
  }
});

test('admin reset restores 25 / 40 / 30 / 5', async () => {
  await call('PUT', URL_W, 'admin', W(10, 10, 10, 70));
  const r = await call('POST', URL_W + '/reset', 'admin', {});
  assert.equal(r.status, 200);
  const w = r.json.weights;
  assert.deepEqual([w.quizzes, w.exam, w.assignments, w.attendance], [25, 40, 30, 5]);
  assert.equal(r.json.updatedBy, 'admin@tcc.edu');
});

const gradeRow = { id: 1, student_email: 's@x.edu', student_name: 'S', subject: 'Math', term: 'Prelim', teacher_email: 'teacher@tcc.edu',
  quizzes: 80, assignments: 90, activities: null, attendance: 8, exam: 70, midterm: null, final: null, remarks: null, admin_status: 'pending' };

test('6. grade calculation uses the latest saved percentages (server-side termPercent)', async () => {
  store.grades = [{ ...gradeRow }];
  await call('PUT', URL_W, 'admin', { ...W(25, 40, 30, 5), maxScores: { quizzes: 100, assignments: 100, attendance: 10, exam: 100 } });
  // 80*.25 + 70*.40 + 90*.30 + (8/10*100=80)*.05 = 20 + 28 + 27 + 4 = 79
  let r = await call('GET', '/api/grades', 'admin');
  assert.equal(r.json.grades[0].termPercent, 79);
  // admin changes the percentages -> same stored scores, new result
  await call('PUT', URL_W, 'admin', { ...W(10, 60, 20, 10), maxScores: { quizzes: 100, assignments: 100, attendance: 10, exam: 100 } });
  // 80*.10 + 70*.60 + 90*.20 + 80*.10 = 8 + 42 + 18 + 8 = 76
  r = await call('GET', '/api/grades', 'admin');
  assert.equal(r.json.grades[0].termPercent, 76);
  // perfect-score normalisation: Attendance out of 20 -> 8/20 = 40%
  await call('PUT', URL_W, 'admin', { ...W(10, 60, 20, 10), maxScores: { quizzes: 100, assignments: 100, attendance: 20, exam: 100 } });
  r = await call('GET', '/api/grades', 'admin');
  assert.equal(r.json.grades[0].termPercent, 72);   // 8 + 42 + 18 + 4
  // a missing weighted score is "incomplete" (null), never silently zero
  store.grades = [{ ...gradeRow, attendance: null }];
  r = await call('GET', '/api/grades', 'admin');
  assert.equal(r.json.grades[0].termPercent, null);
  // Midterm period reads the Major Performance score from the midterm column
  store.grades = [{ ...gradeRow, term: 'Midterm', exam: null, midterm: 50 }];
  await call('PUT', URL_W, 'admin', { ...W(25, 40, 30, 5), maxScores: { quizzes: 100, assignments: 100, attendance: 10, exam: 100 } });
  r = await call('GET', '/api/grades', 'admin');
  assert.equal(r.json.grades[0].termPercent, 20 + 20 + 27 + 4);
});

test('7. existing student grades and records are preserved by every settings change', async () => {
  store.grades = [{ ...gradeRow }];
  const snapshot = JSON.stringify(store.grades);
  store.gradeWrites = 0;
  await call('PUT', URL_W, 'admin', W(30, 30, 30, 10));
  await call('POST', URL_W + '/reset', 'admin', {});
  await call('PUT', URL_W, 'teacher', W(1, 1, 1, 97));   // rejected
  assert.equal(store.gradeWrites, 0, 'no INSERT/UPDATE/DELETE was run against grades');
  assert.equal(JSON.stringify(store.grades), snapshot);
  const r = await call('GET', '/api/grades', 'admin');
  const g = r.json.grades[0];
  assert.deepEqual([g.quizzes, g.assignments, g.attendance, g.exam], [80, 90, 8, 70]);
});

test('an unreadable / non-100 stored row falls back to defaults instead of skewing grades', async () => {
  store.app_settings.set('grade_weights', { setting_key: 'grade_weights', setting_value: JSON.stringify({ quizzes: 50, assignments: 50, activities: 0, attendance: 50, exam: 50 }), updated_by: 'x', updated_at: new Date() });
  assert.deepEqual((await call('GET', URL_W, 'teacher')).json.weights.exam, 40);
  store.app_settings.set('grade_weights', { setting_key: 'grade_weights', setting_value: '{not json', updated_by: 'x', updated_at: new Date() });
  assert.equal((await call('GET', URL_W, 'teacher')).json.weights.exam, 40);
});
