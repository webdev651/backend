const express = require('express');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getTeacherStudents } = require('../utils/teacherStudents');

const router = express.Router();

const CATEGORIES = ['General', 'Academic', 'Enrollment', 'Registration', 'Schedule', 'Important'];
const PRIORITIES = ['Low', 'Normal', 'High', 'Urgent'];
const STATUSES = ['Published', 'Draft', 'Archived'];

function serialize(row, readAt) {
  return {
    id: String(row.id),
    title: row.title,
    body: row.body,
    audience: row.audience,
    category: row.category || 'General',
    priority: row.priority || 'Normal',
    status: row.status || 'Published',
    postedByName: row.posted_by_name,
    postedByRole: row.posted_by_role,
    postedByEmail: row.posted_by_email || '',
    postedAt: row.posted_at,
    readAt: readAt || null,
    isRead: !!readAt
  };
}

router.use(requireAuth);

// GET /api/announcements — audience-scoped to the signed-in role, plus
// this reader's own read/unread state. Drafts are only ever visible to
// their author (or an admin, who can see and manage everything).
router.get('/', async (req, res) => {
  try {
    const { role, email } = req.user;
    let rows;
    if (role === 'admin') {
      [rows] = await pool.query('SELECT * FROM announcements ORDER BY posted_at DESC');
    } else if (role === 'teacher') {
      [rows] = await pool.query(
        `SELECT * FROM announcements
         WHERE (status = 'Published' AND (audience IN ('all','teacher') OR posted_by_email = ?))
            OR posted_by_email = ?
         ORDER BY posted_at DESC`,
        [email, email]
      );
    } else {
      // Students: admin broadcasts ('all' / admin-posted 'student') are
      // always visible. Teacher-posted 'student' announcements are scoped
      // to that teacher's own students only — a teacher's post should not
      // reach the whole student body, just their own classes. Drafts never
      // reach students regardless of audience.
      const [broadcastRows] = await pool.query(
        `SELECT * FROM announcements
         WHERE status = 'Published' AND (audience = 'all' OR (audience = 'student' AND posted_by_role = 'admin'))
         ORDER BY posted_at DESC`
      );
      const [teacherPosts] = await pool.query(
        `SELECT * FROM announcements WHERE status = 'Published' AND audience = 'student' AND posted_by_role = 'teacher' ORDER BY posted_at DESC`
      );

      const rosterCache = new Map();
      const myTeacherPosts = [];
      for (const row of teacherPosts) {
        const cacheKey = (row.posted_by_email || '') + '|' + (row.posted_by_name || '');
        if (!rosterCache.has(cacheKey)) {
          rosterCache.set(cacheKey, await getTeacherStudents(row.posted_by_email, row.posted_by_name));
        }
        const roster = rosterCache.get(cacheKey);
        if (roster.has(String(email || '').trim().toLowerCase())) myTeacherPosts.push(row);
      }

      rows = broadcastRows.concat(myTeacherPosts).sort((a, b) => new Date(b.posted_at) - new Date(a.posted_at));
    }

    let readMap = new Map();
    if (rows.length && email) {
      const ids = rows.map((r) => r.id);
      const [readRows] = await pool.query(
        `SELECT announcement_id, read_at FROM announcement_reads WHERE reader_email = ? AND announcement_id IN (?)`,
        [email, ids]
      );
      readMap = new Map(readRows.map((r) => [r.announcement_id, r.read_at]));
    }

    return res.json({ announcements: rows.map((row) => serialize(row, readMap.get(row.id))) });
  } catch (err) {
    console.error('GET /api/announcements failed:', err);
    return res.status(500).json({ message: 'Could not load announcements.' });
  }
});

// POST /api/announcements — teacher or admin
router.post('/', requireRole('teacher', 'admin'), async (req, res) => {
  try {
    const b = req.body || {};
    const title = String(b.title || '').trim();
    const body = String(b.body || '').trim();
    if (!title || !body) return res.status(400).json({ message: 'Title and body are required.' });

    const audience = req.user.role === 'teacher' ? 'student' : (b.audience || 'all');
    const category = CATEGORIES.includes(b.category) ? b.category : 'General';
    const priority = PRIORITIES.includes(b.priority) ? b.priority : 'Normal';
    const status = STATUSES.includes(b.status) ? b.status : 'Published';

    const [result] = await pool.query(
      `INSERT INTO announcements (title, body, audience, category, priority, status, posted_by_name, posted_by_role, posted_by_email)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      [title, body, audience, category, priority, status, req.user.name, req.user.role, req.user.email]
    );
    const [rows] = await pool.query('SELECT * FROM announcements WHERE id = ?', [result.insertId]);
    return res.status(201).json({ announcement: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/announcements failed:', err);
    return res.status(500).json({ message: 'Could not post the announcement.' });
  }
});

// PUT /api/announcements/:id — admin only
router.put('/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid announcement id.' });
    const [existing] = await pool.query('SELECT * FROM announcements WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Announcement not found.' });

    const b = req.body || {};
    const cur = existing[0];
    const category = b.category !== undefined ? (CATEGORIES.includes(b.category) ? b.category : cur.category) : cur.category;
    const priority = b.priority !== undefined ? (PRIORITIES.includes(b.priority) ? b.priority : cur.priority) : cur.priority;
    const status = b.status !== undefined ? (STATUSES.includes(b.status) ? b.status : cur.status) : cur.status;
    await pool.query(
      'UPDATE announcements SET title=?, body=?, audience=?, category=?, priority=?, status=? WHERE id=?',
      [b.title ?? cur.title, b.body ?? cur.body, b.audience ?? cur.audience, category, priority, status, id]
    );
    const [rows] = await pool.query('SELECT * FROM announcements WHERE id = ?', [id]);
    return res.json({ announcement: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/announcements/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the announcement.' });
  }
});

// DELETE /api/announcements/:id — admin only
router.delete('/:id', requireRole('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid announcement id.' });
    const [result] = await pool.query('DELETE FROM announcements WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/announcements/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the announcement.' });
  }
});

// POST /api/announcements/:id/read — mark read for the signed-in reader.
// Idempotent (INSERT ... ON DUPLICATE KEY does nothing to the timestamp
// on a repeat call, so opening the detail view twice doesn't reset it).
router.post('/:id/read', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid announcement id.' });
    const email = req.user.email;
    if (!email) return res.status(400).json({ message: 'No email on this account to track read state with.' });

    await pool.query(
      `INSERT INTO announcement_reads (announcement_id, reader_email) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE announcement_id = announcement_id`,
      [id, email]
    );
    const [rows] = await pool.query(
      'SELECT read_at FROM announcement_reads WHERE announcement_id = ? AND reader_email = ?',
      [id, email]
    );
    return res.json({ read: true, readAt: rows[0] ? rows[0].read_at : null });
  } catch (err) {
    console.error('POST /api/announcements/:id/read failed:', err);
    return res.status(500).json({ message: 'Could not mark that announcement as read.' });
  }
});

// DELETE /api/announcements/:id/read — mark unread for the signed-in reader.
router.delete('/:id/read', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid announcement id.' });
    const email = req.user.email;
    if (!email) return res.status(400).json({ message: 'No email on this account to track read state with.' });

    await pool.query('DELETE FROM announcement_reads WHERE announcement_id = ? AND reader_email = ?', [id, email]);
    return res.json({ read: false });
  } catch (err) {
    console.error('DELETE /api/announcements/:id/read failed:', err);
    return res.status(500).json({ message: 'Could not mark that announcement as unread.' });
  }
});

module.exports = router;
