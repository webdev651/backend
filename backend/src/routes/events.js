const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

const TYPES = ['announcement', 'registration_deadline', 'enrollment_deadline', 'academic_deadline', 'school_event', 'activity', 'exam'];
const AUDIENCES = ['all', 'student', 'teacher'];

function serialize(row) {
  return {
    id: String(row.id),
    title: row.title,
    description: row.description || '',
    type: row.type,
    eventDate: row.event_date,
    audience: row.audience,
    createdByName: row.created_by_name || '',
    createdByEmail: row.created_by_email || '',
    createdAt: row.created_at
  };
}

router.use(requireAuth);

/**
 * GET /api/events
 * Audience-scoped the same way GET /api/announcements is (see
 * announcements.js): admin sees everything, students/teachers see 'all'
 * plus whatever's targeted at their own role. Query params:
 *   ?upcoming=1   only event_date >= now (what the widget itself wants)
 *   ?days=N       ...and within the next N days (default: no cap)
 * Always ordered soonest-first so the widget can just take the top few.
 */
router.get('/', async (req, res) => {
  try {
    const { role } = req.user;
    const clauses = [];
    const params = [];

    if (role !== 'admin') {
      clauses.push('audience IN (?, ?)');
      params.push('all', role);
    }
    if (req.query.upcoming) {
      clauses.push('event_date >= NOW()');
    }
    const days = Number(req.query.days);
    if (Number.isFinite(days) && days > 0) {
      clauses.push('event_date <= DATE_ADD(NOW(), INTERVAL ? DAY)');
      params.push(days);
    }

    const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
    const [rows] = await pool.query(`SELECT * FROM events ${where} ORDER BY event_date ASC`, params);
    return res.json({ events: rows.map(serialize) });
  } catch (err) {
    console.error('GET /api/events failed:', err);
    return res.status(500).json({ message: 'Could not load events.' });
  }
});

// POST /api/events — admin only. Registration/enrollment deadlines and
// school-wide events are an admin-office concern, same boundary as who
// can send a Notification (see notifications.js) — kept separate from
// announcements.js's teacher-can-post rule, since a mis-dated deadline
// is a bigger foot-gun than a mistimed announcement.
router.post('/', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const title = String(b.title || '').trim();
    const eventDate = String(b.eventDate || '').trim();
    if (!title) return res.status(400).json({ message: 'Title is required.' });
    if (!eventDate || isNaN(new Date(eventDate).getTime())) {
      return res.status(400).json({ message: 'A valid date is required.' });
    }
    const type = TYPES.indexOf(b.type) !== -1 ? b.type : 'school_event';
    const audience = AUDIENCES.indexOf(b.audience) !== -1 ? b.audience : 'all';

    const [result] = await pool.query(
      `INSERT INTO events (title, description, type, event_date, audience, created_by_name, created_by_email)
       VALUES (?,?,?,?,?,?,?)`,
      [title, b.description || null, type, new Date(eventDate), audience, req.user.name, req.user.email]
    );
    const [rows] = await pool.query('SELECT * FROM events WHERE id = ?', [result.insertId]);
    return res.status(201).json({ event: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/events failed:', err);
    return res.status(500).json({ message: 'Could not create the event.' });
  }
});

// PUT /api/events/:id — admin only
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid event id.' });
    const [existing] = await pool.query('SELECT * FROM events WHERE id = ?', [id]);
    if (!existing.length) return res.status(404).json({ message: 'Event not found.' });
    const cur = existing[0];

    const b = req.body || {};
    const title = b.title != null ? String(b.title).trim() : cur.title;
    if (!title) return res.status(400).json({ message: 'Title is required.' });

    let eventDate = cur.event_date;
    if (b.eventDate != null) {
      if (!String(b.eventDate).trim() || isNaN(new Date(b.eventDate).getTime())) {
        return res.status(400).json({ message: 'A valid date is required.' });
      }
      eventDate = new Date(b.eventDate);
    }
    const type = b.type != null ? (TYPES.indexOf(b.type) !== -1 ? b.type : cur.type) : cur.type;
    const audience = b.audience != null ? (AUDIENCES.indexOf(b.audience) !== -1 ? b.audience : cur.audience) : cur.audience;

    await pool.query(
      `UPDATE events SET title=?, description=?, type=?, event_date=?, audience=? WHERE id=?`,
      [title, b.description !== undefined ? (b.description || null) : cur.description, type, eventDate, audience, id]
    );
    const [rows] = await pool.query('SELECT * FROM events WHERE id = ?', [id]);
    return res.json({ event: serialize(rows[0]) });
  } catch (err) {
    console.error('PUT /api/events/:id failed:', err);
    return res.status(500).json({ message: 'Could not update the event.' });
  }
});

// DELETE /api/events/:id — admin only
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid event id.' });
    const [result] = await pool.query('DELETE FROM events WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/events/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the event.' });
  }
});

module.exports = router;
