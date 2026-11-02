const express = require('express');
const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

function serialize(row, readAt) {
  return {
    id: String(row.id),
    title: row.title,
    message: row.message,
    recipientType: row.recipient_type,
    recipientEmail: row.recipient_email || '',
    scheduledFor: row.scheduled_for,
    status: row.status,
    createdAt: row.created_at,
    sentAt: row.sent_at,
    readAt: readAt || null,
    isRead: !!readAt
  };
}

router.use(requireAuth);

// GET /api/notifications — promotes any due "scheduled" notification to
// "sent" first, so the frontend's checkScheduled() is just a refresh().
// Admins (Notification Management) see every notification, scheduled ones
// included, so they can still cancel/edit what hasn't gone out yet.
// Students/teachers only ever see 'sent' notifications actually addressed
// to them ('all', their own role, or a 'specific' post to their email),
// plus their own read/unread state — same shape as GET /api/announcements.
router.get('/', async (req, res) => {
  try {
    await pool.query(
      `UPDATE notifications SET status='sent', sent_at=NOW()
       WHERE status='scheduled' AND scheduled_for IS NOT NULL AND scheduled_for <= NOW()`
    );

    const { role, email } = req.user;
    let rows;
    if (role === 'admin') {
      [rows] = await pool.query('SELECT * FROM notifications ORDER BY created_at DESC');
    } else {
      [rows] = await pool.query(
        `SELECT * FROM notifications
         WHERE status = 'sent'
           AND (recipient_type = 'all' OR recipient_type = ? OR (recipient_type = 'specific' AND recipient_email = ?))
         ORDER BY created_at DESC`,
        [role, email]
      );
    }

    let readMap = new Map();
    if (rows.length && email) {
      const ids = rows.map((r) => r.id);
      const [readRows] = await pool.query(
        `SELECT notification_id, read_at FROM notification_reads WHERE reader_email = ? AND notification_id IN (?)`,
        [email, ids]
      );
      readMap = new Map(readRows.map((r) => [r.notification_id, r.read_at]));
    }

    return res.json({ notifications: rows.map((row) => serialize(row, readMap.get(row.id))) });
  } catch (err) {
    console.error('GET /api/notifications failed:', err);
    return res.status(500).json({ message: 'Could not load notifications.' });
  }
});

// POST /api/notifications — admin only (Notification Management compose form)
router.post('/', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const title = String(b.title || '').trim();
    const message = String(b.message || '').trim();
    if (!title || !message) return res.status(400).json({ message: 'Title and message are required.' });

    const scheduledFor = b.scheduledFor || null;
    const status = scheduledFor && new Date(scheduledFor) > new Date() ? 'scheduled' : 'sent';

    const [result] = await pool.query(
      `INSERT INTO notifications (title, message, recipient_type, recipient_email, scheduled_for, status, sent_at)
       VALUES (?,?,?,?,?,?,?)`,
      [
        title, message, b.recipientType || 'all', b.recipientEmail || null,
        scheduledFor, status, status === 'sent' ? new Date() : null
      ]
    );
    const [rows] = await pool.query('SELECT * FROM notifications WHERE id = ?', [result.insertId]);
    return res.status(201).json({ notification: serialize(rows[0]) });
  } catch (err) {
    console.error('POST /api/notifications failed:', err);
    return res.status(500).json({ message: 'Could not create the notification.' });
  }
});

// POST /api/notifications/:id/cancel — admin only, only meaningful for scheduled ones
router.post('/:id/cancel', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid notification id.' });
    const [result] = await pool.query(`DELETE FROM notifications WHERE id = ? AND status = 'scheduled'`, [id]);
    if (!result.affectedRows) return res.json({ notification: null });
    return res.json({ notification: { id: String(id) } });
  } catch (err) {
    console.error('POST /api/notifications/:id/cancel failed:', err);
    return res.status(500).json({ message: 'Could not cancel the notification.' });
  }
});

// DELETE /api/notifications/:id — admin only
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid notification id.' });
    const [result] = await pool.query('DELETE FROM notifications WHERE id = ?', [id]);
    return res.json({ deleted: result.affectedRows > 0 });
  } catch (err) {
    console.error('DELETE /api/notifications/:id failed:', err);
    return res.status(500).json({ message: 'Could not delete the notification.' });
  }
});

// POST /api/notifications/:id/read — mark read for the signed-in reader
// (student or teacher opening their Notifications tab). Idempotent.
router.post('/:id/read', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid notification id.' });
    const email = req.user.email;
    if (!email) return res.status(400).json({ message: 'No email on this account to track read state with.' });

    await pool.query(
      `INSERT INTO notification_reads (notification_id, reader_email) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE notification_id = notification_id`,
      [id, email]
    );
    const [rows] = await pool.query(
      'SELECT read_at FROM notification_reads WHERE notification_id = ? AND reader_email = ?',
      [id, email]
    );
    return res.json({ read: true, readAt: rows[0] ? rows[0].read_at : null });
  } catch (err) {
    console.error('POST /api/notifications/:id/read failed:', err);
    return res.status(500).json({ message: 'Could not mark that notification as read.' });
  }
});

// DELETE /api/notifications/:id/read — mark unread for the signed-in reader.
router.delete('/:id/read', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ message: 'Invalid notification id.' });
    const email = req.user.email;
    if (!email) return res.status(400).json({ message: 'No email on this account to track read state with.' });

    await pool.query('DELETE FROM notification_reads WHERE notification_id = ? AND reader_email = ?', [id, email]);
    return res.json({ read: false });
  } catch (err) {
    console.error('DELETE /api/notifications/:id/read failed:', err);
    return res.status(500).json({ message: 'Could not mark that notification as unread.' });
  }
});

module.exports = router;
