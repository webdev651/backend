/**
 * Creates (or updates the password of) an admin account directly in the
 * database. Admin accounts are never created through /api/auth/signup —
 * this is the only way to get the first admin in.
 *
 * Usage:
 *   node seed/create-admin.js "Admin Name" admin@tcc.edu somePassword123
 *   npm run seed:admin -- "Admin Name" admin@tcc.edu somePassword123
 */
require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('../src/db');

async function main() {
  const [name, emailRaw, password] = process.argv.slice(2);
  if (!name || !emailRaw || !password) {
    console.error('Usage: node seed/create-admin.js "Admin Name" admin@example.com password123');
    process.exit(1);
  }
  if (password.length < 6) {
    console.error('Password must be at least 6 characters.');
    process.exit(1);
  }

  const email = emailRaw.trim().toLowerCase();
  const rounds = Number(process.env.BCRYPT_ROUNDS || 10);
  const passwordHash = await bcrypt.hash(password, rounds);

  const [existing] = await pool.query(
    `SELECT id FROM users WHERE email = ? AND role = 'admin' LIMIT 1`,
    [email]
  );

  if (existing.length) {
    await pool.query(
      `UPDATE users SET name = ?, password_hash = ?, status = 'approved' WHERE id = ?`,
      [name, passwordHash, existing[0].id]
    );
    console.log(`Updated existing admin account: ${email}`);
  } else {
    await pool.query(
      `INSERT INTO users (name, email, password_hash, role, status, requested_at, decided_at)
       VALUES (?, ?, ?, 'admin', 'approved', NOW(), NOW())`,
      [name, email, passwordHash]
    );
    console.log(`Created admin account: ${email}`);
  }

  await pool.end();
}

main().catch((err) => {
  console.error('Failed to seed admin account:', err);
  process.exit(1);
});
