require('dotenv').config();
const path = require('path');
const os = require('os');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const pool = require('./src/db');
const { runMigrations } = require('./src/migrate');

const authRoutes = require('./src/routes/auth');
const adminRoutes = require('./src/routes/admin');
const profilesRoutes = require('./src/routes/profiles');
const gradesRoutes = require('./src/routes/grades');
const gradebookRoutes = require('./src/routes/gradebook');
const announcementsRoutes = require('./src/routes/announcements');
const feedbackRoutes = require('./src/routes/feedback');
const registrationsRoutes = require('./src/routes/registrations');
const enrollmentsRoutes = require('./src/routes/enrollments');
const schedulesRoutes = require('./src/routes/schedules');
const attendanceRoutes = require('./src/routes/attendance');
const notificationsRoutes = require('./src/routes/notifications');
const staffRoutes = require('./src/routes/staff');
const rosterRoutes = require('./src/routes/roster');
const teacherRoutes = require('./src/routes/teacher');
const sectionsRoutes = require('./src/routes/sections');
const eventsRoutes = require('./src/routes/events');
const academicTermsRoutes = require('./src/routes/academic-terms');
const subjectsRoutes = require('./src/routes/subjects');
const settingsRoutes = require('./src/routes/settings');

const app = express();

// Behind Render's (or any) reverse proxy the real client IP is in X-Forwarded-For;
// without this every visitor looks like one IP and express-rate-limit complains.
// Set TRUST_PROXY=1 in the host's environment. Unset = off (local dev).
if (process.env.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(process.env.TRUST_PROXY) ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY);

// Security headers (clickjacking/MIME-sniffing/referrer-leak protection,
// etc.) via helmet. Content-Security-Policy is left off: this frontend is
// plain multi-page HTML that loads Google Fonts + the Bootstrap CDN and
// uses inline style="" attributes throughout (not a build-tooled SPA), so
// helmet's default CSP would block those without a real audit of every
// page first. Cross-Origin-Embedder-Policy is off for the same CDN-asset
// reason. Every other helmet default stays on.
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({
  origin: corsOrigin === '*' ? true : corsOrigin.split(',').map((s) => s.trim())
}));
app.use(express.json());

// Serve uploaded profile pictures as static files. Read-only, no listing
// (express.static doesn't list directories by default), no execution —
// these are always JPEG/PNG bytes written by utils/secureUpload.js under
// server-generated filenames, never anything derived from user input.
//
// helmet's default Cross-Origin-Resource-Policy: same-origin (set above)
// blocks the browser from loading these as <img>/background-image
// resources whenever the frontend is served from a different origin than
// this API — e.g. frontend on :8000 (a separate static server / LAN IP)
// and this backend on :4000 (backend/.env PORT). That's a common setup
// for this project (see js/core/api-client.js's cross-port auto-detect),
// so pictures under this route specifically need Cross-Origin-Resource-
// Policy: cross-origin — everything else on the app keeps helmet's
// stricter same-origin default.
app.use('/uploads/profile-pictures', (req, res, next) => {
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
});
app.use('/uploads/profile-pictures', express.static(
  path.join(__dirname, 'uploads', 'profile-pictures'),
  { fallthrough: true, index: false, dotfiles: 'deny' }
));

// Serve the static frontend from the same server/port as the API, so a
// school LAN deployment is just "run this one backend process" — visiting
// http://SERVER_IP:PORT/ serves frontend/index.html, and every frontend
// page's relative asset paths (js/..., css/...) resolve the same way they
// already do when the frontend is served on its own. The frontend's own
// API calls still go to http://SERVER_IP:PORT/api/... (see
// js/core/api-client.js, which auto-detects the host it was loaded from —
// no change needed there for this to work). This is additive: nothing
// stops the frontend from still being hosted separately if preferred.
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/profiles', profilesRoutes);
app.use('/api/grades', gradesRoutes);
app.use('/api/gradebook', gradebookRoutes);
app.use('/api/announcements', announcementsRoutes);
app.use('/api/feedback', feedbackRoutes);
app.use('/api/registrations', registrationsRoutes);
app.use('/api/enrollments', enrollmentsRoutes);
app.use('/api/schedules', schedulesRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/notifications', notificationsRoutes);
app.use('/api/staff', staffRoutes);
app.use('/api/roster', rosterRoutes);
app.use('/api/teacher', teacherRoutes);
app.use('/api/sections', sectionsRoutes);
app.use('/api/events', eventsRoutes);
app.use('/api/academic-terms', academicTermsRoutes);
app.use('/api/subjects', subjectsRoutes);
app.use('/api/settings', settingsRoutes);

// 404 fallback for unknown API routes
app.use('/api', (req, res) => res.status(404).json({ message: 'Not found.' }));

// Generic error handler (catches anything that slips past route try/catch)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Something went wrong. Please try again.' });
});

const PORT = process.env.PORT || 4000;
// Bind to all interfaces (required on Render).
const HOST = process.env.HOST || '0.0.0.0';

// Check the database connection *before* accepting traffic. Without this,
// a bad DB_PASSWORD/DB_HOST/missing schema in .env silently makes every
// single API call fail with the generic "Something went wrong" message
// (see route try/catch blocks) and the real reason only ever showed up
// buried in the console per-request — easy to miss. This prints one loud,
// specific diagnosis right at startup instead.
async function checkDatabase() {
  try {
    await pool.query('SELECT 1');
    const [rows] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = ? AND table_name = 'users'`,
      [process.env.DB_NAME]
    );
    if (!rows[0].n) {
      console.warn('\n⚠️  Connected to MySQL, but the "users" table is missing.');
      console.warn('   Run the schema once:  mysql -u ' + (process.env.DB_USER) + ' -p < src/schema.sql\n');
    } else {
      console.log('✅ Database connection OK (' + (process.env.DB_NAME) + ')');
      await runMigrations();
    }
  } catch (err) {
    console.error('\n❌ Could not connect to MySQL — every API call will fail with "Something went wrong" until this is fixed.');
    console.error('   Reason: ' + err.code + ' — ' + err.message);
    if (err.code === 'ER_ACCESS_DENIED_ERROR' || err.code === 'ER_ACCESS_DENIED_NO_PASSWORD_ERROR') {
      console.error('   → The DB_USER/DB_PASSWORD in your .env do not match your MySQL server.');
    } else if (err.code === 'ECONNREFUSED') {
      console.error('   → Cannot reach MySQL at ' + (process.env.DB_HOST) + ':' + (process.env.DB_PORT || 3306) + '.');
      console.error('     Check DB_HOST / DB_PORT in the Render environment variables.');
    } else if (err.code === 'ER_BAD_DB_ERROR') {
      console.error('   → The database "' + (process.env.DB_NAME) + '" does not exist yet.');
      console.error('     Run:  mysql -u ' + (process.env.DB_USER) + ' -p < src/schema.sql');
    }
    console.error('   Server will still start, but sign-in and every other feature will keep failing until this is resolved.\n');
  }
}

checkDatabase().finally(() => {
  app.listen(PORT, HOST, () => {
    console.log(`TCC backend listening on port ${PORT} — https://leteast-backend.onrender.com`);
  });
});
