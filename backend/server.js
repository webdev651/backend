require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const pool = require('./src/db');
const { runMigrations } = require('./src/migrate');

const authRoutes = require('./src/routes/auth');
const adminRoutes = require('./src/routes/admin');
const profilesRoutes = require('./src/routes/profiles');
const profileChangeRequestsRoutes = require('./src/routes/profile-change-requests');
const gradesRoutes = require('./src/routes/grades');
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

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 10000;
const HOST = '0.0.0.0';

const DB_NAME = process.env.DB_NAME || 'defaultdb';

const FRONTEND_URL = 'https://tccsystem.netlify.app';
const BACKEND_URL = 'https://tcc-system-backend.onrender.com';

/* =========================================================
   SECURITY
========================================================= */

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = [
  FRONTEND_URL,
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5500'
];

if (process.env.CORS_ORIGIN) {
  process.env.CORS_ORIGIN
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean)
    .forEach(origin => {
      if (!allowedOrigins.includes(origin)) {
        allowedOrigins.push(origin);
      }
    });
}

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests without Origin header.
      // Useful for health checks and server-to-server requests.
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      if (process.env.CORS_ORIGIN === '*') {
        return callback(null, true);
      }

      console.warn(`CORS blocked request from: ${origin}`);

      return callback(
        new Error(`CORS blocked request from origin: ${origin}`)
      );
    },

    credentials: true
  })
);

/* =========================================================
   BODY PARSER
========================================================= */

app.use(express.json({ limit: '10mb' }));

app.use(
  express.urlencoded({
    extended: true,
    limit: '10mb'
  })
);

/* =========================================================
   PROFILE PICTURES
========================================================= */

app.use(
  '/uploads/profile-pictures',
  (req, res, next) => {
    res.setHeader(
      'Cross-Origin-Resource-Policy',
      'cross-origin'
    );

    next();
  }
);

app.use(
  '/uploads/profile-pictures',
  express.static(
    path.join(
      __dirname,
      'uploads',
      'profile-pictures'
    ),
    {
      fallthrough: true,
      index: false,
      dotfiles: 'deny'
    }
  )
);

// Disk is wiped on redeploy/restart on Render — if a picture file is missing,
// restore it from the database copy instead of returning 404.
app.get('/uploads/profile-pictures/:filename', async (req, res) => {
  try {
    const { restoreImageFromDb } = require('./src/utils/secureUpload');
    const img = await restoreImageFromDb(req.params.filename);
    if (!img) return res.status(404).end();
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Content-Type', img.mime);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    return res.send(img.buffer);
  } catch (err) {
    console.error('Profile picture restore failed:', err.message);
    return res.status(404).end();
  }
});

/* =========================================================
   OPTIONAL FRONTEND
   Used for local/school LAN deployment.

   Production frontend is hosted on Netlify.
========================================================= */

app.use(
  express.static(
    path.join(
      __dirname,
      '..',
      'frontend'
    )
  )
);

/* =========================================================
   ROOT
========================================================= */

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'TCC College Backend',
    status: 'online',
    frontend: FRONTEND_URL,
    backend: BACKEND_URL,
    database: DB_NAME
  });
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      status: 'online',
      service: 'TCC College Backend',
      database: DB_NAME
    });
  } catch (error) {
    console.error(
      'Health check database error:',
      error.message
    );

    res.status(503).json({
      ok: false,
      status: 'database_error',
      service: 'TCC College Backend',
      database: DB_NAME
    });
  }
});

/* =========================================================
   API ROUTES
========================================================= */

app.use('/api/auth', authRoutes);

app.use('/api/admin', adminRoutes);

app.use('/api/profiles', profilesRoutes);

app.use('/api/profile-change-requests', profileChangeRequestsRoutes);

app.use('/api/grades', gradesRoutes);

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

/* =========================================================
   API 404
========================================================= */

app.use('/api', (req, res) => {
  res.status(404).json({
    ok: false,
    message: 'API endpoint not found.'
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);

  if (err.message && err.message.startsWith('CORS blocked')) {
    return res.status(403).json({
      ok: false,
      message: 'CORS policy blocked this request.'
    });
  }

  res.status(500).json({
    ok: false,
    message: 'Something went wrong. Please try again.'
  });
});

/* =========================================================
   DATABASE CHECK
========================================================= */

async function checkDatabase() {
  console.log('');
  console.log('==============================================');
  console.log('CHECKING DATABASE');
  console.log('==============================================');

  console.log(`Database: ${DB_NAME}`);
  console.log(
    `Host: ${process.env.DB_HOST || 'not configured'}`
  );
  console.log(
    `Port: ${process.env.DB_PORT || 'not configured'}`
  );
  console.log(
    `User: ${process.env.DB_USER || 'not configured'}`
  );
  console.log(
    `SSL: ${process.env.DB_SSL || 'not configured'}`
  );

  try {
    /* ---------------------------------------------
       Basic MySQL connection
    --------------------------------------------- */

    await pool.query('SELECT 1');

    console.log('');
    console.log('MySQL connection: OK');

    /* ---------------------------------------------
       Check database
    --------------------------------------------- */

    const [databaseRows] = await pool.query(
      `
      SELECT SCHEMA_NAME
      FROM information_schema.SCHEMATA
      WHERE SCHEMA_NAME = ?
      `,
      [DB_NAME]
    );

    if (databaseRows.length === 0) {
      console.error('');
      console.error(
        `Database "${DB_NAME}" was not found.`
      );

      console.error(
        'Check DB_NAME in your Render environment variables.'
      );

      return;
    }

    console.log(
      `Database "${DB_NAME}": FOUND`
    );

    /* ---------------------------------------------
       Check users table
    --------------------------------------------- */

    const [userTableRows] = await pool.query(
      `
      SELECT COUNT(*) AS n
      FROM information_schema.tables
      WHERE table_schema = ?
      AND table_name = 'users'
      `,
      [DB_NAME]
    );

    if (!userTableRows[0].n) {
      console.warn('');
      console.warn('==============================================');
      console.warn('WARNING: USERS TABLE IS MISSING');
      console.warn('==============================================');

      console.warn(
        `Database "${DB_NAME}" is connected successfully.`
      );

      console.warn(
        'However, the "users" table does not exist.'
      );

      console.warn('');

      console.warn(
        'Import your schema.sql into Aiven MySQL.'
      );

      console.warn(
        'Do NOT change DB_NAME to tcccollege.'
      );

      console.warn(
        `The correct database name is "${DB_NAME}".`
      );

      console.warn('==============================================');
      console.warn('');
    } else {
      console.log(
        'Users table: FOUND'
      );

      /* ---------------------------------------------
         Run migrations
      --------------------------------------------- */

      try {
        await runMigrations();

        console.log(
          'Database migrations: COMPLETED'
        );
      } catch (migrationError) {
        console.error('');
        console.error(
          'Database migration error:'
        );

        console.error(
          migrationError.message
        );

        console.error('');
      }
    }
  } catch (err) {
    console.error('');
    console.error('==============================================');
    console.error('DATABASE CONNECTION ERROR');
    console.error('==============================================');

    console.error(
      `Code: ${err.code || 'UNKNOWN'}`
    );

    console.error(
      `Message: ${
        err.message ||
        'Unknown database error'
      }`
    );

    /* ---------------------------------------------
       Authentication error
    --------------------------------------------- */

    if (
      err.code === 'ER_ACCESS_DENIED_ERROR' ||
      err.code === 'ER_ACCESS_DENIED_NO_PASSWORD_ERROR'
    ) {
      console.error('');
      console.error(
        'Check DB_USER and DB_PASSWORD in Render.'
      );
    }

    /* ---------------------------------------------
       Connection error
    --------------------------------------------- */

    if (
      err.code === 'ECONNREFUSED' ||
      err.code === 'ETIMEDOUT'
    ) {
      console.error('');
      console.error(
        'Could not reach Aiven MySQL.'
      );

      console.error(
        'Check DB_HOST and DB_PORT.'
      );
    }

    /* ---------------------------------------------
       Database does not exist
    --------------------------------------------- */

    if (err.code === 'ER_BAD_DB_ERROR') {
      console.error('');
      console.error(
        `Database "${DB_NAME}" does not exist.`
      );

      console.error(
        'Your Aiven database should be "defaultdb".'
      );
    }

    /* ---------------------------------------------
       SSL error
    --------------------------------------------- */

    if (
      err.code === 'HANDSHAKE_SSL_ERROR' ||
      err.code === 'CERT_HAS_EXPIRED' ||
      err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
    ) {
      console.error('');
      console.error(
        'There is an Aiven SSL connection problem.'
      );

      console.error(
        'Check DB_SSL and the SSL configuration in src/db.js.'
      );
    }

    console.error('==============================================');
    console.error('');
  }
}

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  await checkDatabase();

  app.listen(PORT, HOST, () => {
    console.log('');
    console.log('==============================================');
    console.log('TCC COLLEGE BACKEND STARTED');
    console.log('==============================================');

    console.log(
      `Host: ${HOST}`
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log('');

    console.log(
      `Frontend: ${FRONTEND_URL}/`
    );

    console.log(
      `Backend: ${BACKEND_URL}/`
    );

    console.log(
      `Health: ${BACKEND_URL}/api/health`
    );

    console.log('');

    console.log(
      `Database: ${DB_NAME}`
    );

    console.log('');

    console.log('==============================================');
    console.log('');
  });
}

/* =========================================================
   START
========================================================= */

startServer();