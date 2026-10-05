const pool = require('./db');
const { encryptField, isEncryptedPayload } = require('./utils/crypto');

/* =========================================================================
   Self-healing migrations.
   Whenever a new table is added to schema.sql for a feature after someone
   has already set up their database (e.g. teacher_students for the
   "assign a student to a teacher" / master list feature), running the
   full schema.sql again is the "proper" fix — but it's easy to forget,
   and the error that results ("Table '...' doesn't exist", ER_NO_SUCH_TABLE)
   is confusing if you don't know that's the cause.

   This runs the handful of CREATE TABLE IF NOT EXISTS statements for
   tables added after the original schema on every server start. It's
   fully idempotent and a no-op once the table already exists, so it's
   safe to leave in permanently — no separate "migrate" step to remember.
   ========================================================================= */

const STATEMENTS = [
  {
    name: 'teacher_students',
    sql: `CREATE TABLE IF NOT EXISTS teacher_students (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      teacher_email  VARCHAR(190) NOT NULL,
      teacher_name   VARCHAR(150) NULL,
      student_email  VARCHAR(190) NOT NULL,
      student_name   VARCHAR(150) NOT NULL,
      assigned_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_teacher_student (teacher_email, student_email),
      INDEX idx_teacher_students_teacher (teacher_email),
      INDEX idx_teacher_students_student (student_email)
    ) ENGINE=InnoDB`
  },
  {
    name: 'masterlist_shares',
    sql: `CREATE TABLE IF NOT EXISTS masterlist_shares (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      teacher_email  VARCHAR(190) NOT NULL,
      teacher_name   VARCHAR(150) NOT NULL,
      section        VARCHAR(50)  NULL,
      students       JSON NOT NULL,
      sent_by_name   VARCHAR(150) NOT NULL,
      sent_by_email  VARCHAR(190) NULL,
      sent_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      viewed_at      DATETIME NULL,
      INDEX idx_masterlist_shares_teacher (teacher_email)
    ) ENGINE=InnoDB`
  },
  {
    name: 'announcement_reads',
    sql: `CREATE TABLE IF NOT EXISTS announcement_reads (
      id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      announcement_id  INT UNSIGNED NOT NULL,
      reader_email     VARCHAR(190) NOT NULL,
      read_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_announcement_reads (announcement_id, reader_email),
      CONSTRAINT fk_announcement_reads_announcement FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE,
      INDEX idx_announcement_reads_reader (reader_email)
    ) ENGINE=InnoDB`
  },
  {
    // Mirrors announcement_reads above exactly, for `notifications` instead
    // of `announcements`. Was added to schema.sql but missed here, so any
    // database created before that point never got this table — that's
    // the "Table 'notification_reads' doesn't exist" (ER_NO_SUCH_TABLE)
    // error on GET/POST /api/notifications.
    name: 'notification_reads',
    sql: `CREATE TABLE IF NOT EXISTS notification_reads (
      id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      notification_id  INT UNSIGNED NOT NULL,
      reader_email     VARCHAR(190) NOT NULL,
      read_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_notification_reads (notification_id, reader_email),
      CONSTRAINT fk_notification_reads_notification FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
      INDEX idx_notification_reads_reader (reader_email)
    ) ENGINE=InnoDB`
  },
  {
    name: 'events',
    sql: `CREATE TABLE IF NOT EXISTS events (
      id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      title              VARCHAR(200) NOT NULL,
      description        VARCHAR(500) NULL,
      type               ENUM('announcement','registration_deadline','enrollment_deadline','academic_deadline','school_event','activity','exam')
                           NOT NULL DEFAULT 'school_event',
      event_date         DATETIME NOT NULL,
      audience           ENUM('all','student','teacher') NOT NULL DEFAULT 'all',
      created_by_name    VARCHAR(150) NULL,
      created_by_email   VARCHAR(190) NULL,
      created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_events_date (event_date),
      INDEX idx_events_audience (audience),
      INDEX idx_events_type (type)
    ) ENGINE=InnoDB`
  },
  // ---- Phase 3 — normalized schema (see schema.sql for the full design
  // notes). Order matters: each table below only references ones created
  // before it (students/teachers -> sections -> student_section_assignments
  // -> masterlists -> teacher_masterlist_assignments).
  {
    name: 'students',
    sql: `CREATE TABLE IF NOT EXISTS students (
      id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id           INT UNSIGNED NOT NULL,
      student_id        VARCHAR(20)  NOT NULL,
      program           VARCHAR(150) NULL,
      year_level        VARCHAR(50)  NULL,
      status            ENUM('Regular','Irregular','Inactive') NOT NULL DEFAULT 'Regular',
      date_of_birth     VARCHAR(255)  NULL,
      sex               VARCHAR(20)  NULL,
      civil_status      VARCHAR(50)  NULL,
      nationality       VARCHAR(80)  NULL,
      religion          VARCHAR(80)  NULL,
      address           VARCHAR(255) NULL,
      mobile            VARCHAR(255)  NULL,
      guardian_name     VARCHAR(150) NULL,
      guardian_contact  VARCHAR(255)  NULL,
      date_admitted     VARCHAR(50)  NULL,
      created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_students_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY uq_students_user (user_id),
      UNIQUE KEY uq_students_student_id (student_id),
      INDEX idx_students_program (program)
    ) ENGINE=InnoDB`
  },
  {
    name: 'teachers',
    sql: `CREATE TABLE IF NOT EXISTS teachers (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id        INT UNSIGNED NOT NULL,
      department     VARCHAR(150) NULL,
      subjects       VARCHAR(255) NULL,
      created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_teachers_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY uq_teachers_user (user_id),
      INDEX idx_teachers_department (department)
    ) ENGINE=InnoDB`
  },
  {
    name: 'sections',
    sql: `CREATE TABLE IF NOT EXISTS sections (
      id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      section_code        VARCHAR(50)  NOT NULL,
      program             VARCHAR(150) NULL,
      year_level          VARCHAR(50)  NULL,
      term                VARCHAR(100) NOT NULL,
      adviser_teacher_id  INT UNSIGNED NULL,
      created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_sections_adviser FOREIGN KEY (adviser_teacher_id) REFERENCES teachers(id) ON DELETE SET NULL,
      UNIQUE KEY uq_sections_code_term (section_code, term),
      INDEX idx_sections_adviser (adviser_teacher_id)
    ) ENGINE=InnoDB`
  },
  {
    name: 'student_section_assignments',
    sql: `CREATE TABLE IF NOT EXISTS student_section_assignments (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      student_id     INT UNSIGNED NOT NULL,
      section_id     INT UNSIGNED NOT NULL,
      status         ENUM('active','dropped','completed') NOT NULL DEFAULT 'active',
      assigned_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_ssa_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
      CONSTRAINT fk_ssa_section FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE CASCADE,
      UNIQUE KEY uq_ssa_student_section (student_id, section_id),
      INDEX idx_ssa_section (section_id)
    ) ENGINE=InnoDB`
  },
  {
    name: 'masterlists',
    sql: `CREATE TABLE IF NOT EXISTS masterlists (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      section_id     INT UNSIGNED NOT NULL,
      term           VARCHAR(100) NOT NULL,
      title          VARCHAR(200) NULL,
      generated_by   INT UNSIGNED NULL,
      generated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_masterlists_section FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE CASCADE,
      CONSTRAINT fk_masterlists_generated_by FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL,
      UNIQUE KEY uq_masterlists_section_term (section_id, term),
      INDEX idx_masterlists_generated_by (generated_by)
    ) ENGINE=InnoDB`
  },
  {
    name: 'teacher_masterlist_assignments',
    sql: `CREATE TABLE IF NOT EXISTS teacher_masterlist_assignments (
      id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      masterlist_id       INT UNSIGNED NOT NULL,
      teacher_id          INT UNSIGNED NOT NULL,
      assigned_by         INT UNSIGNED NULL,
      notification_title  VARCHAR(200) NULL,
      notification_body   TEXT NULL,
      status              ENUM('sent','viewed') NOT NULL DEFAULT 'sent',
      assigned_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      viewed_at           DATETIME NULL,
      CONSTRAINT fk_tma_masterlist FOREIGN KEY (masterlist_id) REFERENCES masterlists(id) ON DELETE CASCADE,
      CONSTRAINT fk_tma_teacher FOREIGN KEY (teacher_id) REFERENCES teachers(id) ON DELETE CASCADE,
      CONSTRAINT fk_tma_assigned_by FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
      UNIQUE KEY uq_tma_masterlist_teacher (masterlist_id, teacher_id),
      INDEX idx_tma_teacher (teacher_id)
    ) ENGINE=InnoDB`
  },
  {
    name: 'academic_terms',
    sql: `CREATE TABLE IF NOT EXISTS academic_terms (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      school_year    VARCHAR(20)  NOT NULL,
      semester       ENUM('1st Semester','2nd Semester','Summer') NOT NULL,
      label          VARCHAR(100) NOT NULL,
      status         ENUM('upcoming','active','closed') NOT NULL DEFAULT 'upcoming',
      starts_on      DATE NULL,
      ends_on        DATE NULL,
      activated_at   DATETIME NULL,
      closed_at      DATETIME NULL,
      created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_academic_terms_year_sem (school_year, semester)
    ) ENGINE=InnoDB`
  },
  {
    name: 'subjects',
    sql: `CREATE TABLE IF NOT EXISTS subjects (
      id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      code              VARCHAR(20)  NOT NULL,
      name              VARCHAR(150) NOT NULL,
      units             DECIMAL(3,1) NOT NULL DEFAULT 3,
      teacher_name      VARCHAR(150) NULL,
      schedule_day      VARCHAR(30)  NULL,
      schedule_time     VARCHAR(50)  NULL,
      slots_total       INT UNSIGNED NOT NULL DEFAULT 40,
      academic_term_id  INT UNSIGNED NULL,
      created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_subjects_code_term (code, academic_term_id),
      INDEX idx_subjects_academic_term (academic_term_id)
    ) ENGINE=InnoDB`
  },
  {
    name: 'sensitive_data_access_log',
    sql: `CREATE TABLE IF NOT EXISTS sensitive_data_access_log (
      id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      admin_id          INT UNSIGNED NULL,
      admin_email       VARCHAR(190) NULL,
      target_type       VARCHAR(50)  NOT NULL,
      target_id         INT UNSIGNED NULL,
      fields_requested  VARCHAR(255) NULL,
      success           TINYINT(1)   NOT NULL DEFAULT 0,
      reason            VARCHAR(100) NULL,
      ip_address        VARCHAR(64)  NULL,
      created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_sensitive_log_admin (admin_id),
      INDEX idx_sensitive_log_target (target_type, target_id),
      INDEX idx_sensitive_log_created (created_at)
    ) ENGINE=InnoDB`
  },
  {
    name: 'profile_audit_log',
    sql: `CREATE TABLE IF NOT EXISTS profile_audit_log (
      id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      action        VARCHAR(60)  NOT NULL,   -- e.g. STUDENT_PROFILE_PICTURE_UPLOADED
      actor_id      INT UNSIGNED NULL,       -- users.id of who performed the action (usually an admin)
      actor_email   VARCHAR(190) NULL,
      target_type   VARCHAR(30)  NOT NULL,   -- 'student' | 'teacher'
      target_id     INT UNSIGNED NULL,       -- users.id of the affected profile
      created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_profile_audit_target (target_type, target_id),
      INDEX idx_profile_audit_created (created_at)
    ) ENGINE=InnoDB`
  },
  {
    // Student requests to change their registrar-managed personal information
    // (DOB / sex / civil status / nationality / religion). Nothing on the
    // profile changes until an admin approves — see routes/profile-change-requests.js.
    name: 'profile_change_requests',
    sql: `CREATE TABLE IF NOT EXISTS profile_change_requests (
      id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      profile_id     INT UNSIGNED NOT NULL,   -- student_profiles.id
      student_email  VARCHAR(190) NOT NULL,
      student_name   VARCHAR(150) NOT NULL,
      changes        TEXT NOT NULL,           -- AES-256-GCM encrypted JSON: { field: { from, to } }
      reason         VARCHAR(500) NULL,
      status         ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
      admin_note     VARCHAR(500) NULL,
      reviewed_by    VARCHAR(190) NULL,       -- admin email who approved/rejected
      reviewed_at    DATETIME NULL,
      created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_pcr_email (student_email),
      INDEX idx_pcr_status (status),
      CONSTRAINT fk_pcr_profile FOREIGN KEY (profile_id) REFERENCES student_profiles(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  }
];

async function runMigrations() {
  for (const stmt of STATEMENTS) {
    try {
      const [existing] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = ? AND table_name = ?`,
        [process.env.DB_NAME || 'tcc_college', stmt.name]
      );
      const existed = !!existing[0].n;
      await pool.query(stmt.sql);
      if (!existed) console.log('🔧 Created missing table "' + stmt.name + '" (auto-migration).');
    } catch (err) {
      console.error('⚠️  Could not ensure table "' + stmt.name + '" exists:', err.message);
    }
  }

  await ensureStudentIdColumn();
  await ensureProfilePictureAndTeacherColumns();
  await ensureNotificationsColumns();
  await ensureNotificationsRelatedMasterlistColumn();
  await ensureSectionsSentColumns();
  await ensureEventsTypeEnum();
  await ensureAnnouncementsColumns();
  await seedAcademicTerms();
  await ensureAcademicTermColumns();
  await seedSubjects();
  await ensureWorkflowStatusColumns();
  await ensureTeacherStudentsSectionColumn();
  await ensureSensitiveColumnWidths();
  await encryptSensitiveFields('student_profiles');
  await backfillNormalizedTables();
  await encryptSensitiveFields('students');
  await ensurePasswordResetColumns();
  await ensureEmailVerification();
}

/* =========================================================================
   ensurePasswordResetColumns()
   Adds the two columns the forgot-password/reset-password flow needs on
   `users`. Only a SHA-256 hash of the reset token is ever stored (never
   the raw token itself — that only ever exists in the emailed link),
   plus its expiry so an old/used link stops working. Both nullable and
   cleared again once a reset completes.
   ========================================================================= */
async function ensurePasswordResetColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  async function addColumnIfMissing(table, column, ddl) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
        [dbName, table, column]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
        console.log(`🔧 Added missing column "${table}.${column}" (auto-migration).`);
      }
    } catch (err) {
      console.error(`⚠️  Could not ensure ${table}.${column} exists:`, err.message);
    }
  }

  await addColumnIfMissing('users', 'reset_token_hash', 'reset_token_hash VARCHAR(64) NULL');
  await addColumnIfMissing('users', 'reset_token_expires', 'reset_token_expires DATETIME NULL');
}

/* =========================================================================
   ensureEmailVerification()
   Email verification support:
     - users.email_verified_at (NULL = not verified yet)
     - email_verification_tokens: one row per emailed link. Only a SHA-256
       hash of the token is stored (the raw token only exists in the email),
       with an expiry and used_at so each link is single-use.
   Password-reset storage already exists (users.reset_token_hash /
   reset_token_expires, above), so it is reused rather than duplicated.

   Accounts that existed BEFORE this feature are grandfathered: when the
   column is first added, every existing user is stamped as verified so
   nobody who could already sign in is locked out. Only accounts created
   afterwards have to verify. Safe to run on every start (no-op once done).
   ========================================================================= */
async function ensureEmailVerification() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  try {
    const [cols] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.columns
       WHERE table_schema = ? AND table_name = 'users' AND column_name = 'email_verified_at'`,
      [dbName]
    );
    if (!cols[0].n) {
      await pool.query(`ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL`);
      await pool.query(`UPDATE users SET email_verified_at = NOW() WHERE email_verified_at IS NULL`);
      console.log('🔧 Added users.email_verified_at and grandfathered existing accounts as verified (auto-migration).');
    }
  } catch (err) {
    console.error('⚠️  Could not ensure users.email_verified_at exists:', err.message);
  }

  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS email_verification_tokens (
      id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id     INT UNSIGNED NOT NULL,
      token_hash  VARCHAR(64)  NOT NULL,
      expires_at  DATETIME     NOT NULL,
      used_at     DATETIME     NULL,
      created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_evt_token_hash (token_hash),
      INDEX idx_evt_user (user_id),
      CONSTRAINT fk_evt_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB`);
  } catch (err) {
    console.error('⚠️  Could not ensure table "email_verification_tokens" exists:', err.message);
  }
}

/* =========================================================================
   ensureSensitiveColumnWidths()
   date_of_birth / mobile / guardian_contact were originally VARCHAR(50) —
   fine for plaintext, but an AES-256-GCM payload
   ("v1:<iv>:<tag>:<ciphertext>", all base64) runs ~60+ characters even
   for a short value, which silently fails to fit and causes "Data too
   long for column" errors on write. Widens all four sensitive columns to
   VARCHAR(255) (matching `address`, which was already wide enough) on
   both student_profiles and students. Checked against
   information_schema first so this is a no-op (not a full ALTER) once
   already widened — safe to run on every server start.
   ========================================================================= */
async function ensureSensitiveColumnWidths() {
  const tables = ['student_profiles', 'students'];
  const columns = ['date_of_birth', 'address', 'mobile', 'guardian_contact'];
  const dbName = process.env.DB_NAME || 'tcc_college';

  for (const table of tables) {
    for (const col of columns) {
      try {
        const [rows] = await pool.query(
          `SELECT CHARACTER_MAXIMUM_LENGTH AS len FROM information_schema.columns
           WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
          [dbName, table, col]
        );
        if (!rows.length) continue; // table/column doesn't exist yet (e.g. fresh install order) — schema.sql/STATEMENTS above will create it at the right width already
        if ((rows[0].len || 0) < 255) {
          await pool.query(`ALTER TABLE ${table} MODIFY COLUMN ${col} VARCHAR(255) NULL`);
          console.log(`🔧 Widened ${table}.${col} to VARCHAR(255) to fit encrypted values (auto-migration).`);
        }
      } catch (err) {
        console.error(`⚠️  Could not widen ${table}.${col}:`, err.message);
      }
    }
  }
}

/* =========================================================================
   encryptSensitiveFields(table)
   One-time (safe-to-repeat) pass that encrypts any still-plaintext
   date_of_birth / address / mobile / guardian_contact values on the given
   table with AES-256-GCM (see utils/crypto.js). Idempotent: a value that
   already looks like an encrypted payload (isEncryptedPayload) is left
   untouched, so running this on every server start is safe and does not
   double-encrypt.

   Runs against student_profiles BEFORE backfillNormalizedTables so the
   copy into the normalized `students` table picks up already-encrypted
   values, then again against `students` afterward to catch any rows that
   existed there before this migration was introduced.
   ========================================================================= */
const SENSITIVE_COLUMNS = ['date_of_birth', 'address', 'mobile', 'guardian_contact'];

async function encryptSensitiveFields(table) {
  try {
    const [rows] = await pool.query(
      `SELECT id, ${SENSITIVE_COLUMNS.join(', ')} FROM ${table}`
    );

    let updated = 0;
    for (const row of rows) {
      const sets = [];
      const values = [];

      for (const col of SENSITIVE_COLUMNS) {
        const val = row[col];
        if (val !== null && val !== '' && !isEncryptedPayload(val)) {
          sets.push(`${col} = ?`);
          values.push(encryptField(val));
        }
      }

      if (sets.length) {
        values.push(row.id);
        await pool.query(`UPDATE ${table} SET ${sets.join(', ')} WHERE id = ?`, values);
        updated += 1;
      }
    }

    if (updated) {
      console.log(`🔒 Encrypted sensitive fields on ${updated} existing "${table}" row(s) (auto-migration).`);
    }
  } catch (err) {
    console.error(`⚠️  Could not encrypt sensitive fields on "${table}":`, err.message);
  }
}

/* =========================================================================
   backfillNormalizedTables()
   One-time (but safe-to-repeat) copy of existing email/string-matched data
   into the Phase 3 normalized tables (students, teachers, sections,
   student_section_assignments — see schema.sql). Every statement is
   INSERT IGNORE against a table with a UNIQUE key covering exactly what's
   being inserted, so re-running this on every server start never creates
   duplicates and never overwrites a row someone has since edited directly
   in the new tables.

   Sections backfilled this way get an "Unspecified Term" placeholder,
   since student_profiles.section was never term-scoped — rename/split
   those sections by real term once Section Management is wired to these
   tables.
   ========================================================================= */
const LEGACY_SECTION_TERM = 'Unspecified Term';

async function backfillNormalizedTables() {
  try {
    await pool.query(`
      INSERT IGNORE INTO students
        (user_id, student_id, program, year_level, status, date_of_birth, sex,
         civil_status, nationality, religion, address, mobile,
         guardian_name, guardian_contact, date_admitted)
      SELECT u.id, u.student_id, sp.program, sp.year_level,
             IFNULL(sp.status, 'Regular'), sp.date_of_birth, sp.sex,
             sp.civil_status, sp.nationality, sp.religion, sp.address, sp.mobile,
             sp.guardian_name, sp.guardian_contact, sp.date_admitted
      FROM users u
      LEFT JOIN student_profiles sp ON LOWER(sp.email) = LOWER(u.email)
      WHERE u.role = 'student' AND u.status = 'approved' AND u.student_id IS NOT NULL
    `);

    await pool.query(`
      INSERT IGNORE INTO teachers (user_id, department, subjects)
      SELECT u.id, u.detail, st.subjects
      FROM users u
      LEFT JOIN staff st ON LOWER(st.email) = LOWER(u.email)
      WHERE u.role = 'teacher' AND u.status = 'approved'
    `);

    await pool.query(
      `INSERT IGNORE INTO sections (section_code, term)
       SELECT DISTINCT TRIM(sp.section), ?
       FROM student_profiles sp
       WHERE sp.section IS NOT NULL AND TRIM(sp.section) <> ''`,
      [LEGACY_SECTION_TERM]
    );

    await pool.query(
      `INSERT IGNORE INTO student_section_assignments (student_id, section_id)
       SELECT s.id, sec.id
       FROM student_profiles sp
       JOIN users u ON LOWER(u.email) = LOWER(sp.email)
       JOIN students s ON s.user_id = u.id
       JOIN sections sec ON sec.section_code = TRIM(sp.section) AND sec.term = ?
       WHERE sp.section IS NOT NULL AND TRIM(sp.section) <> ''`,
      [LEGACY_SECTION_TERM]
    );
  } catch (err) {
    console.error('⚠️  Could not backfill normalized tables:', err.message);
  }
}

/* Adds the notifications columns (recipient_type, recipient_email,
   scheduled_for, status, sent_at) to databases whose "notifications" table
   was created before these fields existed in schema.sql. Same idempotent,
   check-then-add pattern as the other ensure*Column() functions — safe to
   run on every server start. */
async function ensureNotificationsColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const columns = [
    { name: 'recipient_type', ddl: `ADD COLUMN recipient_type ENUM('all','student','teacher','specific') NOT NULL DEFAULT 'all' AFTER message` },
    { name: 'recipient_email', ddl: `ADD COLUMN recipient_email VARCHAR(190) NULL AFTER recipient_type` },
    { name: 'scheduled_for', ddl: `ADD COLUMN scheduled_for DATETIME NULL AFTER recipient_email` },
    { name: 'status', ddl: `ADD COLUMN status ENUM('scheduled','sent') NOT NULL DEFAULT 'sent' AFTER scheduled_for` },
    { name: 'sent_at', ddl: `ADD COLUMN sent_at DATETIME NULL AFTER status` }
  ];
  for (const col of columns) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = 'notifications' AND column_name = ?`,
        [dbName, col.name]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE notifications ${col.ddl}`);
        console.log('🔧 Added missing column "notifications.' + col.name + '" (auto-migration).');
      }
    } catch (err) {
      console.error('⚠️  Could not ensure notifications.' + col.name + ' column exists:', err.message);
    }
  }
}

/* Adds notifications.related_masterlist_id to databases that were set up
   before "Send Masterlist to Teacher" existed — same idempotent,
   check-then-add pattern as ensureStudentIdColumn() above. */
async function ensureNotificationsRelatedMasterlistColumn() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  try {
    const [cols] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.columns
       WHERE table_schema = ? AND table_name = 'notifications' AND column_name = 'related_masterlist_id'`,
      [dbName]
    );
    if (!cols[0].n) {
      await pool.query(`ALTER TABLE notifications ADD COLUMN related_masterlist_id INT UNSIGNED NULL AFTER sent_at`);
      await pool.query(`ALTER TABLE notifications ADD INDEX idx_notifications_related_masterlist (related_masterlist_id)`);
      console.log('🔧 Added missing column "notifications.related_masterlist_id" (auto-migration).');
    }
  } catch (err) {
    console.error('⚠️  Could not ensure notifications.related_masterlist_id column exists:', err.message);
  }
}

/* Adds the Announcement Center columns (category, priority, status) to
   databases whose "announcements" table was created before these fields
   existed in schema.sql. Same idempotent, check-then-add pattern as the
   other ensure*Column() functions — safe to run on every server start. */
async function ensureAnnouncementsColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const columns = [
    { name: 'category', ddl: `ADD COLUMN category ENUM('General','Academic','Enrollment','Registration','Schedule','Important') NOT NULL DEFAULT 'General' AFTER audience` },
    { name: 'priority', ddl: `ADD COLUMN priority ENUM('Low','Normal','High','Urgent') NOT NULL DEFAULT 'Normal' AFTER category` },
    { name: 'status', ddl: `ADD COLUMN status ENUM('Published','Draft','Archived') NOT NULL DEFAULT 'Published' AFTER priority` }
  ];
  for (const col of columns) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = 'announcements' AND column_name = ?`,
        [dbName, col.name]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE announcements ${col.ddl}`);
        console.log('🔧 Added missing column "announcements.' + col.name + '" (auto-migration).');
      }
    } catch (err) {
      console.error('⚠️  Could not ensure announcements.' + col.name + ' column exists:', err.message);
    }
  }
  try {
    await pool.query(
      `ALTER TABLE announcements
       ADD INDEX idx_announcements_category (category),
       ADD INDEX idx_announcements_priority (priority),
       ADD INDEX idx_announcements_status (status)`
    );
  } catch (err) {
    // ER_DUP_KEYNAME (1061) just means these indexes already exist — fine to ignore.
    if (err.errno !== 1061) console.error('⚠️  Could not ensure announcements category/priority/status indexes exist:', err.message);
  }
}

/* Adds sections.sent_to_teacher_id + sections.sent_at ("Send to Teacher")
   to databases whose "sections" table was created before this feature
   existed. Same idempotent, check-then-add pattern as the other
   ensure*Column() functions — safe to run on every server start. */
async function ensureSectionsSentColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const columns = [
    { name: 'sent_to_teacher_id', ddl: `ADD COLUMN sent_to_teacher_id INT UNSIGNED NULL AFTER adviser_teacher_id` },
    { name: 'sent_at', ddl: `ADD COLUMN sent_at DATETIME NULL AFTER sent_to_teacher_id` }
  ];
  for (const col of columns) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = 'sections' AND column_name = ?`,
        [dbName, col.name]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE sections ${col.ddl}`);
        console.log('🔧 Added missing column "sections.' + col.name + '" (auto-migration).');
      }
    } catch (err) {
      console.error('⚠️  Could not ensure sections.' + col.name + ' column exists:', err.message);
    }
  }
}

/* Adds users.student_id (+ its UNIQUE index) to databases that were set up
   before the Student ID Number field existed. Same idempotent,
   check-then-add pattern as the table migrations above — safe to run on
   every server start. */
async function ensureStudentIdColumn() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  try {
    const [cols] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.columns
       WHERE table_schema = ? AND table_name = 'users' AND column_name = 'student_id'`,
      [dbName]
    );
    if (!cols[0].n) {
      await pool.query(`ALTER TABLE users ADD COLUMN student_id VARCHAR(20) NULL AFTER detail`);
      console.log('🔧 Added missing column "users.student_id" (auto-migration).');
    }

    const [idx] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.statistics
       WHERE table_schema = ? AND table_name = 'users' AND index_name = 'uq_users_student_id'`,
      [dbName]
    );
    if (!idx[0].n) {
      await pool.query(`ALTER TABLE users ADD UNIQUE KEY uq_users_student_id (student_id)`);
      console.log('🔧 Added missing unique index "uq_users_student_id" (auto-migration).');
    }
  } catch (err) {
    console.error('⚠️  Could not ensure users.student_id column/index exists:', err.message);
  }
}

/* Feature 5 (Calendar) added two more values — 'academic_deadline' and
   'exam' — to events.type after some databases already had the table
   from Feature 4. A plain CREATE TABLE IF NOT EXISTS (the STATEMENTS
   list above) is a no-op once a table exists, so a MODIFY COLUMN is
   needed to widen the ENUM on those. Reads COLUMN_TYPE back from
   information_schema rather than unconditionally re-running the ALTER
   every boot, since MySQL's SHOW/DESCRIBE echoes back the exact enum
   list you gave it (quoted, comma-separated, no spaces), so a plain
   string compare against the same literal is enough to tell "already
   applied" from "still needs it." */
async function ensureEventsTypeEnum() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const desired = "enum('announcement','registration_deadline','enrollment_deadline','academic_deadline','school_event','activity','exam')";
  try {
    const [cols] = await pool.query(
      `SELECT COLUMN_TYPE AS colType FROM information_schema.columns
       WHERE table_schema = ? AND table_name = 'events' AND column_name = 'type'`,
      [dbName]
    );
    if (!cols.length) return; // events table doesn't exist yet — the STATEMENTS loop above will create it with the right enum
    if (cols[0].colType !== desired) {
      await pool.query(
        `ALTER TABLE events MODIFY COLUMN type
         ENUM('announcement','registration_deadline','enrollment_deadline','academic_deadline','school_event','activity','exam')
         NOT NULL DEFAULT 'school_event'`
      );
      console.log('🔧 Widened "events.type" enum with academic_deadline/exam (auto-migration).');
    }
  } catch (err) {
    console.error('⚠️  Could not ensure events.type enum is up to date:', err.message);
  }
}

/* Feature: Academic Year / Semester Management.
   Seeds the same three baseline terms schema.sql inserts on a fresh
   install (INSERT IGNORE against the UNIQUE key — a no-op if they're
   already there), so a database that already existed before this feature
   shipped gets real rows behind the free-text term labels its data
   already uses, instead of starting with an empty Academic Term
   Management screen. */
async function seedAcademicTerms() {
  try {
    await pool.query(
      `INSERT IGNORE INTO academic_terms (school_year, semester, label, status, activated_at, closed_at) VALUES
        ('2025-2026', '1st Semester', ?, 'closed', '2025-08-12 08:00:00', '2026-01-05 00:00:00'),
        ('2025-2026', '2nd Semester', ?, 'closed', '2026-01-06 08:00:00', '2026-06-01 00:00:00'),
        ('2026-2027', '1st Semester', ?, 'active', '2026-06-02 08:00:00', NULL)`,
      ['1st Semester, SY 2025\u20132026', '2nd Semester, SY 2025\u20132026', '1st Semester, SY 2026\u20132027']
    );
  } catch (err) {
    console.error('⚠️  Could not seed academic_terms:', err.message);
  }
}

/* Adds academic_term_id (+ FK + index) to the six term-scoped tables that
   predate Academic Term Management: registrations, enrollments,
   schedules, sections, attendance, grades. Same idempotent,
   check-then-add pattern as the other ensure*Column() functions above —
   safe to run on every server start, and a no-op on a fresh install
   where schema.sql already created these columns. */
async function ensureAcademicTermColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const targets = [
    { table: 'registrations', after: 'term' },
    { table: 'enrollments', after: 'term' },
    { table: 'schedules', after: 'term' },
    { table: 'sections', after: 'term' },
    { table: 'attendance', after: 'remarks' },
    { table: 'grades', after: 'term' }
  ];
  for (const t of targets) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = ? AND column_name = 'academic_term_id'`,
        [dbName, t.table]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE ${t.table} ADD COLUMN academic_term_id INT UNSIGNED NULL AFTER ${t.after}`);
        console.log('🔧 Added missing column "' + t.table + '.academic_term_id" (auto-migration).');
      }
      const idxName = 'idx_' + t.table + '_academic_term';
      const [idx2] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.statistics
         WHERE table_schema = ? AND table_name = ? AND index_name = ?`,
        [dbName, t.table, idxName]
      );
      if (!idx2[0].n) {
        await pool.query(`ALTER TABLE ${t.table} ADD INDEX ${idxName} (academic_term_id)`);
      }
      const fkName = 'fk_' + t.table + '_academic_term';
      const [fk] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.table_constraints
         WHERE table_schema = ? AND table_name = ? AND constraint_name = ?`,
        [dbName, t.table, fkName]
      );
      if (!fk[0].n) {
        await pool.query(
          `ALTER TABLE ${t.table} ADD CONSTRAINT ${fkName} FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL`
        );
      }
    } catch (err) {
      console.error('⚠️  Could not ensure ' + t.table + '.academic_term_id exists:', err.message);
    }
  }
}

/* Feature: Enrollment Workflow Integration.
   Widens registrations.status and enrollments.status to add
   'correction_requested' (admin can ask the student to fix something
   instead of only approve/reject), and adds admin_note to both for the
   rejection reason / correction instructions. Same
   check-COLUMN_TYPE-then-MODIFY pattern as ensureEventsTypeEnum() above. */
async function ensureWorkflowStatusColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  const tables = ['registrations', 'enrollments'];
  const desiredEnum = "enum('pending','approved','rejected','correction_requested')";
  for (const table of tables) {
    try {
      const [cols] = await pool.query(
        `SELECT COLUMN_TYPE AS colType FROM information_schema.columns
         WHERE table_schema = ? AND table_name = ? AND column_name = 'status'`,
        [dbName, table]
      );
      if (cols.length && cols[0].colType !== desiredEnum) {
        await pool.query(`ALTER TABLE ${table} MODIFY COLUMN status ${desiredEnum} NOT NULL DEFAULT 'pending'`);
        console.log('🔧 Widened "' + table + '.status" enum with correction_requested (auto-migration).');
      }
      const [noteCols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = ? AND column_name = 'admin_note'`,
        [dbName, table]
      );
      if (!noteCols[0].n) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN admin_note VARCHAR(500) NULL AFTER status`);
        console.log('🔧 Added missing column "' + table + '.admin_note" (auto-migration).');
      }
    } catch (err) {
      console.error('⚠️  Could not ensure ' + table + ' workflow-status columns exist:', err.message);
    }
  }
}

/* teacher_students.source_section_id — marks a roster link as auto-created
   because the student is on a section's roster and this teacher is its
   adviser (see src/routes/sections.js), as opposed to a manual link made
   directly via /api/roster/assignments. No FK (sections is defined later
   in schema.sql); cleaned up in application code instead. */
/* Feature: Profile pictures (student + teacher) and a fuller teacher
   professional profile. Adds, only if missing:
     - student_profiles.profile_picture, students.profile_picture
       (relative filename under the secure uploads dir — see
       utils/secureUpload.js — never a raw filesystem path)
     - teachers.profile_picture, .phone, .address, .position,
       .specialization, .employment_status — the teachers table
       previously only had department/subjects, nothing else needed for
       the upgraded Teacher Profile page.
   Each column is checked individually against information_schema so this
   is safe to run on every server start (no-op once already applied). */
async function ensureProfilePictureAndTeacherColumns() {
  const dbName = process.env.DB_NAME || 'tcc_college';

  async function addColumnIfMissing(table, column, ddl) {
    try {
      const [cols] = await pool.query(
        `SELECT COUNT(*) AS n FROM information_schema.columns
         WHERE table_schema = ? AND table_name = ? AND column_name = ?`,
        [dbName, table, column]
      );
      if (!cols[0].n) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
        console.log(`🔧 Added missing column "${table}.${column}" (auto-migration).`);
      }
    } catch (err) {
      console.error(`⚠️  Could not ensure ${table}.${column} exists:`, err.message);
    }
  }

  await addColumnIfMissing('student_profiles', 'profile_picture', 'profile_picture VARCHAR(255) NULL');
  await addColumnIfMissing('students', 'profile_picture', 'profile_picture VARCHAR(255) NULL');
  await addColumnIfMissing('teachers', 'profile_picture', 'profile_picture VARCHAR(255) NULL');
  await addColumnIfMissing('teachers', 'phone', 'phone VARCHAR(50) NULL');
  await addColumnIfMissing('teachers', 'address', 'address VARCHAR(255) NULL');
  await addColumnIfMissing('teachers', 'position', 'position VARCHAR(150) NULL');
  await addColumnIfMissing('teachers', 'specialization', 'specialization VARCHAR(150) NULL');
  await addColumnIfMissing('teachers', 'employment_status', "employment_status VARCHAR(50) NULL DEFAULT 'Full-time'");
}

async function ensureTeacherStudentsSectionColumn() {
  const dbName = process.env.DB_NAME || 'tcc_college';
  try {
    const [cols] = await pool.query(
      `SELECT COUNT(*) AS n FROM information_schema.columns
       WHERE table_schema = ? AND table_name = 'teacher_students' AND column_name = 'source_section_id'`,
      [dbName]
    );
    if (!cols[0].n) {
      await pool.query(`ALTER TABLE teacher_students ADD COLUMN source_section_id INT UNSIGNED NULL AFTER student_name`);
      await pool.query(`ALTER TABLE teacher_students ADD INDEX idx_teacher_students_section (source_section_id)`);
      console.log('🔧 Added missing column "teacher_students.source_section_id" (auto-migration).');
    }
  } catch (err) {
    console.error('⚠️  Could not ensure teacher_students.source_section_id exists:', err.message);
  }
}

/* Feature: Subjects catalog. Seeds the same demo subjects schema.sql
   inserts on a fresh install, tied to whichever term is active, so a
   database that predates this feature gets a populated Available
   Subjects list instead of an empty one. No-op (INSERT IGNORE against
   the UNIQUE key) if these already exist. */
async function seedSubjects() {
  try {
    const [[active]] = await pool.query(`SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1`);
    const termId = active ? active.id : null;
    await pool.query(
      `INSERT IGNORE INTO subjects (code, name, units, teacher_name, schedule_day, schedule_time, slots_total, academic_term_id) VALUES
        ('CS201','Data Structures & Algorithms',3,'Prof. Dizon','MWF','8:00–9:30 AM',40,?),
        ('CS202','Discrete Mathematics',3,'Prof. Manalo','MWF','10:00–11:30 AM',40,?),
        ('CS201L','Computer Programming Laboratory',1,'Prof. Dizon','TTh','1:00–3:00 PM',40,?),
        ('CS203','Object-Oriented Programming',3,'Prof. Reyes','TTh','8:00–9:30 AM',40,?),
        ('PE102','Physical Education 2',2,'Prof. Villareal','Sat','1:00–3:00 PM',40,?)`,
      [termId, termId, termId, termId, termId]
    );
  } catch (err) {
    console.error('⚠️  Could not seed subjects:', err.message);
  }
}

module.exports = { runMigrations };
