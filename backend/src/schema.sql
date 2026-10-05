-- Talisay City College Management System — Phase 1 (Auth) schema
-- Run this once against your MySQL server, e.g.:
--   mysql -u root -p < src/schema.sql

USE defaultdb;

CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(150)  NOT NULL,
  email         VARCHAR(190)  NOT NULL,
  password_hash VARCHAR(255)  NOT NULL,
  role          ENUM('student', 'teacher', 'admin') NOT NULL,
  detail        VARCHAR(150)  NULL,               -- program (student) or department (teacher)
  student_id    VARCHAR(20)   NULL,               -- required + unique for role='student'; NULL for teacher/admin
  status        ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
  requested_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at    DATETIME      NULL,
  created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uq_users_student_id (student_id),    -- InnoDB allows any number of NULLs alongside this
  INDEX idx_users_email (email),
  INDEX idx_users_status (status)
) ENGINE=InnoDB;

-- Note: student_id is globally unique (across every status, including
-- rejected/pending) — a Student ID Number identifies one real person, so
-- unlike email it is never recycled. Validated + normalized (trimmed,
-- upper-cased) server-side in src/routes/auth.js before insert; the
-- UNIQUE constraint above is the authoritative guard against race
-- conditions (two concurrent signups with the same ID).

-- Note: email is intentionally NOT a UNIQUE constraint here. A rejected
-- request is allowed to be followed by a fresh signup with the same email
-- (mirrors the original frontend demo behaviour); uniqueness among
-- pending/approved rows for the same email is enforced in the app layer
-- (see src/routes/auth.js). Admin accounts are never created through
-- /api/auth/signup — use `npm run seed:admin` to create the first admin.

-- =========================================================================
-- Phase 4 — Academic Year / Semester management.
-- One row per (school_year, semester) combination the college has ever
-- run — "2026-2027" / "1st Semester", etc. Exactly one row may have
-- status='active' at a time (enforced in src/routes/academic-terms.js,
-- not the DB — MySQL has no partial/filtered unique index, same
-- limitation already noted on student_section_assignments below). Every
-- term-scoped table (registrations, enrollments, schedules, sections,
-- attendance, grades) gets an academic_term_id FK further down, set
-- automatically from whichever term is active when a record is created
-- (see src/utils/academicTerm.js) — students/teachers never pick a term
-- themselves, so records can't end up filed under the wrong one.
CREATE TABLE IF NOT EXISTS academic_terms (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  school_year    VARCHAR(20)  NOT NULL,                              -- "2026-2027"
  semester       ENUM('1st Semester','2nd Semester','Summer') NOT NULL,
  label          VARCHAR(100) NOT NULL,                              -- "1st Semester, SY 2026–2027" — matches the free-text format already used across the frontend
  status         ENUM('upcoming','active','closed') NOT NULL DEFAULT 'upcoming',
  starts_on      DATE NULL,
  ends_on        DATE NULL,
  activated_at   DATETIME NULL,
  closed_at      DATETIME NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_academic_terms_year_sem (school_year, semester)
) ENGINE=InnoDB;

-- Seed data matching the terms the frontend's demo copy already refers to
-- by free-text label, so a fresh install starts with real rows behind
-- that text instead of an empty Academic Term Management screen. No-op
-- (INSERT IGNORE against the UNIQUE key above) on a database that already
-- has these — safe to leave in schema.sql permanently.
INSERT IGNORE INTO academic_terms (school_year, semester, label, status, activated_at, closed_at) VALUES
  ('2025-2026', '1st Semester', '1st Semester, SY 2025–2026', 'closed', '2025-08-12 08:00:00', '2026-01-05 00:00:00'),
  ('2025-2026', '2nd Semester', '2nd Semester, SY 2025–2026', 'closed', '2026-01-06 08:00:00', '2026-06-01 00:00:00'),
  ('2026-2027', '1st Semester', '1st Semester, SY 2026–2027', 'active', '2026-06-02 08:00:00', NULL);

-- =========================================================================
-- Phase 2 — everything that used to live only in localStorage.
-- Same DB (tcc_college), one table per module, mirroring the field names
-- each frontend js/modules/*.js file already used so the API layer is a
-- thin pass-through. All IDs are auto-increment ints returned as strings
-- by the API (so existing frontend code comparing string ids keeps working).
-- =========================================================================

-- Module 6a — student profiles (admin roster)
CREATE TABLE IF NOT EXISTS student_profiles (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name              VARCHAR(150) NOT NULL,
  email             VARCHAR(190) NOT NULL,
  student_id        VARCHAR(50)  NULL,
  program           VARCHAR(150) NULL,
  year_level        VARCHAR(50)  NULL,
  section           VARCHAR(50)  NULL,
  status            ENUM('Regular','Irregular','Inactive') NOT NULL DEFAULT 'Regular',
  date_of_birth     VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext (see backend/src/utils/crypto.js)
  sex               VARCHAR(20)  NULL,
  civil_status      VARCHAR(50)  NULL,
  nationality       VARCHAR(80)  NULL,
  religion          VARCHAR(80)  NULL,
  address           VARCHAR(255) NULL,
  mobile            VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext
  guardian_name     VARCHAR(150) NULL,
  guardian_contact  VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext
  adviser           VARCHAR(150) NULL,
  date_admitted     VARCHAR(50)  NULL,
  profile_picture   VARCHAR(255) NULL,  -- filename under the secure uploads dir; never a raw filesystem path
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_profiles_email (email)
) ENGINE=InnoDB;

-- Module 5a — grades (teacher-entered, admin-verified)
CREATE TABLE IF NOT EXISTS grades (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  student_email     VARCHAR(190) NOT NULL,
  student_name      VARCHAR(150) NOT NULL,
  subject           VARCHAR(150) NOT NULL,
  term              VARCHAR(80)  NOT NULL DEFAULT 'Midterm',  -- grading PERIOD within a semester ('Midterm'/'Final') — NOT the school term, see academic_term_id
  academic_term_id  INT UNSIGNED NULL,                        -- the school year/semester this grade belongs to (see academic_terms above)
  teacher_email     VARCHAR(190) NULL,
  teacher_name      VARCHAR(150) NULL,
  midterm           DECIMAL(5,2) NULL,
  final             DECIMAL(5,2) NULL,
  remarks           VARCHAR(255) NULL,
  admin_status      ENUM('pending','verified') NOT NULL DEFAULT 'pending',
  entered_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_grades_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  INDEX idx_grades_student (student_email),
  INDEX idx_grades_teacher (teacher_email),
  INDEX idx_grades_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Module 5b — announcements
CREATE TABLE IF NOT EXISTS announcements (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title           VARCHAR(200) NOT NULL,
  body            TEXT NOT NULL,
  audience        ENUM('all','student','teacher') NOT NULL DEFAULT 'all',
  category        ENUM('General','Academic','Enrollment','Registration','Schedule','Important') NOT NULL DEFAULT 'General',
  priority        ENUM('Low','Normal','High','Urgent') NOT NULL DEFAULT 'Normal',
  status          ENUM('Published','Draft','Archived') NOT NULL DEFAULT 'Published',
  posted_by_name  VARCHAR(150) NOT NULL DEFAULT 'Staff',
  posted_by_role  ENUM('teacher','admin') NOT NULL DEFAULT 'teacher',
  posted_by_email VARCHAR(190) NULL,
  posted_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_announcements_audience (audience),
  INDEX idx_announcements_category (category),
  INDEX idx_announcements_priority (priority),
  INDEX idx_announcements_status (status)
) ENGINE=InnoDB;

-- Module 5b — announcement read receipts. One row per (announcement,
-- reader) once that reader has opened it in the Announcement Center's
-- detail view — absence of a row means "unread". Matched by email string
-- (same convention as the rest of Phase 2) rather than FK'd to users, so
-- it works uniformly for student/teacher/admin readers alike.
CREATE TABLE IF NOT EXISTS announcement_reads (
  id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  announcement_id  INT UNSIGNED NOT NULL,
  reader_email     VARCHAR(190) NOT NULL,
  read_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_announcement_reads (announcement_id, reader_email),
  CONSTRAINT fk_announcement_reads_announcement FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE,
  INDEX idx_announcement_reads_reader (reader_email)
) ENGINE=InnoDB;

-- Module 5d — teaching staff directory (admin Staff Management screen)
CREATE TABLE IF NOT EXISTS staff (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(150) NOT NULL,
  email          VARCHAR(190) NULL,
  department     VARCHAR(150) NULL,
  subjects       VARCHAR(255) NULL,
  load_sections  VARCHAR(50)  NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_staff_department (department)
) ENGINE=InnoDB;

-- Module 5c — feedback & suggestions
CREATE TABLE IF NOT EXISTS feedback (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name          VARCHAR(150) NOT NULL,
  email         VARCHAR(190) NULL,
  role          ENUM('student','teacher') NOT NULL DEFAULT 'student',
  category      VARCHAR(80) NOT NULL DEFAULT 'General',
  subject       VARCHAR(200) NULL,
  message       TEXT NOT NULL,
  status        ENUM('new','resolved') NOT NULL DEFAULT 'new',
  response      TEXT NULL,
  submitted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  responded_at  DATETIME NULL,
  INDEX idx_feedback_email (email)
) ENGINE=InnoDB;

-- Module 6b — term registrations
CREATE TABLE IF NOT EXISTS registrations (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  student_email     VARCHAR(190) NOT NULL,
  student_name      VARCHAR(150) NOT NULL,
  term              VARCHAR(100) NOT NULL,
  academic_term_id  INT UNSIGNED NULL,
  year_level        VARCHAR(50)  NULL,
  type              ENUM('Regular','Irregular') NOT NULL DEFAULT 'Regular',
  status            ENUM('pending','approved','rejected','correction_requested') NOT NULL DEFAULT 'pending',
  admin_note        VARCHAR(500) NULL,  -- reason for rejection, or what needs fixing when status='correction_requested'
  submitted_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at        DATETIME NULL,
  CONSTRAINT fk_registrations_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  INDEX idx_registrations_student (student_email),
  INDEX idx_registrations_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Module 6c-catalog — subjects available for enrollment. Admin-managed;
-- this is what students' "Available subjects" list (Subject Enrollment
-- page) now reads live from, instead of the hand-typed HTML checkboxes it
-- used to ship with. `enrollments.subjects` below still stores its own
-- JSON snapshot of {code,name,units} per request — this table is only the
-- catalog of what CAN be enrolled in, not a record of who enrolled.
CREATE TABLE IF NOT EXISTS subjects (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code              VARCHAR(20)  NOT NULL,
  name              VARCHAR(150) NOT NULL,
  units             DECIMAL(3,1) NOT NULL DEFAULT 3,
  teacher_name      VARCHAR(150) NULL,
  schedule_day      VARCHAR(30)  NULL,   -- e.g. "MWF"
  schedule_time     VARCHAR(50)  NULL,   -- e.g. "8:00–9:30 AM"
  slots_total       INT UNSIGNED NOT NULL DEFAULT 40,
  academic_term_id  INT UNSIGNED NULL,   -- which term this offering belongs to (see academic_terms above)
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_subjects_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  UNIQUE KEY uq_subjects_code_term (code, academic_term_id),
  INDEX idx_subjects_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Seed data matching the subjects the frontend used to hard-code in
-- student-dashboard.html's Available Subjects list, so a fresh install's
-- enrollment page still looks populated instead of empty. Tied to
-- whichever term is seeded 'active' above. No-op on a database that
-- already has these (INSERT IGNORE against the UNIQUE key above).
INSERT IGNORE INTO subjects (code, name, units, teacher_name, schedule_day, schedule_time, slots_total, academic_term_id)
SELECT * FROM (
  SELECT 'CS201' AS code, 'Data Structures & Algorithms' AS name, 3 AS units, 'Prof. Dizon' AS teacher_name, 'MWF' AS schedule_day, '8:00–9:30 AM' AS schedule_time, 40 AS slots_total, (SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1) AS academic_term_id
  UNION ALL SELECT 'CS202', 'Discrete Mathematics', 3, 'Prof. Manalo', 'MWF', '10:00–11:30 AM', 40, (SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1)
  UNION ALL SELECT 'CS201L', 'Computer Programming Laboratory', 1, 'Prof. Dizon', 'TTh', '1:00–3:00 PM', 40, (SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1)
  UNION ALL SELECT 'CS203', 'Object-Oriented Programming', 3, 'Prof. Reyes', 'TTh', '8:00–9:30 AM', 40, (SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1)
  UNION ALL SELECT 'PE102', 'Physical Education 2', 2, 'Prof. Villareal', 'Sat', '1:00–3:00 PM', 40, (SELECT id FROM academic_terms WHERE status = 'active' LIMIT 1)
) AS seed_subjects;

-- Module 6c — subject enrollments (subjects stored as JSON array of
-- { code, name, units }, matching the frontend's data model exactly)
CREATE TABLE IF NOT EXISTS enrollments (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  student_email     VARCHAR(190) NOT NULL,
  student_name      VARCHAR(150) NOT NULL,
  term              VARCHAR(100) NULL,
  academic_term_id  INT UNSIGNED NULL,
  subjects          JSON NOT NULL,
  total_units       INT NOT NULL DEFAULT 0,
  status            ENUM('pending','approved','rejected','correction_requested') NOT NULL DEFAULT 'pending',
  admin_note        VARCHAR(500) NULL,  -- reason for rejection, or what needs fixing when status='correction_requested'
  source            ENUM('request','assigned') NOT NULL DEFAULT 'request',
  submitted_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at        DATETIME NULL,
  CONSTRAINT fk_enrollments_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  INDEX idx_enrollments_student (student_email),
  INDEX idx_enrollments_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Module 6d — class schedule
CREATE TABLE IF NOT EXISTS schedules (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  subject           VARCHAR(150) NOT NULL,
  section           VARCHAR(50)  NOT NULL DEFAULT 'Sec A',
  day               VARCHAR(20)  NOT NULL,
  time              VARCHAR(50)  NOT NULL,
  room              VARCHAR(50)  NULL,
  teacher_name      VARCHAR(150) NULL,
  teacher_email     VARCHAR(190) NULL,
  term              VARCHAR(100) NULL,
  academic_term_id  INT UNSIGNED NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_schedules_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  INDEX idx_schedules_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Module 6e — attendance
CREATE TABLE IF NOT EXISTS attendance (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  student_email     VARCHAR(190) NOT NULL,
  student_name      VARCHAR(150) NOT NULL,
  subject           VARCHAR(150) NOT NULL,
  date              DATE NOT NULL,
  status            ENUM('Present','Late','Absent') NOT NULL DEFAULT 'Present',
  remarks           VARCHAR(255) NULL,
  academic_term_id  INT UNSIGNED NULL,
  recorded_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_attendance_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  INDEX idx_attendance_student (student_email),
  INDEX idx_attendance_subject_date (subject, date),
  INDEX idx_attendance_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Module 6g — explicit admin-assigned teacher↔student links (on top of the
-- automatic grades/schedule matching in src/utils/teacherStudents.js). Lets
-- admin hand-assign a student to a teacher directly, e.g. for advising or
-- before any grade/schedule record exists yet.
CREATE TABLE IF NOT EXISTS teacher_students (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  teacher_email       VARCHAR(190) NOT NULL,
  teacher_name        VARCHAR(150) NULL,
  student_email       VARCHAR(190) NOT NULL,
  student_name        VARCHAR(150) NOT NULL,
  source_section_id   INT UNSIGNED NULL,  -- set when this link exists because the student is on this section's roster and this teacher is its adviser (see src/routes/sections.js); NULL for a manual admin link made directly via /api/roster/assignments. No FK — `sections` is defined later in this file, and the link is cleaned up in application code (sections.js) rather than via ON DELETE CASCADE.
  assigned_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_teacher_student (teacher_email, student_email),
  INDEX idx_teacher_students_teacher (teacher_email),
  INDEX idx_teacher_students_student (student_email),
  INDEX idx_teacher_students_section (source_section_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notifications (
  id                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title                   VARCHAR(200) NOT NULL,
  message                 TEXT NOT NULL,
  recipient_type          ENUM('all','student','teacher','specific') NOT NULL DEFAULT 'all',
  recipient_email         VARCHAR(190) NULL,
  scheduled_for           DATETIME NULL,
  status                  ENUM('scheduled','sent') NOT NULL DEFAULT 'sent',
  created_at              DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at                 DATETIME NULL,
  related_masterlist_id   INT UNSIGNED NULL,   -- set when this notification is a "master list shared with you" alert (see masterlist_shares below)
  INDEX idx_notifications_related_masterlist (related_masterlist_id)
) ENGINE=InnoDB;

-- Per-recipient read state for `notifications`. Kept as its own table
-- (rather than a column on `notifications`) because one notification can
-- fan out to many recipients ('all'/'student'/'teacher') who each read it
-- independently. Mirrors announcement_reads above exactly.
CREATE TABLE IF NOT EXISTS notification_reads (
  id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  notification_id  INT UNSIGNED NOT NULL,
  reader_email     VARCHAR(190) NOT NULL,
  read_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_notification_reads (notification_id, reader_email),
  CONSTRAINT fk_notification_reads_notification FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE,
  INDEX idx_notification_reads_reader (reader_email)
) ENGINE=InnoDB;

-- Admin "Send Masterlist to Teacher" — a point-in-time snapshot of a
-- teacher's student list (Student ID, Name, Section only, per the
-- requirement) handed to that specific teacher. Kept separate from the
-- live master-list query (getTeacherStudents) so what the teacher opens
-- is exactly what the admin sent, even if rosters change later.
-- Access is enforced in src/routes/teacher.js: a teacher can only ever
-- fetch a row where teacher_email matches their own JWT email.
CREATE TABLE IF NOT EXISTS masterlist_shares (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  teacher_email  VARCHAR(190) NOT NULL,
  teacher_name   VARCHAR(150) NOT NULL,
  section        VARCHAR(50)  NULL,          -- NULL/blank = every section this teacher has
  students       JSON NOT NULL,              -- [{ studentId, name, section }, ...]
  sent_by_name   VARCHAR(150) NOT NULL,
  sent_by_email  VARCHAR(190) NULL,
  sent_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  viewed_at      DATETIME NULL,
  INDEX idx_masterlist_shares_teacher (teacher_email)
) ENGINE=InnoDB;

-- Feature 4 — Upcoming Events widget. Admin-curated calendar entries with
-- a future-facing event_date, covering everything on the widget's list
-- that has no other home in the schema (registration/enrollment
-- deadlines, school events, scheduled activities) plus "important
-- announcement" entries an admin wants pinned with a specific date. The
-- widget itself (js/core/upcoming-events.js) merges GET /api/events with
-- schedules-derived "upcoming classes" — those stay generated from the
-- existing schedules table rather than duplicated in here, so there's
-- only ever one place that owns a class's day/time/room.
CREATE TABLE IF NOT EXISTS events (
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
) ENGINE=InnoDB;

-- =========================================================================
-- Phase 3 — Normalized core academic schema.
--
-- Everything above matches students/teachers by email STRING (no FK) and
-- stores "section" as free text. This section replaces that matching with
-- real foreign keys and unique constraints, per table:
--
--   users (already above)  ---1:1---  students / teachers
--   teachers                ---1:N---  sections            (adviser)
--   students <---N:M (via student_section_assignments)---> sections
--   sections                ---1:1---  masterlists          (per term)
--   masterlists <---N:M (via teacher_masterlist_assignments)---> teachers
--
-- The Phase 2 tables (student_profiles, teacher_students, masterlist_shares)
-- are left in place — src/migrate.js backfills this schema from them on
-- startup — so nothing currently reading those tables breaks. Routes can
-- be switched over to the tables below incrementally; that's tracked as
-- separate application-code work, not part of this schema change.
-- =========================================================================

-- Students — one academic-record row per approved student account
-- (users.role = 'student'). FK'd to the account instead of matched by
-- email string; student_id is duplicated from users.student_id (which
-- exists pre-approval, for signup dedup) so this table has its own
-- authoritative, independently-unique copy once a record exists here.
CREATE TABLE IF NOT EXISTS students (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id           INT UNSIGNED NOT NULL,
  student_id        VARCHAR(20)  NOT NULL,
  program           VARCHAR(150) NULL,
  year_level        VARCHAR(50)  NULL,
  status            ENUM('Regular','Irregular','Inactive') NOT NULL DEFAULT 'Regular',
  date_of_birth     VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext (see backend/src/utils/crypto.js)
  sex               VARCHAR(20)  NULL,
  civil_status      VARCHAR(50)  NULL,
  nationality       VARCHAR(80)  NULL,
  religion          VARCHAR(80)  NULL,
  address           VARCHAR(255) NULL,
  mobile            VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext
  guardian_name     VARCHAR(150) NULL,
  guardian_contact  VARCHAR(255) NULL,  -- widened from 50: stores AES-256-GCM ciphertext, not plaintext
  date_admitted     VARCHAR(50)  NULL,
  profile_picture   VARCHAR(255) NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT fk_students_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_students_user (user_id),
  UNIQUE KEY uq_students_student_id (student_id),
  INDEX idx_students_program (program)
) ENGINE=InnoDB;

-- Teachers — one row per teacher account (users.role = 'teacher').
CREATE TABLE IF NOT EXISTS teachers (
  id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id            INT UNSIGNED NOT NULL,
  department         VARCHAR(150) NULL,
  subjects           VARCHAR(255) NULL,
  phone              VARCHAR(50)  NULL,
  address            VARCHAR(255) NULL,
  position           VARCHAR(150) NULL,
  specialization     VARCHAR(150) NULL,
  employment_status  VARCHAR(50)  NULL DEFAULT 'Full-time',
  profile_picture    VARCHAR(255) NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT fk_teachers_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uq_teachers_user (user_id),
  INDEX idx_teachers_department (department)
) ENGINE=InnoDB;

-- Sections — a real, referenceable class section (e.g. "BSIT-2A", one
-- school term) instead of the free-text student_profiles.section string.
CREATE TABLE IF NOT EXISTS sections (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  section_code        VARCHAR(50)  NOT NULL,   -- e.g. "BSIT-2A"
  program             VARCHAR(150) NULL,
  year_level          VARCHAR(50)  NULL,
  term                VARCHAR(100) NOT NULL,   -- e.g. "2025-2026 1st Sem"
  academic_term_id    INT UNSIGNED NULL,
  adviser_teacher_id  INT UNSIGNED NULL,
  sent_to_teacher_id  INT UNSIGNED NULL,       -- which teachers.id admin last clicked
                                                -- "Send to Teacher" for. Compared against
                                                -- adviser_teacher_id (not FK'd to it) to
                                                -- derive Sent/Not sent: if admin reassigns
                                                -- the section to someone else, the two stop
                                                -- matching and the status flips back to "Not
                                                -- sent" for the new teacher automatically —
                                                -- no extra bookkeeping needed on reassignment.
  sent_at             DATETIME NULL,           -- when that send happened
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT fk_sections_adviser FOREIGN KEY (adviser_teacher_id) REFERENCES teachers(id) ON DELETE SET NULL,
  CONSTRAINT fk_sections_academic_term FOREIGN KEY (academic_term_id) REFERENCES academic_terms(id) ON DELETE SET NULL,
  UNIQUE KEY uq_sections_code_term (section_code, term),
  INDEX idx_sections_adviser (adviser_teacher_id),
  INDEX idx_sections_academic_term (academic_term_id)
) ENGINE=InnoDB;

-- Student Section Assignments — which section a student belongs to. A
-- student can't be added to the exact same section twice, but the same
-- section_code across two different terms is two different sections rows
-- (see uq_sections_code_term above), so re-enrollment across terms is
-- naturally two separate assignment rows.
-- Note: MySQL has no partial/filtered unique index, so "only one ACTIVE
-- section per student per term" can't be a single constraint here —
-- enforce that check in the app layer before inserting/activating a row.
CREATE TABLE IF NOT EXISTS student_section_assignments (
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
) ENGINE=InnoDB;

-- Masterlists — the official roster "event" for one section, one term.
-- The student list itself is NOT duplicated here; it's the live join of
-- student_section_assignments WHERE section_id = ... AND status = 'active'.
-- One row per section+term — regenerating updates generated_at/generated_by
-- on the existing row instead of creating a duplicate.
CREATE TABLE IF NOT EXISTS masterlists (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  section_id     INT UNSIGNED NOT NULL,
  term           VARCHAR(100) NOT NULL,
  title          VARCHAR(200) NULL,
  generated_by   INT UNSIGNED NULL,        -- users.id of the admin who generated it
  generated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_masterlists_section FOREIGN KEY (section_id) REFERENCES sections(id) ON DELETE CASCADE,
  CONSTRAINT fk_masterlists_generated_by FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE SET NULL,
  UNIQUE KEY uq_masterlists_section_term (section_id, term),
  INDEX idx_masterlists_generated_by (generated_by)
) ENGINE=InnoDB;

-- Teacher Masterlist Assignments / Notifications — a master list handed
-- to one specific teacher. Replaces the JSON-snapshot masterlist_shares
-- table above with real FKs to both the master list and the teacher,
-- keeping the same sent/viewed tracking notifications already had.
CREATE TABLE IF NOT EXISTS teacher_masterlist_assignments (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  masterlist_id       INT UNSIGNED NOT NULL,
  teacher_id          INT UNSIGNED NOT NULL,
  assigned_by         INT UNSIGNED NULL,    -- users.id of the admin who sent it
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
) ENGINE=InnoDB;

-- Student requests to change their registrar-managed personal information
-- (date of birth, sex, civil status, nationality, religion). The profile is
-- untouched until an admin approves. `changes` holds AES-256-GCM encrypted
-- JSON ({ field: { from, to } }) because it can contain a date of birth.
-- Also created automatically by src/migrate.js on server start.
CREATE TABLE IF NOT EXISTS profile_change_requests (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  profile_id     INT UNSIGNED NOT NULL,
  student_email  VARCHAR(190) NOT NULL,
  student_name   VARCHAR(150) NOT NULL,
  changes        TEXT NOT NULL,
  reason         VARCHAR(500) NULL,
  status         ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
  admin_note     VARCHAR(500) NULL,
  reviewed_by    VARCHAR(190) NULL,
  reviewed_at    DATETIME NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_pcr_email (student_email),
  INDEX idx_pcr_status (status),
  CONSTRAINT fk_pcr_profile FOREIGN KEY (profile_id) REFERENCES student_profiles(id) ON DELETE CASCADE
) ENGINE=InnoDB;
