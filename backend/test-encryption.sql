-- test-encryption.sql
-- Database-side checks for the sensitive-field encryption feature.
-- Run with:  mysql -u root -p tcc_college < test-encryption.sql
-- or paste individual sections into your MySQL client (Workbench/CLI).
--
-- IMPORTANT: none of these queries can show you the ORIGINAL (decrypted)
-- values — that's by design, since the decryption key lives only in the
-- Node backend's .env, never in the database. To see decrypted values,
-- run `node test-encryption.js` (or run-test.bat) in the backend folder
-- instead — this file only confirms things are stored correctly.

-- 1. Confirm the sensitive columns were widened to fit encrypted payloads
--    (should show 255, not 50, for date_of_birth/mobile/guardian_contact)
SELECT TABLE_NAME, COLUMN_NAME, CHARACTER_MAXIMUM_LENGTH
FROM information_schema.columns
WHERE TABLE_SCHEMA = 'tcc_college'
  AND TABLE_NAME IN ('student_profiles', 'students')
  AND COLUMN_NAME IN ('date_of_birth', 'address', 'mobile', 'guardian_contact')
ORDER BY TABLE_NAME, COLUMN_NAME;

-- 2. View the encrypted values for a specific profile (\G = one field per
--    line, much easier to read than a wrapped table for long ciphertext)
SELECT id, name, date_of_birth, address, mobile, guardian_contact
FROM student_profiles
WHERE id = 1 \G

-- 3. Sanity check: every non-empty sensitive value should start with
--    "v1:" (our encrypted-payload marker). This returns 0 rows if
--    everything is correctly encrypted; any row returned here means a
--    plaintext value slipped through and needs investigating.
SELECT id, name, 'date_of_birth' AS bad_column, date_of_birth AS bad_value
FROM student_profiles
WHERE date_of_birth IS NOT NULL AND date_of_birth <> '' AND date_of_birth NOT LIKE 'v1:%'
UNION ALL
SELECT id, name, 'address', address
FROM student_profiles
WHERE address IS NOT NULL AND address <> '' AND address NOT LIKE 'v1:%'
UNION ALL
SELECT id, name, 'mobile', mobile
FROM student_profiles
WHERE mobile IS NOT NULL AND mobile <> '' AND mobile NOT LIKE 'v1:%'
UNION ALL
SELECT id, name, 'guardian_contact', guardian_contact
FROM student_profiles
WHERE guardian_contact IS NOT NULL AND guardian_contact <> '' AND guardian_contact NOT LIKE 'v1:%';

-- 4. Same normalized-table check, if you use `students` too
SELECT id, 'date_of_birth' AS bad_column, date_of_birth AS bad_value
FROM students
WHERE date_of_birth IS NOT NULL AND date_of_birth <> '' AND date_of_birth NOT LIKE 'v1:%'
UNION ALL
SELECT id, 'mobile', mobile FROM students
WHERE mobile IS NOT NULL AND mobile <> '' AND mobile NOT LIKE 'v1:%'
UNION ALL
SELECT id, 'guardian_contact', guardian_contact FROM students
WHERE guardian_contact IS NOT NULL AND guardian_contact <> '' AND guardian_contact NOT LIKE 'v1:%';

-- 5. Confirm the audit log table exists and is recording attempts
--    (run this AFTER using the reveal-sensitive endpoint at least once)
SELECT admin_email, target_type, target_id, fields_requested, success, reason, ip_address, created_at
FROM sensitive_data_access_log
ORDER BY created_at DESC
LIMIT 20;

-- 6. Never forget: password_hash should ALWAYS look like $2a$10$... or
--    $2b$10$... (bcrypt) — never plaintext, never "v1:..." (encrypted).
--    This confirms passwords were never touched by this feature.
SELECT id, email, password_hash
FROM users
WHERE password_hash NOT LIKE '$2%'
   OR password_hash LIKE 'v1:%';
-- Expect 0 rows here. Any row returned is a serious problem.
