/**
 * test-encryption.js
 * Standalone script to exercise the encrypt -> store -> decrypt flow for
 * student_profiles sensitive fields (date_of_birth, address, mobile,
 * guardian_contact) without needing curl or Postman.
 *
 * USAGE:
 *   1. Make sure the backend is already running (npm start) in another
 *      terminal — this script just calls it over HTTP.
 *   2. Edit ADMIN_EMAIL / ADMIN_PASSWORD / PROFILE_ID / PASSKEY below to
 *      match your setup.
 *   3. Run:  node test-encryption.js
 *
 * It will:
 *   - Log in as admin
 *   - PUT sample sensitive data onto the given student_profiles row
 *     (this is what causes it to be encrypted at rest)
 *   - Call the passkey-gated reveal endpoint to decrypt it back
 *   - Print each step's response so you can confirm the round trip works
 *
 * This file is a dev/test convenience only — it is not used by the
 * running app and is safe to delete once you're done testing.
 */

const http = require('http');

const HOST = 'localhost';
const PORT = 4000;

// ---- EDIT THESE BEFORE RUNNING ----
const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PASSWORD = 'YOUR_ADMIN_PASSWORD';
const PROFILE_ID = 1; // the student_profiles.id to test against
const ADMIN_PASSKEY = 'ukjJ27MlzVAm'; // from backend/.env ADMIN_PASSKEY_HASH comment
// ------------------------------------

function request(method, path, body, token) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: HOST,
        port: PORT,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        }
      },
      (res) => {
        let chunks = '';
        res.on('data', (c) => (chunks += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(chunks || '{}') });
          } catch (e) {
            resolve({ status: res.statusCode, body: chunks });
          }
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  console.log(`\n--- 1. Logging in as ${ADMIN_EMAIL} ---`);
  const login = await request('POST', '/api/auth/login', {
    email: ADMIN_EMAIL,
    password: ADMIN_PASSWORD
  });
  console.log(login);

  const token = login.body && login.body.token;
  if (!token) {
    console.error('\n❌ No token returned — check ADMIN_EMAIL/ADMIN_PASSWORD above and that the backend is running.');
    return;
  }

  console.log(`\n--- 2. Writing sample sensitive data to profile id ${PROFILE_ID} ---`);
  const updated = await request(
    'PUT',
    `/api/profiles/${PROFILE_ID}`,
    {
      dateOfBirth: '2003-05-14',
      address: '123 Rizal St., Talisay City',
      mobile: '09171234567',
      guardianContact: '09189876543'
    },
    token
  );
  console.log(updated);

  console.log('\n--- 3. Reading it back via GET /api/profiles (should be masked, e.g. "••••••") ---');
  const list = await request('GET', '/api/profiles', null, token);
  const row = Array.isArray(list.body.profiles) && list.body.profiles.find((p) => p.id === String(PROFILE_ID));
  console.log(row || list);

  console.log(`\n--- 4. Decrypting via POST /api/profiles/${PROFILE_ID}/reveal-sensitive (passkey-gated) ---`);
  const revealed = await request(
    'POST',
    `/api/profiles/${PROFILE_ID}/reveal-sensitive`,
    { passkey: ADMIN_PASSKEY },
    token
  );
  console.log(revealed);

  console.log('\n--- 5. Confirming a WRONG passkey is rejected ---');
  const rejected = await request(
    'POST',
    `/api/profiles/${PROFILE_ID}/reveal-sensitive`,
    { passkey: 'this-is-not-the-passkey' },
    token
  );
  console.log(rejected);

  console.log('\nDone. Now check MySQL:');
  console.log(
    `  SELECT id, name, date_of_birth, address, mobile, guardian_contact FROM student_profiles WHERE id = ${PROFILE_ID};`
  );
  console.log('  -> those columns should show "v1:..." ciphertext, not the plaintext values above.');
})().catch((err) => {
  console.error('\n❌ Script error (is the backend running on port 4000?):', err.message);
});
