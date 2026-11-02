require('dotenv').config();
const mysql = require('mysql2/promise');

/* Managed MySQL (Aiven) requires an encrypted connection ("SSL mode REQUIRED").
   Set DB_SSL=true on the host (Render). Best practice is to also set DB_SSL_CA
   to the service's CA certificate text (Aiven console > Connection information
   > CA certificate) so the server's identity is verified. Without DB_SSL_CA the
   connection is still encrypted but the certificate is not verified.
*/
let ssl;
if (/^(1|true|yes)$/i.test(String(process.env.DB_SSL || ''))) {
  const ca = (process.env.DB_SSL_CA || '').replace(/\\n/g, '\n').trim();
  ssl = ca ? { ca, rejectUnauthorized: true } : { rejectUnauthorized: false };
  if (!ca) console.warn('[db] DB_SSL=true without DB_SSL_CA: connection is encrypted but the server certificate is not verified.');
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME,
  ssl,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  dateStrings: true
});

module.exports = pool;
