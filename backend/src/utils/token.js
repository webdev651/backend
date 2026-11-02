const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || '12h';

// SECURITY: no insecure fallback secret. A missing/placeholder JWT_SECRET
// would make every issued token forgeable by anyone who read this source
// file (it's a public default). Fail fast at startup instead of silently
// running with a known, guessable secret.
if (!SECRET || SECRET === 'change_this_to_a_long_random_string') {
  throw new Error(
    'JWT_SECRET is missing or still set to the placeholder value in backend/.env. ' +
    'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))" ' +
    'and set it before starting the server.'
  );
}

function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES_IN });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET);
}

module.exports = { signToken, verifyToken };
