// Kept only so any existing `require('../utils/mailer')` keeps working.
// All SMTP logic now lives in src/services/emailService.js.
const { sendPasswordResetEmail } = require('../services/emailService');

module.exports = { sendPasswordResetEmail };
