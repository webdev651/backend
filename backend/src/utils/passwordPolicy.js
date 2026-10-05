/**
 * Password strength rule, shared by every place a password gets set,
 * whether by the account owner (signup, change-password) or by an admin
 * typing a new password for someone else (admin reset-password) — both
 * are human-typed, so both get the same floor.
 *
 * Requirements: 8+ characters, at least one uppercase letter, one
 * lowercase letter, and one number. Special characters are allowed and
 * encouraged but not required, per product decision.
 */
const MIN_LENGTH = 8;

function checkPasswordStrength(password) {
  const pw = String(password || '');
  const problems = [];

  if (pw.length < MIN_LENGTH) problems.push(`at least ${MIN_LENGTH} characters`);
  if (!/[A-Z]/.test(pw)) problems.push('an uppercase letter');
  if (!/[a-z]/.test(pw)) problems.push('a lowercase letter');
  if (!/[0-9]/.test(pw)) problems.push('a number');

  return {
    valid: problems.length === 0,
    message: problems.length
      ? `Password must contain ${problems.join(', ')}.`
      : null
  };
}

module.exports = { checkPasswordStrength };
