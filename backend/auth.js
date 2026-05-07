/**
 * backend/auth.js — Authentication & Authorization Module
 *
 * IMPROVEMENTS:
 *   1. 'moderator' role added (read + delete + rename, but NO write)
 *   2. Stronger password validation: 8+ chars, must contain a digit
 *   3. Session role refresh: requireAuth re-checks role from DB so
 *      admin role changes take effect immediately without re-login
 *   4. VALID_ROLES exported so server.js stays in sync automatically
 */

const bcrypt = require('bcryptjs');
const fs     = require('fs');
const path   = require('path');

const USERS_FILE     = path.join(__dirname, '..', 'data', 'users.json');
const MAX_FAIL_TRIES = 3;

// ─── PERMISSION TABLE (RBAC) ────────────────────────────────────────────────
const PERMISSIONS = {
  admin:     ['read_file', 'write_file', 'delete_file', 'list_files', 'rename_file', 'copy_file'],
  moderator: ['read_file', 'delete_file', 'list_files', 'rename_file'],
  user:      ['read_file', 'write_file',  'list_files', 'copy_file']
};

const VALID_ROLES = Object.keys(PERMISSIONS);

// ─── User File I/O ──────────────────────────────────────────────────────────

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch (e) { console.error('Could not load users.json. Run "node setup.js" first.'); return []; }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findUser(username) {
  return loadUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
}

// ─── Input Validation ──────────────────────────────────────────────────────

function validateLoginInput(username, password) {
  if (!username || typeof username !== 'string') return { valid: false, reason: 'Username is required.' };
  if (!password || typeof password !== 'string') return { valid: false, reason: 'Password is required.' };
  if (!/^[a-zA-Z0-9_]{2,30}$/.test(username.trim())) return { valid: false, reason: 'Username: 2-30 letters/digits/underscores only.' };
  if (password.length < 4) return { valid: false, reason: 'Password too short (min 4 chars).' };
  return { valid: true };
}

/**
 * IMPROVEMENT: Stronger password rules for registration.
 * Original required only 6 chars. Now requires 8+ chars and at least one digit.
 */
function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') return { valid: false, reason: 'Password is required.' };
  if (password.length < 8)   return { valid: false, reason: 'Password must be at least 8 characters.' };
  if (!/\d/.test(password))  return { valid: false, reason: 'Password must contain at least one number.' };
  if (password.length > 128) return { valid: false, reason: 'Password must be under 128 characters.' };
  return { valid: true };
}

// ─── Authentication ─────────────────────────────────────────────────────────

async function authenticate(username, plainPassword) {
  const trimmed = (username || '').trim();
  const check   = validateLoginInput(trimmed, plainPassword);
  if (!check.valid) return { success: false, reason: check.reason };

  const users = loadUsers();
  const user  = users.find(u => u.username.toLowerCase() === trimmed.toLowerCase());

  if (!user) return { success: false, reason: 'Invalid username or password.' };
  if (user.isLocked) return { success: false, reason: `Account locked after ${MAX_FAIL_TRIES} failed attempts. Contact admin.` };

  const passwordMatch = await bcrypt.compare(plainPassword, user.password);

  if (!passwordMatch) {
    user.failedAttempts = (user.failedAttempts || 0) + 1;
    if (user.failedAttempts >= MAX_FAIL_TRIES) {
      user.isLocked = true;
      user.lockedAt = new Date().toISOString();
      saveUsers(users);
      return { success: false, reason: `Too many failed attempts. Account "${trimmed}" is now LOCKED.` };
    }
    saveUsers(users);
    const remaining = MAX_FAIL_TRIES - user.failedAttempts;
    return { success: false, reason: `Invalid password. ${remaining} attempt(s) remaining before lockout.` };
  }

  user.failedAttempts = 0;
  user.lastLogin      = new Date().toISOString();
  saveUsers(users);

  const { password, ...safeUser } = user;
  return { success: true, user: safeUser };
}

// ─── Middleware ─────────────────────────────────────────────────────────────

/**
 * IMPROVEMENT: Session role refresh.
 * Original trusted whatever role was stored in the session at login time.
 * Bug: if admin promotes/demotes a user, their session kept the old role.
 * Fix: re-read the user's role from users.json on every authenticated request.
 */
function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
  }
  const freshUser = findUser(req.session.user.username);
  if (!freshUser) {
    req.session.destroy(() => {});
    return res.status(401).json({ success: false, message: 'Session invalid. Please log in again.' });
  }
  if (freshUser.isLocked) {
    req.session.destroy(() => {});
    return res.status(403).json({ success: false, message: 'Account has been locked. Contact admin.' });
  }
  req.session.user.role = freshUser.role; // sync live role into this request's session
  return next();
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).json({ success: false, message: 'Forbidden. Admin role required.' });
}

function isAuthorized(role, action) { return (PERMISSIONS[role] || []).includes(action); }
function getAllowedActions(role)     { return PERMISSIONS[role] || []; }

module.exports = {
  authenticate, requireAuth, requireAdmin,
  isAuthorized, getAllowedActions,
  findUser, loadUsers, saveUsers,
  validateLoginInput, validatePasswordStrength,
  VALID_ROLES
};
