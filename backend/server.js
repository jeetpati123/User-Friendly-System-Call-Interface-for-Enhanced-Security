/**
 * backend/server.js — Main Express Server
 *
 * IMPROVEMENTS:
 *   1. Security headers middleware (CSP, X-Frame-Options, etc.) — no extra package needed
 *   2. IP-based login rate limiter — prevents brute-forcing many accounts in parallel
 *   3. IP-based register rate limiter — prevents account creation spam (5/IP/hour)
 *   4. Log search API — GET /api/logs now accepts ?username= &status= &action= &from= &to= &limit=
 *   5. POST /api/users/change-password — let logged-in users change their own password
 *   6. change-role now validates against VALID_ROLES instead of a hardcoded list
 *   7. Registration uses validatePasswordStrength (8+ chars, must contain digit)
 *   8. Stats endpoint passes username filter for non-admin users (server-side, not client-side)
 *   9. SESSION_SECRET loaded from .env via dotenv (falls back with warning)
 *  10. CSRF token endpoint + middleware on all state-changing routes
 */

require('dotenv').config();

const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

const { authenticate, requireAuth, requireAdmin,
        getAllowedActions, loadUsers, saveUsers,
        validatePasswordStrength, VALID_ROLES }  = require('./auth');
const { systemCall }                             = require('./systemCall');
const { logEntry, logError, getLogs, searchLogs, clearLogs, getLogStats } = require('./logger');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Security Headers ────────────────────────────────────────────────────────
// IMPROVEMENT: Added security headers without requiring helmet package.
// These headers defend against clickjacking, MIME sniffing, and XSS.
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
    "connect-src 'self';"
  );
  next();
});

// ─── IP-based Login Rate Limiter ─────────────────────────────────────────────
// IMPROVEMENT: Original had per-account lockout but no IP-level rate limiting.
// An attacker could test thousands of accounts without any slowdown.
// This simple in-memory limiter allows 10 login attempts per IP per 15 minutes.
const loginAttempts = new Map(); // ip -> { count, resetAt }
const LOGIN_WINDOW_MS   = 15 * 60 * 1000; // 15 minutes
const LOGIN_MAX_ATTEMPTS = 10;

function loginRateLimiter(req, res, next) {
  const ip  = getIP(req);
  const now = Date.now();
  let   rec = loginAttempts.get(ip);

  if (!rec || now > rec.resetAt) {
    rec = { count: 0, resetAt: now + LOGIN_WINDOW_MS };
    loginAttempts.set(ip, rec);
  }

  if (rec.count >= LOGIN_MAX_ATTEMPTS) {
    const waitSec = Math.ceil((rec.resetAt - now) / 1000);
    return res.status(429).json({
      success: false,
      message: `Too many login attempts from your IP. Try again in ${waitSec} seconds.`
    });
  }

  rec.count++;
  next();
}

// Clean up stale IP entries every 30 minutes to prevent memory growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts.entries()) {
    if (now > rec.resetAt) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ─── Register Rate Limiter ────────────────────────────────────────────────────
// 5 registration attempts per IP per hour — stops account-creation spam.
const registerAttempts   = new Map();
const REG_WINDOW_MS      = 60 * 60 * 1000; // 1 hour
const REG_MAX_ATTEMPTS   = 5;

function registerRateLimiter(req, res, next) {
  const ip  = getIP(req);
  const now = Date.now();
  let   rec = registerAttempts.get(ip);
  if (!rec || now > rec.resetAt) {
    rec = { count: 0, resetAt: now + REG_WINDOW_MS };
    registerAttempts.set(ip, rec);
  }
  if (rec.count >= REG_MAX_ATTEMPTS) {
    const waitMin = Math.ceil((rec.resetAt - now) / 60000);
    return res.status(429).json({
      success: false,
      message: `Too many accounts created from this IP. Try again in ${waitMin} minute(s).`
    });
  }
  rec.count++;
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of registerAttempts.entries()) {
    if (now > rec.resetAt) registerAttempts.delete(ip);
  }
}, 60 * 60 * 1000);

// ─── CSRF Protection ──────────────────────────────────────────────────────────
// Synchronizer token pattern: client fetches token from /api/csrf-token after
// login and includes it as X-CSRF-Token header on all state-changing requests.
function requireCSRF(req, res, next) {
  const token = req.headers['x-csrf-token'];
  if (!token || !req.session.csrfToken || token !== req.session.csrfToken) {
    return res.status(403).json({ success: false, message: 'Invalid or missing CSRF token.' });
  }
  next();
}

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.use(session({
  secret:            process.env.SESSION_SECRET || 'syscall-secret-key-btech-2024',
  resave:            false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 30 * 60 * 1000 }
}));

if (!process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET not set. Using default secret — NEVER do this in production!');
}

function getIP(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
}

// ══════════════════════════════════════════════════════════════════════════
// REGISTER
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/register', registerRateLimiter, async (req, res) => {
  const { username, password, email } = req.body || {};
  const ip = getIP(req);

  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  // Updated username rules: 4–30 chars, must start with a letter, letters/digits/underscore only
  if (username.length < 4)
    return res.status(400).json({ success: false, message: 'Username must be at least 4 characters.' });
  if (!/^[a-zA-Z]/.test(username))
    return res.status(400).json({ success: false, message: 'Username must start with a letter (a–z or A–Z).' });
  if (!/^[a-zA-Z][a-zA-Z0-9_]{3,29}$/.test(username))
    return res.status(400).json({ success: false, message: 'Username may only contain letters, numbers, and underscore (_). No spaces or special characters.' });

  // IMPROVEMENT: Use the stronger validatePasswordStrength (8+ chars, 1 digit required)
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid)
    return res.status(400).json({ success: false, message: pwCheck.reason });

  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ success: false, message: 'Please enter a valid email address.' });

  const users  = loadUsers();
  const exists = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists)
    return res.status(409).json({ success: false, message: `Username "${username}" is already taken.` });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now(), username,
      password: hashedPassword,
      role: 'user',
      email: email || '',
      failedAttempts: 0,
      isLocked: false,
      createdAt: new Date().toISOString(),
      lastLogin: null
    };
    users.push(newUser);
    saveUsers(users);
    logEntry(username, 'REGISTER', 'system', 'SUCCESS', `New account from ${ip}`, ip, 'user');
    return res.status(201).json({ success: true, message: `Account "${username}" created successfully! You can now log in.` });
  } catch (err) {
    logError(username, 'REGISTER', 'system', err.message, ip);
    return res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════

// IMPROVEMENT: loginRateLimiter applied here — caps attempts per IP
app.post('/api/login', loginRateLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const ip = getIP(req);

  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Username and password are required.' });

  try {
    const result = await authenticate(username, password);
    if (result.success) {
      // On successful login, clear this IP's attempt counter
      loginAttempts.delete(ip);
      req.session.user      = result.user;
      req.session.csrfToken = crypto.randomBytes(32).toString('hex'); // generate once at login
      logEntry(username, 'LOGIN', 'system', 'SUCCESS', `Logged in from ${ip}`, ip, result.user.role);
      return res.json({
        success: true,
        message: `Welcome back, ${result.user.username}!`,
        user: { username: result.user.username, role: result.user.role, email: result.user.email, lastLogin: result.user.lastLogin }
      });
    } else {
      logEntry(username, 'LOGIN', 'system', 'DENIED', result.reason, ip, '');
      return res.status(401).json({ success: false, message: result.reason });
    }
  } catch (err) {
    logError(username, 'LOGIN', 'system', err.message, ip);
    return res.status(500).json({ success: false, message: 'Server error during login.' });
  }
});

app.post('/api/logout', (req, res) => {
  const username = req.session.user ? req.session.user.username : 'unknown';
  const role     = req.session.user ? req.session.user.role     : '';
  logEntry(username, 'LOGOUT', 'system', 'SUCCESS', 'User logged out', getIP(req), role);
  req.session.destroy(err => {
    if (err) return res.status(500).json({ success: false, message: 'Logout failed.' });
    res.clearCookie('connect.sid');
    return res.json({ success: true, message: 'Logged out successfully.' });
  });
});

// ══════════════════════════════════════════════════════════════════════════
// FORGOT PASSWORD
// ══════════════════════════════════════════════════════════════════════════

// POST /api/auth/forgot-password
// Generates a 6-digit reset token (valid 15 min), stores it on the user.
// In demo mode the token is returned in the response.
// In production you would email it and NOT return it here.
app.post('/api/auth/forgot-password', async (req, res) => {
  const { username } = req.body || {};
  if (!username)
    return res.status(400).json({ success: false, message: 'Username is required.' });

  try {
    const users = loadUsers();
    const user  = users.find(u => u.username === username);

    // Always respond with success to avoid username enumeration
    if (!user) {
      return res.json({
        success: true,
        message: 'If that username exists, a reset token has been generated.',
        token: '——'   // placeholder so UI doesn't break
      });
    }

    const token    = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();   // 15 min

    user.resetToken        = token;
    user.resetTokenExpires = expiresAt;
    saveUsers(users);

    logEntry(username, 'FORGOT_PASSWORD', 'auth', 'SUCCESS',
      'Reset token generated', getIP(req), user.role);

    return res.json({
      success: true,
      message: `Reset token generated for "${username}". Valid for 15 minutes.`,
      token                  // ← demo only; remove in production and email instead
    });
  } catch (err) {
    console.error('forgot-password error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// POST /api/auth/reset-password
// Validates the token and sets the new password.
app.post('/api/auth/reset-password', async (req, res) => {
  const { username, token, newPassword } = req.body || {};
  if (!username || !token || !newPassword)
    return res.status(400).json({ success: false, message: 'Username, token, and new password are required.' });

  const pwdCheck = validatePasswordStrength(newPassword);
  if (!pwdCheck.valid)
    return res.status(400).json({ success: false, message: pwdCheck.message });

  try {
    const users = loadUsers();
    const user  = users.find(u => u.username === username);

    if (!user || !user.resetToken)
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token.' });

    if (user.resetToken !== token)
      return res.status(400).json({ success: false, message: 'Incorrect reset token.' });

    if (new Date() > new Date(user.resetTokenExpires))
      return res.status(400).json({ success: false, message: 'Reset token has expired. Please request a new one.' });

    // Set new password and clear the token
    user.password           = await bcrypt.hash(newPassword, 12);
    user.resetToken         = null;
    user.resetTokenExpires  = null;
    user.failedAttempts     = 0;     // also unlock account if it was locked
    user.isLocked           = false;
    saveUsers(users);

    logEntry(username, 'RESET_PASSWORD', 'auth', 'SUCCESS',
      'Password reset via token', getIP(req), user.role);

    return res.json({ success: true, message: 'Password reset successfully!' });
  } catch (err) {
    console.error('reset-password error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

app.get('/api/whoami',      requireAuth, (req, res) => res.json({ success: true, user: req.session.user }));
app.get('/api/permissions', requireAuth, (req, res) => res.json({ success: true, allowed: getAllowedActions(req.session.user.role) }));

// CSRF token — generated at login; this endpoint returns it to the frontend.
// Falls back to generating one now if somehow missing.
app.get('/api/csrf-token', requireAuth, (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.save();   // force save so it's available immediately
  }
  res.json({ token: req.session.csrfToken });
});

// ══════════════════════════════════════════════════════════════════════════
// SYSTEM CALL
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/syscall', requireAuth, requireCSRF, (req, res) => {
  const { action, resource, content } = req.body || {};
  const user = req.session.user;
  const ip   = getIP(req);

  if (!action || typeof action !== 'string')
    return res.status(400).json({ success: false, message: 'Action is required.' });

  const result = systemCall(user, action.trim(), (resource || '').trim(), content || '', ip);
  let httpStatus = 200;
  if (!result.success) httpStatus = result.message.includes('ACCESS DENIED') ? 403 : 400;
  return res.status(httpStatus).json(result);
});

// ══════════════════════════════════════════════════════════════════════════
// LOG ROUTES
// ══════════════════════════════════════════════════════════════════════════

/**
 * IMPROVEMENT: GET /api/logs now supports server-side filtering.
 * Query params: ?username= &status= &action= &from= &to= &limit=
 * Previously all filtering was done in the browser — slow for large logs.
 */
app.get('/api/logs', requireAuth, requireAdmin, (req, res) => {
  const { username, status, action, from, to, limit } = req.query;
  const hasFilter = username || status || action || from || to;

  if (hasFilter) {
    const result = searchLogs({ username, status, action, from, to, limit });
    return res.json({ success: true, logs: result.logs, total: result.total, filtered: true });
  }

  const logs = getLogs(limit ? parseInt(limit, 10) : null);
  return res.json({ success: true, logs, total: logs.length, filtered: false });
});

app.get('/api/logs/export', requireAuth, requireAdmin, (req, res) => {
  const logsFile = path.join(__dirname, '..', 'logs', 'logs.json');
  if (!fs.existsSync(logsFile)) return res.status(404).json({ success: false, message: 'No logs file.' });
  logEntry(req.session.user.username, 'EXPORT_LOGS', 'logs.json', 'SUCCESS', 'Admin exported logs', getIP(req), req.session.user.role);
  res.download(logsFile, `syscall-logs-${Date.now()}.json`);
});

app.delete('/api/logs', requireAuth, requireAdmin, requireCSRF, (req, res) => {
  logEntry(req.session.user.username, 'CLEAR_LOGS', 'logs.json', 'SUCCESS', 'Admin cleared logs', getIP(req), req.session.user.role);
  clearLogs();
  res.json({ success: true, message: 'All logs cleared.' });
});

// ══════════════════════════════════════════════════════════════════════════
// STATS
// ══════════════════════════════════════════════════════════════════════════

/**
 * IMPROVEMENT: Stats now return a per-action breakdown.
 * Non-admin users get their own stats server-side (no full log dump needed).
 */
app.get('/api/stats', requireAuth, (req, res) => {
  if (req.session.user.role === 'admin') {
    return res.json({ success: true, stats: getLogStats() });
  }
  return res.json({ success: true, stats: getLogStats(req.session.user.username) });
});

// ══════════════════════════════════════════════════════════════════════════
// USER MANAGEMENT (Admin only)
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers().map(({ password, ...safe }) => safe);
  res.json({ success: true, users });
});

app.post('/api/users/unlock', requireAuth, requireAdmin, requireCSRF, (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ success: false, message: 'Username is required.' });

  const users = loadUsers();
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ success: false, message: `User "${username}" not found.` });

  user.isLocked = false; user.failedAttempts = 0; user.unlockedAt = new Date().toISOString();
  saveUsers(users);
  logEntry(req.session.user.username, 'UNLOCK_USER', username, 'SUCCESS', `Admin unlocked: ${username}`, getIP(req), req.session.user.role);
  res.json({ success: true, message: `Account "${username}" has been unlocked.` });
});

/**
 * IMPROVEMENT: change-role now validates against VALID_ROLES from auth.js.
 * Adding a new role to PERMISSIONS in auth.js automatically enables it here.
 */
app.post('/api/users/change-role', requireAuth, requireAdmin, requireCSRF, (req, res) => {
  const { username, newRole } = req.body || {};
  const adminUsername = req.session.user.username;

  if (!username || !newRole)
    return res.status(400).json({ success: false, message: 'Username and newRole are required.' });
  if (!VALID_ROLES.includes(newRole))
    return res.status(400).json({ success: false, message: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}.` });
  if (username.toLowerCase() === adminUsername.toLowerCase())
    return res.status(403).json({ success: false, message: 'You cannot change your own role. Ask another admin.' });

  const users = loadUsers();
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ success: false, message: `User "${username}" not found.` });
  if (user.role === newRole) return res.status(400).json({ success: false, message: `"${username}" already has the role "${newRole}".` });

  const oldRole      = user.role;
  user.role          = newRole;
  user.roleChangedAt = new Date().toISOString();
  user.roleChangedBy = adminUsername;
  saveUsers(users);

  logEntry(adminUsername, 'CHANGE_ROLE', username, 'SUCCESS',
    `Role changed: ${oldRole} → ${newRole} (by ${adminUsername})`, getIP(req), req.session.user.role);

  res.json({ success: true, message: `"${username}" role changed from "${oldRole}" to "${newRole}".`, oldRole, newRole });
});

/**
 * IMPROVEMENT: Password change endpoint.
 * Any logged-in user can change their own password.
 * Requires current password for verification (prevents session hijacking abuse).
 */
app.post('/api/users/change-password', requireAuth, requireCSRF, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const username = req.session.user.username;
  const ip       = getIP(req);

  if (!currentPassword || !newPassword)
    return res.status(400).json({ success: false, message: 'Current password and new password are required.' });

  const pwCheck = validatePasswordStrength(newPassword);
  if (!pwCheck.valid)
    return res.status(400).json({ success: false, message: pwCheck.reason });

  const users = loadUsers();
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match) {
    logEntry(username, 'CHANGE_PASSWORD', 'system', 'DENIED', 'Wrong current password', ip, user.role);
    return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
  }

  try {
    user.password          = await bcrypt.hash(newPassword, 10);
    user.passwordChangedAt = new Date().toISOString();
    saveUsers(users);
    logEntry(username, 'CHANGE_PASSWORD', 'system', 'SUCCESS', 'Password changed successfully', ip, user.role);
    return res.json({ success: true, message: 'Password changed successfully.' });
  } catch (err) {
    logError(username, 'CHANGE_PASSWORD', 'system', err.message, ip);
    return res.status(500).json({ success: false, message: 'Server error while changing password.' });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// SILENT FILE LIST (no logging — for background UI refresh)
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/files', requireAuth, (req, res) => {
  const vfsPath = path.join(__dirname, '..', 'data', 'virtual_fs.json');
  try {
    const vfs   = JSON.parse(fs.readFileSync(vfsPath, 'utf8'));
    const files = Object.entries(vfs).map(([name, meta]) => ({
      name,
      owner:          meta.owner,
      lastModifiedBy: meta.lastModifiedBy || meta.owner,
      permissions:    meta.permissions,
      size:           meta.size,
      createdAt:      meta.createdAt,
      updatedAt:      meta.updatedAt || null
    }));
    res.json({ success: true, files });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Could not read virtual filesystem.' });
  }
});

// ── Catch-all ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║   🔐 Secure System Call Interface — Running!     ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log(`║   🌐 Open: http://localhost:${PORT}                  ║`);
  console.log('║                                                  ║');
  console.log('║   👑 admin / admin123   (role: admin)            ║');
  console.log('║   🛡  alice / user123    (role: user)             ║');
  console.log('║   👤 guest / guest123   (role: user)             ║');
  console.log('╚══════════════════════════════════════════════════╝\n');

  if (!fs.existsSync(path.join(__dirname, '..', 'data', 'users.json'))) {
    console.warn('⚠️  Run "node setup.js" first!\n');
  }
});
