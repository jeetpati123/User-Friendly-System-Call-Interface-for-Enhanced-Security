/**
 * backend/systemCall.js — System Call Simulation Engine
 *
 * IMPROVEMENTS:
 *   1. Two new syscalls: rename_file and copy_file
 *   2. list_files now returns a 'lastModifiedBy' field
 *   3. write_file tracks who last modified a file (not just who created it)
 *   4. All handlers share a common validateFilename helper (DRY)
 */

const fs   = require('fs');
const path = require('path');
const { isAuthorized } = require('./auth');
const { logEntry }     = require('./logger');

const VFS_FILE = path.join(__dirname, '..', 'data', 'virtual_fs.json');

// ─── Virtual Filesystem I/O ─────────────────────────────────────────────────

function loadVFS() {
  try { return JSON.parse(fs.readFileSync(VFS_FILE, 'utf8')); }
  catch (_) { return {}; }
}

function saveVFS(vfs) {
  fs.writeFileSync(VFS_FILE, JSON.stringify(vfs, null, 2));
}

// ─── Input Validation Helpers ───────────────────────────────────────────────

function validateFilename(filename) {
  if (!filename || typeof filename !== 'string')
    return { valid: false, reason: 'Filename is required.' };
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\'))
    return { valid: false, reason: 'Invalid filename: path traversal not allowed.' };
  if (!/^[a-zA-Z0-9_\-. ]{1,50}$/.test(filename))
    return { valid: false, reason: 'Filename must be 1-50 alphanumeric chars (dots, dashes, spaces allowed).' };
  return { valid: true };
}

function validateContent(content) {
  if (content === null || content === undefined) return { valid: false, reason: 'Content is required for write_file.' };
  if (typeof content !== 'string')              return { valid: false, reason: 'Content must be a string.' };
  if (content.length > 10000)                   return { valid: false, reason: 'Content too large (max 10,000 characters).' };
  return { valid: true };
}

// ─── System Call Handlers ────────────────────────────────────────────────────

function syscall_list_files(vfs) {
  const files = Object.entries(vfs).map(([name, meta]) => ({
    name,
    owner:          meta.owner,
    lastModifiedBy: meta.lastModifiedBy || meta.owner,   // NEW: who last touched it
    permissions:    meta.permissions,
    size:           meta.size,
    createdAt:      meta.createdAt,
    updatedAt:      meta.updatedAt || null
  }));
  return { success: true, data: files, message: `Found ${files.length} file(s) in virtual filesystem.` };
}

function syscall_read_file(vfs, resource) {
  const check = validateFilename(resource);
  if (!check.valid) return { success: false, message: check.reason };
  if (!vfs[resource]) return { success: false, message: `File "${resource}" not found in virtual filesystem.` };

  const file = vfs[resource];
  return {
    success: true,
    data: {
      name:           resource,
      content:        file.content,
      owner:          file.owner,
      lastModifiedBy: file.lastModifiedBy || file.owner,
      permissions:    file.permissions,
      size:           file.size,
      createdAt:      file.createdAt,
      updatedAt:      file.updatedAt || null
    },
    message: `File "${resource}" read successfully.`
  };
}

function syscall_write_file(vfs, resource, content, user) {
  const fileCheck = validateFilename(resource);
  if (!fileCheck.valid) return { success: false, message: fileCheck.reason };

  const contentCheck = validateContent(content);
  if (!contentCheck.valid) return { success: false, message: contentCheck.reason };

  const isNew      = !vfs[resource];
  const existingAt = isNew ? null : vfs[resource].createdAt;

  vfs[resource] = {
    content,
    owner:          isNew ? user.username : vfs[resource].owner,
    lastModifiedBy: user.username,   // IMPROVEMENT: track who last modified
    permissions:    'rw-r--r--',
    size:           content.length,
    createdAt:      isNew ? new Date().toISOString() : existingAt,
    updatedAt:      new Date().toISOString()
  };
  saveVFS(vfs);

  return {
    success: true,
    data:    { name: resource, size: content.length, isNew },
    message: isNew
      ? `File "${resource}" created successfully (${content.length} bytes).`
      : `File "${resource}" updated successfully (${content.length} bytes).`
  };
}

function syscall_delete_file(vfs, resource) {
  const check = validateFilename(resource);
  if (!check.valid) return { success: false, message: check.reason };
  if (!vfs[resource]) return { success: false, message: `File "${resource}" not found.` };

  const owner = vfs[resource].owner;
  delete vfs[resource];
  saveVFS(vfs);

  return { success: true, data: { deleted: resource, previousOwner: owner }, message: `File "${resource}" deleted permanently.` };
}

/**
 * IMPROVEMENT: rename_file syscall
 * Renames a file in the virtual filesystem.
 * - Source must exist; destination must NOT already exist (no silent overwrites).
 * - Both filenames go through the same validateFilename guard.
 * - Available to: admin, moderator (not plain user — users copy instead).
 */
function syscall_rename_file(vfs, resource, content, user) {
  // resource = old name, content = new name (re-use content field as destination)
  const newName = (content || '').trim();

  const srcCheck = validateFilename(resource);
  if (!srcCheck.valid) return { success: false, message: `Source: ${srcCheck.reason}` };

  const dstCheck = validateFilename(newName);
  if (!dstCheck.valid) return { success: false, message: `Destination: ${dstCheck.reason}` };

  if (!vfs[resource]) return { success: false, message: `File "${resource}" not found.` };
  if (vfs[newName])   return { success: false, message: `A file named "${newName}" already exists. Delete it first.` };
  if (resource === newName) return { success: false, message: 'Source and destination names are the same.' };

  vfs[newName] = { ...vfs[resource], updatedAt: new Date().toISOString(), lastModifiedBy: user.username };
  delete vfs[resource];
  saveVFS(vfs);

  return {
    success: true,
    data:    { from: resource, to: newName },
    message: `File renamed: "${resource}" → "${newName}".`
  };
}

/**
 * IMPROVEMENT: copy_file syscall
 * Copies a file to a new name (the original remains).
 * - Destination must NOT already exist.
 * - The copy is owned by the user who copied it (not the original owner).
 * - Available to: admin, user (not moderator — they can only read/delete).
 */
function syscall_copy_file(vfs, resource, content, user) {
  // resource = source name, content = destination name
  const destName = (content || '').trim();

  const srcCheck = validateFilename(resource);
  if (!srcCheck.valid) return { success: false, message: `Source: ${srcCheck.reason}` };

  const dstCheck = validateFilename(destName);
  if (!dstCheck.valid) return { success: false, message: `Destination: ${dstCheck.reason}` };

  if (!vfs[resource])  return { success: false, message: `File "${resource}" not found.` };
  if (vfs[destName])   return { success: false, message: `File "${destName}" already exists. Choose a different name.` };
  if (resource === destName) return { success: false, message: 'Source and destination names are the same.' };

  const original = vfs[resource];
  vfs[destName] = {
    content:        original.content,
    owner:          user.username,       // copy belongs to the user who made it
    lastModifiedBy: user.username,
    permissions:    'rw-r--r--',
    size:           original.size,
    createdAt:      new Date().toISOString(),
    updatedAt:      new Date().toISOString()
  };
  saveVFS(vfs);

  return {
    success: true,
    data:    { source: resource, destination: destName, size: original.size },
    message: `File copied: "${resource}" → "${destName}" (${original.size} bytes).`
  };
}

// ─── SYSCALL TABLE ─────────────────────────────────────────────────────────
const SYSCALL_TABLE = {
  list_files:  (vfs, resource, content, user) => syscall_list_files(vfs),
  read_file:   (vfs, resource, content, user) => syscall_read_file(vfs, resource),
  write_file:  (vfs, resource, content, user) => syscall_write_file(vfs, resource, content, user),
  delete_file: (vfs, resource, content, user) => syscall_delete_file(vfs, resource),
  rename_file: (vfs, resource, content, user) => syscall_rename_file(vfs, resource, content, user),
  copy_file:   (vfs, resource, content, user) => syscall_copy_file(vfs, resource, content, user)
};

const VALID_SYSCALLS = Object.keys(SYSCALL_TABLE);

// ─── Main Dispatcher ────────────────────────────────────────────────────────

function systemCall(user, action, resource, content = '', ip = '') {
  const startTime = Date.now();

  if (!user || !user.username) {
    const log = logEntry('anonymous', action, resource || 'N/A', 'DENIED', 'Not authenticated', ip, '');
    return { success: false, message: 'ACCESS DENIED: You must be logged in to make system calls.', logEntry: log };
  }

  if (!isAuthorized(user.role, action)) {
    const log = logEntry(user.username, action, resource || 'N/A', 'DENIED',
      `Role '${user.role}' is not permitted to perform '${action}'`, ip, user.role);
    return {
      success: false,
      message: `ACCESS DENIED: Your role (${user.role}) cannot perform "${action}". This has been logged.`,
      logEntry: log
    };
  }

  if (!SYSCALL_TABLE[action]) {
    const log = logEntry(user.username, action, resource || 'N/A', 'DENIED', 'Unknown system call', ip, user.role);
    return {
      success: false,
      message: `Unknown system call: "${action}". Valid calls: ${VALID_SYSCALLS.join(', ')}.`,
      logEntry: log
    };
  }

  let result;
  try {
    const vfs = loadVFS();
    result = SYSCALL_TABLE[action](vfs, resource, content, user);
  } catch (err) {
    const log = logEntry(user.username, action, resource || 'N/A', 'ERROR',
      `Server error: ${err.message}`, ip, user.role, Date.now() - startTime);
    return { success: false, message: `System error during "${action}": ${err.message}`, logEntry: log };
  }

  const status     = result.success ? 'SUCCESS' : 'FAILED';
  const durationMs = Date.now() - startTime;
  const log        = logEntry(user.username, action, resource || 'N/A', status, result.message, ip, user.role, durationMs);

  return { ...result, logEntry: log };
}

module.exports = { systemCall, VALID_SYSCALLS };
