/**
 * backend/logger.js — Structured Logging System
 *
 * IMPROVEMENTS:
 *   1. searchLogs(filters) — filter by username, status, action, date range
 *   2. getLogStats() now returns a per-action breakdown, not just totals
 *   3. Log rotation: when MAX_LOG_SIZE is exceeded, oldest entries are dropped
 *      and a ROTATION event is recorded so auditors know entries were trimmed
 */

const fs   = require('fs');
const path = require('path');

const LOG_FILE     = path.join(__dirname, '..', 'logs', 'logs.json');
const MAX_LOG_SIZE = 1000;

function ensureLogFile() {
  const dir = path.dirname(LOG_FILE);
  if (!fs.existsSync(dir))      fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '[]');
}

function readLogs() {
  try { return JSON.parse(fs.readFileSync(LOG_FILE, 'utf8')); }
  catch (_) { return []; }
}

function writeLogs(logs) {
  let rotated = false;
  if (logs.length > MAX_LOG_SIZE) {
    logs    = logs.slice(logs.length - MAX_LOG_SIZE);
    rotated = true;
  }
  fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
  // IMPROVEMENT: append a rotation notice so the audit trail is honest
  if (rotated) {
    logs.push({
      id: Date.now(), timestamp: new Date().toISOString(),
      username: 'system', role: 'system', action: 'LOG_ROTATION',
      resource: 'logs.json', status: 'INFO',
      details: `Log trimmed to last ${MAX_LOG_SIZE} entries.`,
      ip: 'N/A', duration_ms: 0
    });
    fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
  }
}

function logEntry(username, action, resource, status, details = '', ip = '', role = '', durationMs = 0) {
  ensureLogFile();
  const entry = {
    id:          Date.now(),
    timestamp:   new Date().toISOString(),
    username:    username  || 'anonymous',
    role:        role      || 'unknown',
    action:      action    || 'unknown',
    resource:    resource  || 'N/A',
    status,
    details,
    ip:          ip        || 'N/A',
    duration_ms: durationMs
  };
  const logs = readLogs();
  logs.push(entry);
  writeLogs(logs);

  const icon = status === 'SUCCESS' ? '✅' : status === 'DENIED' ? '🚫' : '❌';
  console.log(`[LOG] ${icon} ${entry.timestamp.slice(11,19)} | ${username}(${role}) | ${action} | ${resource} | ${status}`);
  return entry;
}

function logError(username, action, resource, errorMessage, ip = '', role = '') {
  return logEntry(username, action, resource, 'ERROR', `Server error: ${errorMessage}`, ip, role);
}

function getLogs(limit = null) {
  ensureLogFile();
  let logs = readLogs().reverse();
  if (limit) logs = logs.slice(0, limit);
  return logs;
}

/**
 * IMPROVEMENT: searchLogs — server-side log filtering.
 * Previously all filtering happened in the browser (performance issue with large logs).
 * Now the API can filter before sending, reducing payload size significantly.
 *
 * @param {object} filters
 *   filters.username  — partial match, case-insensitive
 *   filters.status    — exact match: SUCCESS | DENIED | FAILED | ERROR
 *   filters.action    — exact match: read_file | write_file | ...
 *   filters.from      — ISO date string — entries on or after this time
 *   filters.to        — ISO date string — entries on or before this time
 *   filters.limit     — max entries to return (after filtering)
 */
function searchLogs(filters = {}) {
  ensureLogFile();
  let logs = readLogs().reverse(); // newest first

  if (filters.username) {
    const q = filters.username.toLowerCase();
    logs = logs.filter(l => l.username.toLowerCase().includes(q));
  }
  if (filters.status) {
    logs = logs.filter(l => l.status === filters.status.toUpperCase());
  }
  if (filters.action) {
    logs = logs.filter(l => l.action === filters.action);
  }
  if (filters.from) {
    const from = new Date(filters.from).getTime();
    logs = logs.filter(l => new Date(l.timestamp).getTime() >= from);
  }
  if (filters.to) {
    const to = new Date(filters.to).getTime();
    logs = logs.filter(l => new Date(l.timestamp).getTime() <= to);
  }

  const total = logs.length;
  if (filters.limit) logs = logs.slice(0, parseInt(filters.limit, 10));
  return { logs, total };
}

function clearLogs() { writeLogs([]); }

/**
 * IMPROVEMENT: getLogStats now includes a per-action breakdown.
 * Original returned only { total, success, denied, failed }.
 * New version adds actionBreakdown so the dashboard can show which
 * syscalls are most used / most denied.
 */
function getLogStats(username = null) {
  let logs = readLogs();
  if (username) logs = logs.filter(l => l.username === username);

  const total   = logs.length;
  const success = logs.filter(l => l.status === 'SUCCESS').length;
  const denied  = logs.filter(l => l.status === 'DENIED').length;
  const failed  = logs.filter(l => l.status === 'FAILED' || l.status === 'ERROR').length;

  // Per-action breakdown
  const actionBreakdown = {};
  for (const log of logs) {
    if (!actionBreakdown[log.action]) actionBreakdown[log.action] = { total: 0, success: 0, denied: 0 };
    actionBreakdown[log.action].total++;
    if (log.status === 'SUCCESS') actionBreakdown[log.action].success++;
    if (log.status === 'DENIED')  actionBreakdown[log.action].denied++;
  }

  return { total, success, denied, failed, actionBreakdown };
}

module.exports = { logEntry, logError, getLogs, searchLogs, clearLogs, getLogStats };
