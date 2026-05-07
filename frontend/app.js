/**
 * frontend/app.js
 * Dashboard Frontend Logic
 *
 * Handles:
 *   1. Session check on load — redirect to login if not authenticated
 *   2. Fetch user permissions from server (dynamic, not hardcoded)
 *   3. Panel navigation (sidebar)
 *   4. System call executions via POST /api/syscall
 *   5. Log viewer with search + status + role filters
 *   6. User management: list, unlock, change role (admin only)
 *   7. Auto-logout after 30 min session timer
 *   8. Stats panel (all users see their own stats)
 */

'use strict';

// ─── Global State ────────────────────────────────────────────────────────────
let currentUser    = null;
let allowedActions = [];
let allLogs        = [];
let allFiles       = [];
let sessionTimeout = 30 * 60;
let timerInterval  = null;
let csrfToken      = null;   // fetched after login, sent on all state-changing requests

// ══════════════════════════════════════════════════════════════════════════
// 1. INITIALISATION
// ══════════════════════════════════════════════════════════════════════════

window.addEventListener('DOMContentLoaded', async () => {
  await checkSession();
  await fetchCsrfToken();
  await fetchPermissions();
  populateUserInfo();
  startSessionTimer();
  startInactivityReset();
  await loadFilesForSelectors();
  await loadFilesSilent();   // silent — no syscall log, no stat inflation
  await refreshStats();      // load real stats once on page open

  // Character counter for write_file textarea
  document.getElementById('wfContent').addEventListener('input', () => {
    const len = document.getElementById('wfContent').value.length;
    const el  = document.getElementById('wfCharCount');
    el.textContent = len;
    el.style.color = len > 9000 ? 'var(--red)' : len > 7000 ? 'var(--yellow)' : 'var(--text-muted)';
  });
});

async function checkSession() {
  try {
    const res  = await fetch('/api/whoami');
    const data = await res.json();
    if (!res.ok || !data.success) { window.location.href = '/'; return; }
    currentUser = data.user;
  } catch (_) { window.location.href = '/'; }
}

async function fetchCsrfToken() {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res  = await fetch('/api/csrf-token');
      const data = await res.json();
      if (data.token) { csrfToken = data.token; return; }
    } catch (_) {}
    // Small delay before retry
    await new Promise(r => setTimeout(r, 200 * attempt));
  }
  console.warn('⚠ Could not fetch CSRF token after 3 attempts.');
}

async function fetchPermissions() {
  try {
    const res  = await fetch('/api/permissions');
    const data = await res.json();
    if (data.success) allowedActions = data.allowed || [];
  } catch (_) { allowedActions = []; }
}

function populateUserInfo() {
  if (!currentUser) return;
  const isAdmin = currentUser.role === 'admin';

  document.getElementById('navUsername').textContent = currentUser.username;
  const roleEl = document.getElementById('navRole');
  roleEl.textContent    = currentUser.role.toUpperCase();
  roleEl.style.background = isAdmin ? 'var(--yellow-dim)' : 'var(--blue-dim)';
  roleEl.style.color      = isAdmin ? 'var(--yellow)'     : 'var(--blue)';

  document.getElementById('sessionPID').textContent  = Math.floor(Math.random()*9000)+1000;
  document.getElementById('sidebarUID').textContent  = currentUser.id || '—';
  document.getElementById('sidebarGID').textContent  = isAdmin ? '0 (root)' : '1000';
  document.getElementById('sidebarRole').textContent = currentUser.role;

  ['lf','rf','wf','df','rnf','cpf'].forEach(prefix => {
    const el = document.getElementById(`sig-${prefix}-user`);
    if (el) { el.textContent = `"${currentUser.username}"`; el.style.color = 'var(--purple)'; }
  });

  if (!isAdmin) {
    document.querySelectorAll('.admin-only').forEach(btn => {
      btn.style.opacity = '0.4';
      btn.title = 'Admin role required';
    });
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 2. PANEL NAVIGATION
// ══════════════════════════════════════════════════════════════════════════

function showPanel(name) {
  document.querySelectorAll('.syscall-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.syscall-btn').forEach(b => b.classList.remove('active'));
  const panel = document.getElementById(`panel-${name}`);
  if (panel) panel.classList.add('active');
  const btn = document.getElementById(`btn-${name}`);
  if (btn) btn.classList.add('active');
  if (name === 'logs')    loadLogs();
  if (name === 'users')   loadUsers();
  if (name === 'profile') loadProfile();
}

// ══════════════════════════════════════════════════════════════════════════
// 3. SYSTEM CALL EXECUTION
// ══════════════════════════════════════════════════════════════════════════

async function executeCall(action, resource, content) {
  try {
    const res = await fetch('/api/syscall', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
      body:    JSON.stringify({ action, resource, content })
    });

    if (res.status === 401) {
      alert('⏰ Session expired. Please log in again.');
      window.location.href = '/';
      return { success: false, message: 'Session expired.' };
    }

    const data = await res.json();

    if (action === 'list_files' && data.success) {
      renderFileList(data.data || []);
      allFiles = (data.data || []).map(f => f.name);
      updateFileSelectors();
      document.getElementById('statFiles').textContent = allFiles.length;
    }

    return data;
  } catch (err) {
    return { success: false, message: 'Network error: ' + err.message };
  }
}

function renderToTerminal(elId, data) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.className = `response-terminal mt-2 ${data.success ? 'success' : 'error'}`;

  if (data.success && data.data) {
    const d = data.data;
    if (d.content !== undefined) {
      el.textContent =
        `[${data.logEntry?.timestamp || new Date().toISOString()}]\n` +
        `File    : ${d.name}\nOwner   : ${d.owner}\nPerms   : ${d.permissions}\n` +
        `Size    : ${d.size} bytes\nUpdated : ${d.updatedAt || 'never'}\n` +
        `─────────────────────────────\nContent:\n${d.content}`;
    } else if (d.deleted) {
      el.textContent = `✓ ${data.message}`;
    } else if (d.name) {
      el.textContent = `✓ ${data.message}\n  Filename : ${d.name}\n  Size     : ${d.size} bytes\n  New file : ${d.isNew ? 'yes' : 'no (updated)'}`;
    } else {
      el.textContent = `✓ ${data.message}`;
    }
  } else {
    el.textContent = `✗ ${data.message || 'Unknown error'}`;
  }
}

function setTerminalLoading(elId, msg) {
  const el = document.getElementById(elId);
  if (el) { el.className = 'response-terminal mt-2 loading'; el.textContent = `⟳ ${msg}`; }
}

// ── List Files ───────────────────────────────────────────────────────────────
function renderFileList(files) {
  const area = document.getElementById('fileListArea');
  if (!files || files.length === 0) {
    area.innerHTML = '<p style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">No files found.</p>';
    return;
  }
  let html = `<table class="file-table"><thead>
    <tr><th>📄 Filename</th><th>Owner</th><th>Last Modified By</th><th>Permissions</th><th>Size</th><th>Created</th><th>Updated</th><th>Action</th></tr>
  </thead><tbody>`;
  files.forEach(f => {
    const modifiedBy = f.lastModifiedBy || f.owner;
    const modifiedColor = modifiedBy !== f.owner ? 'var(--yellow)' : 'var(--text-muted)';
    html += `<tr>
      <td class="file-name">${escHtml(f.name)}</td>
      <td class="owner">${escHtml(f.owner)}</td>
      <td style="color:${modifiedColor};font-family:var(--font-mono);font-size:0.78rem;">${escHtml(modifiedBy)}</td>
      <td class="perm">${escHtml(f.permissions)}</td>
      <td>${f.size} B</td>
      <td>${formatDate(f.createdAt)}</td>
      <td>${formatDate(f.updatedAt) || '—'}</td>
      <td><button class="btn btn-secondary btn-sm" onclick="quickRead('${escHtml(f.name)}')">Read</button></td>
    </tr>`;
  });
  html += '</tbody></table>';
  area.innerHTML = html;
}

/**
 * loadFilesSilent — fetch the file list from /api/files (no syscall log).
 * Use this for background/automatic refreshes so the audit log and stats
 * are not polluted by UI housekeeping calls.
 */
async function loadFilesSilent() {
  try {
    const res  = await fetch('/api/files');
    if (!res.ok) return;
    const data = await res.json();
    if (data.success && Array.isArray(data.files)) {
      renderFileList(data.files);
      allFiles = data.files.map(f => f.name);
      updateFileSelectors();
      document.getElementById('statFiles').textContent = allFiles.length;
    }
  } catch (_) {}
}

function quickRead(filename) {
  showPanel('read_file');
  document.getElementById('rfFilename').value       = filename;
  document.getElementById('sig-rf-res').textContent = filename;
  executeReadFile();
}

// ── Read File ────────────────────────────────────────────────────────────────
async function executeReadFile() {
  const filename = document.getElementById('rfFilename').value.trim();
  if (!filename) {
    document.getElementById('rfResponse').className  = 'response-terminal mt-2 error';
    document.getElementById('rfResponse').textContent = '✗ No filename specified.';
    return;
  }
  setTerminalLoading('rfResponse', `Reading "${filename}"…`);
  const data = await executeCall('read_file', filename, '');
  renderToTerminal('rfResponse', data);
  await refreshStats();
}

// ── Write File ───────────────────────────────────────────────────────────────
async function executeWriteFile() {
  const filename = document.getElementById('wfFilename').value.trim();
  const content  = document.getElementById('wfContent').value;
  if (!filename) {
    document.getElementById('wfResponse').className  = 'response-terminal mt-2 error';
    document.getElementById('wfResponse').textContent = '✗ No filename specified.';
    return;
  }
  setTerminalLoading('wfResponse', `Writing "${filename}"…`);
  const data = await executeCall('write_file', filename, content);
  renderToTerminal('wfResponse', data);
  if (data.success) {
    await loadFilesSilent();   // refresh file list silently — no extra log entry
    await refreshStats();
  }
}

// ── Delete File ──────────────────────────────────────────────────────────────
async function executeDeleteFile() {
  const filename = document.getElementById('dfFilename').value.trim();
  if (!filename) {
    document.getElementById('dfResponse').className  = 'response-terminal mt-2 error';
    document.getElementById('dfResponse').textContent = '✗ No filename specified.';
    return;
  }
  if (!confirm(`Permanently delete "${filename}"? This cannot be undone.`)) return;
  setTerminalLoading('dfResponse', `Deleting "${filename}"…`);
  const data = await executeCall('delete_file', filename, '');
  renderToTerminal('dfResponse', data);
  if (data.success) {
    await loadFilesSilent();   // refresh file list silently — no extra log entry
    await refreshStats();
    updateFileSelectors();
  }
}

async function executeRenameFile() {
  const oldName = document.getElementById('rnfOldName').value.trim();
  const newName = document.getElementById('rnfNewName').value.trim();
  if (!oldName || !newName) {
    document.getElementById('rnfResponse').className  = 'response-terminal mt-2 error';
    document.getElementById('rnfResponse').textContent = '✗ Both current filename and new filename are required.';
    return;
  }
  setTerminalLoading('rnfResponse', `Renaming "${oldName}" → "${newName}"…`);
  const data = await executeCall('rename_file', oldName, newName);
  renderToTerminal('rnfResponse', data);
  if (data.success) {
    document.getElementById('rnfOldName').value = '';
    document.getElementById('rnfNewName').value = '';
    document.getElementById('sig-rnf-src').textContent = 'old_name';
    document.getElementById('sig-rnf-dst').textContent = 'new_name';
    await loadFilesSilent();
    await refreshStats();
    updateFileSelectors();
  }
}

async function executeCopyFile() {
  const srcName = document.getElementById('cpfSrcName').value.trim();
  const dstName = document.getElementById('cpfDstName').value.trim();
  if (!srcName || !dstName) {
    document.getElementById('cpfResponse').className  = 'response-terminal mt-2 error';
    document.getElementById('cpfResponse').textContent = '✗ Both source filename and destination filename are required.';
    return;
  }
  setTerminalLoading('cpfResponse', `Copying "${srcName}" → "${dstName}"…`);
  const data = await executeCall('copy_file', srcName, dstName);
  renderToTerminal('cpfResponse', data);
  if (data.success) {
    document.getElementById('cpfDstName').value = '';
    document.getElementById('sig-cpf-dst').textContent = 'destination';
    await loadFilesSilent();
    await refreshStats();
    updateFileSelectors();
  }
}

// ── File selector chips ──────────────────────────────────────────────────────
function updateFileSelectors() {
  [
    { id: 'rfFileSelector', inputId: 'rfFilename', sigId: 'sig-rf-res' },
    { id: 'wfFileSelector', inputId: 'wfFilename', sigId: 'sig-wf-res' },
    { id: 'dfFileSelector', inputId: 'dfFilename', sigId: 'sig-df-res' },
    { id: 'rnfFileSelector', inputId: 'rnfOldName', sigId: 'sig-rnf-src' },
    { id: 'cpfFileSelector', inputId: 'cpfSrcName', sigId: 'sig-cpf-src' }
  ].forEach(({ id, inputId, sigId }) => {
    const container = document.getElementById(id);
    if (!container) return;
    container.innerHTML = allFiles.length === 0
      ? '<span style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text-muted);">No files</span>'
      : allFiles.map(name =>
          `<span class="file-chip" onclick="selectFile('${id}','${inputId}','${sigId}','${escHtml(name)}')">📄 ${escHtml(name)}</span>`
        ).join('');
  });
}

function selectFile(selectorId, inputId, sigId, filename) {
  document.querySelectorAll(`#${selectorId} .file-chip`).forEach(c => c.classList.remove('selected'));
  document.querySelectorAll(`#${selectorId} .file-chip`).forEach(c => {
    if (c.textContent.trim().includes(filename)) c.classList.add('selected');
  });
  document.getElementById(inputId).value     = filename;
  document.getElementById(sigId).textContent = filename;
}

async function loadFilesForSelectors() {
  // Use silent endpoint — this is background init, not a user syscall
  await loadFilesSilent();
}

// ══════════════════════════════════════════════════════════════════════════
// 4. LOG VIEWER
// ══════════════════════════════════════════════════════════════════════════

const LOGS_PER_PAGE  = 25;
let currentPage      = 1;
let filteredLogs     = [];

async function loadLogs() {
  try {
    const res = await fetch('/api/logs');
    if (res.status === 403) {
      document.getElementById('logsBody').innerHTML =
        '<tr><td colspan="8" style="text-align:center;color:var(--red);padding:2rem;">🚫 Admin role required.</td></tr>';
      return;
    }
    const data = await res.json();
    allLogs      = data.logs || [];
    currentPage  = 1;
    filteredLogs = allLogs;
    renderLogs(filteredLogs);
  } catch (err) { console.error('Failed to load logs:', err); }
}

function renderLogs(logs) {
  filteredLogs = logs;
  const totalPages = Math.max(1, Math.ceil(logs.length / LOGS_PER_PAGE));
  if (currentPage > totalPages) currentPage = totalPages;

  const start  = (currentPage - 1) * LOGS_PER_PAGE;
  const end    = Math.min(start + LOGS_PER_PAGE, logs.length);
  const paged  = logs.slice(start, end);

  document.getElementById('logCount').textContent = `${logs.length} entries`;

  // Pagination UI
  const prevBtn     = document.getElementById('pagePrev');
  const nextBtn     = document.getElementById('pageNext');
  const pageLabel   = document.getElementById('pageLabel');
  const rangeLabel  = document.getElementById('pageRangeLabel');
  if (prevBtn)   prevBtn.disabled   = currentPage <= 1;
  if (nextBtn)   nextBtn.disabled   = currentPage >= totalPages;
  if (pageLabel) pageLabel.textContent = `Page ${currentPage} / ${totalPages}`;
  if (rangeLabel && logs.length > 0) rangeLabel.textContent = `${start + 1}–${end} of ${logs.length}`;
  else if (rangeLabel) rangeLabel.textContent = '0 entries';

  const tbody = document.getElementById('logsBody');
  if (paged.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);font-family:var(--font-mono);padding:2rem;">No log entries found.</td></tr>';
    return;
  }
  tbody.innerHTML = paged.map(log => {
    const sc = log.status === 'SUCCESS' ? 'status-success' : log.status === 'DENIED' ? 'status-denied' : 'status-failed';
    return `<tr>
      <td>${formatDate(log.timestamp)}</td>
      <td style="color:${log.username==='admin'?'var(--yellow)':'var(--blue)'}">${escHtml(log.username)}</td>
      <td style="color:var(--purple);font-size:0.72rem;">${escHtml(log.role||'—')}</td>
      <td style="color:var(--green);font-weight:500">${escHtml(log.action)}</td>
      <td>${escHtml(log.resource)}</td>
      <td><span class="status-badge ${sc}">${log.status}</span></td>
      <td style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">${log.duration_ms!=null?log.duration_ms+'ms':'—'}</td>
      <td style="color:var(--text-muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${escHtml(log.details)}">${escHtml(log.details||'—')}</td>
    </tr>`;
  }).join('');
}

function changePage(delta) {
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / LOGS_PER_PAGE));
  currentPage = Math.min(Math.max(1, currentPage + delta), totalPages);
  renderLogs(filteredLogs);
}

function filterLogs() {
  const search = document.getElementById('logSearch').value.toLowerCase();
  const status = document.getElementById('logStatusFilter').value;
  const role   = document.getElementById('logRoleFilter').value;
  const action = document.getElementById('logActionFilter') ? document.getElementById('logActionFilter').value : '';
  currentPage  = 1;
  renderLogs(allLogs.filter(log => {
    const matchText   = !search || JSON.stringify(log).toLowerCase().includes(search);
    const matchStatus = !status || log.status === status;
    const matchRole   = !role   || log.role   === role;
    const matchAction = !action || log.action === action;
    return matchText && matchStatus && matchRole && matchAction;
  }));
}

async function clearAllLogs() {
  if (!confirm('Clear ALL system logs? This is irreversible.')) return;
  const data = await (await fetch('/api/logs', {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken || '' }
  })).json();
  if (data.success) { allLogs = []; filteredLogs = []; renderLogs([]); await refreshStats(); }
}

// ══════════════════════════════════════════════════════════════════════════
// PROFILE
// ══════════════════════════════════════════════════════════════════════════

async function loadProfile() {
  const el = document.getElementById('profileContent');
  if (!el) return;
  try {
    const [whoRes, statsRes] = await Promise.all([
      fetch('/api/whoami'),
      fetch('/api/stats')
    ]);
    const whoData   = await whoRes.json();
    const statsData = await statsRes.json();
    const u         = whoData.user || currentUser;
    const s         = statsData.stats || {};

    el.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;">
        <div style="background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;padding:1rem;">
          <div style="color:var(--text-muted);font-size:0.68rem;margin-bottom:0.5rem;">ACCOUNT INFO</div>
          <div style="margin-bottom:0.4rem;">👤 <span style="color:var(--blue)">${escHtml(u.username)}</span></div>
          <div style="margin-bottom:0.4rem;">🏷️ Role: <span style="color:var(--yellow)">${escHtml(u.role)}</span></div>
          <div style="margin-bottom:0.4rem;">📧 ${escHtml(u.email || '(no email)')}</div>
          <div style="margin-bottom:0.4rem;">🔒 Status: <span style="color:var(--green)">Active</span></div>
          <div style="color:var(--text-muted);font-size:0.75rem;margin-top:0.6rem;">
            Last login: ${formatDate(u.lastLogin) || 'N/A'}
          </div>
          <div style="color:var(--text-muted);font-size:0.75rem;">
            Account created: ${formatDate(u.createdAt) || 'N/A'}
          </div>
        </div>
        <div style="background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;padding:1rem;">
          <div style="color:var(--text-muted);font-size:0.68rem;margin-bottom:0.5rem;">MY ACTIVITY</div>
          <div style="margin-bottom:0.4rem;">📊 Total calls: <span style="color:var(--green)">${s.total || 0}</span></div>
          <div style="margin-bottom:0.4rem;">✅ Successful: <span style="color:var(--green)">${s.success || 0}</span></div>
          <div style="margin-bottom:0.4rem;">🚫 Denied: <span style="color:var(--red)">${s.denied || 0}</span></div>
          <div style="margin-bottom:0.4rem;">❌ Failed: <span style="color:var(--yellow)">${s.failed || 0}</span></div>
        </div>
      </div>
      ${s.actionBreakdown ? `
      <div style="margin-top:1rem;background:var(--bg-dark);border:1px solid var(--border);border-radius:8px;padding:1rem;">
        <div style="color:var(--text-muted);font-size:0.68rem;margin-bottom:0.75rem;">SYSCALL BREAKDOWN</div>
        <div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
          ${Object.entries(s.actionBreakdown).map(([action, counts]) => `
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:0.4rem 0.75rem;font-size:0.75rem;">
              <span style="color:var(--blue)">${escHtml(action)}</span>
              <span style="color:var(--text-muted);margin-left:0.4rem;">${counts.total} calls</span>
              ${counts.denied > 0 ? `<span style="color:var(--red);margin-left:0.3rem;">(${counts.denied} denied)</span>` : ''}
            </div>
          `).join('')}
        </div>
      </div>` : ''}
    `;
  } catch (err) {
    el.textContent = '✗ Failed to load profile.';
  }
}

// ══════════════════════════════════════════════════════════════════════════
// CHANGE PASSWORD
// ══════════════════════════════════════════════════════════════════════════

function togglePwdField(id) {
  const el = document.getElementById(id);
  if (el) el.type = el.type === 'password' ? 'text' : 'password';
}

function checkNewPwdStrength(val) {
  const bar  = document.getElementById('cpStrengthBar');
  const text = document.getElementById('cpStrengthText');
  if (!bar || !text) return;
  if (!val) { bar.style.width = '0%'; text.textContent = ''; return; }
  let score = 0;
  if (val.length >= 8)  score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^a-zA-Z0-9]/.test(val)) score++;
  const levels = [
    { pct: '20%', color: 'var(--red)',    label: '✗ Too weak' },
    { pct: '40%', color: 'var(--orange)', label: '▲ Weak' },
    { pct: '60%', color: 'var(--yellow)', label: '◆ Fair' },
    { pct: '80%', color: 'var(--blue)',   label: '✓ Good' },
    { pct: '100%',color: 'var(--green)',  label: '✓✓ Strong' }
  ];
  const level = levels[Math.min(score, 4)];
  bar.style.width = level.pct; bar.style.background = level.color;
  text.textContent = level.label; text.style.color = level.color;
}

async function executeChangePassword() {
  const currentPwd = document.getElementById('cpCurrentPwd').value;
  const newPwd     = document.getElementById('cpNewPwd').value;
  const confirmPwd = document.getElementById('cpConfirmPwd').value;
  const alertEl    = document.getElementById('cpAlert');

  const show = (msg, ok = false) => {
    alertEl.textContent = ok ? `✓ ${msg}` : `✗ ${msg}`;
    alertEl.className   = `alert alert-${ok ? 'success' : 'error'} show`;
  };

  if (!currentPwd || !newPwd || !confirmPwd) return show('All fields are required.');
  if (newPwd.length < 8)       return show('New password must be at least 8 characters.');
  if (!/\d/.test(newPwd))      return show('New password must contain at least one number.');
  if (newPwd !== confirmPwd)   return show('New passwords do not match.');
  if (newPwd === currentPwd)   return show('New password must be different from the current password.');

  try {
    const res  = await fetch('/api/users/change-password', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
      body:    JSON.stringify({ currentPassword: currentPwd, newPassword: newPwd })
    });
    const data = await res.json();
    if (data.success) {
      show(data.message, true);
      document.getElementById('cpCurrentPwd').value = '';
      document.getElementById('cpNewPwd').value     = '';
      document.getElementById('cpConfirmPwd').value = '';
      document.getElementById('cpStrengthBar').style.width = '0%';
      document.getElementById('cpStrengthText').textContent = '';
    } else {
      show(data.message);
    }
  } catch (_) {
    show('Connection error.');
  }
}

// ══════════════════════════════════════════════════════════════════════════
// 5. USER MANAGEMENT (Admin)
// ══════════════════════════════════════════════════════════════════════════

async function loadUsers() {
  try {
    const res = await fetch('/api/users');
    if (res.status === 403) {
      document.getElementById('usersList').innerHTML =
        '<p style="font-family:var(--font-mono);font-size:0.82rem;color:var(--red);">🚫 Admin access required.</p>';
      return;
    }
    const data = await res.json();
    renderUsers(data.users || []);
  } catch (err) { console.error('Failed to load users:', err); }
}

/**
 * Render the user list with action buttons for each user.
 * Each user row shows:
 *   - Avatar + username + role badge
 *   - Email, failed attempts, last login
 *   - Lock status + Unlock button (if locked)
 *   - Role change dropdown + Apply button (admin only feature)
 */
function renderUsers(users) {
  const el = document.getElementById('usersList');
  if (users.length === 0) {
    el.innerHTML = '<p style="font-family:var(--font-mono);font-size:0.8rem;color:var(--text-muted);">No users found.</p>';
    return;
  }

  el.innerHTML = users.map(u => {
    const isAdmin     = u.role === 'admin';
    const isSelf      = currentUser && u.username === currentUser.username;
    const avatar      = isAdmin ? '👑' : '👤';
    const roleColor   = isAdmin ? 'var(--yellow)' : 'var(--blue)';
    const roleLabel   = isAdmin ? 'role-admin' : 'role-user';
    const attemptsColor = u.failedAttempts > 0 ? 'var(--yellow)' : 'var(--green)';

    return `
    <div class="user-row" id="userrow-${escHtml(u.username)}">

      <!-- Avatar -->
      <div class="user-avatar ${u.role}">${avatar}</div>

      <!-- Info block -->
      <div class="user-info" style="flex:1;">
        <div class="user-name">
          ${escHtml(u.username)}
          ${isSelf ? '<span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-left:6px;">(you)</span>' : ''}
        </div>
        <div class="user-meta">
          role: <span class="${roleLabel}">${u.role}</span>
          &nbsp;|&nbsp; ${escHtml(u.email || '—')}
          &nbsp;|&nbsp; failed: <span style="color:${attemptsColor}">${u.failedAttempts||0}</span>
          ${u.lastLogin ? `&nbsp;|&nbsp; last login: ${formatDate(u.lastLogin)}` : ''}
          ${u.roleChangedBy ? `&nbsp;|&nbsp; <span style="color:var(--text-muted);font-size:0.68rem;">role set by: ${escHtml(u.roleChangedBy)}</span>` : ''}
        </div>
      </div>

      <!-- Action buttons on the right -->
      <div style="display:flex;flex-direction:column;gap:0.4rem;align-items:flex-end;min-width:180px;">

        <!-- Lock status + Unlock button -->
        ${u.isLocked
          ? `<div style="display:flex;gap:0.4rem;align-items:center;">
               <span class="locked-badge">🔒 LOCKED</span>
               <button class="btn btn-secondary btn-sm" onclick="unlockUser('${escHtml(u.username)}')">Unlock</button>
             </div>`
          : `<span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--green);">✓ Active</span>`
        }

        <!-- Role Change (only shown if NOT the currently logged-in admin) -->
        ${!isSelf
          ? `<div style="display:flex;gap:0.4rem;align-items:center;">
               <select id="roleSelect-${escHtml(u.username)}"
                 style="background:var(--bg-dark);border:1px solid var(--border);
                        color:var(--text-secondary);font-family:var(--font-mono);
                        font-size:0.72rem;padding:3px 6px;border-radius:4px;cursor:pointer;">
                 <option value="user"  ${u.role==='user'  ? 'selected':''}>👤 user</option>
                 <option value="admin" ${u.role==='admin' ? 'selected':''}>👑 admin</option>
               </select>
               <button class="btn btn-blue btn-sm"
                 onclick="changeRole('${escHtml(u.username)}')"
                 title="Apply role change">
                 Apply
               </button>
             </div>`
          : `<span style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);">cannot change own role</span>`
        }

      </div>
    </div>`;
  }).join('');
}

// ── Unlock a locked account ──────────────────────────────────────────────────
async function unlockUser(username) {
  const res  = await fetch('/api/users/unlock', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
    body:    JSON.stringify({ username })
  });
  const data    = await res.json();
  showUsersAlert(data.success, data.message);
  if (data.success) await loadUsers();
}

// ── Change a user's role ─────────────────────────────────────────────────────
/**
 * Called when admin clicks "Apply" next to a user's role dropdown.
 * Reads the selected value from the dropdown and sends it to the server.
 *
 * The server enforces:
 *  - Admin cannot change their own role
 *  - Role must be 'admin' or 'user'
 */
async function changeRole(username) {
  const select  = document.getElementById(`roleSelect-${username}`);
  if (!select) return;
  const newRole = select.value;

  // Confirm before promoting — demotion is less critical but still ask
  const action = newRole === 'admin'
    ? `promote "${username}" to ADMIN? They will get full system access.`
    : `demote "${username}" back to USER? They will lose admin access.`;

  if (!confirm(`Are you sure you want to ${action}`)) return;

  // Disable the button while request is in flight
  const btn = select.nextElementSibling;
  if (btn) { btn.disabled = true; btn.textContent = '…'; }

  const res  = await fetch('/api/users/change-role', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
    body:    JSON.stringify({ username, newRole })
  });
  const data = await res.json();

  if (btn) { btn.disabled = false; btn.textContent = 'Apply'; }

  showUsersAlert(data.success, data.message);

  // Reload the user list so the UI reflects the new role immediately
  if (data.success) await loadUsers();
}

// ── Show alert in the users panel ───────────────────────────────────────────
function showUsersAlert(success, message) {
  const alertEl = document.getElementById('usersAlert');
  alertEl.textContent = success ? `✓ ${message}` : `✗ ${message}`;
  alertEl.className   = `alert alert-${success ? 'success' : 'error'} show`;
  setTimeout(() => { alertEl.className = 'alert'; }, 4000);
}

// ══════════════════════════════════════════════════════════════════════════
// 6. SESSION TIMER & AUTO-LOGOUT
// ══════════════════════════════════════════════════════════════════════════

function startSessionTimer() {
  let secondsLeft    = sessionTimeout;
  let warnShown      = false;
  const fill         = document.getElementById('timerFill');
  const display      = document.getElementById('timerDisplay');

  timerInterval = setInterval(() => {
    secondsLeft--;
    const pct = (secondsLeft / sessionTimeout) * 100;
    if (fill) {
      fill.style.width = `${Math.max(pct, 0)}%`;
      if (pct < 20)      fill.style.background = 'linear-gradient(90deg, var(--red), var(--orange))';
      else if (pct < 50) fill.style.background = 'linear-gradient(90deg, var(--yellow), var(--green))';
    }
    const m = Math.floor(secondsLeft / 60).toString().padStart(2,'0');
    const s = (secondsLeft % 60).toString().padStart(2,'0');
    if (display) display.textContent = `⏱ ${m}:${s}`;

    // Show warning toast at 2 minutes remaining
    if (secondsLeft <= 120 && !warnShown) {
      warnShown = true;
      showSessionWarning(secondsLeft);
    }
    // Update warning countdown if showing
    if (secondsLeft <= 120) {
      const wt = document.getElementById('sessionWarningTime');
      if (wt) wt.textContent = `${m}:${s} remaining — save your work.`;
    }

    if (secondsLeft <= 0) {
      clearInterval(timerInterval);
      alert('⏰ Session expired. You have been logged out.');
      handleLogout();
    }
  }, 1000);
}

function showSessionWarning(secondsLeft) {
  const toast = document.getElementById('sessionWarningToast');
  if (toast) toast.style.display = 'block';
}

function dismissSessionWarning() {
  const toast = document.getElementById('sessionWarningToast');
  if (toast) toast.style.display = 'none';
}

function startInactivityReset() {
  ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
    document.addEventListener(event, () => { /* timer resets on backend via cookie */ });
  });
}

// ══════════════════════════════════════════════════════════════════════════
// 7. LOGOUT
// ══════════════════════════════════════════════════════════════════════════

async function handleLogout() {
  clearInterval(timerInterval);
  try { await fetch('/api/logout', { method: 'POST' }); } catch (_) {}
  window.location.href = '/';
}

// ══════════════════════════════════════════════════════════════════════════
// 8. STATS
// ══════════════════════════════════════════════════════════════════════════

async function refreshStats() {
  try {
    const res  = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    if (data.success && data.stats) {
      document.getElementById('statTotal').textContent   = data.stats.total   || 0;
      document.getElementById('statSuccess').textContent = data.stats.success || 0;
      document.getElementById('statDenied').textContent  = data.stats.denied  || 0;
    }
  } catch (_) {}
}

// ══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════════════

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-IN', {
      year:'2-digit', month:'2-digit', day:'2-digit',
      hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false
    });
  } catch (_) { return iso; }
}

// ══════════════════════════════════════════════════════════════════════════
// THEME MANAGEMENT — Dark / Light Mode
// Reads from localStorage, falls back to system preference.
// ══════════════════════════════════════════════════════════════════════════

function getTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = theme === 'dark' ? '🌙' : '☀️';
}

function toggleTheme() {
  applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
}

// Sync button icon after DOM is ready
window.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = getTheme() === 'dark' ? '🌙' : '☀️';
}, { once: true });


// ══════════════════════════════════════════════════════════════════════════
// PDF EXPORT — "Export Logs as PDF"
// Uses jsPDF + jsPDF-AutoTable (loaded via CDN in dashboard.html).
// Generates a professional, paginated PDF with:
//   - Title + generation timestamp
//   - Summary stats row (total / success / denied)
//   - Full logs table with colour-coded status column
// ══════════════════════════════════════════════════════════════════════════

function exportLogsPDF() {
  // Guard: allLogs is populated by loadLogs() in app.js
  if (!allLogs || allLogs.length === 0) {
    alert('No logs loaded. Click "Refresh" in the Logs panel first, then try again.');
    return;
  }

  // jsPDF is loaded via CDN — check it's available
  if (typeof window.jspdf === 'undefined') {
    alert('PDF library not loaded yet. Please wait a moment and try again.');
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a4' });

  // ── Page dimensions ───────────────────────────────────────────────────
  const pageW  = doc.internal.pageSize.getWidth();
  const margin = 14;

  // ── HEADER BLOCK ──────────────────────────────────────────────────────
  // Dark header bar
  doc.setFillColor(13, 17, 23);           // --bg-dark
  doc.rect(0, 0, pageW, 22, 'F');

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(230, 237, 243);        // --text-primary
  doc.text('System Call Logs', margin, 14);

  // Sub-info (generated at + user count)
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(139, 148, 158);        // --text-secondary
  const now = new Date().toLocaleString();
  const user = (typeof currentUser !== 'undefined' && currentUser)
    ? `Exported by: ${currentUser.username} (${currentUser.role})`
    : '';
  doc.text(`Generated: ${now}     ${user}`, pageW - margin, 14, { align: 'right' });

  // ── SUMMARY STATS ROW ─────────────────────────────────────────────────
  const total   = allLogs.length;
  const success = allLogs.filter(l => l.status === 'SUCCESS').length;
  const denied  = allLogs.filter(l => l.status === 'DENIED').length;
  const failed  = allLogs.filter(l => ['FAILED','ERROR'].includes(l.status)).length;

  let sx = margin;
  const sy = 30;
  const stats = [
    { label: 'Total Entries', value: total,   color: [88, 166, 255]  },
    { label: 'Successful',    value: success, color: [63, 185, 80]   },
    { label: 'Denied',        value: denied,  color: [248, 81, 73]   },
    { label: 'Failed/Error',  value: failed,  color: [227, 179, 65]  }
  ];
  const boxW = 45, boxH = 14;
  stats.forEach(s => {
    doc.setFillColor(28, 33, 40);         // --bg-card
    doc.roundedRect(sx, sy, boxW, boxH, 2, 2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...s.color);
    doc.text(String(s.value), sx + boxW/2, sy + 7.5, { align: 'center' });
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(139, 148, 158);
    doc.text(s.label.toUpperCase(), sx + boxW/2, sy + 12, { align: 'center' });
    sx += boxW + 4;
  });

  // ── LOGS TABLE ────────────────────────────────────────────────────────
  const rows = allLogs.map(log => [
    log.timestamp ? new Date(log.timestamp).toLocaleString() : '—',
    log.username  || '—',
    (log.role     || '—').toUpperCase(),
    log.action    || '—',
    log.resource  || '—',
    log.status    || '—',
    log.duration_ms != null ? `${log.duration_ms}ms` : '—',
    (log.details  || '').substring(0, 60)   // truncate long detail strings
  ]);

  // Status cell colour map
  const STATUS_COLORS = {
    SUCCESS: [63, 185, 80],
    DENIED:  [248, 81, 73],
    FAILED:  [227, 179, 65],
    ERROR:   [255, 123, 114],
    INFO:    [88, 166, 255]
  };

  doc.autoTable({
    startY: sy + boxH + 6,
    head: [['Timestamp', 'User', 'Role', 'Action', 'Resource', 'Status', 'Duration', 'Details']],
    body: rows,
    margin: { left: margin, right: margin },
    styles: {
      font:      'helvetica',
      fontSize:  7.5,
      cellPadding: 2.5,
      lineWidth: 0.1,
      lineColor: [48, 54, 61],          // --border
      textColor: [139, 148, 158],       // --text-secondary
      fillColor: [22, 27, 34]           // --bg-panel
    },
    headStyles: {
      fillColor:  [13, 17, 23],
      textColor:  [139, 148, 158],
      fontStyle:  'bold',
      fontSize:   6.5,
      halign:     'left'
    },
    alternateRowStyles: {
      fillColor: [28, 33, 40]           // --bg-card
    },
    columnStyles: {
      0: { cellWidth: 36 },             // Timestamp
      1: { cellWidth: 22 },             // User
      2: { cellWidth: 16 },             // Role
      3: { cellWidth: 26 },             // Action
      4: { cellWidth: 26 },             // Resource
      5: { cellWidth: 18 },             // Status
      6: { cellWidth: 18 },             // Duration
      7: { cellWidth: 'auto' }          // Details
    },
    // Colour-code the Status column per row
    didParseCell(data) {
      if (data.section === 'body' && data.column.index === 5) {
        const status = String(data.cell.raw);
        const rgb = STATUS_COLORS[status.toUpperCase()];
        if (rgb) data.cell.styles.textColor = rgb;
      }
    },
    // Page footer with page numbers
    didDrawPage(data) {
      const pageCount = doc.internal.getNumberOfPages();
      doc.setFontSize(7);
      doc.setTextColor(72, 79, 88);     // --text-muted
      doc.text(
        `SecureSyscall — Confidential   |   Page ${data.pageNumber} of ${pageCount}`,
        pageW / 2, doc.internal.pageSize.getHeight() - 6,
        { align: 'center' }
      );
    }
  });

  // ── Save file ─────────────────────────────────────────────────────────
  const filename = `syscall-logs-${new Date().toISOString().slice(0,10)}.pdf`;
  doc.save(filename);
}
