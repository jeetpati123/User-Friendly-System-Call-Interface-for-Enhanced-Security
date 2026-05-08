# 🔐 Secure System Call Interface — Improved
### Authentication · Authorization · Logging · RBAC
**B.Tech CSE — Operating Systems Project (v3.0)**

---

## What's New in v3.0

| # | Improvement | File | Why It Matters |
|---|-------------|------|----------------|
| 1 | **IP-based login rate limiter** | `server.js` | Original had per-account lockout but an attacker could still brute-force many accounts in parallel. Now limited to 10 attempts / IP / 15 min. |
| 2 | **Security HTTP headers** | `server.js` | Adds `X-Frame-Options`, `X-Content-Type-Options`, `CSP`, `Referrer-Policy` — defends against clickjacking, MIME sniffing, XSS. No new package needed. |
| 3 | **`moderator` role** | `auth.js` | New RBAC tier: can read + delete + rename, but NOT write. Useful for auditors who clean up without creating/modifying content. |
| 4 | **Session role refresh** | `auth.js` | Original stored the role in the session at login — if admin changed a user's role, the change didn't apply until re-login. Now role is re-read from DB on every request. |
| 5 | **Stronger password rules** | `auth.js` | Registration now requires 8+ characters and at least one digit (original: just 6 chars). |
| 6 | **`rename_file` syscall** | `systemCall.js` | Atomic rename in the virtual FS. Available to admin + moderator. |
| 7 | **`copy_file` syscall** | `systemCall.js` | Duplicate a file under a new name. Available to admin + user. |
| 8 | **`lastModifiedBy` field** | `systemCall.js` | Files now track who last modified them, not just the original owner. |
| 9 | **Log search API** | `server.js` + `logger.js` | `GET /api/logs?username=alice&status=DENIED&action=delete_file&from=...` — filtering now happens server-side, not in the browser. |
| 10 | **Per-action stats breakdown** | `logger.js` | `getLogStats()` now returns `actionBreakdown` so the dashboard can show which syscalls are most used / most denied. |
| 11 | **Password change endpoint** | `server.js` | `POST /api/users/change-password` — any logged-in user can change their password; requires current password for verification. |
| 12 | **Log rotation notice** | `logger.js` | When logs exceed 1000 entries, a `LOG_ROTATION` system entry is written so the audit trail honestly records that trimming occurred. |

---

## Project Structure

```
secure-syscall/
├── backend/
│   ├── server.js        ← Express server + all API routes
│   ├── auth.js          ← Authentication + RBAC (now with moderator role)
│   ├── systemCall.js    ← Syscall engine (now with rename + copy)
│   └── logger.js        ← Audit logging (now with search + action stats)
├── frontend/
│   ├── index.html       ← Login/Register page
│   ├── dashboard.html   ← Main dashboard
│   ├── style.css        ← Dark terminal design
│   └── app.js           ← Frontend JS
├── data/
│   ├── users.json       ← Hashed passwords + roles
│   └── virtual_fs.json  ← Simulated filesystem
├── logs/
│   └── logs.json        ← Full audit log
├── setup.js             ← One-time setup
└── package.json
```

---

## How to Run

```bash
npm install
node setup.js     # one time only
npm start
# open http://localhost:3000
```

---

## Default Accounts

| Username | Password   | Role          | Permissions                                   |
|----------|------------|---------------|-----------------------------------------------|
| admin    | admin123   | admin         | All: read, write, delete, list, rename, copy  |
| alice    | user123    | user          | read, write, list, copy (NO delete/rename)    |
| guest    | guest123   | user          | read, write, list, copy (NO delete/rename)    |

**New role — moderator** (assign via admin panel):
- Can: read, delete, list, rename
- Cannot: write (create/edit content), copy

---

## API Reference

| Method | Endpoint                      | Auth     | Description                                |
|--------|-------------------------------|----------|--------------------------------------------|
| POST   | /api/register                 | No       | Create account (8+ char password required) |
| POST   | /api/login                    | No       | Login — IP rate limited (10/15 min)        |
| POST   | /api/logout                   | Yes      | Destroy session                            |
| GET    | /api/whoami                   | Yes      | Current user info (role refreshed from DB) |
| GET    | /api/permissions              | Yes      | Allowed syscalls for current role          |
| POST   | /api/syscall                  | Yes      | Execute a syscall                          |
| GET    | /api/logs                     | Admin    | Get logs — now supports filter query params |
| GET    | /api/logs?username=&status=&action=&from=&to=&limit= | Admin | Server-side log search |
| GET    | /api/logs/export              | Admin    | Download logs as JSON                      |
| DELETE | /api/logs                     | Admin    | Clear all logs                             |
| GET    | /api/stats                    | Yes      | Stats with per-action breakdown            |
| GET    | /api/users                    | Admin    | List all users                             |
| POST   | /api/users/unlock             | Admin    | Unlock locked account                      |
| POST   | /api/users/change-role        | Admin    | Change role (validates against VALID_ROLES) |
| POST   | /api/users/change-password    | Yes      | Change own password (requires current pw)  |
| GET    | /api/files                    | Yes      | List files silently (no log entry)         |

---

## System Calls

| Syscall       | admin | moderator | user | Description                        |
|---------------|:-----:|:---------:|:----:|------------------------------------|
| `list_files`  | ✅   | ✅        | ✅  | List all files + metadata          |
| `read_file`   | ✅   | ✅        | ✅  | Read file content                  |
| `write_file`  | ✅   | ❌        | ✅  | Create or update a file            |
| `delete_file` | ✅   | ✅        | ❌  | Delete a file permanently          |
| `rename_file` | ✅   | ✅        | ❌  | Rename a file (NEW)                |
| `copy_file`   | ✅   | ❌        | ✅  | Copy a file to a new name (NEW)    |

---

## Concepts Map

| OS Concept           | Project Implementation                               |
|----------------------|------------------------------------------------------|
| System Calls         | `/api/syscall` → `systemCall()` dispatcher           |
| Process Credentials  | Session user object (username, role, id)             |
| User Space / Kernel  | Frontend JS = user space; Express = kernel           |
| UID / GID            | id = UID, role = GID equivalent                      |
| Access Control       | `isAuthorized(role, action)` RBAC (3 roles now)      |
| File Permissions     | `permissions` field + `lastModifiedBy` tracking      |
| Audit Trail (auditd) | `logger.js` → `logs.json` with search/filter         |
| Process Table        | Session store (in-memory express-session)            |
| Privilege Escalation | Admin role = elevated privileges (root-like)         |
| Account Lockout      | Per-account (3 fails) + per-IP (10 fails / 15 min)   |
| Syscall Table        | `SYSCALL_TABLE` map in `systemCall.js`               |

---

*Built for B.Tech CSE — Operating Systems Course Project*
