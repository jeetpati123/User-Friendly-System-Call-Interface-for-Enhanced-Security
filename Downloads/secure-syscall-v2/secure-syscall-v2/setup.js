/**
 * setup.js
 * Run this ONCE before starting the server: node setup.js
 * This creates the initial users.json file with hashed passwords
 * and ensures the logs directory + log file exist.
 */

const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const LOGS_DIR = path.join(__dirname, 'logs');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LOGS_FILE = path.join(LOGS_DIR, 'logs.json');
const VFS_FILE = path.join(DATA_DIR, 'virtual_fs.json');

// ─── Ensure directories exist ──────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });

// ─── Create default users with hashed passwords ────────────────────────────
const SALT_ROUNDS = 10;

async function createUsers() {
  console.log('🔐 Hashing passwords (this may take a moment)...');

  const adminHash = await bcrypt.hash('admin123', SALT_ROUNDS);
  const userHash  = await bcrypt.hash('user123',  SALT_ROUNDS);
  const guestHash = await bcrypt.hash('guest123', SALT_ROUNDS);
  const modHash   = await bcrypt.hash('mod123',   SALT_ROUNDS);

  const users = [
    {
      id: 1,
      username: 'admin',
      password: adminHash,         // hashed "admin123"
      role: 'admin',
      email: 'admin@syscall.local',
      failedAttempts: 0,
      isLocked: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 2,
      username: 'alice',
      password: userHash,          // hashed "user123"
      role: 'user',
      email: 'alice@syscall.local',
      failedAttempts: 0,
      isLocked: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 3,
      username: 'guest',
      password: guestHash,         // hashed "guest123"
      role: 'user',
      email: 'guest@syscall.local',
      failedAttempts: 0,
      isLocked: false,
      createdAt: new Date().toISOString()
    },
    {
      id: 4,
      username: 'moderator',
      password: modHash,         // hashed "mod123"
      role: 'moderator',
      email: 'moderator@syscall.local',
      failedAttempts: 0,
      isLocked: false,
      createdAt: new Date().toISOString()
    }
  ];

  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  console.log('✅ users.json created with 4 accounts:');
  console.log('   👑 admin     / admin123  (role: admin)');
  console.log('   👤 alice     / user123   (role: user)');
  console.log('   👤 guest     / guest123  (role: user)');
  console.log('   🛡️ moderator / mod123    (role: moderator)');
}

// ─── Create initial logs file ──────────────────────────────────────────────
function createLogs() {
  if (!fs.existsSync(LOGS_FILE)) {
    fs.writeFileSync(LOGS_FILE, JSON.stringify([], null, 2));
    console.log('✅ logs/logs.json created (empty)');
  } else {
    console.log('ℹ️  logs/logs.json already exists, skipping');
  }
}

// ─── Create a simulated virtual filesystem ─────────────────────────────────
function createVirtualFS() {
  const vfs = {
    'readme.txt': {
      content: 'Welcome to the Secure System Call Interface!\nThis is a simulated filesystem for demonstration.',
      owner: 'admin',
      permissions: 'rw-r--r--',
      size: 95,
      createdAt: new Date().toISOString()
    },
    'config.cfg': {
      content: '# System Configuration\nmax_users=100\nlog_level=INFO\nsession_timeout=1800',
      owner: 'admin',
      permissions: 'rw-------',
      size: 72,
      createdAt: new Date().toISOString()
    },
    'notes.txt': {
      content: 'Alice\'s personal notes:\n1. Study OS concepts\n2. Complete project\n3. Submit on time',
      owner: 'alice',
      permissions: 'rw-rw-r--',
      size: 74,
      createdAt: new Date().toISOString()
    },
    'report.txt': {
      content: 'System Performance Report\n==========================\nCPU Usage: 45%\nMemory: 2.1GB / 8GB\nDisk: 120GB / 500GB',
      owner: 'admin',
      permissions: 'rw-r--r--',
      size: 103,
      createdAt: new Date().toISOString()
    }
  };

  fs.writeFileSync(VFS_FILE, JSON.stringify(vfs, null, 2));
  console.log('✅ data/virtual_fs.json created with sample files:');
  Object.keys(vfs).forEach(f => console.log(`   📄 ${f}`));
}

// ─── Run setup ─────────────────────────────────────────────────────────────
(async () => {
  try {
    await createUsers();
    createLogs();
    createVirtualFS();
    console.log('\n🚀 Setup complete! Run "npm start" to launch the server.');
    console.log('   Open http://localhost:3000 in your browser.\n');
  } catch (err) {
    console.error('❌ Setup failed:', err.message);
    process.exit(1);
  }
})();
