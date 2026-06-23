// server.js
// Auth service main entrypoint

const express = require('express');
const cors = require('cors');
const User = require('./models/userModel');
const authRoutes = require('./routes/authRoutes');
const { bootstrapSuperAdmin } = require('./bootstrap');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(express.json());

// Kubernetes liveness / readiness probe
app.get('/health', (req, res) =>
  res.status(200).json({ status: 'ok', service: 'auth-service' })
);
app.get('/healthz', (req, res) =>
  res.status(200).json({ status: 'ok', service: 'auth-service' })
);
app.get('/ready', (req, res) =>
  res.status(200).json({ status: 'ok', service: 'auth-service' })
);

// Mount modular auth routes
// Serve at both '/' (local/nginx proxy strips prefix) and '/api/auth' (K8s ALB passes full path)
app.use('/', authRoutes);
app.use('/api/auth', authRoutes);

// ──────────────────────────────────────────────
// SEED — creates demo users if the table is empty
// ──────────────────────────────────────────────
async function seedDemoUsers() {
  const pool = User.getPool();
  try {
    const { rows } = await pool.query('SELECT COUNT(*) AS cnt FROM users');
    if (parseInt(rows[0].cnt, 10) > 0) {
      console.log('ℹ️ Users table already has data — skipping seed.');
      return;
    }
    const elderHash  = await bcrypt.hash('password123', 10);
    const familyHash = await bcrypt.hash('password123', 10);
    
    await pool.query(
      `INSERT INTO users (username, password, email, role, invite_code) VALUES
        ($1, $2, 'grandma@elderpinq.com', 'ELDER', 'DEMO-123'),
        ($3, $4, 'daughter@elderpinq.com', 'FAMILY', NULL)
       ON CONFLICT (username) DO NOTHING`,
      ['grandma', elderHash, 'daughter', familyHash]
    );
    
    // Seed link
    const users = await pool.query('SELECT id, username FROM users WHERE username IN ($1, $2)', ['grandma', 'daughter']);
    const grandma = users.rows.find(u => u.username === 'grandma');
    const daughter = users.rows.find(u => u.username === 'daughter');
    
    if (grandma && daughter) {
      await pool.query(
        'INSERT INTO family_links (family_id, elder_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [daughter.id, grandma.id]
      );
    }
    
    console.log("✅ Demo users seeded → grandma (ELDER) / daughter (FAMILY) — password: password123");
  } catch (err) {
    console.error('⚠️ Seeding failed:', err.message);
  }
}

// ──────────────────────────────────────────────
// STARTUP
// ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

async function start() {
  const pool = User.getPool();
  // Wait for a valid DB connection before seeding / starting
  let retries = 10;
  while (retries--) {
    try {
      await pool.query('SELECT 1');
      console.log('✅ Connected to database successfully.');
      break;
    } catch (err) {
      console.log(`⏳ Waiting for database… (${retries} retries left) error: ${err.message}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  // Seed demo data
  await seedDemoUsers();
  
  // Seed default SUPER_ADMIN if needed (and enabled)
  await bootstrapSuperAdmin();

  app.listen(PORT, () => {
    console.log(`Auth service running on port ${PORT}`);
  });
}

start();
