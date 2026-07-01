// server.js
// Auth service — local JWT mode (no Cognito token validation)

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
// SCHEMA BOOTSTRAP — idempotent, runs on every startup
// ──────────────────────────────────────────────
async function initDb() {
  const pool = User.getPool();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(100) UNIQUE NOT NULL,
      password      VARCHAR(255) NOT NULL,
      email         VARCHAR(255) UNIQUE NOT NULL,
      role          VARCHAR(50) NOT NULL DEFAULT 'FAMILY',
      status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
      invite_code   VARCHAR(20) UNIQUE,
      created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS family_links (
      id          SERIAL PRIMARY KEY,
      family_id   INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      elder_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (family_id, elder_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS doctor_patient_links (
      id            SERIAL PRIMARY KEY,
      doctor_id     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      elder_id      INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      assigned_by   INT NOT NULL REFERENCES users(id),
      created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (doctor_id, elder_id)
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS doctor_patient_links_elder_id_idx ON doctor_patient_links (elder_id)');
  await pool.query('CREATE INDEX IF NOT EXISTS doctor_patient_links_doctor_id_idx ON doctor_patient_links (doctor_id)');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS emergency_contacts (
      id                      SERIAL PRIMARY KEY,
      elder_id                INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      primary_name            VARCHAR(200) NOT NULL,
      primary_phone           VARCHAR(50) NOT NULL,
      primary_relationship    VARCHAR(100),
      secondary_name          VARCHAR(200),
      secondary_phone         VARCHAR(50),
      secondary_relationship  VARCHAR(100),
      doctor_name             VARCHAR(200),
      doctor_phone            VARCHAR(50),
      doctor_specialty        VARCHAR(150),
      hospital_name           VARCHAR(200),
      hospital_phone          VARCHAR(50),
      hospital_address        TEXT,
      created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS consents (
      id                          SERIAL PRIMARY KEY,
      user_id                     INT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      family_access_granted       BOOLEAN DEFAULT FALSE,
      ai_processing_granted       BOOLEAN DEFAULT FALSE,
      doc_sharing_granted         BOOLEAN DEFAULT FALSE,
      emergency_contact_granted   BOOLEAN DEFAULT FALSE,
      updated_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log('Database schema ready (users, family_links, doctor_patient_links, emergency_contacts, consents).');
}

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
    const doctorHash = await bcrypt.hash('password123', 10);

    await pool.query(
      `INSERT INTO users (username, password, email, role, invite_code) VALUES
        ($1, $2, 'grandma@elderpinq.com', 'ELDER', 'DEMO-123'),
        ($3, $4, 'daughter@elderpinq.com', 'FAMILY', NULL),
        ($5, $6, 'doctor@elderpinq.com', 'DOCTOR', NULL)
       ON CONFLICT (username) DO NOTHING`,
      ['grandma', elderHash, 'daughter', familyHash, 'doctor', doctorHash]
    );

    // Seed link
    const users = await pool.query('SELECT id, username FROM users WHERE username IN ($1, $2, $3)', ['grandma', 'daughter', 'doctor']);
    const grandma = users.rows.find(u => u.username === 'grandma');
    const daughter = users.rows.find(u => u.username === 'daughter');

    if (grandma && daughter) {
      await pool.query(
        'INSERT INTO family_links (family_id, elder_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [daughter.id, grandma.id]
      );
    }

    console.log('Demo users seeded: grandma (ELDER) / daughter (FAMILY) / doctor (DOCTOR) - password: password123');
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

  // Create tables if they don't exist yet, then seed demo data
  await initDb();
  await seedDemoUsers();

  // Reset any PENDING users to ACTIVE — cleans up users stuck from a
  // previous Cognito-based registration flow that is no longer in use
  try {
    const r = await pool.query("UPDATE users SET status = 'ACTIVE' WHERE status = 'PENDING'");
    if (r.rowCount > 0) console.log(`✅ Reset ${r.rowCount} PENDING user(s) to ACTIVE.`);
  } catch (err) {
    console.error('⚠️ Could not reset PENDING users:', err.message);
  }

  // Seed default SUPER_ADMIN if needed (and enabled)
  await bootstrapSuperAdmin();

  app.listen(PORT, () => {
    console.log(`Auth service running on port ${PORT}`);
  });
}

start();
