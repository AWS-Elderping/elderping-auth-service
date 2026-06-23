// userModel.js
// Modular data layer for user actions in PostgreSQL

const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     process.env.DB_PORT,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const User = {
  async findByUsername(username) {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    return result.rows[0];
  },

  // Login by email OR username (case-insensitive email)
  async findByEmailOrUsername(identifier) {
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($1)',
      [identifier]
    );
    return result.rows[0];
  },

  async findById(id) {
    const result = await pool.query(
      'SELECT id, username, email, role, status, invite_code, created_at FROM users WHERE id = $1',
      [id]
    );
    return result.rows[0];
  },

  async findRawById(id) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
  },

  async create({ username, hashedPassword, email, role, inviteCode }) {
    const result = await pool.query(
      'INSERT INTO users (username, password, email, role, invite_code) VALUES ($1, $2, $3, $4, $5) RETURNING id, username, email, role, status, invite_code',
      [username, hashedPassword, email, role, inviteCode]
    );
    return result.rows[0];
  },

  async listAll() {
    const result = await pool.query(
      'SELECT id, username, email, role, status, invite_code, created_at FROM users ORDER BY created_at DESC'
    );
    return result.rows;
  },

  async updateRole(id, role) {
    const result = await pool.query(
      'UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, email, role, status',
      [role, id]
    );
    return result.rows[0];
  },

  async updateStatus(id, status) {
    const result = await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2 RETURNING id, username, email, role, status',
      [status, id]
    );
    return result.rows[0];
  },

  async hasSuperAdmin() {
    const result = await pool.query("SELECT 1 FROM users WHERE role = 'SUPER_ADMIN' LIMIT 1");
    return result.rows.length > 0;
  },

  async createSuperAdmin(username, hashedPassword, email) {
    const result = await pool.query(
      "INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, 'SUPER_ADMIN') RETURNING id, username, email, role",
      [username, hashedPassword, email]
    );
    return result.rows[0];
  },

  getPool() {
    return pool;
  }
};

module.exports = User;
