// authController.js
// Controllers for handling auth, user relationships, and administrative requests

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/userModel');
const { logAuditEvent } = require('../../shared/auth');

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Helper for auditing within auth service
const localLogAudit = (req, actionType, resource, resourceId, status, message) => {
  logAuditEvent(req, { actionType, resource, resourceId, status, message });
};

const register = async (req, res) => {
  try {
    const { username, password, email, role } = req.body;
    const finalRole = (role || 'FAMILY').toUpperCase();
    const hashedPassword = await bcrypt.hash(password, 10);
    const inviteCode = finalRole === 'ELDER' ? crypto.randomBytes(3).toString('hex').toUpperCase() : null;

    // Support email-based registration: derive username from email if not provided
    let finalEmail = email;
    let finalUsername = username;
    if (email && !username) {
      // Username = part before '@', sanitized, with random suffix to avoid conflicts
      const base = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
      finalUsername = base + '_' + Math.random().toString(36).slice(2, 6);
    } else if (!email && username) {
      // If username looks like an email, use it as both email and derive clean username
      if (username.includes('@')) {
        finalEmail = username;
        const base = username.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
        finalUsername = base + '_' + Math.random().toString(36).slice(2, 6);
      } else {
        finalEmail = `${username}@elderpinq.com`;
      }
    }

    const user = await User.create({
      username: finalUsername,
      hashedPassword,
      email: finalEmail,
      role: finalRole,
      inviteCode
    });

    // Return the actual username so the frontend knows what was registered
    res.status(201).json({ ...user, registeredUsername: finalUsername });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Email already registered. Please login.' });
    }
    res.status(500).json({ error: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { username, password, email } = req.body;
    // Accept login by email OR username (email field or username field)
    const identifier = email || username;
    const user = await User.findByEmailOrUsername(identifier);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email/username or password' });
    }
    
    // Check user status
    if (user.status === 'SUSPENDED') {
      return res.status(403).json({ error: 'Account suspended. Contact administration.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        status: user.status,
        invite_code: user.invite_code
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const me = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const linkFamily = async (req, res) => {
  try {
    const { inviteCode } = req.body;
    const familyId = req.user.id;
    const pool = User.getPool();

    const elderRes = await pool.query('SELECT id, role FROM users WHERE invite_code = $1', [inviteCode]);
    if (elderRes.rows.length === 0) return res.status(404).json({ error: 'Invalid invite code' });
    const elder = elderRes.rows[0];
    
    // Check if elder role is mapped
    const isElder = elder.role === 'ELDER' || elder.role === 'USER';
    if (!isElder) return res.status(400).json({ error: 'User is not registered as an elder' });

    await pool.query(
      'INSERT INTO family_links (family_id, elder_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [familyId, elder.id]
    );

    localLogAudit(req, 'LINK_FAMILY', 'family_links', `${familyId}-${elder.id}`, 'SUCCESS', `Linked family member ${familyId} to elder ${elder.id}`);
    res.status(201).json({ success: true, elderId: elder.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getEldersLink = async (req, res) => {
  try {
    const familyId = req.user.id;
    const pool = User.getPool();
    const result = await pool.query(
      `SELECT u.id, u.username, u.role FROM users u
       JOIN family_links f ON u.id = f.elder_id
       WHERE f.family_id = $1`,
      [familyId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getFamilyLink = async (req, res) => {
  try {
    const elderId = req.user.id;
    const pool = User.getPool();
    const result = await pool.query(
      `SELECT u.id, u.username, u.role FROM users u
       JOIN family_links f ON u.id = f.family_id
       WHERE f.elder_id = $1`,
      [elderId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const verifyLink = async (req, res) => {
  try {
    const { familyId, elderId } = req.params;
    const pool = User.getPool();
    const result = await pool.query(
      'SELECT 1 FROM family_links WHERE family_id = $1 AND elder_id = $2',
      [familyId, elderId]
    );
    res.json({ linked: result.rows.length > 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const updateEmergencyContacts = async (req, res) => {
  try {
    const { elderId } = req.params;
    const pool = User.getPool();
    const {
      primaryName,
      primaryPhone,
      primaryRelationship,
      secondaryName,
      secondaryPhone,
      secondaryRelationship,
      doctorName,
      doctorPhone,
      doctorSpecialty,
      hospitalName,
      hospitalPhone,
      hospitalAddress
    } = req.body;

    if (!primaryName || !primaryPhone) {
      return res.status(400).json({ error: 'primaryName and primaryPhone are required' });
    }

    const result = await pool.query(
      `INSERT INTO emergency_contacts 
        (elder_id, primary_name, primary_phone, primary_relationship, secondary_name, secondary_phone, secondary_relationship, doctor_name, doctor_phone, doctor_specialty, hospital_name, hospital_phone, hospital_address)
       VALUES 
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (elder_id) 
       DO UPDATE SET
         primary_name = EXCLUDED.primary_name,
         primary_phone = EXCLUDED.primary_phone,
         primary_relationship = EXCLUDED.primary_relationship,
         secondary_name = EXCLUDED.secondary_name,
         secondary_phone = EXCLUDED.secondary_phone,
         secondary_relationship = EXCLUDED.secondary_relationship,
         doctor_name = EXCLUDED.doctor_name,
         doctor_phone = EXCLUDED.doctor_phone,
         doctor_specialty = EXCLUDED.doctor_specialty,
         hospital_name = EXCLUDED.hospital_name,
         hospital_phone = EXCLUDED.hospital_phone,
         hospital_address = EXCLUDED.hospital_address
       RETURNING *`,
      [
        elderId,
        primaryName,
        primaryPhone,
        primaryRelationship || null,
        secondaryName || null,
        secondaryPhone || null,
        secondaryRelationship || null,
        doctorName || null,
        doctorPhone || null,
        doctorSpecialty || null,
        hospitalName || null,
        hospitalPhone || null,
        hospitalAddress || null
      ]
    );

    localLogAudit(req, 'UPDATE_EMERGENCY_CONTACTS', 'emergency_contacts', result.rows[0].id, 'SUCCESS', `Emergency contacts updated for elder: ${elderId}`);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getEmergencyContacts = async (req, res) => {
  try {
    const { elderId } = req.params;
    const pool = User.getPool();
    const result = await pool.query('SELECT * FROM emergency_contacts WHERE elder_id = $1', [elderId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No emergency contacts found for this elder' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const updateConsents = async (req, res) => {
  try {
    const { elderId } = req.params;
    const pool = User.getPool();
    const { familyAccess, aiProcessing, docSharing, emergencyContact } = req.body;

    const result = await pool.query(
      `INSERT INTO consents 
        (user_id, family_access_granted, ai_processing_granted, doc_sharing_granted, emergency_contact_granted, updated_at)
       VALUES 
        ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id) 
       DO UPDATE SET
         family_access_granted = EXCLUDED.family_access_granted,
         ai_processing_granted = EXCLUDED.ai_processing_granted,
         doc_sharing_granted = EXCLUDED.doc_sharing_granted,
         emergency_contact_granted = EXCLUDED.emergency_contact_granted,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [
        elderId,
        familyAccess !== undefined ? !!familyAccess : false,
        aiProcessing !== undefined ? !!aiProcessing : false,
        docSharing !== undefined ? !!docSharing : false,
        emergencyContact !== undefined ? !!emergencyContact : false
      ]
    );

    localLogAudit(req, 'UPDATE_CONSENTS', 'consents', result.rows[0].id, 'SUCCESS', `Consent preferences updated for elder: ${elderId}`);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const getConsents = async (req, res) => {
  try {
    const { elderId } = req.params;
    const pool = User.getPool();
    const result = await pool.query('SELECT * FROM consents WHERE user_id = $1', [elderId]);
    if (result.rows.length === 0) {
      return res.json({
        user_id: elderId,
        family_access_granted: false,
        ai_processing_granted: false,
        doc_sharing_granted: false,
        emergency_contact_granted: false
      });
    }
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// ──────────────────────────────────────────────
// ADMIN CONTROLLERS
// ──────────────────────────────────────────────

const adminListUsers = async (req, res) => {
  try {
    const users = await User.listAll();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const adminGetUser = async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const adminUpdateRole = async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updated = await User.updateRole(id, role.toUpperCase());
    
    // Log audit event asynchronously
    localLogAudit(req, 'ADMIN_UPDATE_USER_ROLE', 'users', id, 'SUCCESS', `Updated user role from ${user.role} to ${role}`);
    
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const adminUpdateStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const updated = await User.updateStatus(id, status.toUpperCase());

    // Log audit event asynchronously
    localLogAudit(req, 'ADMIN_UPDATE_USER_STATUS', 'users', id, 'SUCCESS', `Updated user status from ${user.status || 'ACTIVE'} to ${status}`);

    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

module.exports = {
  register,
  login,
  me,
  getUserById,
  linkFamily,
  getEldersLink,
  getFamilyLink,
  verifyLink,
  updateEmergencyContacts,
  getEmergencyContacts,
  updateConsents,
  getConsents,
  adminListUsers,
  adminGetUser,
  adminUpdateRole,
  adminUpdateStatus
};
