// authRoutes.js
// Router configuration for authentication and administrative user endpoints

const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticate, requirePermission, requireRole, checkRelationship, PERMISSIONS } = require('../../shared/auth');
const validation = require('../validation/authValidation');

// ──────────────────────────────────────────────
// PUBLIC ENDPOINTS
// ──────────────────────────────────────────────
router.post('/register', validation.validateRegister, authController.register);
router.post('/login', validation.validateLogin, authController.login);
router.get('/users/:id', authController.getUserById);
router.get('/links/verify/:familyId/:elderId', authController.verifyLink);
router.get('/doctor-links/verify/:doctorId/:elderId', authController.verifyDoctorLink);

// ──────────────────────────────────────────────
// AUTHENTICATED ENDPOINTS
// ──────────────────────────────────────────────
router.get('/me', authenticate, authController.me);
router.post('/link', authenticate, requireRole('FAMILY'), authController.linkFamily);
router.get('/links/elders', authenticate, authController.getEldersLink);
router.get('/links/family', authenticate, authController.getFamilyLink);
router.get('/doctors', authenticate, authController.listDoctors);
router.post('/doctors/assign', authenticate, requireRole('FAMILY'), checkRelationship('elderId'), authController.assignDoctor);
router.get('/doctor-links/my-patients', authenticate, requireRole('DOCTOR'), authController.getMyPatients);

// ──────────────────────────────────────────────
// PROTECTED WITH ABAC RELATIONSHIP CHECKS
// ──────────────────────────────────────────────
router.post('/contacts/:elderId', authenticate, checkRelationship('elderId'), authController.updateEmergencyContacts);
router.get('/contacts/:elderId', authenticate, checkRelationship('elderId'), authController.getEmergencyContacts);
router.post('/consents/:elderId', authenticate, checkRelationship('elderId'), authController.updateConsents);
router.get('/consents/:elderId', authenticate, checkRelationship('elderId'), authController.getConsents);

// ──────────────────────────────────────────────
// ADMIN USER MANAGEMENT ENDPOINTS
// ──────────────────────────────────────────────
router.get('/admin/users', authenticate, requirePermission(PERMISSIONS.USER_MANAGE), authController.adminListUsers);
router.get('/admin/users/:id', authenticate, requirePermission(PERMISSIONS.USER_MANAGE), authController.adminGetUser);
router.patch('/admin/users/:id/role', authenticate, requirePermission(PERMISSIONS.USER_MANAGE), validation.validateUpdateRole, authController.adminUpdateRole);
router.patch('/admin/users/:id/status', authenticate, requirePermission(PERMISSIONS.USER_MANAGE), validation.validateUpdateStatus, authController.adminUpdateStatus);

module.exports = router;
