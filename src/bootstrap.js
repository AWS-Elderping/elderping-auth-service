// bootstrap.js
// Bootstrapper for initial SUPER_ADMIN seeding

const User = require('./models/userModel');
const bcrypt = require('bcrypt');

const bootstrapSuperAdmin = async () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const enableBootstrap = process.env.ENABLE_SUPER_ADMIN_BOOTSTRAP === 'true';

  // Disabled by default in production
  if (isProduction && !enableBootstrap) {
    console.log('ℹ️ SUPER_ADMIN bootstrap is disabled by default in production.');
    return;
  }

  // Also skip if no password configured
  const password = process.env.SUPER_ADMIN_PASSWORD;
  const email = process.env.SUPER_ADMIN_EMAIL || 'superadmin@elderpinq.com';

  if (!password) {
    console.log('ℹ️ SUPER_ADMIN_PASSWORD not set. Skipping default SUPER_ADMIN bootstrap.');
    return;
  }

  try {
    const exists = await User.hasSuperAdmin();
    if (exists) {
      console.log('ℹ️ SUPER_ADMIN exists in database. Skipping bootstrap.');
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.createSuperAdmin('superadmin', hashedPassword, email);
    console.log(`✅ Default SUPER_ADMIN 'superadmin' (${email}) successfully bootstrapped.`);
  } catch (err) {
    console.error('⚠️ Failed to bootstrap SUPER_ADMIN:', err.message);
  }
};

module.exports = { bootstrapSuperAdmin };
