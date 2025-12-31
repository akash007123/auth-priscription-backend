require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Prescription = require('./models/Prescription');
const User = require('./models/User');
const auth = require('./middleware/auth');

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Enable CORS for all origins
app.use(cors());

// Parse JSON bodies
app.use(express.json());

// Serve static files from uploads
app.use('/uploads', express.static('uploads'));

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// Routes

// Auth routes

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();

    // Send email
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password/${resetToken}`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Password Reset Request - PrescriptionMaker',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #4F46E5;">Password Reset Request</h2>
          <p>Hello ${user.name || 'User'},</p>
          <p>You have requested to reset your password for your PrescriptionMaker account.</p>
          <p>Please click the link below to reset your password:</p>
          <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0;">Reset Password</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this password reset, please ignore this email.</p>
          <p>Best regards,<br>PrescriptionMaker Team</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to send reset email' });
  }
});

// POST /api/auth/reset-password/:token
app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// POST /api/auth/signup
app.post('/api/auth/signup', upload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'logoPic', maxCount: 1 }]), async (req, res) => {
  try {
    const { role, email, mobile, password, name, address, clinicHospitalName, qualification, registrationNo } = req.body;

    if (!role || !email || !mobile || !password) {
      return res.status(400).json({ error: 'Role, email, mobile, and password are required' });
    }

    if (!['Admin', 'Doctor'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    if (!req.files.profilePic) {
      return res.status(400).json({ error: 'Profile picture is required' });
    }

    const profilePic = req.files.profilePic[0].path;

    let logoPic = null;
    if (role === 'Doctor') {
      if (!req.files.logoPic) {
        return res.status(400).json({ error: 'Logo picture is required for doctors' });
      }
      logoPic = req.files.logoPic[0].path;

      if (!name || !address || !clinicHospitalName || !qualification || !registrationNo) {
        return res.status(400).json({ error: 'All doctor fields are required' });
      }
    }

    const user = new User({
      role,
      email,
      mobile,
      password,
      name: role === 'Doctor' ? name : undefined,
      address: role === 'Doctor' ? address : undefined,
      clinicHospitalName: role === 'Doctor' ? clinicHospitalName : undefined,
      qualification: role === 'Doctor' ? qualification : undefined,
      registrationNo: role === 'Doctor' ? registrationNo : undefined,
      profilePic,
      logoPic
    });

    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ user: { id: user._id, role: user.role, email: user.email, name: user.name }, token });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ user: { id: user._id, role: user.role, email: user.email, name: user.name }, token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me - Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const userData = {
    id: req.user._id,
    role: req.user.role,
    email: req.user.email,
    name: req.user.name,
    profilePic: req.user.profilePic ? `${baseUrl}/${req.user.profilePic}` : null,
    logoPic: req.user.logoPic ? `${baseUrl}/${req.user.logoPic}` : null
  };
  if (req.user.role === 'Doctor') {
    userData.clinicHospitalName = req.user.clinicHospitalName;
    userData.qualification = req.user.qualification;
    userData.registrationNo = req.user.registrationNo;
    userData.address = req.user.address;
    userData.mobile = req.user.mobile;
  }
  res.json({ user: userData });
});

// GET /api/auth/profile - Get current user profile (same as /me)
app.get('/api/auth/profile', auth, async (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const userData = {
    id: req.user._id,
    role: req.user.role,
    email: req.user.email,
    name: req.user.name,
    profilePic: req.user.profilePic ? `${baseUrl}/${req.user.profilePic}` : null,
    logoPic: req.user.logoPic ? `${baseUrl}/${req.user.logoPic}` : null
  };
  if (req.user.role === 'Doctor') {
    userData.clinicHospitalName = req.user.clinicHospitalName;
    userData.qualification = req.user.qualification;
    userData.registrationNo = req.user.registrationNo;
    userData.address = req.user.address;
    userData.mobile = req.user.mobile;
  }
  res.json({ user: userData });
});

// PUT /api/auth/profile - Update user profile
app.put('/api/auth/profile', auth, upload.fields([{ name: 'profilePic', maxCount: 1 }, { name: 'logoPic', maxCount: 1 }]), async (req, res) => {
  try {
    const { name, email, mobile, address, clinicHospitalName, qualification, registrationNo, specialty } = req.body;
    
    // Check if email is already taken by another user
    if (email && email !== req.user.email) {
      const existingUser = await User.findOne({ email: email.toLowerCase(), _id: { $ne: req.user._id } });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already exists' });
      }
    }

    // Prepare update data
    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email.toLowerCase();
    if (mobile !== undefined) updateData.mobile = mobile;
    if (address !== undefined) updateData.address = address;
    if (clinicHospitalName !== undefined) updateData.clinicHospitalName = clinicHospitalName;
    if (qualification !== undefined) updateData.qualification = qualification;
    if (registrationNo !== undefined) updateData.registrationNo = registrationNo;
    if (specialty !== undefined) updateData.specialty = specialty;

    // Handle file uploads
    if (req.files.profilePic) {
      updateData.profilePic = req.files.profilePic[0].path;
    }
    
    if (req.files.logoPic) {
      updateData.logoPic = req.files.logoPic[0].path;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true, runValidators: true }
    );

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const userData = {
      id: updatedUser._id,
      role: updatedUser.role,
      email: updatedUser.email,
      name: updatedUser.name,
      profilePic: updatedUser.profilePic ? `${baseUrl}/${updatedUser.profilePic}` : null,
      logoPic: updatedUser.logoPic ? `${baseUrl}/${updatedUser.logoPic}` : null
    };
    
    if (updatedUser.role === 'Doctor') {
      userData.clinicHospitalName = updatedUser.clinicHospitalName;
      userData.qualification = updatedUser.qualification;
      userData.registrationNo = updatedUser.registrationNo;
      userData.address = updatedUser.address;
      userData.mobile = updatedUser.mobile;
    }

    res.json({ user: userData });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Prescription routes

// GET /api/prescriptions - Get all prescriptions with optional filters
app.get('/api/prescriptions', auth, async (req, res) => {
  try {
    const { search, fromDate, toDate } = req.query;
    let query = {};

    if (req.user.role === 'Doctor') {
      query.doctorId = req.user._id;
    }

    if (search) {
      query['patientData.name'] = { $regex: search, $options: 'i' };
    }

    if (fromDate || toDate) {
      query['patientData.date'] = {};
      if (fromDate) {
        query['patientData.date'].$gte = fromDate;
      }
      if (toDate) {
        query['patientData.date'].$lte = toDate;
      }
    }

    const prescriptions = await Prescription.find(query).populate('doctorId', 'name clinicHospitalName qualification registrationNo address mobile logoPic');
    res.json(prescriptions);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch prescriptions' });
  }
});

// GET /api/prescriptions/:id - Get a single prescription
app.get('/api/prescriptions/:id', auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id).populate('doctorId', 'name clinicHospitalName qualification registrationNo address mobile logoPic');
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    if (req.user.role === 'Doctor' && prescription.doctorId._id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json(prescription);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch prescription' });
  }
});

// POST /api/prescriptions - Create a new prescription
app.post('/api/prescriptions', auth, async (req, res) => {
  try {
    if (req.user.role !== 'Doctor') {
      return res.status(403).json({ error: 'Only doctors can create prescriptions' });
    }
    const { patientData, medicines, note } = req.body;
    if (!patientData || !medicines) {
      return res.status(400).json({ error: 'Patient data and medicines are required' });
    }
    const newPrescription = new Prescription({ doctorId: req.user._id, patientData, medicines, note: note || '' });
    await newPrescription.save();
    res.status(201).json(newPrescription);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create prescription' });
  }
});

// PUT /api/prescriptions/:id - Update a prescription
app.put('/api/prescriptions/:id', auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id);
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    if (req.user.role === 'Doctor' && prescription.doctorId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const { patientData, medicines, note } = req.body;
    if (!patientData || !medicines) {
      return res.status(400).json({ error: 'Patient data and medicines are required' });
    }
    const updatedPrescription = await Prescription.findByIdAndUpdate(
      req.params.id,
      { patientData, medicines, note: note || '' },
      { new: true }
    );
    res.json(updatedPrescription);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update prescription' });
  }
});

// DELETE /api/prescriptions/:id - Delete a prescription
app.delete('/api/prescriptions/:id', auth, async (req, res) => {
  try {
    const prescription = await Prescription.findById(req.params.id);
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    if (req.user.role === 'Doctor' && prescription.doctorId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }
    await Prescription.findByIdAndDelete(req.params.id);
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete prescription' });
  }
});

// Admin routes

// GET /api/admin/users - Get all users for admin with pagination and filters
app.get('/api/admin/users', auth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const { search, role, status } = req.query;

    const baseUrl = `${req.protocol}://${req.get('host')}`;

    // Build query for filters
    let query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { mobile: { $regex: search, $options: 'i' } }
      ];
    }
    if (role && role !== 'All') {
      query.role = role;
    }
    if (status && status !== 'All') {
      query.status = status;
    }

    // Get total count for pagination (with filters applied)
    const totalUsers = await User.countDocuments(query);

    // Get paginated users with filters
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    // Transform the data to include full URLs for images
    const formattedUsers = users.map(user => ({
      id: user._id,
      role: user.role,
      email: user.email,
      name: user.name || 'N/A',
      mobile: user.mobile,
      address: user.address || 'N/A',
      clinicHospitalName: user.clinicHospitalName || 'N/A',
      qualification: user.qualification || 'N/A',
      registrationNo: user.registrationNo || 'N/A',
      profilePic: user.profilePic ? `${baseUrl}/${user.profilePic}` : null,
      logoPic: user.logoPic ? `${baseUrl}/${user.logoPic}` : null,
      status: user.status,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    }));

    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      users: formattedUsers,
      pagination: {
        currentPage: page,
        totalPages,
        totalUsers,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    });
  } catch (error) {
    console.error('Admin users fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// PUT /api/admin/users/:id - Update a user
app.put('/api/admin/users/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }

    const { name, email, mobile, role, status } = req.body;

    // Check if email is already taken by another user
    if (email) {
      const existingUser = await User.findOne({ email: email.toLowerCase(), _id: { $ne: req.params.id } });
      if (existingUser) {
        return res.status(400).json({ error: 'Email already exists' });
      }
    }

    const updateData = {};
    if (name !== undefined) updateData.name = name;
    if (email !== undefined) updateData.email = email.toLowerCase();
    if (mobile !== undefined) updateData.mobile = mobile;
    if (role !== undefined) updateData.role = role;
    if (status !== undefined) updateData.status = status;

    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const userData = {
      id: updatedUser._id,
      role: updatedUser.role,
      email: updatedUser.email,
      name: updatedUser.name || 'N/A',
      mobile: updatedUser.mobile,
      profilePic: updatedUser.profilePic ? `${baseUrl}/${updatedUser.profilePic}` : null,
      status: updatedUser.status
    };

    res.json(userData);
  } catch (error) {
    console.error('Admin user update error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// DELETE /api/admin/users/:id - Delete a user
app.delete('/api/admin/users/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Access denied. Admin role required.' });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await User.findByIdAndDelete(req.params.id);
    res.status(204).send();
  } catch (error) {
    console.error('Admin user delete error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});