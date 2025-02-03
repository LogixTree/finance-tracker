const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Setup Express app
const app = express();
app.use(express.json());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/role_permission_demo', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.log('MongoDB connection error: ', err);
});

// Permission Model
const PermissionSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  description: {
    type: String,
    required: true
  }
});

const Permission = mongoose.model('Permission', PermissionSchema);

// Role Model
const RoleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }]
});

const Role = mongoose.model('Role', RoleSchema);

// User Model
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }
});

// Encrypt password before saving user
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  
  next();
});

const User = mongoose.model('User', UserSchema);

// Middleware to check if user has permission
async function checkPermission(permissionName) {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id).populate('role');
      if (!user) return res.status(404).json({ message: 'User not found' });

      const role = user.role;
      const permission = await Permission.findOne({ name: permissionName });
      if (!role.permissions.includes(permission._id)) {
        return res.status(403).json({ message: 'Forbidden: You do not have permission to perform this action' });
      }

      next();
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server Error' });
    }
  };
}

// JWT Authentication Middleware
async function authenticateToken(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const decoded = jwt.verify(token, 'secretKey');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(400).json({ message: 'Invalid Token' });
  }
}

// Create a permission
app.post('/permissions', async (req, res) => {
  const { name, description } = req.body;
  try {
    const permission = new Permission({ name, description });
    await permission.save();
    res.status(201).json(permission);
  } catch (err) {
    res.status(400).json({ message: 'Error creating permission', error: err });
  }
});

// Create a role
app.post('/roles', async (req, res) => {
  const { name, permissions } = req.body;
  try {
    const role = new Role({ name, permissions });
    await role.save();
    res.status(201).json(role);
  } catch (err) {
    res.status(400).json({ message: 'Error creating role', error: err });
  }
});

// Create a user
app.post('/users', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const user = new User({ username, password, role });
    await user.save();
    res.status(201).json(user);
  } catch (err) {
    res.status(400).json({ message: 'Error creating user', error: err });
  }
});

// Login to get a token
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username }).populate('role');
  if (!user) return res.status(400).json({ message: 'Invalid username or password' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid username or password' });

  const token = jwt.sign({ id: user._id }, 'secretKey', { expiresIn: '1h' });
  res.json({ token });
});

// Example route with permission check
app.get('/restricted', authenticateToken, checkPermission('view_dashboard'), (req, res) => {
  res.status(200).json({ message: 'You have access to this page' });
});

// Start the server
const port = 5000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

