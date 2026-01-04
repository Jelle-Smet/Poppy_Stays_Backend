// Routes/Users.js
const express = require('express');
const router = express.Router();

const userController = require('../Controllers/Users_Controller');
const { protect } = require('../Middleware/Auth'); // Importing 'protect'

// Public auth routes (No token needed)
router.post('/signup', userController.signup);
router.post('/login', userController.login);

// Protected routes (Token IS needed)
// Use 'protect' here so req.userId is defined for the controller
router.put('/update-profile', protect, userController.updateProfile);
router.get('/account', protect, userController.getAccountDetails);

module.exports = router;