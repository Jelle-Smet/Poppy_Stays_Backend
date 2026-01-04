const express = require('express');
const router = express.Router();
const Object_Controller = require('../Controllers/Object_Controller');
const { protect } = require('../Middleware/Auth'); // 1. Import your auth middleware

// 🌌 This one stays public (no protect needed)
router.get('/pool', protect, Object_Controller.getCelestialPool); 

module.exports = router;