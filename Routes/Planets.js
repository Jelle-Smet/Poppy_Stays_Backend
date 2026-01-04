const express = require('express');
const router = express.Router();
const planetsController = require('../Controllers/Planets_Controller');
const { protect } = require('../Middleware/Auth');

// ---------------- PLANET ENCYCLOPEDIA ----------------
router.get('/encyclopedia', protect, planetsController.getPlanetEncyclopedia);

// ---------------- PLANET DETAIL ----------------
router.get('/:id', protect, planetsController.getPlanetById);

module.exports = router;
