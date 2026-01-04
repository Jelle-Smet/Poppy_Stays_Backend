const express = require('express');
const router = express.Router();
const starsController = require('../Controllers/Stars_Controller');
const { protect } = require('../Middleware/Auth');

// ---------------- ENCYCLOPEDIA ----------------
router.get('/encyclopedia',protect, starsController.getStarEncyclopedia);

// ---------------- USER STARS ----------------
router.get('/mystars', protect, starsController.getMyStars);

// ---------------- STAR Owners ----------------
router.get('/owned_stars', protect, starsController.getOwnedStars);

// ---------------- STAR DETAIL ----------------
router.get('/:id', protect, starsController.getStarById);

// ---------------- STAR Purhcase ----------------
router.post('/purchase/:id', protect, starsController.claimStar);

module.exports = router;
