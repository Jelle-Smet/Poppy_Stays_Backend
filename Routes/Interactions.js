const express = require('express');
const router = express.Router();
const interactionsController = require('../Controllers/Interactions_Controller');
const { protect } = require('../Middleware/Auth');

// Protected routes
router.post('/rate', protect, interactionsController.rateObject);
router.post('/like', protect, interactionsController.likeObject);
router.get('/user-interactions', protect, interactionsController.getUserInteractions)

module.exports = router;
