const express = require('express');
const router = express.Router();
const mlController = require('../Controllers/ML_Controller');
const { protect } = require('../Middleware/Auth'); // 1. Import your auth middleware

// Layer 2
router.post('/layer2/data', protect, mlController.getLayer2Data);
router.post('/layer2/run', protect, mlController.runLayer2Model);

// Layer 3
router.post('/layer3/data', protect, mlController.getLayer3Data);
router.post('/layer3/run', protect, mlController.runLayer3Model);

// Layer 4
router.post('/layer4/data', protect, mlController.getLayer4Data);
router.post('/layer4/run', protect, mlController.runLayer4Model);

module.exports = router;
