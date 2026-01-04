const express = require('express');
const router = express.Router();
const engineController = require('../Controllers/Engine_Controller');
const { protect } = require('../Middleware/Auth'); // 1. Import your auth middleware

// 🌌 This one stays public (no protect needed)
router.get('/pool', protect, engineController.getCelestialPool); 

// 👤 This one NEEDS protect to populate req.userId
router.post('/user', protect, engineController.getUserConfig); 

// ML Data Probes
router.get('/l2', protect, engineController.getLayer2Data);
router.get('/l3', protect, engineController.getLayer3Data);
router.get('/l4', protect, engineController.getLayer4Data);

// runners
// Layer 1
router.post('/run-l1', protect, engineController.runLayer1Full);
// Layer 1 + Layer 2
router.post('/run-l1-l2', protect, engineController.runLayer1And2);
// Layer 1 + Layer 3
router.post('/run-l1-l3', protect, engineController.runLayer1And3);
// Layer 1 + Layer 4
router.post('/run-l1-l4', protect, engineController.runLayer1And4);
// Layer 1 --> 5
router.post('/run-l1-l5', protect, engineController.runFullUniverseOptimization);


module.exports = router;