const express = require('express');
const router = express.Router();
const maintenanceController = require('../Controllers/Maintenance_Controller');

// 💓 Heartbeat: Keeps the DB, Engine, and ML models awake
// We leave this unprotected so UptimeRobot can hit it easily
router.get('/heartbeat', maintenanceController.keepUniverseAlive);

module.exports = router;