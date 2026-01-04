const express = require('express');
const router = express.Router();
const statusController = require('../Controllers/Status_Controller');

router.get('/', statusController.getSystemStatus);

module.exports = router;