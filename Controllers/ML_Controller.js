const db = new (require('../Classes/database'))();
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

// ENDPOINTS TO EXTRACT DATA FROM DATABASE

// ---------------- LAYER 2 ----------------
exports.getLayer2Data = async (req, res) => {
  try {
    const sql = `
      SELECT
        Interaction_ID,
        User_ID,
        Object_Type,
        Object_Reference_ID AS Object_ID,
        Interaction_Type,
        Interaction_Rating,
        Interaction_Timestamp AS Timestamp
      FROM Interactions
      WHERE Interaction_Type IN ('Like', 'Rate', 'View');
    `;

    const data = await db.getQuery(sql, []);
    return res.json({ success: true, data });
  } catch (err) {
    console.error('Error fetching Layer 2 data:', err);
    return res.status(500).json({ message: 'Failed to fetch Layer 2 data' });
  }
};

// ---------------- LAYER 3 ----------------
exports.getLayer3Data = async (req, res) => {
  try {
    const sql = `
      SELECT
        i.Interaction_ID,
        i.User_ID,
        i.Object_Type AS Category_Type,
        CASE i.Object_Type
            WHEN 'Star' THEN s.Star_SpType
            WHEN 'Planet' THEN p.Planet_Type
            WHEN 'Moon' THEN m.Parent_Planet_Name
        END AS Category_Value,
        CASE i.Interaction_Type
            WHEN 'Like' THEN 1
            WHEN 'Rate' THEN i.Interaction_Rating
            ELSE 0
        END AS Strength,
        i.Interaction_Timestamp AS Timestamp
      FROM Interactions i
      LEFT JOIN Stars s ON i.Object_Type='Star' AND i.Object_Reference_ID = s.Star_ID
      LEFT JOIN Planets p ON i.Object_Type='Planet' AND i.Object_Reference_ID = p.Planet_ID
      LEFT JOIN Moons m ON i.Object_Type='Moon' AND i.Object_Reference_ID = m.Moon_ID
      WHERE i.Interaction_Type IN ('Like', 'Rate');
    `;

    const data = await db.getQuery(sql, []);
    return res.json({ success: true, data });
  } catch (err) {
    console.error('Error fetching Layer 3 data:', err);
    return res.status(500).json({ message: 'Failed to fetch Layer 3 data' });
  }
};

// ---------------- LAYER 4 ----------------
exports.getLayer4Data = async (req, res) => {
  try {
    const sql = `
      SELECT
        i.Interaction_ID,
        i.User_ID,
        i.Object_Type AS Category_Type,
        CASE i.Object_Type
            WHEN 'Star' THEN s.Star_SpType
            WHEN 'Planet' THEN p.Planet_Type
            WHEN 'Moon' THEN m.Parent_Planet_Name
        END AS Category_Value,
        CASE i.Interaction_Type
            WHEN 'Like' THEN 1
            WHEN 'Rate' THEN i.Interaction_Rating
            ELSE 0
        END AS Strength,
        i.Interaction_Timestamp AS Timestamp
      FROM Interactions i
      LEFT JOIN Stars s ON i.Object_Type='Star' AND i.Object_Reference_ID = s.Star_ID
      LEFT JOIN Planets p ON i.Object_Type='Planet' AND i.Object_Reference_ID = p.Planet_ID
      LEFT JOIN Moons m ON i.Object_Type='Moon' AND i.Object_Reference_ID = m.Moon_ID
      WHERE i.Interaction_Type IN ('Like', 'Rate');
    `;

    const data = await db.getQuery(sql, []);
    return res.json({ success: true, data });
  } catch (err) {
    console.error('Error fetching Layer 4 data:', err);
    return res.status(500).json({ message: 'Failed to fetch Layer 4 data' });
  }
};

// CALLS TO RUN ML MODELS 

// ---------------- LAYER 2 : RUN MODEL ----------------
exports.runLayer2Model = async (req, res) => {
    const startedAt = new Date();
    try {
        const sql = `SELECT COUNT(*) AS count FROM Interactions WHERE Interaction_Type IN ('Like', 'Rate', 'View')`;
        const countData = await db.getQuery(sql, []);
        const dbCount = countData[0]?.count || 0;

        let mode = dbCount >= 300 ? 'run' : 'cached';
        let dataSource = mode === 'run' ? 'database' : 'fictional';

        const response = await fetch(`${process.env.ML_SERVICE_URL}/run-layer/2`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${process.env.HF_TOKEN}`,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ mode: mode })
        });

        const mlResult = await response.json();

        if (!response.ok || mlResult.status === 'error') {
            const errorMsg = mlResult.message || mlResult.trace || "HF Error";
            if (res) {
                return res.status(500).json({ success: false, cloudError: errorMsg });
            }
            throw new Error(errorMsg);
        }

        const finalData = mlResult.data || [];

        // ✨ HYBRID CHECK: If res is null, return raw data for Engine. If not, send JSON.
        if (res) {
            return res.json({
                success: true,
                dataSource,
                dbCount,
                totalRowsProcessed: mlResult.total_rows || 0,
                startedAt,
                finishedAt: new Date(),
                rows: finalData.length,
                data: finalData 
            });
        }
        return finalData; 

    } catch (err) {
        console.error('Layer 2 Cloud Trigger failed:', err);
        if (res) return res.status(500).json({ success: false, error: err.message });
        throw err;
    }
};

// ---------------- LAYER 3 : RUN MASTER MODEL ----------------
exports.runLayer3Model = async (req, res) => {
    const startedAt = new Date();
    try {
        const sql = `SELECT COUNT(*) AS count FROM Interactions WHERE Interaction_Type IN ('Like', 'Rate')`;
        const countData = await db.getQuery(sql, []);
        const dbCount = countData[0]?.count || 0;

        let mode = dbCount >= 500 ? 'run' : 'cached';
        let dataSource = mode === 'run' ? 'database' : 'fictional';

        const response = await fetch(`${process.env.ML_SERVICE_URL}/run-layer/3`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${process.env.HF_TOKEN}`,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ mode: mode })
        });

        const mlResult = await response.json();
        if (!response.ok || mlResult.status === 'error') {
            const errorMsg = mlResult.trace || "HF Error";
            if (res) return res.status(500).json({ success: false, error: errorMsg });
            throw new Error(errorMsg);
        }

        const finalData = mlResult.data || [];

        if (res) {
            return res.json({
                success: true,
                dataSource,
                dbCount,
                totalRowsProcessed: mlResult.total_rows || 0,
                startedAt,
                finishedAt: new Date(),
                rows: finalData.length,
                data: finalData 
            });
        }
        return finalData;

    } catch (err) {
        if (res) return res.status(500).json({ success: false, error: err.message });
        throw err;
    }
};

// ---------------- LAYER 4 : RUN MASTER NN MODEL ----------------
exports.runLayer4Model = async (req, res) => {
    const startedAt = new Date();
    try {
        const sql = `SELECT COUNT(*) AS count FROM Interactions WHERE Interaction_Type IN ('Like', 'Rate')`;
        const countData = await db.getQuery(sql, []);
        const dbCount = countData[0]?.count || 0;

        let mode = dbCount >= 500 ? 'run' : 'cached';
        let dataSource = mode === 'run' ? 'database' : 'fictional';

        const response = await fetch(`${process.env.ML_SERVICE_URL}/run-layer/4`, {
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${process.env.HF_TOKEN}`,
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ mode: mode })
        });

        const mlResult = await response.json();
        if (!response.ok || mlResult.status === 'error') {
            const errorMsg = mlResult.trace || "HF Error";
            if (res) return res.status(500).json({ success: false, error: errorMsg });
            throw new Error(errorMsg);
        }

        const finalData = mlResult.data || [];

        if (res) {
            return res.json({
                success: true,
                dataSource,
                dbCount,
                totalRowsProcessed: mlResult.total_rows || 0,
                startedAt,
                finishedAt: new Date(),
                rows: finalData.length,
                data: finalData 
            });
        }
        return finalData;

    } catch (err) {
        if (res) return res.status(500).json({ success: false, error: err.message });
        throw err;
    }
};

// --- UPDATED HELPER: Now handles internal calls ---
function returnCsvAsJson(csvPath, dataSource, startedAt, res, meta = {}) {
    if (!fs.existsSync(csvPath)) {
        if (res) return res.status(404).json({ success: false, error: "CSV not found" });
        return []; // Return empty array for internal engine call
    }

    const csvRaw = fs.readFileSync(csvPath, 'utf8');
    const lines = csvRaw.trim().split('\n');
    if (lines.length < 2) return res ? res.json({ success: true, data: [] }) : [];

    const headers = lines[0].split(',');
    const data = lines.slice(1).map(line => {
        const values = line.split(',');
        const obj = {};
        headers.forEach((h, i) => (obj[h.trim()] = values[i]?.trim()));
        return obj;
    });

    // ✨ THE FORK: If 'res' exists, send to web. If not, return to Engine Controller.
    if (res) {
        return res.json({
            success: true,
            dataSource,
            dbCount: meta.dbCount,
            totalRowsProcessed: meta.totalRowsProcessed,
            startedAt,
            finishedAt: new Date(),
            rows: data.length,
            data
        });
    } else {
        return data; 
    }
}