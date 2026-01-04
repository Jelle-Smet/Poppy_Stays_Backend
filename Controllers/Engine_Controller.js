const db = new (require('../Classes/database'))();
const mlController = require('./ML_Controller');
const path = require('path');
const { spawn } = require('child_process');

/**
 * 🌌 GET CELESTIAL POOL
 * Fetches 2000 random stars (filtered for 100% complete data), all planets, and all moons.
 */
exports.getCelestialPool = async (req, res) => { 
    try {
        // 1️⃣ Query Stars: Applying your dynamic "Complete Stars" logic
        // This ensures every star has all values for the C# engine to work with.
        const starSql = `
            SELECT 
                Star_ID AS Id, 
                Star_Name AS Name, 
                Star_Source AS Source, 
                Star_RA AS RA_ICRS, 
                Star_DE AS DE_ICRS, 
                Star_GMag AS Gmag, 
                Star_BPMag AS BPmag, 
                Star_RPMag AS RPmag, 
                NULL AS Parallax, 
                Star_SpType AS SpectralType, 
                Star_Teff AS Teff, 
                Star_Luminosity AS Luminosity, 
                Star_Mass AS Mass, 
                NULL AS IsBinary, 
                NULL AS HasPlanetCandidates
            FROM Stars
            WHERE 
                -- String columns MUST NOT BE NULL
                Star_Name IS NOT NULL AND 
                Star_Source IS NOT NULL AND 
                Star_SpType IS NOT NULL AND
                -- Numeric columns MUST NOT BE NULL (replicating your COLUMN = COLUMN logic)
                Star_RA = Star_RA AND 
                Star_DE = Star_DE AND 
                Star_GMag = Star_GMag AND
                Star_BPMag = Star_BPMag AND
                Star_RPMag = Star_RPMag AND
                Star_Teff = Star_Teff AND
                Star_Luminosity = Star_Luminosity AND
                Star_Mass = Star_Mass AND
                -- Brightness threshold
                Star_GMag < 12
            ORDER BY RAND() 
            LIMIT 2000`;

        // 2️⃣ Query Planets: Mapping exactly to your Planet_Objects.cs
        const planetSql = `
            SELECT 
                Planet_ID AS Id, 
                Planet_Name AS Name, 
                Planet_Type AS Type, 
                Planet_Color AS Color, 
                Planet_Distance_From_Sun AS DistanceFromSun, 
                Planet_Distance_From_Earth AS DistanceFromEarth, 
                Planet_Diameter AS Diameter, 
                Planet_Mass AS Mass, 
                Planet_Mean_Temperature AS MeanTemperature, 
                Planet_Number_of_Moons AS NumberOfMoons, 
                Planet_Has_Rings AS HasRings, 
                Planet_Has_Magnetic_Field AS HasMagneticField, 
                Planet_Magnitude AS Magnitude, 
                Planet_SemiMajorAxisAU AS SemiMajorAxis, 
                NULL AS Eccentricity,
                Planet_Orbital_Inclination AS OrbitalInclination, 
                Planet_Longitude_Ascending_Node AS LongitudeOfAscendingNode, 
                Planet_Argument_Periapsis AS ArgumentOfPeriapsis, 
                Planet_Mean_Anomaly AS MeanAnomalyAtEpoch, 
                NULL AS MeanMotion, 
                Planet_Orbital_Period AS OrbitalPeriod
            FROM Planets`;

        // 3️⃣ Query Moons: Mapping exactly to your Moon_Objects.cs
        const moonSql = `
            SELECT 
                Moon_ID AS Id, 
                Moon_Name AS Name, 
                Parent_Planet_Name AS Parent, 
                Moon_Color AS Color, 
                Moon_Diameter AS Diameter, 
                Moon_Mass AS Mass, 
                Moon_Surface_Temperature AS SurfaceTemperature, 
                Moon_Composition AS Composition, 
                Moon_Surface_Features AS SurfaceFeatures, 
                NULL AS Magnitude, 
                Moon_Distance_From_Earth AS DistanceFromEarth, 
                NULL AS Density, 
                NULL AS SurfaceGravity, 
                NULL AS EscapeVelocity, 
                NULL AS RotationPeriod, 
                NULL AS NumberOfRings, 
                Moon_SemiMajorAxisKm AS SemiMajorAxisKm, 
                NULL AS Eccentricity, 
                Moon_Inclination AS Inclination, 
                NULL AS LongitudeOfAscendingNode, 
                NULL AS ArgumentOfPeriapsis, 
                NULL AS MeanAnomalyAtEpoch, 
                NULL AS MeanMotion, 
                Moon_Orbital_Period AS OrbitalPeriod
            FROM Moons`;

        // Run all queries simultaneously
        const [stars, planets, moons] = await Promise.all([
            db.getQuery(starSql),
            db.getQuery(planetSql),
            db.getQuery(moonSql)
        ]);

        const pool = {
            Stars: stars,
            Planets: planets,
            Moons: moons
        };

        if (res) {
            return res.json({
                success: true,
                count: { stars: stars.length, planets: planets.length, moons: moons.length },
                data: pool
            });
        }
        return { success: true, data: pool };

    } catch (err) {
        console.error("Celestial Pool Error:", err);
        if (res) res.status(500).json({ success: false, error: "Failed to gather celestial data pool." });
    }
};

exports.getUserConfig = async (req, res) => {
    // 🛡️ SECURITY CHECK: Ensure the middleware actually caught the ID
    const userId = req.userId; 

    if (!userId) {
        return res.status(401).json({ success: false, message: "Unauthorized: No explorer ID found." });
    }

    // Capture location/time from body (sent by Postman or Frontend)
    const { 
        latitude = 51.016, 
        longitude = 4.242, 
        observationTime = new Date().toISOString() 
    } = req.body; 

    try {
        // 1️⃣ Fetch Basic User Info (Using your specific column names like User_Name)
        const userRows = await db.getQuery(
            "SELECT User_ID, User_Name FROM Users WHERE User_ID = ?", 
            [userId]
        );
        
        if (userRows.length === 0) {
            return res.status(404).json({ success: false, message: "Explorer not found." });
        }

        // 2️⃣ Fetch 'Liked_Objects' (Updating the table name and joins)
        const likesSql = `
            SELECT lo.Object_Type, 
                   CASE 
                     WHEN lo.Object_Type = 'Star' THEN s.Star_Name
                     WHEN lo.Object_Type = 'Planet' THEN p.Planet_Name
                     WHEN lo.Object_Type = 'Moon' THEN m.Moon_Name
                   END AS Name
            FROM Liked_Objects lo
            LEFT JOIN Stars s ON lo.Object_Type = 'Star' AND lo.Object_Reference_ID = s.Star_ID
            LEFT JOIN Planets p ON lo.Object_Type = 'Planet' AND lo.Object_Reference_ID = p.Planet_ID
            LEFT JOIN Moons m ON lo.Object_Type = 'Moon' AND lo.Object_Reference_ID = m.Moon_ID
            WHERE lo.User_ID = ?
        `;
        const likeRows = await db.getQuery(likesSql, [userId]);

        // 3️⃣ Format for C#
        const userConfig = {
            ID: userId,
            Name: userRows[0].User_Name,
            Latitude: parseFloat(latitude),
            Longitude: parseFloat(longitude),
            ObservationTime: observationTime,
            LikedStars: likeRows.filter(l => l.Object_Type === 'Star').map(l => l.Name),
            LikedPlanets: likeRows.filter(l => l.Object_Type === 'Planet').map(l => l.Name),
            LikedMoons: likeRows.filter(l => l.Object_Type === 'Moon').map(l => l.Name)
        };

        if (res) {
            return res.json({ success: true, data: userConfig });
        } else {
            return { success: true, data: userConfig };
        }

    } catch (err) {
        console.error("User Config Fetch Error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
};

/**
 * 📈 GET LAYER 2 (TRENDING)
 */
exports.getLayer2Data = async (req, res) => {
    try {
        // Pass null for req and res to mlController to trigger internal return
        const trendingData = await mlController.runLayer2Model(null, null);
        
        // ✨ THE FIX: Only call .json() if 'res' actually exists!
        if (res) {
            return res.json({
                success: true,
                source: "ML_Controller_Internal",
                count: trendingData?.length || 0,
                data: trendingData
            });
        }

        // If res is null, we just return the data object so executeEngine can use it
        return { success: true, data: trendingData };

    } catch (err) {
        console.error("Layer 2 Engine Call Error:", err);
        if (res) {
            return res.status(500).json({ success: false, error: err.message });
        }
        throw err; // Throw so executeEngine knows something went wrong
    }
};

/**
 * 🧬 GET LAYER 3 (COLLABORATIVE FILTERING)
 * Updated to be "Hybrid" so it doesn't crash the engine.
 */
exports.getLayer3Data = async (req, res) => {
    try {
        // 1. Handle both ID-only calls and standard req/res calls
        // If 'req' is just an ID string/number, use it. Otherwise, look for req.userId.
        const userId = (typeof req !== 'object') ? req : (req.userId || req.body?.userId);

        if (!userId) {
            throw new Error("User ID is required for Layer 3 personalization.");
        }

        // 2. Run the model
        const l3Data = await mlController.runLayer3Model(userId, null);
        
        // ✨ THE HYBRID CHECK: Only call .json() if 'res' actually exists!
        if (res) {
            return res.json({
                success: true,
                count: l3Data?.length || 0,
                data: l3Data
            });
        }

        // 3. Internal Return: If res is null, we just return the data object
        // This is what executeEngine will receive.
        return { success: true, data: l3Data };

    } catch (err) {
        console.error("Layer 3 Engine Call Error:", err);
        
        // Only try to use res.status if res exists
        if (res) {
            return res.status(500).json({ success: false, error: err.message });
        }
        
        // Throw so executeEngine's try/catch can handle it
        throw err; 
    }
};

/**
 * 🧠 GET LAYER 4 (NEURAL NETWORK)
 * Hybrid function: Works for both direct API calls and Engine execution.
 */
exports.getLayer4Data = async (req, res) => {
    try {
        // Handle ID-only calls from the engine vs standard req/res calls
        const userId = (typeof req !== 'object') ? req : (req.userId || req.body?.userId);

        if (!userId) {
            throw new Error("User ID is required for Layer 4 NN personalization.");
        }

        const l4Data = await mlController.runLayer4Model(userId, null);
        
        // If called by the browser/Postman
        if (res) {
            return res.json({
                success: true,
                count: l4Data?.length || 0,
                data: l4Data
            });
        }

        // If called internally by executeEngine
        return { success: true, data: l4Data };

    } catch (err) {
        console.error("Layer 4 Engine Call Error:", err);
        if (res) return res.status(500).json({ success: false, error: err.message });
        throw err;
    }
};


// --------------------------------------
// Run Engine Endpoints (Cloud Version)
// --------------------------------------

// Helper to safely extract only the number from a string like "2.5%" or "Boosted: 10"
const safeParseFloat = (val) => {
    if (!val) return 0;
    const match = String(val).match(/[-+]?([0-9]*\.[0-9]+|[0-9]+)/);
    return match ? parseFloat(match[0]) : 0;
};

// ═══════════════════════════════════════════════════════════════
// 🛠️ MAPPING HELPERS (Flattens C# nested data into clean JSON)
// ═══════════════════════════════════════════════════════════════

const mapStarResult = (s) => {
    // ✨ FIX: Check for lowercase 'layer5_FinalRank'
    const isL5 = s.layer5_FinalRank !== undefined; 
    return {
        Star_ID: isL5 ? s.object_ID : s.star?.id,
        Star_Name: isL5 ? s.object_Name : s.star?.name,
        Star_SpType: isL5 ? s.spectralType : s.star?.spectralType,
        Altitude: s.altitude,
        Azimuth: s.azimuth,
        Is_Visible: s.isVisible,
        Match_Score: isL5 ? s.layer5_FinalScore : s.score,
        Match_Percentage: s.matchPercentage,
        GA_Rank: isL5 ? s.layer5_FinalRank + 1 : null,
        Rank_Summary: isL5 ? s.gaSummary : "Standard Ranking",
        Boost_Amount_Pct: isL5 ? 0 : safeParseFloat(s.boostDescription),
        Weather_Visibility_Chance: s.visibilityChance,
        Weather_Explanation: s.chanceReason
    };
};

const mapPlanetResult = (p) => {
    const isL5 = p.layer5_FinalRank !== undefined;
    return {
        Planet_ID: isL5 ? p.object_ID : p.planet?.id,
        Planet_Name: isL5 ? p.object_Name : p.planet?.name,
        Planet_Type: isL5 ? p.type : p.planet?.type,
        Altitude: p.altitude,
        Azimuth: p.azimuth,
        Is_Visible: p.isVisible,
        Match_Score: isL5 ? p.layer5_FinalScore : p.score,
        Match_Percentage: p.matchPercentage,
        GA_Rank: isL5 ? p.layer5_FinalRank + 1 : null,
        Rank_Summary: isL5 ? p.gaSummary : "Standard Ranking",
        Boost_Amount_Pct: isL5 ? 0 : safeParseFloat(p.boostDescription),
        Weather_Visibility_Chance: p.visibilityChance,
        Weather_Explanation: p.chanceReason
    };
};

const mapMoonResult = (m) => {
    const isL5 = m.layer5_FinalRank !== undefined;
    return {
        Moon_ID: isL5 ? m.object_ID : m.moon?.id,
        Moon_Name: isL5 ? m.object_Name : m.moon?.name,
        Parent_Planet: m.parent,
        Altitude: m.altitude,
        Azimuth: m.azimuth,
        Is_Visible: m.isVisible,
        Match_Score: isL5 ? m.layer5_FinalScore : m.score,
        Match_Percentage: m.matchPercentage,
        GA_Rank: isL5 ? m.layer5_FinalRank + 1 : null,
        Rank_Summary: isL5 ? m.gaSummary : "Standard Ranking",
        Boost_Amount_Pct: isL5 ? 0 : safeParseFloat(m.boostDescription),
        Weather_Visibility_Chance: m.visibilityChance,
        Weather_Explanation: m.chanceReason
    };
};

// ═══════════════════════════════════════════════════════════════
// 🌌 THE MASTER ENGINE EXECUTOR
// ═══════════════════════════════════════════════════════════════

/**
 * 🚀 MASTER ENGINE EXECUTOR (Cloud Edition)
 */
const executeEngine = async (req, res, layers = { l2: false, l3: false, l4: false, l5: false }) => {
    try {
        // 1️⃣ Gather Base Data
        const poolData = await exports.getCelestialPool(null, null); 
        const userConfig = await exports.getUserConfig(req, null); 

        const userId = userConfig.data?.ID;
        if (!userId) {
            return res.status(401).json({ success: false, message: "Unauthorized: No explorer ID found." });
        }

        // 2️⃣ Build Payload Shell
        const enginePayload = {
            User: userConfig.data,
            Pool: poolData.data,
            Config: layers, 
            Layer2Data: null,
            Layer3Data: null,
            Layer4Data: null 
        };

        // Populate optional layers
        if (layers.l2) {
            const trendingResponse = await exports.getLayer2Data(null, null);
            enginePayload.Layer2Data = trendingResponse.data;
        }

        if (layers.l3) {
            const matrixResponse = await exports.getLayer3Data(userId);
            enginePayload.Layer3Data = Array.isArray(matrixResponse.data) 
                ? matrixResponse.data[0] 
                : matrixResponse.data;
        }

        if (layers.l4) {
            const historyResponse = await exports.getLayer4Data(userId);
            enginePayload.Layer4Data = Array.isArray(historyResponse.data) 
                ? historyResponse.data[0] 
                : historyResponse.data;
        }

        // 3️⃣ Send to Cloud C# Engine via HTTP POST
        // Make sure ENGINE_URL is in your .env (e.g., https://poppy-engine.onrender.com)
        const cloudUrl = `${process.env.ENGINE_URL}/run-engine`;
        console.log(`🌐 Dispatching payload to Cloud Engine: ${cloudUrl}`);

        const response = await fetch(cloudUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(enginePayload)
        });

        if (!response.ok) {
            const errorMsg = await response.text();
            throw new Error(`Cloud Engine returned error: ${errorMsg}`);
        }

        // 4️⃣ Receive Results
        const rawResults = await response.json();

        // 5️⃣ Map and Return (Using lowercase property names from C# JSON)
        return res.json({
            success: true,
            active_layers: layers,
            results: {
                // Change rawResults.Stars -> rawResults.stars
                Stars: (rawResults.stars || []).map(mapStarResult),
                Planets: (rawResults.planets || []).map(mapPlanetResult),
                Moons: (rawResults.moons || []).map(mapMoonResult)
            }
        });

    } catch (err) {
        console.error("❌ CLOUD ENGINE EXECUTION FAILED:", err);
        if (!res.headersSent) {
            res.status(500).json({ success: false, error: err.message });
        }
    }
};

// ═══════════════════════════════════════════════════════════════
// 🌟 THE ENDPOINTS
// ═══════════════════════════════════════════════════════════════

exports.runLayer1Full = async (req, res) => {
    return executeEngine(req, res, { l2: false, l3: false, l4: false, l5: false });
};

exports.runLayer1And2 = async (req, res) => {
    return executeEngine(req, res, { l2: true, l3: false, l4: false, l5: false });
};

exports.runLayer1And3 = async (req, res) => {
    return executeEngine(req, res, { l2: false, l3: true, l4: false, l5: false });
};

exports.runLayer1And4 = async (req, res) => {
    return executeEngine(req, res, { l2: false, l3: false, l4: true, l5: false });
};

exports.runFullUniverseOptimization = async (req, res) => {
    return executeEngine(req, res, { l2: true, l3: true, l4: true, l5: true });
};