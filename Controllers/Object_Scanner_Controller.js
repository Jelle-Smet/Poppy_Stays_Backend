const db = new (require('../Classes/database'))();
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