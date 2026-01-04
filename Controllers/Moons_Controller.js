const db = new (require('../Classes/database'))();

// ---------------- GET MOON BY ID ----------------
exports.getMoonById = async (req, res) => {
  try {
    const moonId = req.params.id;
    if (!moonId) return res.status(400).json({ message: 'Moon ID required' });

    const moon = await db.getQuery(
      `SELECT
         Moon_ID,
         Moon_Name,
         Parent_Planet_ID,
         Parent_Planet_Name,
         Moon_Color,
         Moon_Diameter,
         Moon_Mass,
         Moon_Orbital_Period,
         Moon_SemiMajorAxisKm,
         Moon_Inclination,
         Moon_Surface_Temperature,
         Moon_Composition,
         Moon_Surface_Features,
         Moon_Distance_From_Earth
       FROM Moons
       WHERE Moon_ID = ?`,
      [moonId]
    );

    if (!moon.length) return res.status(404).json({ message: 'Moon not found' });

    return res.json({ moon: moon[0] });
  } catch (err) {
    console.error('Error fetching moon:', err);
    return res.status(500).json({ message: 'Failed to fetch moon' });
  }
};

// ---------------- GET MOON ENCYCLOPEDIA (PAGINATED) ----------------
exports.getMoonEncyclopedia = async (req, res) => {
  try {
    let limit = parseInt(req.query.limit) || 50;
    limit = Math.min(Math.max(limit, 1), 200);

    let offset = parseInt(req.query.offset) || 0;
    offset = Math.max(offset, 0);

    const parentPlanetId = req.query.planetId ? parseInt(req.query.planetId) : null;

    let query = `
      SELECT
        Moon_ID,
        Moon_Name,
        Parent_Planet_ID,
        Parent_Planet_Name,
        Moon_Color,
        Moon_Diameter,
        Moon_Mass
      FROM Moons
    `;

    const params = [];
    if (parentPlanetId) {
      query += ` WHERE Parent_Planet_ID = ?`;
      params.push(parentPlanetId);
    }

    query += ` ORDER BY Moon_ID LIMIT ${limit} OFFSET ${offset}`;

    const moons = await db.getQuery(query, params);

    return res.json({
      moons,
      limit,
      offset,
      count: moons.length
    });
  } catch (err) {
    console.error('Error fetching moon encyclopedia:', err);
    return res.status(500).json({ message: 'Failed to fetch moon encyclopedia' });
  }
};
