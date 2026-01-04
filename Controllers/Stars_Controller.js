// Stars_Controller.js
const db = new (require('../Classes/database'))();

// ---------------- GET MY STARS ----------------
const getMyStars = async (req, res) => {
  try {
    const ownerId = req.userId; // use req.userId from your Auth middleware
    if (!ownerId) return res.status(401).json({ message: 'Not authenticated' });

    const stars = await db.getQuery(
      `SELECT Star_ID, Star_Name, Star_Source, Star_RA, Star_DE, Star_Distance,
              Star_SpType, Star_Luminosity, Star_Mass, Star_Age, Star_RV_Category
       FROM Stars
       WHERE Owner_ID = ?`,
      [ownerId]
    );

    return res.json({ stars });
  } catch (err) {
    console.error('Error fetching stars:', err);
    return res.status(500).json({ message: 'Failed to fetch stars' });
  }
};

// ---------------- GET STAR BY ID ----------------
const getStarById = async (req, res) => {
  try {
    const starId = req.params.id;
    if (!starId) return res.status(400).json({ message: 'Star ID required' });

    const star = await db.getQuery(
      `SELECT s.Star_ID, s.Star_Name, s.Star_Source, s.Star_RA, s.Star_DE, s.Star_Distance,
              s.Star_GMag, s.Star_BPMag, s.Star_RPMag, s.Star_Teff, s.Star_LogG, s.Star_FeH,
              s.Star_Radius, s.Star_Luminosity, s.Star_Mass, s.Star_Age, s.Star_SpType,
              s.Star_RV_Category, s.Star_Evol_Category,
              u.User_Name, u.User_FN, u.User_LN
       FROM Stars s
       LEFT JOIN Users u ON s.Owner_ID = u.User_ID
       WHERE s.Star_ID = ?`,
      [starId]
    );

    if (!star.length) return res.status(404).json({ message: 'Star not found' });

    const starData = star[0];
    const ownerName = starData.first_name && starData.last_name 
                      ? `${starData.first_name} ${starData.last_name}` 
                      : starData.username;

    return res.json({ star: starData, owner: ownerName });
  } catch (err) {
    console.error('Error fetching star:', err);
    return res.status(500).json({ message: 'Failed to fetch star' });
  }
};

// ---------------- GET STAR ENCYCLOPEDIA (PAGINATED) ----------------
const getStarEncyclopedia = async (req, res) => {
  try {
    // Parse and sanitize params
    let limit = parseInt(req.query.limit) || 50;
    limit = Math.min(Math.max(limit, 1), 200); // between 1 and 200

    let offset = parseInt(req.query.offset) || 0;
    offset = Math.max(offset, 0); // cannot be negative

    const typeFilter = req.query.type || null; // optional: O, B, A, ...
    const randomize = req.query.random === 'true'; // optional: true/false

    // build query
    let query = `
      SELECT 
        s.Star_ID,
        s.Star_Name,
        s.Star_Source,
        s.Star_SpType,
        s.Star_Evol_Category,
        s.Star_Age,
        s.Star_Teff,
        s.Star_Luminosity,
        s.Star_Mass,
        s.Star_Radius,
        s.Star_Distance
      FROM Stars s
    `;

    const params = [];

    if (typeFilter) {
      query += ` WHERE s.Star_SpType = ?`;
      params.push(typeFilter);
    }

    if (randomize) {
      query += ` ORDER BY RAND()`;
    } else {
      query += ` ORDER BY s.Star_ID`;
    }

    // Interpolate limit and offset directly (can't be parameterized)
    query += ` LIMIT ${limit} OFFSET ${offset}`;

    // run query
    const stars = await db.getQuery(query, params);

    return res.json({
      stars,
      limit,
      offset,
      count: stars.length
    });

  } catch (err) {
    console.error('Error fetching star encyclopedia:', err);
    return res.status(500).json({ message: 'Failed to fetch star encyclopedia' });
  }
};

// starsController.js
const claimStar = async (req, res) => {
  try {
    const starId = req.params.id;
    
    // MATCHING YOUR PATTERN: Use req.userId
    const userId = req.userId; 

    if (!userId) {
      return res.status(401).json({ message: "User authentication failed." });
    }

    // 1. Fetch the star to check ownership
    const checkQuery = "SELECT Owner_ID FROM Stars WHERE Star_ID = ?";
    const results = await db.getQuery(checkQuery, [starId]);

    if (results.length === 0) return res.status(404).json({ message: "Star not found." });

    // 2. Prevent buying if owner already exists
    if (results[0].Owner_ID !== null) {
      return res.status(400).json({ message: "This celestial body is already claimed." });
    }

    // 3. Update the owner
    const updateQuery = "UPDATE Stars SET Owner_ID = ? WHERE Star_ID = ?";
    await db.getQuery(updateQuery, [userId, starId]);

    return res.json({ message: "Ownership confirmed." });
  } catch (err) {
    console.error('Error claiming star:', err);
    return res.status(500).json({ message: "Registry update failed." });
  }
};

// ---------------- GET STARS WITH OWNERS (PROTECTED) ----------------
const getOwnedStars = async (req, res) => {
  try {
    const query = `
      SELECT 
        s.Star_ID, 
        s.Star_Name, 
        s.Star_SpType, 
        s.Star_Distance, 
        s.Star_Luminosity,
        u.User_Name,  /* Confirmed column name */
        u.User_FN, 
        u.User_LN
      FROM Stars s
      INNER JOIN Users u ON s.Owner_ID = u.User_ID
      WHERE s.Owner_ID IS NOT NULL
        AND s.Star_Name IS NOT NULL
      ORDER BY s.Star_ID DESC 
      LIMIT 50`; 

    const ownedStars = await db.getQuery(query);

    // This helps you see in your deployment logs if the DB actually found rows
    console.log(`Query executed. Rows found: ${ownedStars.length}`);

    const formattedStars = ownedStars.map(star => {
      // Use First Name + Last Name if they exist; otherwise, fallback to User_Name
      const displayName = (star.User_FN && star.User_LN) 
                          ? `${star.User_FN} ${star.User_LN}` 
                          : star.User_Name;
      
      return {
        starId: star.Star_ID,
        starName: star.Star_Name,
        type: star.Star_SpType,
        distance: star.Star_Distance,
        luminosity: star.Star_Luminosity,
        ownerDisplay: displayName
      };
    });

    return res.json({ 
      success: true, 
      count: formattedStars.length, 
      stars: formattedStars 
    });

  } catch (err) {
    console.error('Error fetching owned stars:', err);
    return res.status(500).json({ message: 'Failed to access the Protected Wall of Fame' });
  }
};

// ---------------- EXPORT ----------------
module.exports = {
  getMyStars,
  getStarById,
  getStarEncyclopedia,
  claimStar,
  getOwnedStars
};
