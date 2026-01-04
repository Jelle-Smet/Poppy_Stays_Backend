const db = new (require('../Classes/database'))();

// ---------------- RATE OBJECT ----------------
const rateObject = async (req, res) => {
  try {
    const userId = req.userId;
    const { objectType, objectId, rating } = req.body;

    if (!userId) return res.status(401).json({ message: 'Not authenticated' });
    if (!objectType || !objectId || !rating) {
      return res.status(400).json({ message: 'Missing objectType, objectId, or rating' });
    }

    // Check if rating already exists
    const existing = await db.getQuery(
      `SELECT Interaction_ID 
       FROM Interactions
       WHERE User_ID = ?
         AND Object_Type = ?
         AND Object_Reference_ID = ?
         AND Interaction_Type = 'Rate'`,
      [userId, objectType, objectId]
    );

    if (existing.length > 0) {
      // Update rating
      await db.getQuery(
        `UPDATE Interactions
         SET Interaction_Rating = ?
         WHERE Interaction_ID = ?`,
        [rating, existing[0].Interaction_ID]
      );

      return res.status(200).json({ message: 'Rating updated' });
    } else {
      // Insert new rating
      await db.getQuery(
        `INSERT INTO Interactions
         (User_ID, Object_Type, Object_Reference_ID, Interaction_Type, Interaction_Rating)
         VALUES (?, ?, ?, 'Rate', ?)`,
        [userId, objectType, objectId, rating]
      );

      return res.status(200).json({ message: 'Rating created' });
    }
  } catch (err) {
    console.error('Error rating object:', err);
    return res.status(500).json({ message: 'Failed to rate object' });
  }
};

// ---------------- LIKE OBJECT ----------------
const likeObject = async (req, res) => {
  try {
    const userId = req.userId;
    const { objectType, objectId } = req.body;

    if (!userId) return res.status(401).json({ message: 'Not authenticated' });
    if (!objectType || !objectId) {
      return res.status(400).json({ message: 'Missing objectType or objectId' });
    }

    // Check if already liked
    const existing = await db.getQuery(
      `SELECT Interaction_ID
       FROM Interactions
       WHERE User_ID = ?
         AND Object_Type = ?
         AND Object_Reference_ID = ?
         AND Interaction_Type = 'Like'`,
      [userId, objectType, objectId]
    );

    if (existing.length > 0) {
      // Already liked → do nothing
      return res.status(200).json({ message: 'Already liked' });
    }

    // Insert like once
    await db.getQuery(
      `INSERT INTO Interactions
       (User_ID, Object_Type, Object_Reference_ID, Interaction_Type)
       VALUES (?, ?, ?, 'Like')`,
      [userId, objectType, objectId]
    );

    return res.status(200).json({ message: 'Liked' });
  } catch (err) {
    console.error('Error liking object:', err);
    return res.status(500).json({ message: 'Failed to like object' });
  }
};

// ---------------- GET USER INTERACTIONS (GROUPED) ----------------
const getUserInteractions = async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) return res.status(401).json({ message: 'Not authenticated' });

    // -------- STARS --------
    const stars = await db.getQuery(`
      SELECT 
        s.Star_ID AS id,
        s.Star_Name AS name,
        s.Star_SpType AS spectralType,
        s.Star_Luminosity AS luminosity,
        i.Interaction_Type AS interactionType,
        i.Interaction_Rating AS rating
      FROM Interactions i
      INNER JOIN Stars s
        ON s.Star_ID = i.Object_Reference_ID
      WHERE i.User_ID = ?
        AND i.Object_Type = 'Star'
    `, [userId]);

    // -------- PLANETS --------
    const planets = await db.getQuery(`
      SELECT 
        p.Planet_ID AS id,
        p.Planet_Name AS name,
        p.Planet_Color AS color,
        p.Planet_Magnitude AS magnitude,
        i.Interaction_Type AS interactionType,
        i.Interaction_Rating AS rating
      FROM Interactions i
      INNER JOIN Planets p
        ON p.Planet_ID = i.Object_Reference_ID
      WHERE i.User_ID = ?
        AND i.Object_Type = 'Planet'
    `, [userId]);

    // -------- MOONS --------
    const moons = await db.getQuery(`
      SELECT 
        m.Moon_ID AS id,
        m.Moon_Name AS name,
        m.Parent_Planet_Name AS parent,
        m.Moon_Color AS color,
        i.Interaction_Type AS interactionType,
        i.Interaction_Rating AS rating
      FROM Interactions i
      INNER JOIN Moons m
        ON m.Moon_ID = i.Object_Reference_ID
      WHERE i.User_ID = ?
        AND i.Object_Type = 'Moon'
    `, [userId]);

    return res.json({
      stars,
      planets,
      moons
    });

  } catch (err) {
    console.error('Error fetching user interactions:', err);
    return res.status(500).json({ message: 'Failed to fetch user interactions' });
  }
};


module.exports = {
  rateObject,
  likeObject,
  getUserInteractions
};
