const db = new (require('../Classes/database'))();

// ---------------- TOGGLE LIKE ----------------
const toggleLike = async (req, res) => {
  try {
    const userId = req.userId;
    const { objectType, objectId } = req.body;

    if (!userId || !objectType || !objectId) {
      return res.status(400).json({ message: 'Missing user, objectType, or objectId' });
    }

    // Check if already liked
    const existing = await db.getQuery(
      `SELECT Liked_Object_ID 
       FROM Liked_Objects 
       WHERE User_ID = ? AND Object_Type = ? AND Object_Reference_ID = ?`,
      [userId, objectType, objectId]
    );

    // -------- UNLIKE --------
    if (existing.length > 0) {
      await db.getQuery(
        `DELETE FROM Liked_Objects 
         WHERE User_ID = ? AND Object_Type = ? AND Object_Reference_ID = ?`,
        [userId, objectType, objectId]
      );

      return res.json({
        liked: false,
        message: 'Object unliked'
      });
    }

    // -------- LIKE --------
    await db.getQuery(
      `INSERT INTO Liked_Objects (User_ID, Object_Type, Object_Reference_ID)
       VALUES (?, ?, ?)`,
      [userId, objectType, objectId]
    );

    return res.json({
      liked: true,
      message: 'Object liked'
    });

  } catch (err) {
    console.error('Error toggling like:', err);
    return res.status(500).json({ message: 'Failed to toggle like' });
  }
};

// ---------------- GET LIKE STATUS ----------------
const getLikeStatus = async (req, res) => {
  try {
    const userId = req.userId;
    const { type, id } = req.query; // type=Star, id=Star_ID

    if (!userId || !type || !id) {
      return res.status(400).json({ message: 'Missing user, type, or id' });
    }

    const existing = await db.getQuery(
      `SELECT Liked_Object_ID 
       FROM Liked_Objects 
       WHERE User_ID = ? AND Object_Type = ? AND Object_Reference_ID = ?`,
      [userId, type, id]
    );

    return res.json({ isLiked: existing.length > 0 });

  } catch (err) {
    console.error('Error getting like status:', err);
    return res.status(500).json({ message: 'Failed to get like status' });
  }
};

// ---------------- GET USER LIKES (GROUPED) ----------------
const getUserLikes = async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) return res.status(400).json({ message: 'User ID required' });

    // -------- STARS --------
    const stars = await db.getQuery(`
      SELECT s.Star_ID AS id, s.Star_Name AS name, s.Star_SpType AS spectralType, s.Star_Luminosity AS luminosity
      FROM Stars s
      INNER JOIN Liked_Objects l
        ON l.Object_Reference_ID = s.Star_ID
      WHERE l.User_ID = ? AND l.Object_Type = 'Star'
    `, [userId]);

    // -------- PLANETS --------
    const planets = await db.getQuery(`
      SELECT p.Planet_ID AS id, p.Planet_Name AS name, p.Planet_Color AS color, p.Planet_Magnitude AS magnitude
      FROM Planets p
      INNER JOIN Liked_Objects l
        ON l.Object_Reference_ID = p.Planet_ID
      WHERE l.User_ID = ? AND l.Object_Type = 'Planet'
    `, [userId]);

    // -------- MOONS --------
    const moons = await db.getQuery(`
      SELECT m.Moon_ID AS id, m.Moon_Name AS name, m.Parent_Planet_Name AS parent, m.Moon_Color AS color
      FROM Moons m
      INNER JOIN Liked_Objects l
        ON l.Object_Reference_ID = m.Moon_ID
      WHERE l.User_ID = ? AND l.Object_Type = 'Moon'
    `, [userId]);

    return res.json({
      stars,
      planets,
      moons
    });

  } catch (err) {
    console.error('Error fetching user likes:', err);
    return res.status(500).json({ message: 'Failed to fetch user likes' });
  }
};

module.exports = {
  toggleLike,
  getLikeStatus,
  getUserLikes
};

