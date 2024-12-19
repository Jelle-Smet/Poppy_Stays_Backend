const express = require('express');
const cors = require('cors');
const Database = require('./classes/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const db = new Database();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = user; // Decoded user object is stored in req.user
        next();
    });
};

// Signup Route: Handles user registration
app.post('/api/signup', async (req, res) => {
    const { User_FN, User_LN, User_Email, User_Password, User_Number, User_Date_Of_Birth, User_Address } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(User_Password, 10);

        const sql = `INSERT INTO User (User_FN, User_LN, User_Email, User_password, User_Number, User_Date_Of_Birth, User_Address) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)`;

        await db.getQuery(sql, [User_FN, User_LN, User_Email, hashedPassword, User_Number, User_Date_Of_Birth, User_Address]);

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

// Login Route: Handles user authentication
app.post('/api/login', async (req, res) => {
    const { User_Email, User_Password } = req.body;
    
    if (!User_Email || !User_Password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const sql = `SELECT User_ID, User_Email, User_password, User_FN, User_LN
                     FROM User WHERE User_Email = ? LIMIT 1`;
        
        // Check the query result
        const results = await db.getQuery(sql, [User_Email]);
        console.log('Database results:', results);  // Log to check

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        if (!user.User_password) {
            return res.status(500).json({ message: 'Authentication error' });
        }

        const isPasswordValid = await bcrypt.compare(User_Password, user.User_password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign(
            { 
                userId: user.User_ID,
                email: user.User_Email,
                firstName: user.User_FN,
                lastName: user.User_LN
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Ensure that this is the last response sent
        return res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.User_ID,
                email: user.User_Email,
                firstName: user.User_FN,
                lastName: user.User_LN
            }
        });
    } catch (error) {
        console.error('Login error:', error); // Log error for debugging
        return res.status(500).json({ 
            message: 'Error during login process',
            error: error.message 
        });
    }
});

// New route to get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const sql = `SELECT u.*, 
                            CASE WHEN o.Owner_ID IS NOT NULL THEN 'owner' ELSE 'user' END as role
                     FROM User u
                     LEFT JOIN Owner o ON u.User_ID = o.User_ID
                     WHERE u.User_ID = ?`;

        const results = await db.getQuery(sql, [req.user.userId]);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        res.json({
            id: user.User_ID,
            firstName: user.User_FN,
            lastName: user.User_LN,
            email: user.User_Email,
            profilePic: user.User_Pfp,
            bio: user.User_Bio,
            role: user.role
        });
        console.log('Profile Picture:', user.User_Pfp); // Log profile picture for debugging
    } catch (error) {
        res.status(500).json({ message: 'Error fetching profile', error: error.message });
    }
});

// Update bio
app.put('/api/profile/bio', authenticateToken, async (req, res) => {
    const { bio } = req.body;
    try {
        const sql = 'UPDATE User SET User_Bio = ? WHERE User_ID = ?';
        await db.getQuery(sql, [bio, req.user.userId]);
        res.json({ message: 'Bio updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating bio', error: error.message });
    }
});

// Update profile picture
app.put('/api/profile/picture', authenticateToken, async (req, res) => {
    const { pictureUrl } = req.body;
    try {
        const sql = 'UPDATE User SET User_pfp = ? WHERE User_ID = ?';
        await db.getQuery(sql, [pictureUrl, req.user.userId]);
        res.json({ message: 'Profile picture updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating profile picture', error: error.message });
    }
});

// Become an owner
app.post('/api/become-owner', authenticateToken, async (req, res) => {
    const { ownerName } = req.body;
    try {
        const checkSql = 'SELECT Owner_ID FROM Owner WHERE User_ID = ?';
        const existingOwner = await db.getQuery(checkSql, [req.user.userId]);

        if (existingOwner && existingOwner.length > 0) {
            return res.status(400).json({ message: 'User is already an owner' });
        }

        const sql = 'INSERT INTO Owner (User_ID, Owner_Name) VALUES (?, ?)';
        await db.getQuery(sql, [req.user.userId, ownerName]);
        
        res.json({ message: 'Successfully became an owner' });
    } catch (error) {
        res.status(500).json({ message: 'Error becoming owner', error: error.message });
    }
});

app.get('/api/spots', async (req, res) => {
    try {
        const sql = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Description,
            S.Spot_Price_Per_Night,
            S.Spot_Max_Guests,
            Ci.City_Name AS City_Name,
            Co.Country_Name AS Country_Name,
            Str.Street_Name AS Street_Address,
            S.Spot_Number AS Street_Number, 
            SC.Spot_Category_Name AS Category_Name,
            M.Media_File_Url AS Image_URL
        FROM spots AS S
        INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
        INNER JOIN Spot_Category AS SC ON SC.Spot_Category_ID = SSC.Spot_Category_ID
        INNER JOIN Country AS Co ON S.Country_ID = Co.Country_ID
        INNER JOIN City AS Ci ON S.City_ID = Ci.City_ID
        INNER JOIN Street AS Str ON S.Street_ID = Str.Street_ID
        INNER JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
        INNER JOIN Media AS M ON SM.Media_ID = M.Media_ID`;

        const results = await db.getQuery(sql);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'No spots found' });
        }

        // Group spots by ID
        const spotsMap = new Map();
        
        results.forEach(row => {
            if (!spotsMap.has(row.Spot_ID)) {
                spotsMap.set(row.Spot_ID, {
                    id: row.Spot_ID,
                    name: row.Spot_Name,
                    description: row.Spot_Description,
                    pricePerNight: row.Spot_Price_Per_Night,
                    maxGuests: row.Spot_Max_Guests,
                    location: {
                        city: row.City_Name,
                        country: row.Country_Name,
                        street: `${row.Street_Address} ${row.Street_Number}` // Concatenate street name and number
                    },
                    category: row.Category_Name, // Only 1 category
                    images: [] // Initialize images as an array
                });
            }

            // Add image to the images array
            spotsMap.get(row.Spot_ID).images.push(row.Image_URL);
        });

        // Convert map to array and limit to 20 spots
        const spots = Array.from(spotsMap.values()).slice(0, 20);

        res.json({
            message: 'Spots retrieved successfully',
            spots: spots
        });
    } catch (error) {
        console.error('Error fetching spots:', error);
        res.status(500).json({ 
            message: 'Error fetching spots',
            error: error.message 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
