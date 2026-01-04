// controllers/Users_Controller.js

require('dotenv').config();
const db = new (require('../Classes/database'))();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

/**
 * 🛰️ SIGNUP (POST /api/signup)
 */
exports.signup = async (req, res) => {
    const { User_FN, User_LN, User_Username, User_Email, User_Password } = req.body;

    if (!User_FN || !User_LN || !User_Email || !User_Password) {
        return res.status(400).json({ message: "All required explorer data missing." });
    }

    if (User_Password.length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters long." });
    }

    // Generate username
    const finalUsername = User_Username?.trim()
        ? User_Username.trim()
        : `${User_FN.trim()} ${User_LN.trim()}`;

    try {
        // Check email uniqueness
        const existingUser = await db.getQuery(
            "SELECT User_ID FROM Users WHERE User_Email = ?",
            [User_Email]
        );

        if (existingUser.length > 0) {
            return res.status(409).json({ message: "Email already in use." });
        }

        const hashedPassword = await bcrypt.hash(User_Password, 10);

        const sql = `
            INSERT INTO Users 
            (User_FN, User_LN, User_Name, User_Email, User_Password, User_Created)
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        const result = await db.getQuery(sql, [
            User_FN,
            User_LN,
            finalUsername,
            User_Email,
            hashedPassword
        ]);

        res.status(201).json({
            message: `Explorer "${finalUsername}" registered successfully.`,
            userId: result.insertId
        });

    } catch (err) {
        console.error("Signup Error:", err);
        res.status(500).json({ message: "Registration failed due to a cosmic anomaly." });
    }
};

/**
 * 👽 LOGIN (POST /api/login)
 */
exports.login = async (req, res) => {
    const { User_Email, User_Password } = req.body;

    if (!User_Email || !User_Password) {
        return res.status(400).json({ message: "Email and password required." });
    }

    try {
        const users = await db.getQuery(
            "SELECT * FROM Users WHERE User_Email = ?",
            [User_Email]
        );

        const user = users[0];
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const isMatch = await bcrypt.compare(User_Password, user.User_Password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const token = jwt.sign(
            {
                id: user.User_ID,
                username: user.User_Name
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: "Login successful.",
            token,
            user: {
                id: user.User_ID,
                username: user.User_Name,
                firstName: user.User_FN,
                lastName: user.User_LN,
                email: user.User_Email
            }
        });

    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Login failed. Try again." });
    }
};

/**
 * 👤 ACCOUNT DETAILS (GET /api/account)
 */
exports.getAccountDetails = async (req, res) => {
    const userId = req.userId;

    try {
        const users = await db.getQuery(
            `
            SELECT User_FN, User_LN, User_Name, User_Email, User_Created
            FROM Users
            WHERE User_ID = ?
            `,
            [userId]
        );

        const user = users[0];
        if (!user) {
            return res.status(404).json({ message: "Explorer not found." });
        }

        res.json({
            username: user.User_Name,
            firstName: user.User_FN,
            lastName: user.User_LN,
            email: user.User_Email,
            memberSince: new Date(user.User_Created).toLocaleDateString()
        });

    } catch (err) {
        console.error("Account Error:", err);
        res.status(500).json({ message: "Failed to retrieve account data." });
    }
};

/**
 * 🛠️ UPDATE PROFILE (PUT /api/update-profile)
 */
exports.updateProfile = async (req, res) => {
    const userId = req.userId; // Provided by your auth middleware
    const { User_FN, User_LN, User_Name, User_Email, User_Password } = req.body;

    try {
        // 1. Fetch current user to verify existence
        const users = await db.getQuery("SELECT * FROM Users WHERE User_ID = ?", [userId]);
        const user = users[0];

        if (!user) {
            return res.status(404).json({ message: "Explorer not found." });
        }

        // 2. Prepare dynamic updates
        let updates = [];
        let params = [];

        if (User_FN) { updates.push("User_FN = ?"); params.push(User_FN); }
        if (User_LN) { updates.push("User_LN = ?"); params.push(User_LN); }
        if (User_Name) { updates.push("User_Name = ?"); params.push(User_Name); }
        
        // Handle Email (check uniqueness if changing)
        if (User_Email && User_Email !== user.User_Email) {
            const existing = await db.getQuery("SELECT User_ID FROM Users WHERE User_Email = ? AND User_ID != ?", [User_Email, userId]);
            if (existing.length > 0) {
                return res.status(409).json({ message: "This email is already claimed by another explorer." });
            }
            updates.push("User_Email = ?");
            params.push(User_Email);
        }

        // Handle Password hashing
        if (User_Password) {
            if (User_Password.length < 8) {
                return res.status(400).json({ message: "New password must be at least 8 characters." });
            }
            const hashedPassword = await bcrypt.hash(User_Password, 10);
            updates.push("User_Password = ?");
            params.push(hashedPassword);
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: "No changes provided." });
        }

        // 3. Execute Update
        params.push(userId);
        const sql = `UPDATE Users SET ${updates.join(", ")} WHERE User_ID = ?`;
        await db.getQuery(sql, params);

        res.json({ message: "Profile updated successfully! ✨" });

    } catch (err) {
        console.error("Update Error:", err);
        res.status(500).json({ message: "Failed to update profile due to a database anomaly." });
    }
};
