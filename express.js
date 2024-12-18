const express = require('express');
const Database = require('./classes/database'); // Import the Database class
const bcrypt = require('bcrypt'); // For hashing passwords
const jwt = require('jsonwebtoken'); // For creating a JWT token
require('dotenv').config(); // Load environment variables

const app = express();
app.use(express.json()); // Middleware to parse JSON

const db = new Database(); // Instantiate the Database class

// Signup Route (Register a new user)
app.post('/api/signup', async (req, res) => {
    const { User_FN, User_LN, User_Email, User_Password, User_Number, User_Date_Of_Birth, User_Address } = req.body;

    try {
        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(User_Password, 10);

        // SQL query to insert a new user
        const sql = `INSERT INTO User (User_FN, User_LN, User_Email, User_Password, User_Number, User_Date_Of_Birth, User_Address) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)`;

        // Execute the query
        const result = await db.getQuery(sql, [User_FN, User_LN, User_Email, hashedPassword, User_Number, User_Date_Of_Birth, User_Address]);

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

// Login Route (Authenticate user)
app.post('/api/login', async (req, res) => {
    const { User_Email, User_Password } = req.body;

    try {
        // SQL query to find the user by email
        const sql = 'SELECT * FROM User WHERE User_Email = ?';
        const user = await db.getQuery(sql, [User_Email]);

        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Compare the password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(User_Password, user[0].User_Password);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // Create a JWT token for the user
        const token = jwt.sign({ User_ID: user[0].User_ID }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// Starting the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
