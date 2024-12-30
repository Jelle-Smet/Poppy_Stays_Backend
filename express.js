const express = require('express');
const cors = require('cors');
const Database = require('./classes/database');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const moment = require('moment'); // For date handling
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

app.post('/api/login', async (req, res) => {
    const { User_Email, User_Password } = req.body;
    
    if (!User_Email || !User_Password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const sql = `SELECT U.User_ID, U.User_Email, U.User_password, U.User_FN, U.User_LN, O.Owner_ID
                     FROM User as U
                     INNER JOIN owner as O
                     ON U.User_ID = O.User_ID
                     WHERE U.User_Email = ? LIMIT 1`;

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

        return res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.User_ID,
                email: user.User_Email,
                firstName: user.User_FN,
                lastName: user.User_LN,
                ownerId: user.Owner_ID  // Ensure this field is correct
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

app.get('/api/all-spots', async (req, res) => {
    try {
        const sql = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            Ci.City_Name AS City_Name,
            Co.Country_Name AS Country_Name,
            SC.Spot_Category_Name AS Category_Name,
            M.Media_File_Url AS Image_URL
        FROM spots AS S
        INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
        INNER JOIN Spot_Category AS SC ON SC.Spot_Category_ID = SSC.Spot_Category_ID
        INNER JOIN Country AS Co ON S.Country_ID = Co.Country_ID
        INNER JOIN City AS Ci ON S.City_ID = Ci.City_ID
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
                    pricePerNight: row.Spot_Price_Per_Night,
                    location: {
                        city: row.City_Name,
                        country: row.Country_Name
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

// Fetch spot details
app.get('/api/spot_details/:id', async (req, res) => {
    const spotId = req.params.id;

    try {
        const sql = `SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Description,
            S.Spot_Price_Per_Night,
            S.Spot_Max_Guests,
            S.Spot_Latitude,
            S.Spot_Longitude,
            S.Spot_Number,
            O.Owner_Name AS Owner_Name,
            M.Media_File_Url AS Image_URL,
            SC.Spot_Category_Name AS Category_Name,
            A.Amenity_Name AS Amenity_Name,
            R.Review_Rating,
            R.Review_Comment,
            R.Review_Image,
            R.Review_Date,
            B.Booking_ID,
            B.Booking_Start,
            B.Booking_End,
            Co.Country_Name AS Country_Name,
            Ci.City_Name AS City_Name,
            St.Street_Name AS Street_Name
        FROM spots AS S
        INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
        INNER JOIN Spot_Category AS SC ON SSC.Spot_Category_ID = SC.Spot_Category_ID
        LEFT JOIN Spot_Amenity AS SA ON S.Spot_ID = SA.Spot_ID
        LEFT JOIN Amenity AS A ON SA.Amenity_ID = A.Amenity_ID
        LEFT JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
        LEFT JOIN Media AS M ON SM.Media_ID = M.Media_ID
        LEFT JOIN Review AS R ON R.Spot_ID = S.Spot_ID
        LEFT JOIN Booking AS B ON B.Spot_ID = S.Spot_ID
        INNER JOIN Country AS Co ON S.Country_ID = Co.Country_ID
        INNER JOIN City AS Ci ON S.City_ID = Ci.City_ID
        INNER JOIN Street AS St ON S.Street_ID = St.Street_ID
        INNER JOIN Owner AS O ON S.Owner_ID = O.Owner_ID
        WHERE S.Spot_ID = ?`;

        const results = await db.getQuery(sql, [spotId]);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'Spot not found' });
        }

        const spot = {
            id: results[0].Spot_ID,
            name: results[0].Spot_Name,
            description: results[0].Spot_Description,
            pricePerNight: results[0].Spot_Price_Per_Night,
            maxGuests: results[0].Spot_Max_Guests,
            latitude: results[0].Spot_Latitude,
            longitude: results[0].Spot_Longitude,
            streetNumber: results[0].Spot_Number,
            ownerName: results[0].Owner_Name,
            categoryName: results[0].Category_Name,
            location: {
                country: results[0].Country_Name,
                city: results[0].City_Name,
                street: results[0].Street_Name,
            },
            images: [],
            amenities: [],
            reviews: [],
            bookings: []
        };

        // Process the results to group data into arrays
        results.forEach(row => {
            if (row.Image_URL && !spot.images.includes(row.Image_URL)) {
                spot.images.push(row.Image_URL); // Add only unique images
            }
            if (row.Amenity_Name && !spot.amenities.includes(row.Amenity_Name)) {
                spot.amenities.push(row.Amenity_Name); // Add only unique amenities
            }
            if (row.Review_Rating && !spot.reviews.some(review => review.rating === row.Review_Rating && review.comment === row.Review_Comment)) {
                spot.reviews.push({
                    rating: row.Review_Rating,
                    comment: row.Review_Comment,
                    image: row.Review_Image,
                    date: row.Review_Date // Assuming this is already stored as is
                });
            }
            if (row.Booking_ID && !spot.bookings.some(booking => booking.bookingId === row.Booking_ID)) {
                const startDate = new Date(row.Booking_Start); // This will be in local time
                const endDate = new Date(row.Booking_End); // This will be in local time

                // Ensure the date is formatted as YYYY-MM-DD (without shifting)
                const formattedStartDate = startDate.toLocaleDateString('en-CA'); // Using the 'en-CA' format for YYYY-MM-DD
                const formattedEndDate = endDate.toLocaleDateString('en-CA'); // Using the 'en-CA' format for YYYY-MM-DD

                spot.bookings.push({
                    bookingId: row.Booking_ID,
                    start: formattedStartDate, // Correct date format
                    end: formattedEndDate      // Correct date format
                });
            }
        });

        res.json({ spot });
    } catch (error) {
        console.error('Error fetching spot details:', error);
        res.status(500).json({
            message: 'Error fetching spot details',
            error: error.message
        });
    }
});


// Fetch spot availability
app.get('/api/spot-availability/:spotId', async (req, res) => {
    const spotId = req.params.spotId;
    
    try {
        const availabilitySql = `
            SELECT 
                Availability_Start,
                Availability_Stop
            FROM availability 
            WHERE Spot_ID = ?`;

        const availabilityResult = await db.getQuery(availabilitySql, [spotId]);

        if (!availabilityResult || availabilityResult.length === 0) {
            return res.status(404).json({ 
                message: 'No availability information found',
                availabilityStart: null,
                availabilityStop: null
            });
        }

        // Return the date as is, no conversion
        const availabilityStart = availabilityResult[0].Availability_Start;
        const availabilityStop = availabilityResult[0].Availability_Stop;

        res.json({ 
            message: 'Spot availability retrieved',
            availabilityStart: availabilityStart,
            availabilityStop: availabilityStop
        });
    } catch (error) {
        console.error('Error checking availability:', error);
        res.status(500).json({ message: 'Error checking availability', error: error.message });
    }
});

// Promo code check endpoint
app.post('/api/check-promo', async (req, res) => {
    const { promoCode } = req.body;

    try {
        const sql = `
            SELECT * 
            FROM Promotions 
            WHERE Promotion_Code LIKE ? 
            AND Promotion_Active = TRUE 
            AND CURRENT_DATE BETWEEN Promotion_Start AND Promotion_End`;

        const results = await db.getQuery(sql, [promoCode]);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'Promo code not found or is inactive' });
        }

        const promotion = results[0];

        res.json({
            message: 'Promo code valid',
            promotion: {
                id: promotion.Promotion_ID,
                name: promotion.Promotion_Name,
                description: promotion.Promotion_Description,
                start: promotion.Promotion_Start,
                end: promotion.Promotion_End,
                type: promotion.Promotion_Type,
                amount: promotion.Promotion_Amount
            }
        });
    } catch (error) {
        console.error('Error checking promo code:', error);
        res.status(500).json({
            message: 'Error checking promo code',
            error: error.message
        });
    }
});

// Create payment and booking
app.post('/api/create-payment', authenticateToken, async (req, res) => {
    const { paymentAmount, paymentMethod } = req.body;

    try {
        const transactionId = 'TXN' + Date.now() + Math.random().toString(36).substr(2, 9);

        const paymentSql = `INSERT INTO Payment 
            (Payment_Date, Payment_Amount, Payment_Status, Payment_Method, Payment_Transaction) 
            VALUES (NOW(), ?, 'Paid', ?, ?)`;

        const paymentResult = await db.getQuery(paymentSql, [
            paymentAmount,
            paymentMethod,
            transactionId
        ]);

        res.json({ 
            message: 'Payment created successfully',
            paymentId: paymentResult.insertId,
            transactionId: transactionId
        });
    } catch (error) {
        console.error('Error creating payment:', error);
        res.status(500).json({ 
            message: 'Error creating payment',
            error: error.message 
        });
    }
});

// Create booking
app.post('/api/create-booking', authenticateToken, async (req, res) => {
    const { 
        spotId,
        startDate,
        endDate,
        totalAmount,
        paymentId,
        promotionId
    } = req.body;

    try {
        // Use the date as it is, no conversion needed
        const startDateFormatted = startDate; // Assume the frontend sends the date in a consistent format (e.g., 'YYYY-MM-DD')
        const endDateFormatted = endDate; // Same for end date

        const bookingSql = `INSERT INTO Booking 
            (User_ID, Spot_ID, Booking_Start, Booking_End, 
             Booking_Status, Booking_Total, Booking_Date, 
             Promotion_ID, Payment_ID) 
            VALUES (?, ?, ?, ?, 'Pending', ?, NOW(), ?, ?)`;

        const bookingResult = await db.getQuery(bookingSql, [
            req.user.userId,
            spotId,
            startDateFormatted, // Directly use the date as it is
            endDateFormatted,   // Same for end date
            totalAmount,
            promotionId || null,
            paymentId
        ]);

        res.json({ 
            message: 'Booking created successfully',
            bookingId: bookingResult.insertId
        });
    } catch (error) {
        console.error('Error creating booking:', error);
        res.status(500).json({ 
            message: 'Error creating booking',
            error: error.message 
        });
    }
});

// Toggle favorite
app.post('/api/toggle-favorite', authenticateToken, async (req, res) => {
    const { spotId } = req.body;

    try {
        // Check if the spot is already favorited by the user
        const checkFavoriteSql = `SELECT Favorite_ID FROM Favorite 
                                   WHERE User_ID = ? AND Spot_ID = ?`;
        const favoriteResult = await db.getQuery(checkFavoriteSql, [
            req.user.userId,
            spotId
        ]);

        if (favoriteResult.length > 0) {
            // Spot is already favorited, unfavorite it
            const unfavoriteSql = `DELETE FROM Favorite WHERE Favorite_ID = ?`;
            await db.getQuery(unfavoriteSql, [favoriteResult[0].Favorite_ID]);

            return res.json({
                message: 'Spot unfavorited successfully'
            });
        } else {
            // Spot is not favorited, add it to favorites
            const favoriteSql = `INSERT INTO Favorite (User_ID, Spot_ID, Favorite_Time) 
                                 VALUES (?, ?, NOW())`;
            const favoriteInsertResult = await db.getQuery(favoriteSql, [
                req.user.userId,
                spotId
            ]);

            return res.json({
                message: 'Spot favorited successfully',
                favoriteId: favoriteInsertResult.insertId
            });
        }
    } catch (error) {
        console.error('Error toggling favorite:', error);
        res.status(500).json({
            message: 'Error toggling favorite',
            error: error.message
        });
    }
});

// api category enpoint
app.get('/api/categories', async (req, res) => {
    try {
      const categories = await db.getQuery('SELECT Spot_Category_Name, Spot_Category_ID FROM Spot_Category');
      
      // Filter out duplicate categories based on Spot_Category_Name
      const uniqueCategories = categories.filter((value, index, self) => 
        index === self.findIndex((t) => (
          t.Spot_Category_Name === value.Spot_Category_Name
        ))
      );
      
      res.json({
        message: 'Categories retrieved successfully',
        categories: uniqueCategories
      });
    } catch (error) {
      console.error('Error fetching categories:', error);
      res.status(500).json({
        message: 'Error fetching categories',
        error: error.message
      });
    }
});

// API endpoint to fetch unique amenities
app.get('/api/amenities', async (req, res) => {
    try {
      // Fetch amenities from the database
      const amenities = await db.getQuery('SELECT Amenity_ID, Amenity_Name FROM Amenity');
      
      // Remove duplicates based on Amenity_Name
      const uniqueAmenities = amenities.filter((value, index, self) =>
        index === self.findIndex((t) => (
          t.Amenity_Name === value.Amenity_Name
        ))
      );
      
      res.json({
        message: 'Amenities retrieved successfully',
        amenities: uniqueAmenities
      });
    } catch (error) {
      console.error('Error fetching amenities:', error);
      res.status(500).json({
        message: 'Error fetching amenities',
        error: error.message
      });
    }
});

// enpoint to get basic spot information based on category_ids.
app.post('/api/spots-category', async (req, res) => {
    try {
        // Extract category IDs from the request body
        let categoryIds = req.body.categoryIds;

        // Validate categoryIds (should be an array)
        if (!categoryIds || !Array.isArray(categoryIds) || categoryIds.length === 0) {
            return res.status(400).json({ message: 'Category IDs are required and must be an array.' });
        }

        // Convert categoryIds array to a comma-separated string for the SQL query
        const categoryIdsString = categoryIds.join(',');

        // SQL query with dynamic WHERE clause for category filtering
        const sql = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            Ci.City_Name AS City_Name,
            Co.Country_Name AS Country_Name,
            SC.Spot_Category_Name AS Category_Name,
            M.Media_File_Url AS Image_URL
        FROM spots AS S
        INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
        INNER JOIN Spot_Category AS SC ON SC.Spot_Category_ID = SSC.Spot_Category_ID
        INNER JOIN Country AS Co ON S.Country_ID = Co.Country_ID
        INNER JOIN City AS Ci ON S.City_ID = Ci.City_ID
        INNER JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
        INNER JOIN Media AS M ON SM.Media_ID = M.Media_ID
        WHERE SSC.Spot_Category_ID IN (${categoryIdsString})
        `;

        // Execute the query
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
                    pricePerNight: row.Spot_Price_Per_Night,
                    location: {
                        city: row.City_Name,
                        country: row.Country_Name
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

// endpoint to fetch owners
app.get('/api/owners', async (req, res) => {
    try {
        const owners = await db.getQuery('SELECT Owner_ID, Owner_Name FROM Owner');
        
        // Filter out duplicate owners based on Owner_Name
        const uniqueOwners = owners.filter((value, index, self) =>
            index === self.findIndex((t) => (
                t.Owner_Name === value.Owner_Name
            ))
        );

        res.json({
            message: 'Owners retrieved successfully',
            owners: uniqueOwners
        });
    } catch (error) {
        console.error('Error fetching owners:', error);
        res.status(500).json({
            message: 'Error fetching owners',
            error: error.message
        });
    }
});

// Endpoint to get basic spot information based on owner_ids
app.post('/api/spots-owner', async (req, res) => {
    try {
        // Extract owner IDs from the request body
        let ownerIds = req.body.ownerIds;

        // Validate ownerIds (should be an array)
        if (!ownerIds || !Array.isArray(ownerIds) || ownerIds.length === 0) {
            return res.status(400).json({ message: 'Owner IDs are required and must be an array.' });
        }

        // Convert ownerIds array to a comma-separated string for the SQL query
        const ownerIdsString = ownerIds.join(',');

        // SQL query with dynamic WHERE clause for owner filtering
        const sql = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            Ci.City_Name AS City_Name,
            Co.Country_Name AS Country_Name,
            SC.Spot_Category_Name AS Category_Name,
            M.Media_File_Url AS Image_URL
        FROM spots AS S
        INNER JOIN Owner AS O ON S.Owner_ID = O.Owner_ID
        INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
        INNER JOIN Spot_Category AS SC ON SC.Spot_Category_ID = SSC.Spot_Category_ID
        INNER JOIN Country AS Co ON S.Country_ID = Co.Country_ID
        INNER JOIN City AS Ci ON S.City_ID = Ci.City_ID
        INNER JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
        INNER JOIN Media AS M ON SM.Media_ID = M.Media_ID
        WHERE O.Owner_ID IN (${ownerIdsString})
        `;

        // Execute the query
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
                    pricePerNight: row.Spot_Price_Per_Night,
                    location: {
                        city: row.City_Name,
                        country: row.Country_Name
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

app.get('/api/spots/:id', async (req, res) => {
    const spotId = req.params.id;

    try {
        const sql = `
            SELECT 
                S.Spot_ID,
                S.Spot_Name,
                S.Spot_Description,
                S.Spot_Price_Per_Night,
                S.Spot_Max_Guests,
                SC.Spot_Category_ID AS Category_ID,
                A.Amenity_ID AS Amenity_ID,  
                M.Media_File_Url AS Image_URL
            FROM spots AS S
            INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
            INNER JOIN Spot_Category AS SC ON SSC.Spot_Category_ID = SC.Spot_Category_ID
            LEFT JOIN Spot_Amenity AS SA ON S.Spot_ID = SA.Spot_ID
            LEFT JOIN Amenity AS A ON SA.Amenity_ID = A.Amenity_ID
            LEFT JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
            LEFT JOIN Media AS M ON SM.Media_ID = M.Media_ID
            WHERE S.Spot_ID = ?`;

        const results = await db.getQuery(sql, [spotId]);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'Spot not found' });
        }

        const spot = {
            id: results[0].Spot_ID,
            name: results[0].Spot_Name,
            description: results[0].Spot_Description,
            pricePerNight: results[0].Spot_Price_Per_Night,
            maxGuests: results[0].Spot_Max_Guests,
            categoryId: results[0].Category_ID,
            amenities: [],  // Now stores Amenity_IDs
            images: [],
        };

        // Process results for amenities (using Amenity_ID now) and images
        results.forEach(row => {
            if (row.Amenity_ID && !spot.amenities.includes(row.Amenity_ID)) {
                spot.amenities.push(row.Amenity_ID);  // Push Amenity_ID instead of Amenity_Name
            }
            if (row.Image_URL && !spot.images.includes(row.Image_URL)) {
                spot.images.push(row.Image_URL);
            }
        });

        res.json(spot);
    } catch (error) {
        console.error('Error fetching spot details:', error);
        res.status(500).json({ message: 'Error fetching spot details', error: error.message });
    }
});


// Update spots endpoint
app.put("/api/update-spot/:spotId", authenticateToken, async (req, res) => {
    const spotId = req.params.spotId;
    const userId = req.user.userId; // Assuming JWT payload includes userId
    const {
        name,
        description,
        pricePerNight,
        maxGuests,
        categoryId,
        amenities,
        imageUrls,
    } = req.body;

    // Check if imageUrls is an array
    if (!Array.isArray(imageUrls)) {
        return res.status(400).json({ error: "Invalid image URLs provided." });
    }

    let connection; // Declare connection here

    try {
        // Log the incoming data for debugging
        console.log('Spot ID:', spotId);
        console.log('User ID:', userId);
        console.log('Request Body:', req.body);  // Log the entire request body

        // Get a connection from the pool
        connection = await db.pool.getConnection();
        await connection.beginTransaction(); // Start a transaction

        // 1. Check if spot exists
        const [spot] = await connection.query(
            `SELECT * FROM Spots WHERE Spot_ID = ?`,
            [spotId]
        );

        if (!spot) {
            connection.release();
            return res.status(404).json({ error: "Spot not found." });
        }

        // Authorization Check: Ensure the user owns the spot
        const [spotOwner] = await connection.query(
            `SELECT U.User_ID 
            FROM Spots as S
            INNER JOIN Owner as O ON O.Owner_ID = S.Owner_ID
            INNER JOIN User AS U ON O.User_ID = U.User_ID
            WHERE Spot_ID = ?`,
            [spotId]
        );

        if (!spotOwner || spotOwner[0].User_ID !== userId) {  // Access the User_ID from the first result
            connection.release();
            return res.status(403).json({ error: "You are not authorized to update this spot." });
        }

        // 2. Check if category exists
        const [category] = await connection.query(
            `SELECT * FROM Spot_Category WHERE Spot_Category_ID = ?`,
            [categoryId]
        );

        if (!category) {
            connection.release();
            return res.status(400).json({ error: "Invalid category ID." });
        }

        // 3. Check if amenities exist
        for (const amenityId of amenities) {
            const [amenity] = await connection.query(
                `SELECT * FROM Amenity WHERE Amenity_ID = ?`,
                [amenityId]
            );
            if (!amenity) {
                connection.release();
                return res.status(400).json({ error: `Invalid amenity ID: ${amenityId}` });
            }
        }

        // 4. Update Spot Details
        await connection.query(
            `UPDATE Spots
             SET Spot_name = ?, Spot_Description = ?, Spot_price_Per_Night = ?, Spot_Max_Guests = ?
             WHERE Spot_ID = ?`,
            [name, description, pricePerNight, maxGuests, spotId]
        );

        // 5. Update Spot Category
        await connection.query(`DELETE FROM Spot_Spot_Category WHERE Spot_ID = ?`, [spotId]);
        await connection.query(
            `INSERT INTO Spot_Spot_Category (Spot_ID, Spot_Category_ID) VALUES (?, ?)`,
            [spotId, categoryId]
        );

        // 6. Update Spot Amenities
        await connection.query(`DELETE FROM Spot_Amenity WHERE Spot_ID = ?`, [spotId]);
        for (const amenityId of amenities) {
            // Check if Amenity_ID exists before inserting
            const [amenity] = await connection.query(
                `SELECT * FROM Amenity WHERE Amenity_ID = ?`,
                [amenityId]
            );
            if (!amenity) {
                return res.status(400).json({ error: `Amenity ID ${amenityId} does not exist.` });
            }

            await connection.query(
                `INSERT INTO Spot_Amenity (Spot_ID, Amenity_ID) VALUES (?, ?)`,
                [spotId, amenityId]
            );
        }

        // 7. Update Spot Media
        await connection.query(`DELETE FROM Spot_Media WHERE Spot_ID = ?`, [spotId]);
        for (const url of imageUrls) {
            console.log('Inserting image URL:', url);  // Log image URL
            const [mediaResult] = await connection.query(
                `INSERT INTO Media (media_Type, Media_File_URL, Media_Description, Media_Upload_Time)
                 VALUES ('image', ?, NULL, NOW())`,
                [url]
            );
            const mediaId = mediaResult.insertId;

            await connection.query(
                `INSERT INTO Spot_Media (Spot_ID, Media_ID) VALUES (?, ?)`,
                [spotId, mediaId]
            );
        }

        // Commit the transaction
        await connection.commit();
        connection.release();
        res.status(200).json({ message: "Spot updated successfully!" });
    } catch (error) {
        if (connection) {
            await connection.rollback();  // Rollback if there was an error
            connection.release();
        }
        console.error("Error updating spot:", error.message);  // Log the error message
        res.status(500).json({ error: `An error occurred while updating the spot: ${error.message}` });
    }
});

// API endpoint to fetch unique countries
app.get('/api/countries', async (req, res) => {
    try {
      // Fetch countries from the database
      const countries = await db.getQuery('SELECT Country_ID, Country_Name FROM Country');
      
      // Remove duplicates based on Country_Name
      const uniqueCountries = countries.filter((value, index, self) =>
        index === self.findIndex((t) => (
          t.Country_Name === value.Country_Name
        ))
      );
      
      res.json({
        message: 'Countries retrieved successfully',
        countries: uniqueCountries
      });
    } catch (error) {
      console.error('Error fetching countries:', error);
      res.status(500).json({
        message: 'Error fetching countries',
        error: error.message
      });
    }
});

// API endpoint to fetch unique cities
app.get('/api/cities', async (req, res) => {
    try {
      // Fetch cities from the database
      const cities = await db.getQuery('SELECT City_ID, City_Name FROM City');
      
      // Remove duplicates based on City_Name
      const uniqueCities = cities.filter((value, index, self) =>
        index === self.findIndex((t) => (
          t.City_Name === value.City_Name
        ))
      );
      
      res.json({
        message: 'Cities retrieved successfully',
        cities: uniqueCities
      });
    } catch (error) {
      console.error('Error fetching cities:', error);
      res.status(500).json({
        message: 'Error fetching cities',
        error: error.message
      });
    }
});

// API endpoint to fetch unique streets
app.get('/api/streets', async (req, res) => {
    try {
      // Fetch streets from the database
      const streets = await db.getQuery('SELECT Street_ID, Street_Name FROM Street');
      
      // Remove duplicates based on Street_Name
      const uniqueStreets = streets.filter((value, index, self) =>
        index === self.findIndex((t) => (
          t.Street_Name === value.Street_Name
        ))
      );
      
      res.json({
        message: 'Streets retrieved successfully',
        streets: uniqueStreets
      });
    } catch (error) {
      console.error('Error fetching streets:', error);
      res.status(500).json({
        message: 'Error fetching streets',
        error: error.message
      });
    }
});

// Add Spot Endpoint
app.post("/api/add-spot", authenticateToken, async (req, res) => {
    const {
        name,
        description,
        pricePerNight,
        maxGuests,
        categoryId,
        amenities,
        imageUrls,
        cityId,
        streetId,
        countryId,
        startDate,  // Added for availability
        endDate,    // Added for availability
        ownerId,     // Added for owner
        houseNumber,
        latitude,
        longitude,
    } = req.body;

    // Check if imageUrls is an array
    if (!Array.isArray(imageUrls)) {
        return res.status(400).json({ error: "Invalid image URLs provided." });
    }

    let connection;

    try {
        // Log the incoming data for debugging
        console.log("Owner ID:", ownerId);
        console.log("Request Body:", req.body);

        // Get a connection from the pool
        connection = await db.pool.getConnection();
        await connection.beginTransaction(); // Start a transaction

        // 1. Validate Spot Category
        const [category] = await connection.query(
            `SELECT * FROM Spot_Category WHERE Spot_Category_ID = ?`,
            [categoryId]
        );
        if (!category) {
            connection.release();
            return res.status(400).json({ error: "Invalid category ID." });
        }

        // 2. Validate Amenities
        for (const amenityId of amenities) {
            const [amenity] = await connection.query(
                `SELECT * FROM Amenity WHERE Amenity_ID = ?`,
                [amenityId]
            );
            if (!amenity) {
                connection.release();
                return res.status(400).json({ error: `Invalid amenity ID: ${amenityId}` });
            }
        }

        // 3. Validate Location (City, Country)
        const [city] = await connection.query(
            `SELECT * FROM City WHERE City_ID = ?`,
            [cityId]
        );
        if (!city) {
            connection.release();
            return res.status(400).json({ error: "Invalid city ID." });
        }

        const [country] = await connection.query(
            `SELECT * FROM Country WHERE Country_ID = ?`,
            [countryId]
        );
        if (!country) {
            connection.release();
            return res.status(400).json({ error: "Invalid country ID." });
        }

        // 4. Insert Spot Details
        const [spotResult] = await connection.query(
            `INSERT INTO Spots (Spot_Name, Spot_Description, Country_ID, City_ID, Street_ID, Spot_Number, Spot_Latitude, Spot_Longitude, Spot_Price_Per_Night, Spot_Max_Guests, Owner_ID)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, description, countryId, cityId, streetId, houseNumber, latitude, longitude, pricePerNight, maxGuests, ownerId]
        );

        const spotId = spotResult.insertId; // Get the newly created Spot ID

        // 5. Insert Spot Category
        await connection.query(
            `INSERT INTO Spot_Spot_Category (Spot_ID, Spot_Category_ID) VALUES (?, ?)`,
            [spotId, categoryId]
        );

        // 6. Insert Spot Amenities
        for (const amenityId of amenities) {
            await connection.query(
                `INSERT INTO Spot_Amenity (Spot_ID, Amenity_ID) VALUES (?, ?)`,
                [spotId, amenityId]
            );
        }

        // 7. Insert Spot Media
        for (const url of imageUrls) {
            const [mediaResult] = await connection.query(
                `INSERT INTO Media (media_Type, Media_File_URL, Media_Description, Media_Upload_Time)
                 VALUES ('image', ?, NULL, NOW())`,
                [url]
            );
            const mediaId = mediaResult.insertId;

            await connection.query(
                `INSERT INTO Spot_Media (Spot_ID, Media_ID) VALUES (?, ?)`,
                [spotId, mediaId]
            );
        }

        // 8. Insert Availability with corrected column names
        const [availabilityResult] = await connection.query(
            `INSERT INTO Availability (Spot_ID, Availability_Start, Availability_Stop)
             VALUES (?, ?, ?)`,
            [spotId, startDate, endDate]
        );

        // Commit the transaction
        await connection.commit();
        connection.release();
        res.status(201).json({ message: "Spot added successfully!", spotId });
    } catch (error) {
        if (connection) {
            await connection.rollback(); // Rollback if there was an error
            connection.release();
        }
        console.error("Error adding spot:", error.message); // Log the error message
        res.status(500).json({ error: `An error occurred while adding the spot: ${error.message}` });
    }
});

// endpoint to delete a spot.
app.delete("/api/delete-spot", authenticateToken, async (req, res) => {
    const { spotId } = req.body;
    let connection;

    try {
        connection = await db.pool.getConnection();
        await connection.beginTransaction();

        // Get Payment_IDs from Booking table
        const [bookingRecords] = await connection.query(
            `SELECT Payment_ID FROM Booking WHERE Spot_ID = ?`,
            [spotId]
        );

        // Delete related payments
        for (const record of bookingRecords) {
            await connection.query(
                `DELETE FROM Payment WHERE Payment_ID = ?`,
                [record.Payment_ID]
            );
        }

        // Delete bookings
        await connection.query(
            `DELETE FROM Booking WHERE Spot_ID = ?`,
            [spotId]
        );

        // Original deletion logic
        await connection.query(`DELETE FROM Availability WHERE Spot_ID = ?`, [spotId]);

        const [mediaRecords] = await connection.query(
            `SELECT Media_ID FROM Spot_Media WHERE Spot_ID = ?`,
            [spotId]
        );
        
        await connection.query(`DELETE FROM Spot_Media WHERE Spot_ID = ?`, [spotId]);

        for (const record of mediaRecords) {
            await connection.query(`DELETE FROM Media WHERE Media_ID = ?`, [record.Media_ID]);
        }

        await connection.query(`DELETE FROM Spot_Amenity WHERE Spot_ID = ?`, [spotId]);
        await connection.query(`DELETE FROM Spot_Spot_Category WHERE Spot_ID = ?`, [spotId]);
        await connection.query(`DELETE FROM Spots WHERE Spot_ID = ?`, [spotId]);

        await connection.commit();
        connection.release();
        res.status(200).json({ message: "Spot deleted successfully" });

    } catch (error) {
        if (connection) {
            await connection.rollback();
            connection.release();
        }
        res.status(500).json({ error: `Error deleting spot: ${error.message}` });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
