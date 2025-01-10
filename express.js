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

        const sql = `INSERT INTO User (User_FN, User_LN, User_Email, User_password, User_Number, User_Date_Of_Birth, User_Address, User_Creation_Date) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`;

        await db.getQuery(sql, [User_FN, User_LN, User_Email, hashedPassword, User_Number, User_Date_Of_Birth, User_Address]);

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { User_Email, User_Password } = req.body;

    // Ensure both email and password are provided
    if (!User_Email || !User_Password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        // SQL query to fetch the user by email and join with owner information
        const sql = `SELECT U.User_ID, U.User_Email, U.User_password, U.User_FN, U.User_LN, O.Owner_ID
                     FROM User as U
                     LEFT JOIN owner as O
                     ON U.User_ID = O.User_ID
                     WHERE U.User_Email = ? LIMIT 1`;

        // Execute query with provided email
        const results = await db.getQuery(sql, [User_Email]);
        //console.log('Database results:', results);  // Log to check results

        // Check if user is found
        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        // Check if password is stored in the database
        if (!user.User_password) {
            return res.status(500).json({ message: 'Authentication error, password missing' });
        }

        // Compare the password with the hashed password in the database
        const isPasswordValid = await bcrypt.compare(User_Password, user.User_password);

        // If password is invalid, return an error
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // Generate JWT token upon successful login
        const token = jwt.sign(
            { 
                userId: user.User_ID,
                email: user.User_Email,
                firstName: user.User_FN,
                lastName: user.User_LN
            },
            process.env.JWT_SECRET,  // Ensure this is set in your environment variables
            { expiresIn: '1h' } // Token expiration time
        );

        // Respond with the login success message and token
        return res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.User_ID,
                email: user.User_Email,
                firstName: user.User_FN,
                lastName: user.User_LN,
                ownerId: user.Owner_ID  // Ensure this field is correct from the query
            }
        });
    } catch (error) {
        console.error('Login error:', error); // Log the error for debugging
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
            phoneNumber: user.User_Number,
            address: user.User_Address,
            role: user.role,
            password: user.User_Password,
        });
        //console.log('Profile Picture:', user.User_Pfp); // Log profile picture for debugging
        
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

// Update email
app.put('/api/profile/email', authenticateToken, async (req, res) => {
    const { email } = req.body;
    try {
        const sql = 'UPDATE User SET User_Email = ? WHERE User_ID = ?';
        await db.getQuery(sql, [email, req.user.userId]);
        res.json({ message: 'Email updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating email', error: error.message });
    }
});

// endpoint to check password. 
app.put('/api/profile/password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const token = req.headers['authorization'].split(' ')[1]; // Get the token from the headers

    // Decode the token to get user information (you might use jwt.decode here)
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    try {
        // Get the user data from the database
        const sql = `SELECT User_password FROM User WHERE User_ID = ?`;
        const results = await db.getQuery(sql, [userId]);

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        // Compare the current password with the hashed password in the database
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.User_password);

        if (!isCurrentPasswordValid) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Proceed to update the password (hash the new password)
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the database
        const updateSql = `UPDATE User SET User_password = ? WHERE User_ID = ?`;
        await db.getQuery(updateSql, [hashedNewPassword, userId]);

        return res.status(200).json({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Error updating password:', error);
        return res.status(500).json({ message: 'Error updating password', error: error.message });
    }
});


// Update address
app.put('/api/profile/address', authenticateToken, async (req, res) => {
    const { address } = req.body;
    try {
        const sql = 'UPDATE User SET User_Address = ? WHERE User_ID = ?';
        await db.getQuery(sql, [address, req.user.userId]);
        res.json({ message: 'Address updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating address', error: error.message });
    }
});

// Update phone number
app.put('/api/profile/phone-number', authenticateToken, async (req, res) => {
    const { phoneNumber } = req.body;
    try {
        const sql = 'UPDATE User SET User_Number = ? WHERE User_ID = ?';
        await db.getQuery(sql, [phoneNumber, req.user.userId]);
        res.json({ message: 'Phone number updated successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating phone number', error: error.message });
    }
});

// get all spots. 
app.get('/api/all-spots', async (req, res) => {
    try {
        const sql = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            S.Spot_Latitude,
            S.Spot_Longitude,
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
                    latitude: row.Spot_Latitude,
                    longitude: row.Spot_Longitude,
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
    console.log("id = " + spotId);
    console.log("----------------------------------------------------------------");

    try {
        // SQL query to get spot details, including bookings not cancelled
        const sql = `
            SELECT 
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
            LEFT JOIN Country AS Co ON S.Country_ID = Co.Country_ID
            LEFT JOIN City AS Ci ON S.City_ID = Ci.City_ID
            LEFT JOIN Street AS St ON S.Street_ID = St.Street_ID
            LEFT JOIN Owner AS O ON S.Owner_ID = O.Owner_ID
            LEFT JOIN Cancellation AS C ON B.Booking_ID = C.Booking_ID
            WHERE S.Spot_ID = ? AND C.Booking_ID IS NULL`; // Exclude canceled bookings

        // Execute query to fetch the spot details
        const results = await db.getQuery(sql, [spotId]);
        console.log(results);  // Log the raw results
        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'Spot not found' });
        }

        // Prepare the spot object
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
                spot.images.push(row.Image_URL); // Add unique images
            }
            if (row.Amenity_Name && !spot.amenities.includes(row.Amenity_Name)) {
                spot.amenities.push(row.Amenity_Name); // Add only unique amenities
            }
            if (row.Review_Rating && row.Review_Comment) {
                // Check if this review is already in the array (based on rating and comment)
                const reviewExists = spot.reviews.some(review => 
                    review.rating === row.Review_Rating && review.comment === row.Review_Comment
                );
                if (!reviewExists) {
                    spot.reviews.push({
                        rating: row.Review_Rating,
                        comment: row.Review_Comment,
                        image: row.Review_Image || null, // Image is optional (null if missing)
                        date: row.Review_Date // Assuming this is always available
                    });
                }
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
        

        // Return the spot details as a JSON response
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

// Promo code and gift card check endpoint
app.post('/api/check-promo-or-giftcard', async (req, res) => {
    const { code } = req.body;  // Either promoCode or giftCardCode from the client
    //console.log(code);
    try {
        // Log the incoming request
        //console.log(`Received request with code: ${code}`);

        // Check if it's a promo code first
        let result = await db.getQuery(`
            SELECT * 
            FROM Promotions 
            WHERE Promotion_Code LIKE ? 
            AND Promotion_Active = TRUE 
            AND CURRENT_DATE BETWEEN Promotion_Start AND Promotion_End
        `, [code]);

        if (result && result.length > 0) {
            const promo = result[0];
            //console.log(`Promo code ${code} is valid`);

            res.json({
                type: "promotion",
                message: "Promo code valid",
                promotion: {
                    id: promo.Promotion_ID,
                    name: promo.Promotion_Name,
                    description: promo.Promotion_Description,
                    start: promo.Promotion_Start,
                    end: promo.Promotion_End,
                    type: promo.Promotion_Type,
                    amount: promo.Promotion_Amount
                }
            });
            return;
        }

        // If no valid promo code, check if it's a gift card code
        result = await db.getQuery(`
            SELECT * 
            FROM Gift_Card_Purchase 
            WHERE Gift_Card_Purchase_Code = ? 
            AND Gift_Card_Purchase_Used = FALSE
        `, [code]);

        if (result && result.length > 0) {
            const giftCardPurchase = result[0];
            const giftCardResult = await db.getQuery(`
                SELECT * FROM Gift_Card WHERE Gift_Card_ID = ?
            `, [giftCardPurchase.Gift_Card_ID]);

            const giftCard = giftCardResult[0];
            console.log(`Gift card code ${code} is valid`);

            // Optionally, mark the gift card as used immediately after successful validation
            await db.getQuery(`
                UPDATE Gift_Card_Purchase 
                SET Gift_Card_Purchase_Used = TRUE 
                WHERE Gift_Card_Purchase_Code = ?
            `, [code]);

            res.json({
                type: "giftcard",
                message: "Gift card valid",
                giftCard: {
                    id: 4,
                    name: giftCard.Gift_Card_Name,
                    type: "Fixed",
                    amount: giftCard.Gift_Card_Amount
                }
            });
            return;
        }

        // If neither promo code nor gift card code is valid
        //console.log(`Code ${code} is invalid or already used`);

        res.status(404).json({
            message: "Code not found or invalid"
        });

    } catch (error) {
        // Log any error that occurs
        console.log(`Error processing code ${code}: ${error.message}`);
        res.status(500).json({
            message: "Error processing code",
            error: error.message
        });
    }
});

// Create payment 
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
    console.log(paymentId)
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

        console.log(`Category IDs received: ${categoryIdsString}`);

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

        console.log(`Number of spots found: ${results.length}`);

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
        //console.log('Spot ID:', spotId);
        //console.log('User ID:', userId);
        //console.log('Request Body:', req.body);  // Log the entire request body

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
            //console.log('Inserting image URL:', url);  // Log image URL
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
    const userId = req.user.userId;
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

        // 8. Insert Availability
        const [availabilityResult] = await connection.query(
            `INSERT INTO Availability (Spot_ID, Availability_Start, Availability_Stop)
             VALUES (?, ?, ?)`,
            [spotId, startDate, endDate]
        );

        // 9. Insert Booking (with owner as the user, and fixed price and dates)
        const bookingStartDate = '2000-01-01';
        const bookingEndDate = '2000-01-01';
        const bookingTotal = 0; // Set the price to 0
        const bookingStatus = 'Confirmed'; // You can change this as per your business logic

        await connection.query(
            `INSERT INTO Booking (User_ID, Spot_ID, Booking_Start, Booking_End, Booking_Status, Booking_Total, Booking_Date)
             VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [userId, spotId, bookingStartDate, bookingEndDate, bookingStatus, bookingTotal]
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

// Endpoint to get spots based on user's favorite Spot_IDs
app.post('/api/spots-favorites', authenticateToken, async (req, res) => {
    try {
        // Extract User_ID from the token
        const userId = req.user.userId;

        // Validate User_ID
        if (!userId || typeof userId !== 'number') {
            return res.status(400).json({ message: 'User ID is invalid.' });
        }

        // Fetch Spot_IDs from the favorite table
        const favoriteQuery = `
            SELECT Spot_ID
            FROM favorite
            WHERE User_ID = ?
        `;
        const favoriteResults = await db.getQuery(favoriteQuery, [userId]);

        if (!favoriteResults || favoriteResults.length === 0) {
            return res.status(404).json({ message: 'No favorite spots found for this user.' });
        }

        // Extract Spot_IDs as an array
        const spotIds = favoriteResults.map(row => row.Spot_ID);

        // Validate Spot_IDs
        if (spotIds.length === 0) {
            return res.status(404).json({ message: 'No valid Spot IDs found in favorites.' });
        }

        // Convert Spot_IDs array to a comma-separated string for the SQL query
        const spotIdsString = spotIds.join(',');

        // SQL query to fetch spot details based on Spot_IDs
        const spotsQuery = `
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
            WHERE S.Spot_ID IN (${spotIdsString})
        `;

        // Execute the query to fetch spot details
        const spotsResults = await db.getQuery(spotsQuery);

        if (!spotsResults || spotsResults.length === 0) {
            return res.status(404).json({ message: 'No spots found for the given Spot IDs.' });
        }

        // Group spots by ID
        const spotsMap = new Map();

        spotsResults.forEach(row => {
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
            message: 'Favorite spots retrieved successfully',
            spots: spots
        });
    } catch (error) {
        console.error('Error fetching favorite spots:', error);
        res.status(500).json({
            message: 'Error fetching favorite spots',
            error: error.message
        });
    }
});


// endpoint to fetch upcoming, past, and canceled bookings
app.post('/api/bookings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        if (!userId || typeof userId !== 'number') {
            return res.status(400).json({ message: 'User ID is invalid.' });
        }

        const sql = `
            SELECT 
                B.Booking_ID,
                B.Booking_Start AS Check_In_Date,
                B.Booking_End AS Check_Out_Date,
                B.Booking_Status,
                B.Booking_Total,
                B.Booking_Date,
                P.Payment_Date,
                P.Payment_Status,
                P.Payment_Method,
                PR.Promotion_Name,
                PR.Promotion_Type,
                PR.Promotion_Amount,
                S.Spot_ID,
                S.Spot_Name,
                S.Spot_Description,
                S.Spot_Price_Per_Night,
                S.Spot_Max_Guests,
                SC.Spot_Category_ID AS Category_ID,
                SC.Spot_Category_Name AS Category_Name,
                M.Media_File_Url AS Image_URL,
                CASE
                    WHEN B.Booking_End >= CURRENT_DATE THEN 'Upcoming'
                    ELSE 'Past'
                END AS Booking_Type,
                C.Cancellation_Time 
            FROM Booking AS B
            LEFT JOIN Payment AS P ON P.Payment_ID = B.Payment_ID
            LEFT JOIN Promotions AS PR ON PR.Promotion_ID = B.Promotion_ID
            INNER JOIN spots AS S ON B.Spot_ID = S.Spot_ID
            INNER JOIN Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
            INNER JOIN Spot_Category AS SC ON SSC.Spot_Category_ID = SC.Spot_Category_ID
            LEFT JOIN Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
            LEFT JOIN Media AS M ON SM.Media_ID = M.Media_ID
            LEFT JOIN cancellation AS C ON C.Booking_ID = B.Booking_ID
            WHERE B.User_ID = ?
            ORDER BY B.Booking_Start ASC;
        `;

        const results = await db.getQuery(sql, [userId]);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'No bookings found for this user.' });
        }

        const upcomingBookings = [];
        const pastBookings = [];
        const canceledBookings = [];
        const seenBookings = new Set();

        results.forEach(row => {
            const bookingId = row.Booking_ID;

            if (seenBookings.has(bookingId)) {
                return;
            }
            seenBookings.add(bookingId);

            const booking = {
                bookingId: bookingId,
                checkInDate: row.Check_In_Date,
                checkOutDate: row.Check_Out_Date,
                bookingStatus: row.Booking_Status,
                bookingTotal: row.Booking_Total,
                bookingDate: row.Booking_Date,
                paymentDate: row.Payment_Date,
                paymentStatus: row.Payment_Status,
                paymentMethod: row.Payment_Method,
                promotion: {
                    name: row.Promotion_Name,
                    type: row.Promotion_Type,
                    amount: row.Promotion_Amount
                },
                spot: {
                    spotId: row.Spot_ID,
                    spotName: row.Spot_Name,
                    spotDescription: row.Spot_Description,
                    spotPricePerNight: row.Spot_Price_Per_Night,
                    spotMaxGuests: row.Spot_Max_Guests,
                    categoryId: row.Category_ID,
                    categoryName: row.Category_Name,
                    images: [] // Ensure images are empty to start with
                },
                cancellationDate: row.Cancellation_Time // Check if cancellation exists
            };

            // Accumulate images (all images for this booking)
            if (row.Image_URL && !booking.spot.images.includes(row.Image_URL)) {
                booking.spot.images.push(row.Image_URL);
            }

            // Group bookings into upcoming, past, or canceled
            if (booking.cancellationDate) {
                canceledBookings.push(booking); // If there's a cancellation date, it's considered canceled
            } else if (row.Booking_Type === 'Upcoming') {
                upcomingBookings.push(booking);
            } else {
                pastBookings.push(booking);
            }
        });

        res.json({
            message: 'Bookings retrieved successfully',
            upcomingBookings: upcomingBookings,
            pastBookings: pastBookings,
            canceledBookings: canceledBookings  // Include canceled bookings in a third array
        });
    } catch (error) {
        console.error('Error fetching bookings:', error);
        res.status(500).json({
            message: 'Error fetching bookings',
            error: error.message
        });
    }
});

// Endpoint to cancel a booking
app.post('/api/cancel-booking', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { bookingId, cancellationReason } = req.body;

        if (!bookingId || !cancellationReason) {
            return res.status(400).json({ message: 'Booking ID and cancellation reason are required.' });
        }

        // Step 1: Fetch the booking details for the provided Booking_ID
        const bookingSql = `
            SELECT Booking_ID, Booking_Total, Booking_Status, User_ID
            FROM Booking
            WHERE Booking_ID = ?
        `;
        
        const bookingResults = await db.getQuery(bookingSql, [bookingId]);

        if (!bookingResults || bookingResults.length === 0) {
            return res.status(404).json({ message: 'Booking not found.' });
        }

        const booking = bookingResults[0];

        // Log the fetched booking details
        //console.log('Fetched Booking:', booking);

        // Step 2: Ensure the user is the owner of the booking
        if (booking.User_ID !== userId) {
            return res.status(403).json({ message: 'You are not authorized to cancel this booking.' });
        }

        // Step 3: Ensure the booking is not already canceled
        if (booking.Booking_Status === 'Cancelled') {
            return res.status(400).json({ message: 'This booking has already been canceled.' });
        }

        // Step 4: Calculate the refund (75% of Booking_Total)
        const refundAmount = (booking.Booking_Total * 0.75).toFixed(2);
        //console.log('Calculated Refund Amount:', refundAmount);

        // Step 5: Insert the cancellation record into the 'calcellation' table
        const cancellationSql = `
            INSERT INTO Cancellation (Booking_ID, Cancellation_Reason, Cancellation_Time, Cancellation_Refund_Amount)
            VALUES (?, ?, NOW(), ?)
        `;

        // Log the cancellation data before inserting
        // console.log('Cancellation Data:', {
        //     bookingId,
        //     cancellationReason,
        //     refundAmount
        // });

        await db.getQuery(cancellationSql, [bookingId, cancellationReason, refundAmount]);

        // Step 6: Return success response
        res.json({
            message: 'Booking successfully canceled.',
            refundAmount: refundAmount
        });

    } catch (error) {
        console.error('Error canceling booking:', error);
        res.status(500).json({
            message: 'Error canceling booking.',
            error: error.message
        });
    }
});

// endpoint to submit a review
app.post('/api/submit-review', authenticateToken, async (req, res) => {
    try {
        // Log the incoming data for debugging purposes
        // console.log('Request body:', req.body);
        // console.log('Uploaded file:', req.file); // If you're uploading a file

        const userId = req.user.userId;
        const { spotId, reviewRating, reviewComment } = req.body;
        let reviewImage = null;

        // If an image is uploaded, assign the file path
        if (req.file) {
            reviewImage = req.file.path;  // Store the image path in the database
        }

        // Step 1: Validate the input fields
        if (!spotId || !reviewRating || !reviewComment) {
            return res.status(400).json({ message: 'Spot ID, rating, and comment are required.' });
        }

        if (reviewRating < 1 || reviewRating > 5) {
            return res.status(400).json({ message: 'Rating must be between 1 and 5.' });
        }

        // Step 2: Insert the review into the database
        const reviewSql = `
            INSERT INTO Review (User_ID, Spot_ID, Review_Rating, Review_Comment, Review_Image, Review_Date)
            VALUES (?, ?, ?, ?, ?, NOW())
        `;

        await db.getQuery(reviewSql, [userId, spotId, reviewRating, reviewComment, reviewImage]);

        // Step 3: Return success response
        res.json({ message: 'Review submitted successfully!' });

    } catch (error) {
        console.error('Error submitting review:', error);
        res.status(500).json({
            message: 'Error submitting review.',
            error: error.message
        });
    }
});

// endpoint to fetch upcoming, past, and canceled bookings based on spot_Id
app.post('/api/Owner_Bookings', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Retrieve the userId from the JWT token
        const spotId = req.body.spotId; // Retrieve the spotId from the request body

        if (!userId || typeof userId !== 'number' || !spotId || typeof spotId !== 'number') {
            return res.status(400).json({ message: 'User ID or Spot ID is invalid.' });
        }

        const sql = `
            SELECT 
                B.Booking_ID,
                B.Booking_Start AS Check_In_Date,
                B.Booking_End AS Check_Out_Date,
                B.Booking_Status,
                B.Booking_Total,
                B.Booking_Date,
                P.Payment_Date,
                P.Payment_Status,
                P.Payment_Method,
                PR.Promotion_Name,
                PR.Promotion_Type,
                PR.Promotion_Amount,
                S.Spot_ID,
                S.Spot_Name,
                CASE
                    WHEN B.Booking_End >= CURRENT_DATE THEN 'Upcoming'
                    ELSE 'Past'
                END AS Booking_Type,
                C.Cancellation_Time 
            FROM Booking AS B
            LEFT JOIN Payment AS P ON P.Payment_ID = B.Payment_ID
            LEFT JOIN Promotions AS PR ON PR.Promotion_ID = B.Promotion_ID
            INNER JOIN spots AS S ON B.Spot_ID = S.Spot_ID
            LEFT JOIN cancellation AS C ON C.Booking_ID = B.Booking_ID
            WHERE S.Spot_ID = ? AND B.User_ID = ?
            ORDER BY B.Booking_Start ASC;
        `;

        const results = await db.getQuery(sql, [spotId, userId]);

        if (!results || results.length === 0) {
            // Return empty arrays for each category when no bookings exist
            return res.json({
                message: 'No bookings found for this spot.',
                upcomingBookings: [],
                pastBookings: [],
                canceledBookings: []
            });
        }

        const upcomingBookings = [];
        const pastBookings = [];
        const canceledBookings = [];
        const seenBookings = new Set();

        results.forEach(row => {
            const bookingId = row.Booking_ID;

            if (seenBookings.has(bookingId)) {
                return;
            }
            seenBookings.add(bookingId);

            const booking = {
                bookingId: bookingId,
                checkInDate: row.Check_In_Date,
                checkOutDate: row.Check_Out_Date,
                bookingStatus: row.Booking_Status,
                bookingTotal: row.Booking_Total,
                bookingDate: row.Booking_Date,
                paymentDate: row.Payment_Date,
                paymentStatus: row.Payment_Status,
                paymentMethod: row.Payment_Method,
                promotion: {
                    name: row.Promotion_Name,
                    type: row.Promotion_Type,
                    amount: row.Promotion_Amount
                },
                spot: {
                    spotId: row.Spot_ID,
                    spotName: row.Spot_Name  // Only include the spot name
                },
                cancellationDate: row.Cancellation_Time
            };

            // Group bookings into upcoming, past, or canceled
            if (booking.cancellationDate) {
                canceledBookings.push(booking);
            } else if (row.Booking_Type === 'Upcoming') {
                upcomingBookings.push(booking);
            } else {
                pastBookings.push(booking);
            }
        });

        res.json({
            message: 'Bookings retrieved successfully',
            upcomingBookings,
            pastBookings,
            canceledBookings
        });
    } catch (error) {
        console.error('Error fetching bookings:', error);
        res.status(500).json({
            message: 'Error fetching bookings',
            error: error.message
        });
    }
});

// Update booking status to "Confirmed" and create a notification
app.put('/api/booking/:bookingId/status', authenticateToken, async (req, res) => {
    const { bookingId } = req.params;
    const { spotName } = req.body;  // Get SpotName from the request body

    try {
        // SQL query to check if the booking exists and get associated details
        const checkSql = 'SELECT Booking_Status, User_ID, Booking_Start, Booking_End FROM Booking WHERE Booking_ID = ?';
        const booking = await db.getQuery(checkSql, [bookingId]);
        
        if (booking.length === 0) {
            return res.status(404).json({ message: 'Booking not found' });
        }

        // Check if the booking is already confirmed or not
        if (booking[0].Booking_Status === 'Confirmed') {
            return res.status(400).json({ message: 'Booking is already confirmed' });
        }

        // SQL query to update the booking status to "Confirmed"
        const updateSql = 'UPDATE Booking SET Booking_Status = ? WHERE Booking_ID = ?';
        
        await db.getQuery(updateSql, ['Confirmed', bookingId]);
        
        // Create a notification for the user
        const userId = booking[0].User_ID;
        const bookingStart = booking[0].Booking_Start;
        const bookingEnd = booking[0].Booking_End;
        const notificationContent = `Exciting news! Your booking at ${spotName} from ${bookingStart} to ${bookingEnd} has just been confirmed by the owner. Get ready for your adventure!`;
        
        const notificationSql = 'INSERT INTO Notification (User_ID, Notification_Content, Notification_Read, Notification_Time) VALUES (?, ?, false, NOW())';
        
        await db.getQuery(notificationSql, [userId, notificationContent]);

        res.json({ message: 'Booking status updated to "Confirmed" successfully and notification sent.' });
    } catch (error) {
        res.status(500).json({ message: 'Error updating booking status and creating notification', error: error.message });
    }
});

// endpoint to fetch the most booked spots.
app.get('/api/top-booked-spots', async (req, res) => {
    try {
        // Step 1: Query to get top 5 Spot_IDs based on non-canceled bookings
        const topSpotsQuery = `
        SELECT 
            S.Spot_ID,
            COUNT(B.Booking_ID) AS Booking_Count
        FROM spots AS S
        LEFT JOIN Booking AS B ON S.Spot_ID = B.Spot_ID
        LEFT JOIN Cancellation AS C ON B.Booking_ID = C.Booking_ID
        WHERE C.Booking_ID IS NULL  -- Exclude canceled bookings
        GROUP BY S.Spot_ID
        ORDER BY Booking_Count DESC
        LIMIT 5`;

        const topSpotsResult = await db.getQuery(topSpotsQuery);

        if (!topSpotsResult || topSpotsResult.length === 0) {
            return res.status(404).json({ message: 'No spots found' });
        }

        // Extract Spot_IDs into an array
        const spotIds = topSpotsResult.map(row => row.Spot_ID);
        
        // Step 2: Query to get detailed info for the fetched Spot_IDs
        const spotDetailsQuery = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            S.Spot_Latitude,
            S.Spot_Longitude,
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
        WHERE S.Spot_ID IN (${spotIds.map(() => '?').join(', ')})`;

        // Execute the query with the IDs as individual parameters
        const spotDetailsResult = await db.getQuery(spotDetailsQuery, spotIds);

        if (!spotDetailsResult || spotDetailsResult.length === 0) {
            return res.status(404).json({ message: 'No details found for the top spots' });
        }

        // Step 3: Process results to group spot details by ID
        const spotsMap = new Map();

        spotDetailsResult.forEach(row => {
            if (!spotsMap.has(row.Spot_ID)) {
                spotsMap.set(row.Spot_ID, {
                    id: row.Spot_ID,
                    name: row.Spot_Name,
                    pricePerNight: row.Spot_Price_Per_Night,
                    latitude: row.Spot_Latitude,
                    longitude: row.Spot_Longitude,
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

        // Convert map to array
        const spots = Array.from(spotsMap.values());

        // Respond with the detailed spots information
        res.json({
            message: 'Top booked spots retrieved successfully',
            spots: spots
        });
    } catch (error) {
        console.error('Error fetching top booked spots:', error);
        res.status(500).json({
            message: 'Error fetching top booked spots',
            error: error.message
        });
    }
});

// Endpoint to search for spots by name
app.get('/api/search-spots', async (req, res) => {
    try {
        // Get the search term from the query parameter
        const searchTerm = req.query.q;

        if (!searchTerm) {
            return res.status(400).json({ message: 'Search term is required' });
        }

        // Step 1: Query to get distinct Spot_IDs matching the search term
        const searchQuery = `
            SELECT DISTINCT 
                S.Spot_ID
            FROM spots AS S
            WHERE S.Spot_Name LIKE ? 
        `;

        // Execute query with wildcard search term
        const spotIds = await db.getQuery(searchQuery, [`%${searchTerm}%`]);

        if (spotIds.length === 0) {
            return res.status(404).json({ message: 'No spots found' });
        }

        // Extract Spot_IDs into an array
        const spotIdsArray = spotIds.map(row => row.Spot_ID);

        // Step 2: Query to get detailed info for the fetched Spot_IDs
        const spotDetailsQuery = `
        SELECT 
            S.Spot_ID,
            S.Spot_Name,
            S.Spot_Price_Per_Night,
            S.Spot_Latitude,
            S.Spot_Longitude,
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
        WHERE S.Spot_ID IN (${spotIds.map(() => '?').join(', ')})`;

        // Execute the query with the Spot_IDs as individual parameters
        const spotDetails = await db.getQuery(spotDetailsQuery, spotIdsArray);
        
        if (!spotDetails || spotDetails.length === 0) {
            return res.status(404).json({ message: 'No spot details found' });
        }

        // Step 3: Group spots by ID
        const spotsMap = new Map();
        
        spotDetails.forEach(row => {
            if (!spotsMap.has(row.Spot_ID)) {
                spotsMap.set(row.Spot_ID, {
                    id: row.Spot_ID,
                    name: row.Spot_Name,
                    pricePerNight: row.Spot_Price_Per_Night,
                    latitude: row.Spot_Latitude,
                    longitude: row.Spot_Longitude,
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

        // Convert map to array
        const spots = Array.from(spotsMap.values());
        // Respond with the detailed spots information
        res.json({
            message: 'Search results retrieved successfully',
            spots: spots
        });

    } catch (error) {
        console.error('Error searching spots:', error);
        res.status(500).json({
            message: 'Error searching spots',
            error: error.message,
        });
    }
});

// Endpoint to fetch Poppy's pick (most booked categories by a specific user)
app.get('/api/poppys-pick', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Get userId from JWT token (auth middleware)
        
        // Step 1: Query to get the most booked categories by the user, excluding canceled bookings
        const topCategoriesQuery = `
            SELECT
                SC.Spot_Category_ID AS Category,
                COUNT(*) AS Booked_Count
            FROM
                Booking AS B
            JOIN
                Spots AS S ON B.Spot_ID = S.Spot_ID
            JOIN
                Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
            JOIN
                Spot_Category AS SC ON SSC.Spot_Category_ID = SC.Spot_Category_ID
            LEFT JOIN
                Cancellation AS C ON B.Booking_ID = C.Booking_ID
            WHERE
                B.User_ID = ?  -- Dynamic user ID from token
                AND C.Booking_ID IS NULL  -- Exclude canceled bookings
            GROUP BY
                SC.Spot_Category_ID
            ORDER BY
                Booked_Count DESC
        `;

        const topCategoriesResult = await db.getQuery(topCategoriesQuery, [userId]);

        if (!topCategoriesResult || topCategoriesResult.length === 0) {
            return res.status(404).json({ message: 'No categories found for this user' });
        }

        // Extract category IDs into an array
        const categoryIds = topCategoriesResult.map(row => row.Category);

        // Step 2: Query to get detailed info for the spots that belong to the top categories
        const spotsQuery = `
            SELECT 
                S.Spot_ID,
                S.Spot_Name,
                S.Spot_Price_Per_Night,
                S.Spot_Latitude,
                S.Spot_Longitude,
                Ci.City_Name AS City_Name,
                Co.Country_Name AS Country_Name,
                SC.Spot_Category_Name AS Category_Name,
                M.Media_File_Url AS Image_URL
            FROM 
                spots AS S
            INNER JOIN 
                Spot_Spot_Category AS SSC ON S.Spot_ID = SSC.Spot_ID
            INNER JOIN 
                Spot_Category AS SC ON SC.Spot_Category_ID = SSC.Spot_Category_ID
            INNER JOIN 
                Country AS Co ON S.Country_ID = Co.Country_ID
            INNER JOIN 
                City AS Ci ON S.City_ID = Ci.City_ID
            INNER JOIN 
                Spot_Media AS SM ON S.Spot_ID = SM.Spot_ID
            INNER JOIN 
                Media AS M ON SM.Media_ID = M.Media_ID
            WHERE 
                SC.Spot_Category_ID IN (${categoryIds.map(() => '?').join(', ')})  -- Dynamically created placeholders
        `;

        // Execute the query with the category IDs as parameters
        const spotsResult = await db.getQuery(spotsQuery, categoryIds);

        if (!spotsResult || spotsResult.length === 0) {
            return res.status(404).json({ message: 'No spots found for the top categories' });
        }

        // Step 3: Process results to group spot details by ID
        const spotsMap = new Map();

        spotsResult.forEach(row => {
            if (!spotsMap.has(row.Spot_ID)) {
                spotsMap.set(row.Spot_ID, {
                    id: row.Spot_ID,
                    name: row.Spot_Name,
                    pricePerNight: row.Spot_Price_Per_Night,
                    latitude: row.Spot_Latitude,
                    longitude: row.Spot_Longitude,
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

        // Convert map to array
        const spots = Array.from(spotsMap.values());

        // Respond with the detailed spots information
        res.json({
            message: 'Poppy\'s pick (top booked spots) retrieved successfully',
            spots: spots
        });
    } catch (error) {
        console.error('Error fetching Poppy\'s pick spots:', error);
        res.status(500).json({
            message: 'Error fetching Poppy\'s pick spots',
            error: error.message
        });
    }
});

// Endpoint to fetch notifications for a given user
app.post('/api/Notifications', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Retrieve the userId from the JWT token

        if (!userId || typeof userId !== 'number') {
            return res.status(400).json({ message: 'User ID is invalid.' });
        }

        const sql = `
            SELECT 
                N.Notification_ID,
                N.Notification_Content,
                N.Notification_Time,
                N.Notification_Read
            FROM Notification AS N
            WHERE N.User_ID = ?
            ORDER BY N.Notification_Time DESC;
        `;

        const results = await db.getQuery(sql, [userId]);

        if (!results || results.length === 0) {
            // Return empty arrays when no notifications exist
            return res.json({
                message: 'No notifications found for this user.',
                readNotifications: [],
                unreadNotifications: []
            });
        }

        const readNotifications = [];
        const unreadNotifications = [];

        results.forEach(row => {
            const notification = {
                notificationId: row.Notification_ID,
                content: row.Notification_Content,
                time: row.Notification_Time
            };

            // Group notifications into read or unread
            if (row.Notification_Read) {
                readNotifications.push(notification);
            } else {
                unreadNotifications.push(notification);
            }
        });

        res.json({
            message: 'Notifications retrieved successfully',
            readNotifications,
            unreadNotifications
        });
    } catch (error) {
        console.error('Error fetching notifications:', error);
        res.status(500).json({
            message: 'Error fetching notifications',
            error: error.message
        });
    }
});

// Endpoint to mark a notification as read
app.post('/api/mark-notification-read', authenticateToken, async (req, res) => {
    const { notificationId } = req.body;

    try {
        // Check if the notification exists
        const checkSql = 'SELECT Notification_ID FROM Notification WHERE Notification_ID = ?';
        const notification = await db.getQuery(checkSql, [notificationId]);

        if (notification.length === 0) {
            return res.status(404).json({ message: 'Notification not found.' });
        }

        // Update the notification's read status
        const updateSql = 'UPDATE Notification SET Notification_Read = true WHERE Notification_ID = ?';
        await db.getQuery(updateSql, [notificationId]);

        res.json({ message: 'Notification marked as read successfully.' });
    } catch (error) {
        res.status(500).json({
            message: 'Error marking notification as read',
            error: error.message,
        });
    }
});

// GET /api/gift-cards - Fetch all gift cards
app.get('/api/gift-cards', async (req, res) => {
    try {
        const sql = `
            SELECT 
                Gift_Card_Id,
                Gift_Card_name,
                Gift_Card_amount,
                Gift_Card_description
            FROM Gift_Card
        `;

        const results = await db.getQuery(sql);

        if (!results || results.length === 0) {
            return res.status(404).json({ message: 'No gift cards found' });
        }

        // Optionally, you can format the results before sending
        const giftCards = results.map(row => ({
            id: row.Gift_Card_Id,
            name: row.Gift_Card_name,
            amount: row.Gift_Card_amount,
            description: row.Gift_Card_description
        }));

        res.json({
            message: 'Gift cards retrieved successfully',
            giftCards: giftCards
        });
    } catch (error) {
        console.error('Error fetching gift cards:', error);
        res.status(500).json({ 
            message: 'Error fetching gift cards',
            error: error.message 
        });
    }
});

// endpoint to get giftcard details
app.get('/api/gift-card-details/:id', async (req, res) => {
    const giftCardId = req.params.id;
  
    try {
      const sql = `
        SELECT 
          GC.Gift_Card_ID, 
          GC.Gift_Card_Name, 
          GC.Gift_Card_Amount, 
          GC.Gift_Card_Description
        FROM Gift_Card AS GC
        WHERE GC.Gift_Card_ID = ?
      `;
  
      const results = await db.getQuery(sql, [giftCardId]);
  
      if (!results || results.length === 0) {
        return res.status(404).json({ message: 'Gift card not found' });
      }
  
      res.json({
        message: 'Gift card details retrieved successfully',
        giftCard: results[0]
      });
    } catch (error) {
      console.error('Error fetching gift card details:', error);
      res.status(500).json({
        message: 'Error fetching gift card details',
        error: error.message
      });
    }
});  

// Create gift card purchase and send a notification
app.post('/api/create-gift-card-purchase', authenticateToken, async (req, res) => {
    const { 
        giftCardId,
        paymentId
    } = req.body;

    // console.log("card_ID = " + giftCardId);
    // console.log("Payment_ID = " + paymentId);

    try {
        // Generate a unique Gift Card Purchase Code (e.g., a random 6-digit integer)
        const giftCardPurchaseCode = Math.floor(Math.random() * 1000000);

        // SQL to create the gift card purchase
        const giftCardPurchaseSql = `
            INSERT INTO Gift_Card_Purchase 
                (User_ID, Gift_Card_ID, Payment_ID, Gift_Card_Purchase_Code, Gift_Card_Purchase_Used) 
            VALUES (?, ?, ?, ?, false)
        `;

        // Execute the SQL query
        const giftCardPurchaseResult = await db.getQuery(giftCardPurchaseSql, [
            req.user.userId,
            giftCardId,
            paymentId,
            giftCardPurchaseCode
        ]);

        // Create a notification for the user
        const notificationContent = `Congratulations! Your gift card purchase is successful. Your unique purchase code is ${giftCardPurchaseCode}. Save this code for future use.`;
        const notificationSql = `
            INSERT INTO Notification 
                (User_ID, Notification_Content, Notification_Read, Notification_Time) 
            VALUES (?, ?, false, NOW())
        `;

        // Execute the notification query
        await db.getQuery(notificationSql, [req.user.userId, notificationContent]);

        // Respond with success
        res.json({ 
            message: 'Gift card purchase created successfully',
            giftCardPurchaseId: giftCardPurchaseResult.insertId,
            purchaseCode: giftCardPurchaseCode // Return the purchase code
        });
    } catch (error) {
        console.error('Error creating gift card purchase:', error);
        res.status(500).json({ 
            message: 'Error creating gift card purchase',
            error: error.message 
        });
    }
});

// Fetch promotions
app.get('/api/promotions', async (req, res) => {
    try {
        
        const promotionsSql = `
            SELECT 
                Promotion_Name, 
                Promotion_Description, 
                Promotion_Start, 
                Promotion_End, 
                Promotion_Code, 
                Promotion_Amount
                promotion_Active
            FROM Promotions 
            WHERE Promotion_Active = TRUE`;  // Optional: Filter for active promotions only

        const promotionsResult = await db.getQuery(promotionsSql);

        if (!promotionsResult || promotionsResult.length === 0) {
            return res.status(404).json({
                message: 'No active promotions found',
                promotions: []
            });
        }

        res.json({
            message: 'Active promotions retrieved',
            promotions: promotionsResult
        });
    } catch (error) {
        console.error('Error fetching promotions:', error);
        res.status(500).json({ message: 'Error fetching promotions', error: error.message });
    }
});

// API Contact Types Endpoint
app.get('/api/contact-types', async (req, res) => {
    try {
        // Query to fetch contact types from the Contact_Type table
        const contactTypes = await db.getQuery('SELECT Contact_Type_Name, Contact_Type_ID FROM Contact_Type');
        
        // Filter out duplicate contact types based on Contact_Type_Name
        const uniqueContactTypes = contactTypes.filter((value, index, self) => 
            index === self.findIndex((t) => (
                t.Contact_Type_Name === value.Contact_Type_Name
            ))
        );

        res.json({
            message: 'Contact types retrieved successfully',
            contactTypes: uniqueContactTypes
        });
    } catch (error) {
        console.error('Error fetching contact types:', error);
        res.status(500).json({
            message: 'Error fetching contact types',
            error: error.message
        });
    }
});

// Create Contact Message
app.post('/api/contact-message', authenticateToken, async (req, res) => {
    const { contactTypeId, message } = req.body; // Get type ID and message from frontend
    // console.log(contactTypeId);
    // console.log(message);
    try {
        // SQL to insert the contact message
        const contactMessageSql = `
            INSERT INTO Contact
                (User_ID, Contact_Type_ID, Contact_Message, Contact_Time) 
            VALUES (?, ?, ?, NOW())
        `;

        // Execute the SQL query
        const contactMessageResult = await db.getQuery(contactMessageSql, [
            req.user.userId, // User_ID from authentication
            contactTypeId,   // Contact_Type_ID from frontend
            message          // Contact_Message from frontend
        ]);

        // Respond with success
        res.json({ 
            message: 'Contact message submitted successfully',
            contactMessageId: contactMessageResult.insertId // Return the new message ID
        });
    } catch (error) {
        console.error('Error creating contact message:', error);
        res.status(500).json({ 
            message: 'Error creating contact message',
            error: error.message 
        });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
