const bcrypt = require('bcrypt');
const Database = require('./classes/database'); // Import your database class

// Create an instance of the Database class
const db = new Database();

// Function to hash existing user passwords
const hashExistingPasswords = async () => {
    try {
        // Fetch all users with plain text passwords from the database
        const sql = 'SELECT User_ID, User_Password FROM User';
        const users = await db.getQuery(sql);

        // Loop through all users and hash their passwords
        for (let user of users) {
            const hashedPassword = await bcrypt.hash(user.User_Password, 10);

            // Update the user's password with the hashed version
            const updateSql = 'UPDATE User SET User_Password = ? WHERE User_ID = ?';
            await db.getQuery(updateSql, [hashedPassword, user.User_ID]);

            console.log(`Password for user ID ${user.User_ID} updated.`);
        }

        console.log('All existing passwords have been hashed and updated.');
    } catch (error) {
        console.error('Error hashing passwords:', error);
    }
};

// Run the function to hash and update passwords
hashExistingPasswords();
