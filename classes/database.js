// db.js
const mysql = require('mysql2/promise');
require('dotenv').config();

class Database {
    constructor() {
        // Create a connection pool
        this.pool = mysql.createPool({
            host: process.env.db_host,
            user: process.env.db_user,
            password: process.env.db_pass,
            database: process.env.db_name,
            port: process.env.db_port,
        });
    }

    // Method to query the database
    async getQuery(sql, params) {
        try {
            // Execute the query using the connection pool
            const [rows] = await this.pool.execute(sql, params);
            return rows;
        } catch (error) {
            console.error('Error executing query:', error.message);
            throw error; // Rethrow error to be handled by the calling function
        }
    }

    // Method to close the connection pool gracefully (optional)
    async close() {
        try {
            await this.pool.end();
            console.log('Database pool closed');
        } catch (error) {
            console.error('Error closing database pool:', error.message);
        }
    }
}

module.exports = Database;  // Exporting the class itself, not the instance
