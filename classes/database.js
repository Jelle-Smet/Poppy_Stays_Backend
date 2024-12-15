const mysql = require('mysql2/promise');
require('dotenv').config();

class Database {
    async connect() {
        try {
            console.log('Connecting to the database...');
            const connection = await mysql.createConnection({
                host: process.env.db_host,
                user: process.env.db_user,
                password: process.env.db_pass,
                database: process.env.db_name,
                port: process.env.db_port
            });

            console.log('Successfully connected to the database');
            return connection;
        } catch (error) {
            console.error('Error connecting to the database:', error.message);
            throw error; // Throw error to be handled by the calling function
        }
    }

    async getQuery(sql, params) {
        const connection = await this.connect();

        try {
            const [rows] = await connection.execute(sql, params);
            return rows;
        } catch (error) {
            console.error('Error executing query:', error.message);
            throw error; // Throw error to be handled by the calling function
        } finally {
            await connection.end(); // Close the connection after the query is done
            console.log('Database connection closed');
        }
    }
}

module.exports = Database;
