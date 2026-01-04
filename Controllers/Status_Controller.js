// We create the instance exactly like your working Maintenance Controller
const db = new (require('../Classes/database'))(); 

exports.getSystemStatus = async (req, res) => {
    console.log("🔍 System Status Check triggered...");
    
    let dbStatus = 'Online'; 

    try {
        // We use the exact same method that worked in your heartbeat: getQuery
        // We 'await' it to ensure the code waits for the database to respond
        await db.getQuery("SELECT 1"); 
        console.log("✅ Database is responsive.");
    } catch (error) {
        // If the query fails, we catch the error and mark it as offline
        console.error('❌ Database check failed:', error.message);
        dbStatus = 'Offline'; 
    }

    // Return the response in the format you wanted
    return res.status(200).json({
        serviceStatus: 'Online',      // The Express server itself is running
        databaseStatus: dbStatus      // 'Online' or 'Offline'
    });
};