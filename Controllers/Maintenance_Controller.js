// We need to create an instance of the database class using 'new'
const db = new (require('../Classes/database'))(); 

exports.keepUniverseAlive = async (req, res) => {
    console.log("💓 Heartbeat started: Poking all systems...");
    
    // We use Promise.allSettled so one failure doesn't crash the whole script
    const results = await Promise.allSettled([
        // 1. Poke Aiven DB (Using your custom getQuery method)
        db.getQuery("SELECT 1"),

        // 2. Poke C# Engine
        fetch(`${process.env.ENGINE_URL}/`).catch(err => console.log("Engine Poke Failed:", err.message)),

        // 3. Poke ML Service
        fetch(`${process.env.ML_SERVICE_URL}/`, {
            headers: { 'Authorization': `Bearer ${process.env.HF_TOKEN}` }
        }).catch(err => console.log("ML Poke Failed:", err.message))
    ]);

    const status = results.map((res, i) => ({
        service: ["Database", "Engine", "ML_Service"][i],
        status: res.status === "fulfilled" ? "✅ Awake" : "❌ Failed/Sleeping"
    }));

    console.log("📊 Heartbeat Result:", status);

    return res.status(200).json({ 
        success: true, 
        message: "Heartbeat pulse sent to the Poppy Universe.",
        system_status: status
    });
};