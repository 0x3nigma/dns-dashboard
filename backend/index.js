const express = require('express');

// App Setup
const app = express();
const PORT = 3000;

// Middleware for parsing JSON Request Bodies
app.use(express.json());

// Handling CORS (Cross-Origin-Resource Sharing)

app.use((req, res, next)=>{
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Method", "GET");
    next();
});

// Querying the backend api for dns
async function queryArgus(endpoint, domain){
    const response = await fetch(`http://argus-service:5000/${endpoint}/${domain}`);
    const data = await response.json();
    return data;
}

// get health
app.get("/health", (req, res) => {
    res.json({ status: "ok", uptime: Math.floor(process.uptime()) });
});

// get for /api/dns/domain
app.get("/api/dns/:domain", async (req, res)=>{
    try{
        const data = await queryArgus("scan", req.params.domain);
        res.json(data);
    }
    catch(err){
        res.status(500).json({error: err.message});
    }
});

// get for /api/dnssec/domain
app.get("/api/dnssec/:domain", async (req, res)=>{
    try{
        const data = await queryArgus("dnssec", req.params.domain);
        res.json(data);
    }
    catch(err){
        res.status(500).json({error: err.message});
    }
});

// get for /api/compare/domain
app.get("/api/compare/:domain", async (req, res)=>{
    try{
        const data = await queryArgus("compare", req.params.domain);
        res.json(data);
    }
    catch(err){
        res.status(500).json({error: err.message});
    }
});

app.listen(PORT, ()=>{
    console.log(`DNS Dashboard API running on port ${PORT}`);
});
