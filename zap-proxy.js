const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const cors = require("cors");

const app = express();
const PORT = 3001;

// Enable CORS for all routes
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  })
);

// Proxy all requests to ZAP API
app.use(
  "/zap",
  createProxyMiddleware({
    target: "http://localhost:8080",
    changeOrigin: true,
    pathRewrite: {
      "^/zap": "/JSON",
    },
    onError: (err, req, res) => {
      console.error("Proxy Error:", err);
      res.status(500).json({ error: "ZAP API not accessible" });
    },
  })
);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "ZAP Proxy Server Running" });
});

app.listen(PORT, () => {
  console.log(`🚀 ZAP Proxy Server running on http://localhost:${PORT}`);
  console.log(`📡 Proxying requests to ZAP API at http://localhost:8080`);
  console.log(`🔗 Use http://localhost:${PORT}/zap/ for ZAP API calls`);
});


