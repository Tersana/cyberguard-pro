/**
 * Dedicated AbuseIPDB API proxy endpoint.
 * Accepts the API key and IP as query parameters and makes the request
 * server-side with the correct headers, bypassing all CORS/proxy issues.
 *
 * Usage: GET /api/abuseipdb?ip=1.2.3.4&key=YOUR_KEY&maxAge=90
 */
export default async function handler(req, res) {
  const ip = req.query.ip;
  const apiKey = req.query.key;
  const maxAge = req.query.maxAge || '90';

  if (!ip) {
    return res.status(400).json({ error: 'Missing ip parameter' });
  }
  if (!apiKey) {
    return res.status(400).json({ error: 'Missing key parameter' });
  }

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${encodeURIComponent(maxAge)}&verbose=true`;

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    const body = await response.text();

    // Set CORS headers for browser access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');

    // Return the upstream status and body directly
    return res.status(response.status).end(body);
  } catch (error) {
    return res.status(500).json({ error: `AbuseIPDB request failed: ${error.message}` });
  }
}
