export default async function handler(req, res) {
  // Extract URL from query
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  try {
    // Perform server-side fetch bypassing CORS
    const response = await fetch(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
      }
    });

    const html = await response.text();
    const headersObj = {};
    response.headers.forEach((value, key) => {
      headersObj[key] = value;
    });

    // Match exact proxy structure for seamless drop-in operation
    res.status(200).json({
      contents: html,
      headers: headersObj,
      status: {
        http_code: response.status
      }
    });
  } catch (error) {
    res.status(500).json({ error: `Failed to proxy request: ${error.message}` });
  }
}
