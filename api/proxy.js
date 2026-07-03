export default async function handler(req, res) {
  // Extract URL from query
  const targetUrl = req.query.url;
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  try {
    // Forward incoming request headers while ignoring host/connection/Vercel-specific headers
    const headers = {};
    const ignoredHeaders = [
      'host',
      'connection',
      'origin',
      'referer',
      'cookie',
      'sec-ch-ua',
      'sec-ch-ua-mobile',
      'sec-ch-ua-platform',
      'sec-fetch-dest',
      'sec-fetch-mode',
      'sec-fetch-site',
      'x-forwarded-for',
      'x-forwarded-proto',
      'x-vercel-id',
      'x-vercel-ip-country'
    ];

    Object.keys(req.headers).forEach(key => {
      if (!ignoredHeaders.includes(key.toLowerCase())) {
        headers[key] = req.headers[key];
      }
    });

    // Support extra headers passed as JSON via the `headers` query param.
    // This lets the client inject API-specific auth headers (e.g. AbuseIPDB Key)
    // server-side, avoiding browser CORS restrictions on custom headers.
    if (req.query.headers) {
      try {
        const extraHeaders = JSON.parse(req.query.headers);
        Object.assign(headers, extraHeaders);
      } catch (_) {
        // Ignore malformed JSON
      }
    }

    // Ensure User-Agent is present
    if (!headers['user-agent'] && !headers['User-Agent']) {
      headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }

    // Perform server-side fetch bypassing CORS
    const response = await fetch(targetUrl, {
      method: req.method,
      headers: headers
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
