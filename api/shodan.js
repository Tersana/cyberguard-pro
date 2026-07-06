import dns from 'dns';

/**
 * Dedicated Shodan API proxy endpoint.
 * Accepts the IP/Domain as query parameters and queries Shodan server-side,
 * resolving domains to IPs if needed, bypassing CORS issues.
 *
 * Usage: GET /api/shodan?host=8.8.8.8&key=YOUR_KEY
 */
export default async function handler(req, res) {
  const host = req.query.host || req.query.ip;
  const apiKey = req.query.key || 'oL1wHP4qa2zzeF08o31ZIACZQqkb3Rzw';

  if (!host) {
    return res.status(400).json({ error: 'Missing host parameter' });
  }

  // Set CORS headers for browser access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  let ip = host.trim();

  // Helper to check if string is a valid IPv4
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;

  // If host is a domain, resolve it
  if (!ipv4Regex.test(ip)) {
    try {
      const records = await dns.promises.resolve4(ip);
      if (records && records.length > 0) {
        ip = records[0];
      } else {
        return res.status(400).json({ error: `Could not resolve domain ${host} to an IPv4 address` });
      }
    } catch (err) {
      // Fallback: if DNS resolution fails, try Cloudflare/Google DNS over HTTPS
      try {
        const dohResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ip)}&type=A`, {
          headers: { Accept: 'application/dns-json' }
        });
        if (dohResponse.ok) {
          const data = await dohResponse.json();
          const aRecord = data.Answer?.find(r => r.type === 1);
          if (aRecord?.data) {
            ip = aRecord.data;
          } else {
            return res.status(400).json({ error: `DNS resolution failed for domain: ${host}` });
          }
        } else {
          return res.status(400).json({ error: `DNS resolution failed for domain: ${host}` });
        }
      } catch (dohErr) {
        return res.status(400).json({ error: `Failed to resolve host ${host}: ${err.message}` });
      }
    }
  }

  const shodanUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`;

  try {
    const response = await fetch(shodanUrl);
    
    // If the Shodan Host API succeeds, return its contents
    if (response.ok) {
      const data = await response.json();
      return res.status(200).json(data);
    }

    // If Shodan Host API returns 404 (host not found) or another error (rate limit, etc.),
    // fall back to Shodan InternetDB
    const internetDbUrl = `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;
    const idbResponse = await fetch(internetDbUrl);
    
    if (idbResponse.ok) {
      const idbData = await idbResponse.json();
      
      // Map InternetDB response to look like Shodan Host API response
      const mappedData = {
        ip_str: ip,
        ports: idbData.ports || [],
        hostnames: idbData.hostnames || [],
        vulns: idbData.vulns || [],
        tags: idbData.tags || [],
        cpes: idbData.cpes || [],
        org: 'Shodan InternetDB (Cached)',
        isp: 'Shodan InternetDB (Cached)',
        os: 'Unknown',
        last_update: new Date().toISOString(),
        location: {
          country_name: 'Unknown',
          city: 'Unknown'
        },
        data: (idbData.ports || []).map(port => {
          // Map each port to the service name if possible
          const PORT_SERVICES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            3000: "Dev-Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB"
          };
          return {
            port,
            transport: 'tcp',
            product: PORT_SERVICES[port] || 'Unknown',
            version: '',
            data: '',
            vulns: idbData.vulns || []
          };
        })
      };
      return res.status(200).json(mappedData);
    }

    // If both failed, return the original Shodan Host API error message
    const errorText = await response.text();
    let errorJson;
    try {
      errorJson = JSON.parse(errorText);
    } catch (_) {}
    return res.status(response.status).json({
      error: errorJson?.error || `Shodan query failed with status ${response.status}`
    });
  } catch (error) {
    // If fetch failed completely, try InternetDB as final failover
    try {
      const internetDbUrl = `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;
      const idbResponse = await fetch(internetDbUrl);
      if (idbResponse.ok) {
        const idbData = await idbResponse.json();
        return res.status(200).json({
          ip_str: ip,
          ports: idbData.ports || [],
          hostnames: idbData.hostnames || [],
          vulns: idbData.vulns || [],
          tags: idbData.tags || [],
          cpes: idbData.cpes || [],
          org: 'Shodan InternetDB (Cached)',
          isp: 'Shodan InternetDB (Cached)',
          os: 'Unknown',
          last_update: new Date().toISOString(),
          location: {
            country_name: 'Unknown',
            city: 'Unknown'
          },
          data: (idbData.ports || []).map(port => ({
            port,
            transport: 'tcp',
            product: 'Unknown',
            version: '',
            data: '',
            vulns: idbData.vulns || []
          }))
        });
      }
    } catch (_) {}
    return res.status(500).json({ error: `Failed to query Shodan: ${error.message}` });
  }
}
