/**
 * Quick test: verify the AbuseIPDB API endpoint works with a direct fetch.
 * Usage: node scratch/test-abuseipdb.js <YOUR_API_KEY>
 */

const apiKey = process.argv[2];
if (!apiKey) {
  console.error('Usage: node scratch/test-abuseipdb.js <API_KEY>');
  process.exit(1);
}

const testIP = '172.234.163.154';
const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${testIP}&maxAgeInDays=90&verbose=true`;

console.log('--- AbuseIPDB Direct Test ---');
console.log('URL:', url);
console.log('Key header (first 8 chars):', apiKey.substring(0, 8) + '...');

(async () => {
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });
    console.log('Status:', res.status, res.statusText);
    const body = await res.text();
    console.log('Body:', body.substring(0, 500));
  } catch (err) {
    console.error('Fetch error:', err);
  }
})();
