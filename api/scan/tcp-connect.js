import net from 'net';

export default async function handler(req, res) {
  const host = req.query.host || req.body?.host;
  const portsParam = req.query.ports || req.body?.ports;

  if (!host || !portsParam) {
    return res.status(400).json({ error: 'Missing host or ports parameter' });
  }

  let ports = [];
  if (Array.isArray(portsParam)) {
    ports = portsParam.map(Number);
  } else {
    ports = String(portsParam).split(',').map(p => Number(p.trim())).filter(p => !isNaN(p));
  }

  if (ports.length === 0) {
    return res.status(400).json({ error: 'No valid ports specified' });
  }

  try {
    const results = await Promise.all(
      ports.map(port => {
        return new Promise((resolve) => {
          const socket = new net.Socket();
          let status = 'closed';
          const startTime = Date.now();

          socket.setTimeout(1500);

          socket.on('connect', () => {
            status = 'open';
            socket.destroy();
          });

          socket.on('timeout', () => {
            status = 'timeout';
            socket.destroy();
          });

          socket.on('error', () => {
            status = 'closed';
          });

          socket.on('close', () => {
            resolve({
              port,
              status,
              latency: Date.now() - startTime
            });
          });

          socket.connect(port, host);
        });
      })
    );

    return res.status(200).json({ host, results });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
