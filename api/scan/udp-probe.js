import dgram from 'dgram';

const PROBES = {
  53: Buffer.from([
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01
  ]),
  123: (() => {
    const buf = Buffer.alloc(48);
    buf[0] = 0x1B;
    return buf;
  })(),
  1900: Buffer.from(
    'M-SEARCH * HTTP/1.1\r\n' +
    'HOST: 239.255.255.250:1900\r\n' +
    'MAN: "ssdp:discover"\r\n' +
    'MX: 1\r\n' +
    'ST: ssdp:all\r\n\r\n'
  ),
  5353: Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x09, 0x5f, 0x73, 0x65,
    0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f,
    0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 0x04, 0x5f,
    0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01
  ])
};

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
        const payload = PROBES[port] || Buffer.alloc(8);
        return new Promise((resolve) => {
          const client = dgram.createSocket('udp4');
          let answered = false;
          const startTime = Date.now();

          client.on('message', () => {
            answered = true;
            client.close();
          });

          client.on('error', () => {
            client.close();
          });

          client.on('close', () => {
            resolve({
              port,
              status: answered ? 'open' : 'closed/filtered',
              latency: Date.now() - startTime
            });
          });

          client.send(payload, 0, payload.length, port, host, (err) => {
            if (err) {
              client.close();
            }
          });

          setTimeout(() => {
            if (!answered) {
              client.close();
            }
          }, 1500);
        });
      })
    );

    return res.status(200).json({ host, results });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
