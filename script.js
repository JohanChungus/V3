const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const auth = require("basic-auth");
const { DNSOverTLS } = require('dns2'); // Tambahkan dependensi dns2

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Inisialisasi resolver DNS over TLS
const dotResolver = new DNSOverTLS({
  dns: '7df33f.dns.nextdns.io',
  port: 853
});

// Fungsi untuk parsing host dari pesan (termasuk ATYP)
function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  if (ATYP === 1) { // IPv4
    const ipBytes = msg.slice(offset, offset + 4);
    offset += 4;
    return { host: Array.from(ipBytes).join('.'), offset, atyp: ATYP };
  } else if (ATYP === 2) { // Domain
    const len = msg.readUInt8(offset++);
    const host = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
    return { host, offset, atyp: ATYP };
  } else if (ATYP === 3) { // IPv6
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    return { host: segments.join(':'), offset, atyp: ATYP };
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
}

wss.on('connection', (ws) => {
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const interval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', async (msg) => {
    try {
      let offset = msg.readUInt8(17) + 19;
      const targetPort = msg.readUInt16BE(offset);
      offset += 2;

      let host, atyp;
      try {
        ({ host, offset, atyp } = parseHost(msg, offset));
      } catch (err) {
        console.error('Error parsing host:', err);
        ws.close();
        return;
      }

      ws.send(Buffer.from([msg[0], 0]));

      const duplex = WebSocket.createWebSocketStream(ws);
      let resolvedHost = host;

      // Resolve via DoT jika ATYP adalah domain (2)
      if (atyp === 2) {
        try {
          const response = await dotResolver.resolveA(host);
          if (response.answers.length === 0) {
            throw new Error('DNS block: ' + host);
          }
          resolvedHost = response.answers[0].address;
        } catch (err) {
          console.error('DNS error:', err);
          ws.close();
          return;
        }
      }

      const socket = net.connect({
        host: resolvedHost,
        port: targetPort
      }, () => {
        socket.write(msg.slice(offset));
        duplex.pipe(socket).pipe(duplex);
      });

      socket.on('error', (err) => {
        console.error('Socket error:', err);
        socket.destroy();
      });

      duplex.on('error', (err) => {
        console.error('Duplex error:', err);
        socket.destroy();
      });

      ws.on('close', () => {
        socket.destroy();
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      ws.close();
    }
  });
});

app.use((req, res, next) => {
  const user = auth(req);
  if (user && user.name === username && user.pass === password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  res.status(401).send();
});

app.get('*', (req, res) => {
  const protocol = req.protocol;
  let host = req.get('host');
  let portNum = protocol === 'https' ? 443 : 80;
  const path = req.path;

  if (host.includes(':')) {
    [host, portNum] = host.split(':');
  }

  const link = protocol === 'https'
    ? `pler://${uuid}@${host}:${portNum}?path=${path}&security=tls&encryption=none&host=${host}&type=ws&sni=${host}#node-pler`
    : `pler://${uuid}@${host}:${portNum}?type=ws&encryption=none&flow=&host=${host}&path=${path}#node-pler`;

  res.send(`<html><body><pre>${link}</pre></body></html>`);
});

server.listen(port, () => {});
