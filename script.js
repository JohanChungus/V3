const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const auth = require("basic-auth");

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;
// KHUSUS UNTUK NODE.JS
const { exec } = require('child_process');
(async () => {
  exec('./nezha-agent &', (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
  });
})();
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Fungsi untuk parsing host dari pesan
function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  if (ATYP === 1) { // IPv4
    const ipBytes = msg.slice(offset, offset + 4);
    offset += 4;
    return { host: Array.from(ipBytes).join('.'), offset };
  } else if (ATYP === 2) { // Domain
    const len = msg.readUInt8(offset++);
    const host = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
    return { host, offset };
  } else if (ATYP === 3) { // IPv6
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    return { host: segments.join(':'), offset };
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
}

// Menangani koneksi baru
wss.on('connection', (ws) => {
  ws.isAlive = true;

  // Jika menerima pong, berarti koneksi masih hidup
  ws.on('pong', () => {
    ws.isAlive = true;
  });

  // Heartbeat interval untuk menjaga koneksi tetap aktif
  const interval = setInterval(() => {
    if (!ws.isAlive) {
      ws.terminate(); // Terminasi jika tidak responsif
      return;
    }
    ws.isAlive = false;
    ws.ping(); // Kirim ping untuk mengecek koneksi
  }, 30000); // Ping setiap 30 detik

  ws.on('close', () => {
    console.log('WebSocket telah tertutup.');
    clearInterval(interval);
  });

  ws.once('message', (msg) => {
    let offset = msg.readUInt8(17) + 19;
    const targetPort = msg.readUInt16BE(offset);
    offset += 2;

    let host;
    try {
      ({ host, offset } = parseHost(msg, offset));
    } catch (err) {
      console.error('Error parsing host:', err);
      ws.close();
      return;
    }

    ws.send(Buffer.from([msg[0], 0]));

    const duplex = WebSocket.createWebSocketStream(ws);
    const socket = net.connect({ host, port: targetPort }, () => {
      socket.write(msg.slice(offset));
      duplex.pipe(socket).pipe(duplex);
    });

    // Menangani error pada socket dan duplex
    socket.on('error', (err) => {
      console.error('Socket error:', err);
      socket.destroy(); // Hentikan socket jika terjadi error
    });

    duplex.on('error', (err) => {
      console.error('Duplex stream error:', err);
      socket.destroy(); // Hentikan socket jika duplex stream error
    });

    ws.on('close', () => {
      console.log('WebSocket ditutup, menghentikan koneksi socket.');
      socket.destroy(); // Hentikan socket jika WebSocket ditutup
    });
  });
});

// Middleware untuk autentikasi
app.use((req, res, next) => {
  const user = auth(req);
  if (user && user.name === username && user.pass === password) {
    return next();
  }
  res.set("WWW-Authenticate", 'Basic realm="Node"');
  res.status(401).send();
});

// Endpoint untuk menghasilkan konfigurasi
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

// Menjalankan server
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
