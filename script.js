const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const auth = require("basic-auth");

// Tambahkan modul dns2 untuk DoT
const { DNSoverTLS, Packet } = require('dns2');
const client = new DNSoverTLS({
  dns: '7df33f.dns.nextdns.io',
  port: 853,
  // Jika perlu, tambahkan opsi lain seperti rejectUnauthorized
});

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Fungsi untuk parsing host dari pesan dan mengembalikan juga tipe address
function parseHost(msg, offset) {
  const ATYP = msg.readUInt8(offset++);
  if (ATYP === 1) { // IPv4
    const ipBytes = msg.slice(offset, offset + 4);
    offset += 4;
    return { host: Array.from(ipBytes).join('.'), offset, type: 'IPv4' };
  } else if (ATYP === 2) { // Domain
    const len = msg.readUInt8(offset++);
    const host = msg.slice(offset, offset + len).toString('utf8');
    offset += len;
    return { host, offset, type: 'domain' };
  } else if (ATYP === 3) { // IPv6
    const ipBytes = msg.slice(offset, offset + 16);
    offset += 16;
    const segments = [];
    for (let j = 0; j < 16; j += 2) {
      segments.push(ipBytes.readUInt16BE(j).toString(16));
    }
    return { host: segments.join(':'), offset, type: 'IPv6' };
  } else {
    throw new Error("Unsupported address type: " + ATYP);
  }
}

// Fungsi untuk membuat koneksi ke host target
function connectToTarget(host, targetPort, msg, duplex, ws, offset) {
  const socket = net.connect({ host, port: targetPort }, () => {
    socket.write(msg.slice(offset));
    duplex.pipe(socket).pipe(duplex);
  });

  socket.on('error', (err) => {
    console.error('Socket error:', err);
    socket.destroy();
  });
  duplex.on('error', (err) => {
    console.error('Duplex stream error:', err);
    socket.destroy();
  });
  ws.on('close', () => {
    socket.destroy();
  });
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
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('close', () => {
    clearInterval(interval);
  });

  ws.once('message', (msg) => {
    let offset = msg.readUInt8(17) + 19;
    const targetPort = msg.readUInt16BE(offset);
    offset += 2;

    let parsed;
    try {
      parsed = parseHost(msg, offset);
    } catch (err) {
      console.error('Error parsing host:', err);
      ws.close();
      return;
    }

    ws.send(Buffer.from([msg[0], 0]));

    const duplex = WebSocket.createWebSocketStream(ws);

    // Jika tipe adalah domain, lakukan resolusi via DoT
    if (parsed.type === 'domain') {
      client.resolve(parsed.host, Packet.TYPE.A)
        .then((answer) => {
          const aRecord = answer.answers.find(record => record.address);
          if (!aRecord) {
            console.error("Tidak ditemukan A record untuk domain:", parsed.host);
            ws.close();
            return;
          }
          connectToTarget(aRecord.address, targetPort, msg, duplex, ws, parsed.offset);
        })
        .catch((err) => {
          console.error("Kesalahan DoT resolution:", err);
          ws.close();
        });
    } else {
      // Untuk IPv4 atau IPv6, langsung gunakan host yang telah diparsing
      connectToTarget(parsed.host, targetPort, msg, duplex, ws, parsed.offset);
    }
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
  // Error saja yang akan dicatat di console jika terjadi
});
