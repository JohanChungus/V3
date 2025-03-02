const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const auth = require("basic-auth");

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

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

wss.on('connection', (ws) => {
  ws.once('message', (msg) => {
    let offset = msg.readUInt8(17) + 19;
    const targetPort = msg.readUInt16BE(offset);
    offset += 2;

    let host;
    try {
      ({ host, offset } = parseHost(msg, offset));
    } catch (err) {
      ws.close();
      return;
    }

    ws.send(Buffer.from([msg[0], 0]));

    const duplex = WebSocket.createWebSocketStream(ws);
    const socket = net.connect({ host, port: targetPort }, () => {
      socket.write(msg.slice(offset));
      duplex.pipe(socket).pipe(duplex);
    });
    socket.on('error', () => {});
    duplex.on('error', () => {});
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

server.listen(port);
