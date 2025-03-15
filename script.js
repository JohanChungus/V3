const net = require('net');
const WebSocket = require('ws');
const express = require('express');
const http = require('http');
const auth = require('basic-auth');
const dns = require('dns'); // Modul DNS bawaan Node.js

const username = process.env.WEB_USERNAME || "admin";
const password = process.env.WEB_PASSWORD || "password";

const uuid = (process.env.UUID || '37a0bd7c-8b9f-4693-8916-bd1e2da0a817').replace(/-/g, '');
const port = process.env.PORT || 7860;

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Konfigurasi NextDNS DoT
dns.setServers(['7df33f.dns.nextdns.io:53']); // Gunakan server DoT NextDNS (dengan port 53)


// Fungsi untuk parsing host dari pesan (validasi ATYP yang lebih baik)
function parseHost(msg, offset) {
    const ATYP = msg.readUInt8(offset++);
    if (ATYP === 1) { // IPv4
        const ipBytes = msg.slice(offset, offset + 4);
        offset += 4;
        return { host: Array.from(ipBytes).join('.'), offset, type: 'IPv4' };
    } else if (ATYP === 4) { // Domain
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

    ws.once('message', async (msg) => { // Gunakan async/await
        try {
            let offset = msg.readUInt8(17) + 19;
            const targetPort = msg.readUInt16BE(offset);
            offset += 2;

            let hostInfo;
            try {
                hostInfo = parseHost(msg, offset);
            } catch (err) {
                console.error('Error parsing host:', err);
                ws.close(1002, 'Protocol Error'); // Tutup dengan kode dan pesan
                return;
            }

            ws.send(Buffer.from([msg[0], 0]));

            const duplex = WebSocket.createWebSocketStream(ws);
             // Resolve DNS using NextDNS *if* it's a domain
            let resolvedHost = hostInfo.host;  // Default to original host (if already an IP)
           if (hostInfo.type === 'domain') {
                try {
                  const addresses = await new Promise((resolve, reject) => {
                    dns.resolve4(hostInfo.host, (err, addresses) => {
                        if(err) reject(err);
                        else resolve(addresses);
                    });
                });
                
                if (!addresses || addresses.length === 0) {
                  throw new Error("No addresses found for host: " + hostInfo.host);
                }
                  resolvedHost = addresses[0]; // Ambil alamat pertama (bisa diubah)
                  console.log(`Resolved ${hostInfo.host} to ${resolvedHost}`); // Log resolusi

                } catch (resolveErr) {
                    console.error('DNS resolution error:', resolveErr);
                    ws.close(1002, 'DNS Resolution Error');
                    return;
                }
            }

            const socket = net.connect({ host: resolvedHost, port: targetPort }, () => {
                socket.write(msg.slice(hostInfo.offset)); // Use original offset
                duplex.pipe(socket).pipe(duplex);
            });

            socket.on('error', (err) => {
                console.error('Socket error:', err);
                socket.destroy(); // Hentikan socket jika terjadi error
            });

            duplex.on('error', (err) => {
                console.error('Duplex stream error:', err);
                socket.destroy(); // Hentikan socket jika duplex stream error
            });

            ws.on('close', () => {
                socket.destroy(); // Hentikan socket jika WebSocket ditutup
            });


        } catch (err) {
            console.error('Unhandled error in message handler:', err);
            ws.close(1011, 'Internal Error'); // Tutup dengan kode 1011 (Internal Error)
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


server.listen(port, () => {
  // Tidak ada console.log, hanya error yang dicatat
});
