const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Tail } = require('tail');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "http://localhost:3000" }
});

const NETWORK_FEATURES = '../Processing/ml_network_features.jsonl';
const SYSTEM_FEATURES = '../Processing/system_ml_features.jsonl';
const BACKUPS_FILE = '../Processing/backups.jsonl';
const ALERTS_FEATURES = '../Processing/alerts.jsonl';
const RAW_SYSTEM = '../Collectors/system_events.jsonl';
const EVENT_LOGS = '../Collectors/event_logs.jsonl'; 

if (!fs.existsSync(NETWORK_FEATURES)) fs.writeFileSync(NETWORK_FEATURES, '');
if (!fs.existsSync(SYSTEM_FEATURES)) fs.writeFileSync(SYSTEM_FEATURES, '');
if (!fs.existsSync(ALERTS_FEATURES)) fs.writeFileSync(ALERTS_FEATURES, '');
if (!fs.existsSync(BACKUPS_FILE)) fs.writeFileSync(BACKUPS_FILE, '');
if (!fs.existsSync(RAW_SYSTEM)) fs.writeFileSync(RAW_SYSTEM, '');
if (!fs.existsSync(EVENT_LOGS)) fs.writeFileSync(EVENT_LOGS, '');

// NEW: Force Tail to aggressively watch the file system, preventing silent crashes
const tailOpts = { useWatchFile: true, fsWatchOptions: { interval: 500 } };

const tailNetwork = new Tail(NETWORK_FEATURES, tailOpts);
const tailSystem = new Tail(SYSTEM_FEATURES, tailOpts);
const tailAlerts = new Tail(ALERTS_FEATURES, tailOpts);
const tailBackups = new Tail(BACKUPS_FILE, tailOpts);
const tailRawSystem = new Tail(RAW_SYSTEM, tailOpts);
const tailEventLogs = new Tail(EVENT_LOGS, tailOpts);

io.on('connection', (socket) => {
    console.log(`[+] Dashboard client connected: ${socket.id}`);
});

tailAlerts.on("line", (data) => { try { io.emit('ml_alert', JSON.parse(data)); } catch (e) {} });
tailBackups.on("line", (data) => { try { io.emit('s3_backup', JSON.parse(data)); } catch (e) {} });
tailNetwork.on("line", (data) => { try { io.emit('network_update', JSON.parse(data)); } catch (e) {} });
tailSystem.on("line", (data) => { try { io.emit('system_update', JSON.parse(data)); } catch (e) {} });
tailRawSystem.on("line", (data) => { try { io.emit('raw_system_update', JSON.parse(data)); } catch (e) {} });
tailEventLogs.on("line", (data) => { try { io.emit('raw_event_log', JSON.parse(data)); } catch (e) {} });

server.listen(4000, () => {
    console.log('[*] API Server streaming on http://localhost:4000');
}); 