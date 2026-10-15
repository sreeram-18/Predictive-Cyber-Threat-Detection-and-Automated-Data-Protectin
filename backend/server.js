const express = require('express');
const http = require('http');
const AWS = require('aws-sdk');
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

// 1. CONFIGURE AWS FIRST
AWS.config.update({
  accessKeyId: "AKIASAJYQTTZGXFIZAS6", 
  secretAccessKey: "xGvIzzNwT5ZFPAhN3HSkOPB/gq/BYXADCnBsgGI1", 
  region: 'us-east-1', // Ensure this matches your bucket's region (e.g., ap-south-1 for Mumbai, us-east-1 for N. Virginia)
  signatureVersion: 'v4'
});

// 2. INITIALIZE S3 SECOND
const s3 = new AWS.S3();

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

app.get('/api/download', async (req, res) => {
  let fileName = req.query.file;
  const bucketName = req.query.bucket || 'siem-backup-prajwal-2026';

  if (!fileName) {
    return res.status(400).json({ error: "Missing file name" });
  }

  try {
    let resolvedKey = fileName;

    // If the React frontend only sends the filename, search the S3 bucket for the full path
    if (!resolvedKey.startsWith("vault/")) {
      const listParams = {
        Bucket: bucketName,
        Prefix: 'vault/'
      };

      const listedObjects = await s3.listObjectsV2(listParams).promise();
      
      // Look for the exact file inside the vault folders
      const match = listedObjects.Contents.find(item => item.Key.endsWith(fileName));

      if (match) {
        resolvedKey = match.Key; // We found the full path (e.g., vault/2026-10-15_1792077979/sensitive_document.txt)
      } else {
        return res.status(404).json({ error: `File ${fileName} not found in AWS vault.` });
      }
    }

    const downloadParams = {
      Bucket: bucketName,
      Key: resolvedKey,
      Expires: 900 // Link expires in 15 minutes
    };

    s3.getSignedUrl('getObject', downloadParams, (err, url) => {
      if (err) {
        console.error("AWS S3 Error:", err);
        return res.status(500).json({ error: "Failed to generate download link" });
      }
      res.json({ url });
    });

  } catch (error) {
    console.error("S3 Lookup Error:", error);
    res.status(500).json({ error: "Failed to locate file in S3" });
  }
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