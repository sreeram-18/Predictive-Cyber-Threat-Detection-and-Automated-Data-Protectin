import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { io } from 'socket.io-client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const socket = io('http://localhost:4000');

const getEventDescription = (id) => {
  const descriptions = {
    2: "File Creation Time Changed",
    5: "Background Process Terminated",
    1102: "🚨 Audit Log Cleared (Potential Evasion)",
    4624: "Successful Logon", 
    4625: "❌ Failed Logon Attempt", 
    4634: "Logoff",
    4648: "Logon using explicit credentials", 
    4672: "Admin/Special Privileges Assigned",
    4688: "New Process Created", 
    4689: "Process Terminated",
    4697: "Service Installed (Potential Persistence)",
    4720: "New User Account Created",
    4732: "User Added to Privileged Group",
    4798: "Local Group Enumerated (Routine)", 
    4799: "Security Group Enumerated (Routine)",
    5058: "Cryptographic Key Operation (Routine)",
    5061: "Cryptographic Operation (Routine)",
    5140: "Network Share Accessed", 
    5145: "Network Share Object Accessed",
    5379: "Windows Credentials/Password Vault Read",
    7045: "New System Service Installed"
  };
  return descriptions[id] || `Unmapped System Event (${id})`;
};

// --- SUB-COMPONENTS (PAGES) ---

const Navigation = () => {
  const location = useLocation();
  const navStyle = (path) => ({
    color: location.pathname === path ? '#1890ff' : 'white',
    textDecoration: 'none',
    fontWeight: 'bold',
    padding: '10px 15px',
    borderBottom: location.pathname === path ? '3px solid #1890ff' : '3px solid transparent'
  });

  return (
    <nav style={{ backgroundColor: '#001529', padding: '0 20px', display: 'flex', gap: '15px', marginBottom: '20px' }}>
      <h2 style={{ color: 'white', marginRight: '20px' }}>🛡️ SIEM</h2>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Link to="/" style={navStyle('/')}>Metrics Home</Link>
        <Link to="/backups" style={navStyle('/backups')}>S3 Backups</Link>
        <Link to="/ips" style={navStyle('/ips')}>IPS Interventions</Link>
        <Link to="/alerts" style={navStyle('/alerts')}>Security Alerts</Link>
        <Link to="/logs" style={navStyle('/logs')}>System Logs</Link>
      </div>
    </nav>
  );
};

const MetricsHome = ({ cpuLoad, cpuData, networkBytes, networkData }) => {
  // Dynamic threshold logic for CPU
  let cpuDesc = "Normal operation. System resources are stable.";
  let cpuColor = "#389e0d"; 
  if (cpuLoad > 80) {
    cpuDesc = "CRITICAL: High resource consumption detected. Potential anomalous process or malware execution.";
    cpuColor = "#cf1322"; 
  } else if (cpuLoad > 50) {
    cpuDesc = "ELEVATED: Moderate CPU load. A heavy application or intensive script is currently running.";
    cpuColor = "#faad14"; 
  }

  // Dynamic threshold logic for Network
  let netDesc = "Normal background traffic. No unusual data transfers detected.";
  let netColor = "#389e0d"; 
  if (networkBytes > 100000) {
    netDesc = "WARNING: Massive data spike detected. Potential data exfiltration, flood attack, or large transfer.";
    netColor = "#cf1322"; 
  } else if (networkBytes > 20000) {
    netDesc = "ACTIVE: Elevated network activity. Typical of active web browsing, downloading, or media streaming.";
    netColor = "#faad14"; 
  }

  return (
    <div style={{ display: 'flex', gap: '20px', height: '450px' }}>
      {/* CPU Card */}
      <div style={{ flex: 1, backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
          <h3 style={{ margin: 0 }}>System CPU Load (%)</h3>
          <span style={{ fontSize: '20px', fontWeight: 'bold', color: cpuLoad > 80 ? '#cf1322' : '#389e0d' }}>
            {cpuLoad.toFixed(2)}%
          </span>
        </div>
        <div style={{ flex: 1, minHeight: 0, marginBottom: '15px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={cpuData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" hide={true} />
              <YAxis domain={[0, 100]} width={30} />
              <Tooltip />
              <Line type="monotone" dataKey="load" stroke="#ff4d4f" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div style={{ padding: '12px', backgroundColor: '#fafafa', borderRadius: '4px', borderLeft: `4px solid ${cpuColor}` }}>
          <strong style={{ color: cpuColor }}>Status: </strong> 
          <span style={{ fontSize: '14px', color: '#595959', marginLeft: '5px' }}>{cpuDesc}</span>
        </div>
      </div>

      {/* Network Card */}
      <div style={{ flex: 1, backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
          <h3 style={{ margin: 0 }}>Network Throughput (Bytes)</h3>
          <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#096dd9' }}>
            {networkBytes}
          </span>
        </div>
        <div style={{ flex: 1, minHeight: 0, marginBottom: '15px' }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={networkData}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" hide={true} />
              <YAxis width={60} />
              <Tooltip />
              <Line type="monotone" dataKey="bytes" stroke="#1890ff" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div style={{ padding: '12px', backgroundColor: '#fafafa', borderRadius: '4px', borderLeft: `4px solid ${netColor}` }}>
          <strong style={{ color: netColor }}>Status: </strong> 
          <span style={{ fontSize: '14px', color: '#595959', marginLeft: '5px' }}>{netDesc}</span>
        </div>
      </div>
    </div>
  );
};

const BackupsPage = ({ backups, handleDownload }) => (
  <div style={{
    backgroundColor: '#001529',
    color: 'white',
    padding: '30px',
    borderRadius: '10px',
    minHeight: 'calc(100vh - 120px)',
    boxSizing: 'border-box',
    display: 'flex',
    flexDirection: 'column',
    gap: '24px'
  }}>
    <div>
      <h2 style={{ color: '#1890ff', margin: '0 0 8px 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span>☁</span> AWS S3 Emergency Backups & Vault Restoration
      </h2>
      <p style={{ color: '#8c8c8c', margin: 0, fontSize: '14px' }}>
        Encrypted snapshot repository managed by automated incident response triggers.
      </p>
    </div>

    {/* Informational Guidance Cards */}
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
      <div style={{
        backgroundColor: '#0b2138',
        border: '1px solid #173d63',
        borderRadius: '6px',
        padding: '16px'
      }}>
        <div style={{ color: '#52c41a', fontWeight: 'bold', marginBottom: '6px' }}>
          ✔ Automatic Trigger Reason
        </div>
        <div style={{ fontSize: '13px', color: '#bfbfbf', lineHeight: '1.5' }}>
          When behavioral or ML models detect unauthorized file access, rapid disk modifications, or ransomware traits, critical system targets are immediately mirrored to isolated cloud storage before local encryption can take place.
        </div>
      </div>

      <div style={{
        backgroundColor: '#0b2138',
        border: '1px solid #173d63',
        borderRadius: '6px',
        padding: '16px'
      }}>
        <div style={{ color: '#faad14', fontWeight: 'bold', marginBottom: '6px' }}>
          ⚠ Safe Restoration Protocol
        </div>
        <div style={{ fontSize: '13px', color: '#bfbfbf', lineHeight: '1.5' }}>
          Do not pull files down to an active threat zone. Ensure offending host processes and suspicious network connections have been halted and verified via the IPS Interventions tab prior to initiating file downloads.
        </div>
      </div>

      <div style={{
        backgroundColor: '#0b2138',
        border: '1px solid #173d63',
        borderRadius: '6px',
        padding: '16px'
      }}>
        <div style={{ color: '#1890ff', fontWeight: 'bold', marginBottom: '6px' }}>
          🔒 Ephemeral Access Links
        </div>
        <div style={{ fontSize: '13px', color: '#bfbfbf', lineHeight: '1.5' }}>
          Clicking "Restore" generates a time-bounded AWS Presigned URL valid for 15 minutes. Links automatically invalidate upon expiry, preventing open-ended exposure of your S3 storage keys.
        </div>
      </div>
    </div>

    {/* Backups Table */}
    <div style={{
      backgroundColor: '#071524',
      border: '1px solid #1f364d',
      borderRadius: '8px',
      padding: '20px',
      flex: 1
    }}>
      <h3 style={{ margin: '0 0 16px 0', fontSize: '16px', color: '#e6f7ff' }}>Secured Snapshot Ledger</h3>
      <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #1f364d', color: '#8c8c8c', fontSize: '13px' }}>
            <th style={{ paddingBottom: '12px' }}>File Name</th>
            <th style={{ paddingBottom: '12px' }}>Status</th>
            <th style={{ paddingBottom: '12px', textAlign: 'right' }}>Restore Action</th>
          </tr>
        </thead>
        <tbody>
          {backups.map((b, i) => (
            <tr key={i} style={{ borderBottom: '1px solid #112538', fontSize: '14px' }}>
              <td style={{ padding: '14px 0', color: '#e6f7ff' }}>📄 {b.filename}</td>
              <td>
                <span style={{
                  color: '#52c41a',
                  backgroundColor: 'rgba(82, 196, 26, 0.1)',
                  border: '1px solid #274916',
                  borderRadius: '4px',
                  padding: '4px 8px',
                  fontSize: '12px',
                  fontWeight: 'bold'
                }}>
                  {b.status}
                </span>
              </td>
              <td style={{ textAlign: 'right' }}>
                <button 
                  onClick={() => handleDownload(b.filename, b.bucket)}
                  style={{
                    backgroundColor: '#1890ff',
                    color: 'white',
                    border: 'none',
                    padding: '7px 14px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontWeight: 'bold',
                    fontSize: '13px',
                    transition: 'opacity 0.2s'
                  }}
                  onMouseOver={(e) => e.target.style.opacity = '0.85'}
                  onMouseOut={(e) => e.target.style.opacity = '1'}
                >
                  ⬇️ Restore
                </button>
              </td>
            </tr>
          ))}
          {backups.length === 0 && (
            <tr>
              <td colSpan="3" style={{ padding: '24px 0', textAlign: 'center', color: '#595959' }}>
                No emergency snapshots triggered yet. Cloud vault is currently standing by.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
);

const IPSPage = ({ mitigations }) => {
  // Helper to parse unstructured status strings into clean data cards
  const parseIntervention = (m) => {
    const raw = m.status || '';
    const isProcessKill = raw.includes('Terminated');
    const isFirewall = raw.includes('Firewall') || raw.includes('Blocked');

    if (isProcessKill) {
      const nameMatch = raw.match(/Terminated\s+([^\s(]+)/);
      const pidMatch = raw.match(/PID\s+(\d+)/);
      const cpuMatch = raw.match(/CPU:\s*([0-9.]+%?)/);
      const pathMatch = raw.match(/Path:\s*(.+)$/);

      return {
        type: 'PROCESS_KILL',
        badge: 'PROCESS TERMINATED',
        badgeBg: '#fff1f0',
        badgeBorder: '#ffa39e',
        badgeColor: '#cf1322',
        title: nameMatch ? nameMatch[1] : 'Unknown Process',
        pid: pidMatch ? pidMatch[1] : 'N/A',
        cpu: cpuMatch ? cpuMatch[1] : 'N/A',
        path: pathMatch ? pathMatch[1] : 'Unknown Execution Path',
        reason: 'Executed outside trusted system directories (e.g., Desktop/Downloads/Temp) while exhibiting anomalous resource spikes and non-whitelisted binary signatures.',
        timestamp: m.timestamp || 'Just now',
        source: m.source || 'IPS Heuristic EDR'
      };
    }

    if (isFirewall) {
      const ipMatch = raw.match(/(?:IP\s*|for\s+)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
      return {
        type: 'FIREWALL_BLOCK',
        badge: 'FIREWALL RULE INJECTED',
        badgeBg: '#e6f7ff',
        badgeBorder: '#91d5ff',
        badgeColor: '#096dd9',
        title: ipMatch ? `Blocked Host: ${ipMatch[1]}` : 'Inbound Connection Dropped',
        pid: 'Kernel / Netfilter',
        cpu: 'N/A',
        path: 'Host Windows Defender Firewall Rule (Inbound DROP)',
        reason: 'High-frequency volumetric burst or abnormal connection handshake patterns matched network anomaly signatures.',
        timestamp: m.timestamp || 'Just now',
        source: m.source || 'IPS Firewall Manager'
      };
    }

    return {
      type: 'GENERIC',
      badge: 'CONTAINMENT ACTION',
      badgeBg: '#f6ffed',
      badgeBorder: '#b7eb8f',
      badgeColor: '#389e0d',
      title: m.source || 'Automated Action',
      pid: 'N/A',
      cpu: 'N/A',
      path: 'N/A',
      reason: raw,
      timestamp: m.timestamp || 'Just now',
      source: m.source || 'Active Defense Subsystem'
    };
  };

  return (
    <div style={{
      backgroundColor: '#f0f5ff',
      border: '1px solid #adc6ff',
      padding: '30px',
      borderRadius: '10px',
      minHeight: 'calc(100vh - 120px)',
      boxSizing: 'border-box',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px'
    }}>
      {/* Header */}
      <div>
        <h2 style={{ color: '#002c8c', margin: '0 0 6px 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span>🛡️</span> Automated IPS Interventions & Active Containment
        </h2>
        <p style={{ color: '#4d7ab5', margin: 0, fontSize: '14px' }}>
          Live record of host-level process terminations and firewall blocks executed by the automated response pipeline.
        </p>
      </div>

      {/* Logic & Policy Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #cf1322', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
          <div style={{ fontWeight: 'bold', color: '#cf1322', marginBottom: '6px' }}>
            Heuristic EDR Termination Policy
          </div>
          <div style={{ fontSize: '13px', color: '#595959', lineHeight: '1.5' }}>
            Processes executing from user-writable directories (such as Desktop, Downloads, or Temp) consuming anomalous CPU resources and failing system whitelists are halted immediately via OS-level termination.
          </div>
        </div>

        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #096dd9', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
          <div style={{ fontWeight: 'bold', color: '#096dd9', marginBottom: '6px' }}>
            Automated Firewall Isolation
          </div>
          <div style={{ fontSize: '13px', color: '#595959', lineHeight: '1.5' }}>
            Network ML anomaly detections trigger direct kernel/firewall command executions (via <code>netsh advfirewall</code>), denying subsequent ingress packets from the offending source IP address.
          </div>
        </div>

        <div style={{ backgroundColor: 'white', padding: '16px', borderRadius: '8px', borderLeft: '4px solid #389e0d', boxShadow: '0 1px 3px rgba(0,0,0,0.06)' }}>
          <div style={{ fontWeight: 'bold', color: '#389e0d', marginBottom: '6px' }}>
            Whitelist & System Safeguards
          </div>
          <div style={{ fontSize: '13px', color: '#595959', lineHeight: '1.5' }}>
            Core Windows services, protected developer processes, and binaries verified under <code>C:\Windows</code> or <code>C:\Program Files</code> are preserved to maintain host stability.
          </div>
        </div>
      </div>

      {/* Main Ledger Section */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', padding: '20px', border: '1px solid #d6e4ff', flex: 1, boxShadow: '0 2px 4px rgba(0,0,0,0.04)' }}>
        <h3 style={{ margin: '0 0 16px 0', color: '#002c8c', fontSize: '16px' }}>
          Intervention Activity History ({mitigations.length})
        </h3>

        {mitigations.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '50px 0', color: '#8c8c8c' }}>
            No malicious processes killed or IP blocks injected yet. Active protection is standing by.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {mitigations.map((item, index) => {
              const details = parseIntervention(item);
              return (
                <div key={index} style={{
                  border: '1px solid #e8e8e8',
                  borderRadius: '6px',
                  padding: '16px',
                  backgroundColor: '#fafafa',
                  transition: 'background-color 0.2s'
                }}>
                  {/* Top line: Badges & Timestamp */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{
                        backgroundColor: details.badgeBg,
                        color: details.badgeColor,
                        border: `1px solid ${details.badgeBorder}`,
                        borderRadius: '4px',
                        padding: '3px 8px',
                        fontSize: '11px',
                        fontWeight: 'bold',
                        letterSpacing: '0.5px'
                      }}>
                        {details.badge}
                      </span>
                      <strong style={{ fontSize: '15px', color: '#262626' }}>
                        {details.title}
                      </strong>
                    </div>
                    <span style={{ fontSize: '12px', color: '#8c8c8c', fontWeight: 'bold' }}>
                      ⏱ {details.timestamp}
                    </span>
                  </div>

                  {/* Metadata Grid */}
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                    gap: '10px',
                    fontSize: '13px',
                    marginBottom: '10px',
                    backgroundColor: '#ffffff',
                    padding: '10px',
                    borderRadius: '4px',
                    border: '1px solid #f0f0f0'
                  }}>
                    <div>
                      <span style={{ color: '#8c8c8c' }}>Subsystem: </span>
                      <span style={{ fontWeight: 'bold', color: '#002c8c' }}>{details.source}</span>
                    </div>
                    <div>
                      <span style={{ color: '#8c8c8c' }}>Process ID (PID): </span>
                      <span style={{ fontWeight: 'bold', color: '#262626' }}>{details.pid}</span>
                    </div>
                    <div>
                      <span style={{ color: '#8c8c8c' }}>CPU Draw: </span>
                      <span style={{ fontWeight: 'bold', color: '#cf1322' }}>{details.cpu}</span>
                    </div>
                  </div>

                  {/* Execution Path */}
                  <div style={{ fontSize: '13px', marginBottom: '8px' }}>
                    <span style={{ color: '#8c8c8c' }}>Binary Location: </span>
                    <code style={{
                      backgroundColor: '#f5f5f5',
                      padding: '2px 6px',
                      borderRadius: '3px',
                      color: '#d4380d',
                      fontSize: '12px'
                    }}>
                      {details.path}
                    </code>
                  </div>

                  {/* Reason for Termination */}
                  <div style={{ fontSize: '13px', color: '#595959', backgroundColor: '#f0f5ff', padding: '8px 12px', borderRadius: '4px', borderLeft: '3px solid #1890ff' }}>
                    <strong style={{ color: '#002c8c' }}>Containment Justification: </strong>
                    {details.reason}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

const AlertsPage = ({ alerts }) => {
  // 1. Overall Status Logic: Check the 10 most recent alerts for anomalies
  const recentAlerts = alerts.slice(0, 10);
  const isUnderAttack = recentAlerts.some(a => 
    (a.is_anomaly === true || a.status?.includes('ANOMALY') || a.status?.includes('RANSOMWARE')) && !a.status?.includes('NORMAL')
  );

  const healthStatus = isUnderAttack
    ? { 
        bg: '#fff1f0', border: '#cf1322', color: '#cf1322', icon: '🚨', 
        title: 'CRITICAL: ACTIVE THREAT DETECTED', 
        desc: 'Recent ML telemetry indicates active anomalies or ransomware signatures. Active IPS containment pipelines may be engaging.' 
      }
    : { 
        bg: '#f6ffed', border: '#52c41a', color: '#389e0d', icon: '✅', 
        title: 'SYSTEM SECURE: NORMAL BASELINE', 
        desc: 'All recent network and system telemetry models report normal baseline activity. No active threats detected.' 
      };

  // 2. Helper to format ugly ISO timestamps into clean local time
  const formatTimestamp = (rawTime) => {
    if (!rawTime) return 'Unknown Time';
    try {
      // Force the browser to treat the raw Python string as UTC by appending 'Z'
      let timeString = typeof rawTime === 'string' ? rawTime.trim() : String(rawTime);
      if (!timeString.endsWith('Z') && !timeString.includes('+')) {
        timeString += 'Z';
      }
      
      const date = new Date(timeString);
      if (isNaN(date.getTime())) return rawTime; 
      
      // Explicitly format to local Indian Standard Time (Asia/Kolkata)
      return date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
    } catch (e) {
      return rawTime;
    }
  };

  return (
    <div style={{ backgroundColor: '#f0f5ff', padding: '30px', borderRadius: '10px', minHeight: 'calc(100vh - 120px)' }}>
      <h2 style={{ color: '#002c8c', margin: '0 0 20px 0' }}>📡 Security Alert Feed</h2>

      {/* OVERALL SYSTEM HEALTH BANNER */}
      <div style={{ 
        backgroundColor: healthStatus.bg, 
        border: `2px solid ${healthStatus.border}`, 
        borderRadius: '8px', 
        padding: '20px', 
        marginBottom: '24px',
        boxShadow: '0 4px 6px rgba(0,0,0,0.05)'
      }}>
        <div style={{ fontSize: '20px', fontWeight: 'bold', color: healthStatus.color, marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span>{healthStatus.icon}</span> {healthStatus.title}
        </div>
        <div style={{ color: '#595959', fontSize: '15px' }}>
          <strong>Justification: </strong>{healthStatus.desc}
        </div>
      </div>

      {/* ALERTS LEDGER */}
      <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', border: '1px solid #d6e4ff', boxShadow: '0 2px 4px rgba(0,0,0,0.04)' }}>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {alerts.map((alert, i) => {
            const isRansomware = alert.status?.includes('RANSOMWARE') || alert.source?.includes('Ransomware');
            const isAnomaly = (alert.is_anomaly === true || alert.status?.includes('ANOMALY')) && !alert.status?.includes('NORMAL');
            
            const bgColor = isRansomware ? '#ffeef0' : isAnomaly ? '#fff1f0' : '#f6ffed';
            const borderColor = isRansomware ? '#b71c1c' : isAnomaly ? '#ff4d4f' : '#52c41a';
            const titleColor = isRansomware ? '#b71c1c' : isAnomaly ? '#cf1322' : '#595959';
            const textColor = isRansomware ? '#cf1322' : isAnomaly ? '#cf1322' : '#389e0d';
            
            return (
              <li key={i} style={{ 
                borderBottom: '1px solid #f0f0f0', 
                padding: '16px', 
                backgroundColor: bgColor, 
                borderLeft: `5px solid ${borderColor}`, 
                marginBottom: '12px', 
                borderRadius: '6px' 
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <strong style={{ color: titleColor, fontSize: '15px' }}>
                    {alert.source} Model Inference
                  </strong>
                  
                  {/* CLEAN TIMESTAMP DISPLAY */}
                  <span style={{ fontSize: '13px', color: '#8c8c8c', fontWeight: 'bold' }}>
                    {formatTimestamp(alert.timestamp)}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ color: textColor, fontWeight: 'bold', fontSize: '15px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {isAnomaly || isRansomware ? '⚠️' : '✅'} {alert.status}
                  </div>
                  
                  {/* SEPARATED CONFIDENCE METRIC */}
                  {alert.confidence && (
                    <div style={{ backgroundColor: '#ffffff', border: '1px solid #e8e8e8', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold', color: '#595959' }}>
                      Confidence: {alert.confidence}%
                    </div>
                  )}
                </div>
              </li>
            );
          })}
          {alerts.length === 0 && <p style={{ color: '#8c8c8c', textAlign: 'center', padding: '30px 0' }}>Waiting for ML telemetry stream...</p>}
        </ul>
      </div>
    </div>
  );
};

const LogsPage = ({ eventLogs }) => {
  // 1. Added 5379 to the noise filter to stop credential read spam
  // Add the spammy Event ID to this list (e.g., adding 4663 and 4656)
  const filteredLogs = eventLogs.filter(log => {
    const id = log.event_id || log.EventID;
    return id !== 4798 && id !== 4799 && id !== 5379 && id !== 4663 && id !== 4656; 
  });

  return (
    <div style={{ backgroundColor: '#141414', color: '#00ff00', padding: '20px', borderRadius: '8px', fontFamily: 'Consolas, monospace', minHeight: 'calc(100vh - 120px)' }}>
      <h3 style={{ margin: '0 0 15px 0', color: '#fff' }}>System Event Log</h3>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {filteredLogs.map((log, i) => {
          const eventId = log.event_id || log.EventID;
          // 2. We can remove 5379 from the warning list since we are filtering it out entirely
          const isWarning = eventId === 4625 || eventId === 1102;
          
          return (
            <li key={i} style={{ borderBottom: '1px solid #333', padding: '12px 0' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                <span style={{ color: '#096dd9', fontWeight: 'bold' }}>Event {eventId}</span>
                <span style={{ color: '#52c41a' }}>User: {log.user || log.User || 'System'}</span>
              </div>
              <div style={{ color: isWarning ? '#ff4d4f' : '#fff', fontWeight: 'bold', marginBottom: '4px' }}>
                {getEventDescription(eventId)}
              </div>
              <div style={{ color: '#ccc', fontSize: '12px' }}>{log.task || log.source || 'Windows Security Subsystem'}</div>
            </li>
          );
        })}
        {filteredLogs.length === 0 && <p style={{ color: '#555', textAlign: 'center' }}>Awaiting relevant Windows event logs...</p>}
      </ul>
    </div>
  );
};

// --- MAIN APP COMPONENT ---

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [mitigations, setMitigations] = useState([]); 
  const [backups, setBackups] = useState([]);
  const [cpuLoad, setCpuLoad] = useState(0);
  const [networkBytes, setNetworkBytes] = useState(0);
  const [cpuData, setCpuData] = useState([]);
  const [networkData, setNetworkData] = useState([]);
  const [eventLogs, setEventLogs] = useState([]);

  useEffect(() => {
    socket.on('ml_alert', (data) => {
      if (data.is_mitigation) {
        setMitigations((prev) => [data, ...prev].slice(0, 100));
      } else {
        setAlerts((prev) => [data, ...prev].slice(0, 100));
      }
    });
    
    socket.on('s3_backup', (data) => setBackups((prev) => [data, ...prev]));

    socket.on('system_update', (data) => {
      const loadVal = data.avg_cpu_percent || 0;
      setCpuLoad(loadVal);
      setCpuData((prev) => [...prev, { time: new Date().toLocaleTimeString(), load: loadVal }].slice(-30));
    });

    // --- BULLETPROOF NETWORK ACCUMULATOR ---
    socket.on('network_update', (data) => {
      // 1. Force the bytes into a strict number, pulling from whichever format the Python script outputs
      const rawBytes = data.additional_network_features?.total_bytes || data.src_bytes || 0;
      const flowBytes = Number(rawBytes);

      // 2. Sync directly to the Python script's 10-second window
      const windowTime = data.window_end ? new Date(data.window_end).toLocaleTimeString() : new Date().toLocaleTimeString();
      
      setNetworkData((prev) => {
        const arr = [...prev];
        const lastPoint = arr[arr.length - 1];
        let newArr;

        // If this packet is from the same 10-second window, add the bytes together to build the spike
        if (lastPoint && lastPoint.time === windowTime) {
          arr[arr.length - 1] = { ...lastPoint, bytes: lastPoint.bytes + flowBytes };
          newArr = arr;
        } 
        // Otherwise, 10 seconds have passed. Start a new spike.
        else {
          arr.push({ time: windowTime, bytes: flowBytes });
          newArr = arr.slice(-30);
        }

        // 3. Ensure the Big Blue Number perfectly matches the top of the graph spike
        setNetworkBytes(newArr[newArr.length - 1].bytes);
        return newArr;
      });
    });

    socket.on('raw_event_log', (data) => setEventLogs((prev) => [data, ...prev].slice(0, 100)));

    return () => {
      socket.off('ml_alert'); socket.off('s3_backup'); socket.off('system_update'); socket.off('network_update'); socket.off('raw_event_log');
    };
  }, []);

  const handleDownload = async (filename, bucket) => {
    const isSafe = window.confirm("🛡️ SECURITY WARNING: Ensure this machine has been completely scrubbed of malware before restoring files.\n\nGenerate secure link?");
    if (isSafe) {
      try {
        const response = await fetch(`http://localhost:4000/api/download?file=${filename}&bucket=${bucket}`);
        const data = await response.json();
        if (data.url) window.open(data.url, '_blank');
        else alert("Failed to generate secure link.");
      } catch (err) {
        alert("Network error. Could not contact the SIEM backend.");
      }
    }
  };

  return (
    <Router>
      <div style={{ fontFamily: 'Arial, sans-serif', backgroundColor: '#f0f2f5', minHeight: '100vh' }}>
        <Navigation />
        <div style={{ padding: '0 20px 20px 20px' }}>
          <Routes>
            <Route path="/" element={<MetricsHome cpuLoad={cpuLoad} cpuData={cpuData} networkBytes={networkData.length > 0 ? networkData[networkData.length - 1].bytes : 0} networkData={networkData} />} />
            <Route path="/backups" element={<BackupsPage backups={backups} handleDownload={handleDownload} />} />
            <Route path="/ips" element={<IPSPage mitigations={mitigations} />} />
            <Route path="/alerts" element={<AlertsPage alerts={alerts} />} />
            <Route path="/logs" element={<LogsPage eventLogs={eventLogs} />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
} 