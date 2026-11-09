// KJAGU Background Service Worker
// Manages native messaging connection to Python bridge

const HOST_NAME = 'com.kjagu.ridit';
let port = null;
let isConnected = false;
let scanStatus = 'idle';
let pendingApprovals = [];

// Connect to native host
function connectHost() {
  if (port) return;

  try {
    port = chrome.runtime.connectNative(HOST_NAME);

    port.onMessage.addListener((msg) => {
      handleHostMessage(msg);
    });

    port.onDisconnect.addListener(() => {
      console.log('[KJAGU] Host disconnected');
      isConnected = false;
      port = null;
      updateBadge('OFF', '#ff3333');

      // Try reconnect after 5 seconds
      setTimeout(connectHost, 5000);
    });

    isConnected = true;
    updateBadge('ON', '#00cc66');
    console.log('[KJAGU] Connected to bridge');

    // Send ping
    sendToHost({ command: 'ping', id: 'ping_' + Date.now() });

  } catch (e) {
    console.error('[KJAGU] Failed to connect:', e);
    isConnected = false;
    updateBadge('ERR', '#ff3333');
  }
}

function sendToHost(msg) {
  if (port && isConnected) {
    port.postMessage(msg);
    return true;
  }
  return false;
}

function handleHostMessage(msg) {
  console.log('[KJAGU] Host msg:', msg.type, msg);

  switch (msg.type) {
    case 'pong':
      isConnected = true;
      break;

    case 'bridge_ready':
      isConnected = true;
      updateBadge('ON', '#00cc66');
      break;

    case 'scan_started':
      scanStatus = 'scanning';
      updateBadge('RUN', '#ffaa00');
      broadcastToTabs({ type: 'kjagu_scan_started', data: msg });
      break;

    case 'scan_complete':
      scanStatus = 'complete';
      updateBadge('OK', '#00cc66');
      broadcastToTabs({ type: 'kjagu_scan_complete', data: msg.data });
      break;

    case 'scan_error':
      scanStatus = 'error';
      updateBadge('ERR', '#ff3333');
      broadcastToTabs({ type: 'kjagu_scan_error', data: msg.data });
      break;

    case 'scan_phase':
      broadcastToTabs({ type: 'kjagu_scan_phase', data: msg.data });
      break;

    case 'approval_required':
      pendingApprovals.push(msg.data);
      scanStatus = 'awaiting_approval';
      updateBadge('ACT', '#ffaa00');
      broadcastToTabs({ type: 'kjagu_approval_required', data: msg.data });
      break;

    case 'action_resolved':
      pendingApprovals = pendingApprovals.filter(a => a.action_id !== msg.data.action_id);
      broadcastToTabs({ type: 'kjagu_action_resolved', data: msg.data });
      break;

    case 're_complete':
      broadcastToTabs({ type: 'kjagu_re_complete', data: msg.data });
      break;

    case 'event':
      broadcastToTabs({ type: 'kjagu_event', event: msg.event, data: msg.data });
      break;

    case 'error':
      console.error('[KJAGU] Bridge error:', msg.error);
      broadcastToTabs({ type: 'kjagu_error', data: msg });
      break;
  }
}

function broadcastToTabs(message) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      if (tab.url && (tab.url.includes('deepseek') || tab.url.includes('kimi'))) {
        chrome.tabs.sendMessage(tab.id, message).catch(() => {});
      }
    });
  });
}

function updateBadge(text, color) {
  chrome.action.setBadgeText({ text: text });
  chrome.action.setBadgeBackgroundColor({ color: color });
}

// Handle messages from popup/content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.command === 'get_status') {
    sendResponse({
      connected: isConnected,
      scanStatus: scanStatus,
      pendingApprovals: pendingApprovals
    });
    return true;
  }

  if (request.command === 'start_scan') {
    const sent = sendToHost({
      command: 'start_scan',
      scan_type: request.scan_type || 'full',
      id: 'scan_' + Date.now()
    });
    sendResponse({ sent: sent });
    return true;
  }

  if (request.command === 'approve_action') {
    const sent = sendToHost({
      command: 'approve_action',
      action_id: request.action_id,
      approved: request.approved,
      id: 'approval_' + Date.now()
    });
    sendResponse({ sent: sent });
    return true;
  }

  if (request.command === 'accept_policy') {
    const sent = sendToHost({
      command: 'accept_policy',
      id: 'policy_' + Date.now()
    });
    sendResponse({ sent: sent });
    return true;
  }

  if (request.command === 'encrypt_cookies') {
    const sent = sendToHost({
      command: 'encrypt_cookies',
      id: 'cookies_' + Date.now()
    });
    sendResponse({ sent: sent });
    return true;
  }

  if (request.command === 'get_pending_approvals') {
    sendResponse({ approvals: pendingApprovals });
    return true;
  }
});

// Auto-connect on startup
connectHost();
