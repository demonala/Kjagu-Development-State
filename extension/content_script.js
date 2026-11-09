// KJAGU Content Script
// Injected into DeepSeek and Kimi chat pages
// Bridges the AI chat with the local scanner

(function() {
  'use strict';

  const PLATFORM = detectPlatform();
  let kjaguActive = false;
  let kjaguPanel = null;

  function detectPlatform() {
    const url = window.location.href;
    if (url.includes('deepseek')) return 'deepseek';
    if (url.includes('kimi')) return 'kimi';
    return 'unknown';
  }

  // Listen for messages from background
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'kjagu_scan_started') {
      injectScanStatus('Scanning system...');
    }
    if (msg.type === 'kjagu_scan_phase') {
      injectScanStatus(msg.data.message || msg.data.phase);
    }
    if (msg.type === 'kjagu_scan_complete') {
      injectScanStatus('Scan complete! Check popup for results.');
      setTimeout(() => removeScanStatus(), 5000);
    }
    if (msg.type === 'kjagu_scan_error') {
      injectScanStatus('Scan error: ' + (msg.data.error || 'Unknown'));
    }
    if (msg.type === 'kjagu_approval_required') {
      showApprovalDialog(msg.data);
    }
    if (msg.type === 'kjagu_action_resolved') {
      removeApprovalDialog(msg.data.action_id);
    }
    if (msg.type === 'kjagu_re_complete') {
      appendREResults(msg.data);
    }
    if (msg.type === 'kjagu_event') {
      handleEvent(msg.event, msg.data);
    }
  });

  // Inject KJAGU UI into chat page
  function injectKjaguUI() {
    if (document.getElementById('kjagu-panel')) return;

    const panel = document.createElement('div');
    panel.id = 'kjagu-panel';
    panel.innerHTML = `
      <div id="kjagu-header">
        <span id="kjagu-title">KJAGU // AI SHIELD</span>
        <span id="kjagu-status">Ready</span>
      </div>
      <div id="kjagu-controls">
        <button id="kjagu-start">START AI SCAN</button>
        <button id="kjagu-cookies">ENCRYPT COOKIES</button>
        <button id="kjagu-toggle">Hide</button>
      </div>
      <div id="kjagu-output"></div>
    `;

    document.body.appendChild(panel);
    kjaguPanel = panel;

    // Style it
    const style = document.createElement('style');
    style.textContent = `
      #kjagu-panel {
        position: fixed;
        top: 80px;
        right: 20px;
        width: 320px;
        background: #0a0a0f;
        border: 1px solid #ff3333;
        border-radius: 8px;
        padding: 12px;
        z-index: 999999;
        font-family: 'Segoe UI', monospace;
        color: #e0e0e0;
        box-shadow: 0 4px 20px rgba(255, 51, 51, 0.3);
      }
      #kjagu-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
        padding-bottom: 8px;
        border-bottom: 1px solid #333;
      }
      #kjagu-title { font-weight: bold; color: #ff4444; font-size: 14px; }
      #kjagu-status { font-size: 11px; color: #888; }
      #kjagu-controls { display: flex; gap: 6px; margin-bottom: 10px; flex-wrap: wrap; }
      #kjagu-controls button {
        flex: 1;
        min-width: 80px;
        padding: 6px 10px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 11px;
        font-weight: bold;
        transition: all 0.2s;
      }
      #kjagu-start {
        background: linear-gradient(135deg, #ff3333, #cc0000);
        color: white;
      }
      #kjagu-start:hover { background: linear-gradient(135deg, #ff5555, #dd2222); }
      #kjagu-cookies {
        background: #1a1a2e;
        color: #aaaaff;
        border: 1px solid #333366;
      }
      #kjagu-toggle {
        background: #222;
        color: #888;
      }
      #kjagu-output {
        max-height: 300px;
        overflow-y: auto;
        font-size: 11px;
        line-height: 1.4;
      }
      #kjagu-output .log { padding: 4px 0; border-bottom: 1px solid #1a1a1a; }
      #kjagu-output .log.error { color: #ff6666; }
      #kjagu-output .log.success { color: #66ff66; }
      #kjagu-output .log.warn { color: #ffaa44; }
      .kjagu-approval {
        background: #1a0a0a;
        border: 1px solid #ff4444;
        border-radius: 4px;
        padding: 8px;
        margin: 6px 0;
      }
      .kjagu-approval .risk-CRITICAL { color: #ff2222; font-weight: bold; }
      .kjagu-approval .risk-HIGH { color: #ff8844; font-weight: bold; }
      .kjagu-approval-buttons {
        display: flex;
        gap: 6px;
        margin-top: 6px;
      }
      .kjagu-approval-buttons button {
        flex: 1;
        padding: 4px;
        border-radius: 3px;
        border: none;
        cursor: pointer;
        font-size: 10px;
      }
      .kjagu-approve { background: #cc0000; color: white; }
      .kjagu-deny { background: #333; color: #888; }
    `;
    document.head.appendChild(style);

    // Event listeners
    document.getElementById('kjagu-start').addEventListener('click', startScan);
    document.getElementById('kjagu-cookies').addEventListener('click', encryptCookies);
    document.getElementById('kjagu-toggle').addEventListener('click', () => {
      const out = document.getElementById('kjagu-output');
      out.style.display = out.style.display === 'none' ? 'block' : 'none';
    });
  }

  function startScan() {
    log('Starting AI scan...', 'warn');
    chrome.runtime.sendMessage({ command: 'start_scan', scan_type: 'full' }, (resp) => {
      if (resp && !resp.sent) {
        log('ERROR: Bridge not connected. Run run.bat first!', 'error');
      }
    });
  }

  function encryptCookies() {
    log('Encrypting cookies...', 'warn');
    chrome.runtime.sendMessage({ command: 'encrypt_cookies' });
  }

  function log(msg, type = '') {
    const out = document.getElementById('kjagu-output');
    if (!out) return;
    const div = document.createElement('div');
    div.className = 'log ' + type;
    div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
  }

  function injectScanStatus(msg) {
    const status = document.getElementById('kjagu-status');
    if (status) status.textContent = msg;
    log(msg, 'warn');
  }

  function removeScanStatus() {
    const status = document.getElementById('kjagu-status');
    if (status) status.textContent = 'Ready';
  }

  function showApprovalDialog(data) {
    const out = document.getElementById('kjagu-output');
    if (!out) return;

    const div = document.createElement('div');
    div.className = 'kjagu-approval';
    div.id = 'approval_' + data.action_id;
    div.innerHTML = `
      <div class="risk-${data.risk_level}">[${data.risk_level}] ${data.action_type}</div>
      <div style="margin:4px 0;color:#ccc;">${data.description}</div>
      <div style="font-size:10px;color:#888;">Target: ${data.target}</div>
      <div style="font-size:10px;color:#66aaff;margin:4px 0;">AI: ${data.ai_recommendation.substring(0, 120)}...</div>
      <div class="kjagu-approval-buttons">
        <button class="kjagu-approve" data-id="${data.action_id}">[TERMINATE]</button>
        <button class="kjagu-deny" data-id="${data.action_id}">[IGNORE]</button>
      </div>
    `;

    out.appendChild(div);
    out.scrollTop = out.scrollHeight;

    // Add listeners
    div.querySelector('.kjagu-approve').addEventListener('click', (e) => {
      const id = e.target.dataset.id;
      chrome.runtime.sendMessage({ command: 'approve_action', action_id: id, approved: true });
      log('Approved: ' + id, 'success');
    });
    div.querySelector('.kjagu-deny').addEventListener('click', (e) => {
      const id = e.target.dataset.id;
      chrome.runtime.sendMessage({ command: 'approve_action', action_id: id, approved: false });
      log('Denied: ' + id, 'warn');
    });
  }

  function removeApprovalDialog(actionId) {
    const el = document.getElementById('approval_' + actionId);
    if (el) {
      el.style.opacity = '0.5';
      setTimeout(() => el.remove(), 2000);
    }
  }

  function appendREResults(data) {
    const out = document.getElementById('kjagu-output');
    if (!out) return;

    const div = document.createElement('div');
    div.className = 'log';
    const risk = data.risk_score || 0;
    const color = risk > 0.7 ? '#ff4444' : risk > 0.4 ? '#ffaa44' : '#66ff66';
    const fileName = (data.file_path || '').split(/[/\\\\]/).pop();
    div.innerHTML = `<span style="color:${color}">[RE] ${fileName} -- Risk: ${(risk*100).toFixed(0)}%</span>`;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
  }

  function handleEvent(event, data) {
    if (event === 'action_expired') {
      log('Action expired: ' + data.message, 'warn');
    }
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectKjaguUI);
  } else {
    injectKjaguUI();
  }

  // Also try after a delay (for SPAs)
  setTimeout(injectKjaguUI, 3000);

})();
