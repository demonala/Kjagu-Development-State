// KJAGU Popup Script

document.addEventListener('DOMContentLoaded', () => {
  const btnStart = document.getElementById('btn-start');
  const btnCookies = document.getElementById('btn-cookies');
  const btnPolicy = document.getElementById('btn-policy');
  const dot = document.getElementById('connection-dot');
  const connText = document.getElementById('connection-text');
  const scanInfo = document.getElementById('scan-info');
  const scanStatus = document.getElementById('scan-status');
  const evidenceCount = document.getElementById('evidence-count');
  const pendingCount = document.getElementById('pending-count');
  const approvalsList = document.getElementById('approvals-list');
  const reportLink = document.getElementById('report-link');

  // Check status periodically
  updateStatus();
  setInterval(updateStatus, 2000);

  btnStart.addEventListener('click', () => {
    btnStart.disabled = true;
    btnStart.innerHTML = '<span class="btn-icon">...</span><span class="btn-text">SCANNING...</span>';
    chrome.runtime.sendMessage({ command: 'start_scan', scan_type: 'full' }, (resp) => {
      if (!resp || !resp.sent) {
        alert('Bridge not connected!\n\n1. Run run_bridge.bat as Administrator\n2. Reload this extension');
        btnStart.disabled = false;
        btnStart.innerHTML = '<span class="btn-icon">></span><span class="btn-text">START AI SCAN</span>';
      }
    });
  });

  btnCookies.addEventListener('click', () => {
    chrome.runtime.sendMessage({ command: 'encrypt_cookies' }, (resp) => {
      if (!resp || !resp.sent) {
        alert('Bridge not connected! Run run_bridge.bat first.');
      } else {
        btnCookies.innerHTML = '<span class="btn-icon">*</span><span class="btn-text">Encrypting...</span>';
        setTimeout(() => {
          btnCookies.innerHTML = '<span class="btn-icon">#</span><span class="btn-text">Encrypt Cookies</span>';
        }, 3000);
      }
    });
  });

  btnPolicy.addEventListener('click', () => {
    chrome.runtime.sendMessage({ command: 'accept_policy' }, (resp) => {
      if (!resp || !resp.sent) {
        alert('Bridge not connected! Run run_bridge.bat first.');
      } else {
        btnPolicy.innerHTML = '<span class="btn-icon">*</span><span class="btn-text">Policy Accepted</span>';
        btnPolicy.disabled = true;
      }
    });
  });

  function updateStatus() {
    chrome.runtime.sendMessage({ command: 'get_status' }, (status) => {
      if (!status) return;

      // Connection dot
      dot.className = '';
      if (status.connected) {
        dot.classList.add('connected');
        connText.textContent = 'Bridge Connected';
      } else {
        dot.classList.add('disconnected');
        connText.textContent = 'Bridge Disconnected — Run run.bat';
      }

      if (status.scanStatus === 'scanning') {
        dot.classList.add('scanning');
        connText.textContent = 'Scanning system...';
      }

      // Scan info
      if (status.scanStatus !== 'idle') {
        scanInfo.style.display = 'block';
        scanStatus.textContent = status.scanStatus.toUpperCase();
        evidenceCount.textContent = status.evidence_count || 0;
        pendingCount.textContent = status.pending_approvals || 0;
      }

      // Pending approvals
      if (status.pending_approvals > 0) {
        loadApprovals();
      }

      // Re-enable button if scan complete
      if (status.scanStatus === 'complete' || status.scanStatus === 'error') {
        btnStart.disabled = false;
        btnStart.innerHTML = '<span class="btn-icon">></span><span class="btn-text">START AI SCAN</span>';
      }
    });
  }

  function loadApprovals() {
    chrome.runtime.sendMessage({ command: 'get_pending_approvals' }, (resp) => {
      if (!resp || !resp.approvals) return;

      approvalsList.innerHTML = '';
      resp.approvals.forEach(appr => {
        const div = document.createElement('div');
        div.className = 'approval-item';
        div.innerHTML = `
          <div class="risk-${appr.risk_level}">[${appr.risk_level}] ${appr.action_type}</div>
          <div class="appr-desc">${appr.description}</div>
          <div class="appr-target">${appr.target}</div>
          <div class="appr-ai">AI: ${appr.ai_recommendation.substring(0, 80)}...</div>
          <div class="appr-buttons">
            <button class="appr-destroy" data-id="${appr.action_id}">DESTROY</button>
            <button class="appr-ignore" data-id="${appr.action_id}">IGNORE</button>
          </div>
        `;
        approvalsList.appendChild(div);

        div.querySelector('.appr-destroy').addEventListener('click', (e) => {
          const id = e.target.dataset.id;
          chrome.runtime.sendMessage({ command: 'approve_action', action_id: id, approved: true });
          e.target.parentElement.parentElement.style.opacity = '0.5';
        });

        div.querySelector('.appr-ignore').addEventListener('click', (e) => {
          const id = e.target.dataset.id;
          chrome.runtime.sendMessage({ command: 'approve_action', action_id: id, approved: false });
          e.target.parentElement.parentElement.style.opacity = '0.5';
        });
      });
    });
  }
});
