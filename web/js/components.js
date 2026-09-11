// UI Component rendering functions for RAVEN Dashboard.

const UI = {
  renderTraffic(req, res) {
    const reqViewer = document.getElementById('viewer-request');
    const resViewer = document.getElementById('viewer-response');

    if (!req) {
      reqViewer.textContent = 'No traffic recorded for this step.';
      resViewer.textContent = 'No traffic recorded for this step.';
      return;
    }

    const headersStr = Object.entries(req.headers || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    const bodyStr = req.body ? `\n\n${JSON.stringify(req.body, null, 2)}` : '';
    reqViewer.textContent = `${req.method} ${req.path} HTTP/1.1\nHost: localhost:8000\n${headersStr}${bodyStr}`;

    const resStatusText = res.status === 200 ? 'OK' : res.status === 403 ? 'FORBIDDEN' : 'STATUS ' + res.status;
    const resBodyStr = JSON.stringify(res.body || {}, null, 2);
    resViewer.textContent = `HTTP/1.1 ${res.status} ${resStatusText}\nContent-Type: application/json\n\n${resBodyStr}`;
  },

  renderEvidence(evidenceList) {
    const container = document.getElementById('evidence-container');
    const countBadge = document.getElementById('evidence-count');

    if (!evidenceList || evidenceList.length === 0) {
      container.innerHTML = '<div class="empty-state">No evidence recorded yet.</div>';
      countBadge.textContent = '0 Evidence Items';
      return;
    }

    countBadge.textContent = `${evidenceList.length} Evidence Items`;
    container.innerHTML = evidenceList.map(ev => `
      <div class="evidence-card">
        <div class="ev-header">
          <span class="ev-id">[${ev.id}]</span>
          <span class="ev-type">${ev.evidence_type}</span>
          <span class="ev-status" style="color: ${ev.response_status === 200 ? '#10b981' : '#f43f5e'}">
            HTTP ${ev.response_status}
          </span>
        </div>
        <div class="ev-desc">${ev.observation}</div>
      </div>
    `).join('');
  },

  renderFinding(finding, isPatched = false) {
    const container = document.getElementById('finding-container');
    if (!finding) {
      if (isPatched) {
        container.innerHTML = `
          <div class="finding-alert" style="border-color: #10b981; background: rgba(16, 185, 129, 0.1);">
            <div class="finding-title" style="color: #10b981;">[TARGET SECURE] Authorization Enforced</div>
            <div class="finding-desc">Cross-user access denied. Unauthorized request for Order 102 was blocked with HTTP 403 Forbidden.</div>
          </div>
        `;
      } else {
        container.innerHTML = '';
      }
      return;
    }

    container.innerHTML = `
      <div class="finding-alert">
        <div class="finding-title">[VULNERABILITY DETECTED] ${finding.vulnerability_type} (${finding.severity})</div>
        <div class="finding-desc">${finding.impact}</div>
        <div style="font-size: 11px; margin-top: 6px; color: #38bdf8;">
          Confirmed by Evidence: <strong>${finding.evidence_ids.join(', ')}</strong>
        </div>
      </div>
    `;
  },

  updateTopology(step, isCompromised = false) {
    const conn1 = document.getElementById('conn-1');
    const conn2 = document.getElementById('conn-2');
    const conn3 = document.getElementById('conn-3');
    const nodeTarget = document.getElementById('node-target');
    const nodeDb = document.getElementById('node-db');

    conn1.classList.remove('active');
    conn2.classList.remove('active');
    conn3.classList.remove('active');
    nodeTarget.classList.remove('compromised');
    nodeDb.classList.remove('compromised');

    if (step >= 1) conn1.classList.add('active');
    if (step >= 2) conn2.classList.add('active');
    if (step >= 3) {
      conn3.classList.add('active');
      if (isCompromised) {
        nodeTarget.classList.add('compromised');
        nodeDb.classList.add('compromised');
      }
    }
  },

  renderRemediationDiff(diffData) {
    document.getElementById('code-vulnerable').textContent = diffData.vulnerable || '';
    document.getElementById('code-secure').textContent = diffData.secure || '';
  },
};

window.UI = UI;
