// UI Component rendering functions for RAVEN Dashboard.

const UI = {
  renderTraffic(req, res) {
    const reqViewer = document.getElementById('viewer-request');
    const resViewer = document.getElementById('viewer-response');

    if (!req) {
      reqViewer.textContent = 'No traffic recorded for this step/module.';
      resViewer.textContent = 'No traffic recorded for this step/module.';
      return;
    }

    const headersStr = Object.entries(req.headers || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    const bodyStr = req.body ? `\n\n${typeof req.body === 'string' ? req.body : JSON.stringify(req.body, null, 2)}` : '';
    reqViewer.textContent = `${req.method || 'GET'} ${req.path || '/'} HTTP/1.1\nHost: localhost:8000\n${headersStr}${bodyStr}`;

    const status = res.status || res.response_status || 200;
    const resStatusText = status === 200 ? 'OK' : status === 403 ? 'FORBIDDEN' : status === 404 ? 'NOT FOUND' : 'STATUS ' + status;
    const resHeadersStr = Object.entries(res.headers || res.response_headers || {})
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
    const rawResBody = res.body || res.response_body || {};
    const resBodyStr = typeof rawResBody === 'string' ? rawResBody : JSON.stringify(rawResBody, null, 2);

    resViewer.textContent = `HTTP/1.1 ${status} ${resStatusText}\n${resHeadersStr}\n\n${resBodyStr}`;
  },

  renderEvidence(evidenceList, onSelectEvidence) {
    const container = document.getElementById('evidence-container');
    const countBadge = document.getElementById('evidence-count');

    if (!evidenceList || evidenceList.length === 0) {
      container.innerHTML = '<div class="empty-state">No evidence recorded yet. Execute an assessment module to capture HTTP observations.</div>';
      countBadge.textContent = '0 Evidence Items';
      return;
    }

    countBadge.textContent = `${evidenceList.length} Items (HMAC Signed)`;
    container.innerHTML = evidenceList.map((ev, idx) => `
      <div class="evidence-card" data-idx="${idx}">
        <div class="ev-header">
          <span class="ev-id">[${ev.id}]</span>
          <span class="ev-type">${ev.evidence_type}</span>
          <span class="ev-status" style="color: ${ev.response_status === 200 ? '#10b981' : ev.response_status === 403 ? '#f59e0b' : '#f43f5e'}">
            HTTP ${ev.response_status}
          </span>
        </div>
        <div class="ev-desc">${ev.observation}</div>
        <div style="font-size: 10px; color: #64748b; margin-top: 4px; font-family: monospace;">
          Chain Hash: ${ev.chain_hash ? ev.chain_hash.substring(0, 16) + '...' : 'GENESIS'}
        </div>
      </div>
    `).join('');

    // Attach click listeners to inspect traffic
    container.querySelectorAll('.evidence-card').forEach(card => {
      card.addEventListener('click', () => {
        container.querySelectorAll('.evidence-card').forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        const idx = parseInt(card.dataset.idx, 10);
        const ev = evidenceList[idx];
        if (onSelectEvidence && ev) {
          onSelectEvidence(ev);
        }
      });
    });
  },

  renderFindingsList(findingsList, isPatched = false) {
    const container = document.getElementById('finding-container');

    if (!findingsList || findingsList.length === 0) {
      if (isPatched) {
        container.innerHTML = `
          <div class="finding-alert" style="border-color: #10b981; background: rgba(16, 185, 129, 0.1);">
            <div class="finding-title" style="color: #10b981;">[TARGET SECURE] All Security Controls Verified</div>
            <div class="finding-desc">No vulnerabilities detected. All authorization checks, security headers, origin restrictions, and data serializers are enforcing remediated state.</div>
          </div>
        `;
      } else {
        container.innerHTML = '<div class="empty-state">No confirmed findings yet. Execute an assessment module.</div>';
      }
      return;
    }

    container.innerHTML = `
      <div class="finding-list">
        ${findingsList.map(f => {
          const sevClass = (f.severity || 'low').toLowerCase();
          return `
            <div class="finding-alert ${sevClass}">
              <div class="finding-header-row">
                <span class="finding-title">${f.vulnerability_type}</span>
                <span class="severity-pill ${sevClass}">${f.severity}</span>
              </div>
              <div class="finding-desc">${f.impact || f.root_cause || ''}</div>
              <div class="finding-meta">
                <span>Endpoint: <strong>${f.endpoint || '/'}</strong></span>
                <span>Status: <strong>${f.status || 'CONFIRMED'}</strong></span>
                <span>Evidence: <strong>${(f.evidence_ids || []).join(', ')}</strong></span>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  },

  renderExecutiveSummary(findingsList) {
    const summaryElem = document.getElementById('exec-summary-bar');
    if (!summaryElem) return;

    let crit = 0, high = 0, med = 0, low = 0;
    (findingsList || []).forEach(f => {
      const sev = (f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') crit++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') med++;
      else low++;
    });

    summaryElem.innerHTML = `
      <div class="exec-stat-box"><div class="exec-stat-value" style="color: #f43f5e;">${crit}</div><div class="exec-stat-label">Critical</div></div>
      <div class="exec-stat-box"><div class="exec-stat-value" style="color: #f97316;">${high}</div><div class="exec-stat-label">High</div></div>
      <div class="exec-stat-box"><div class="exec-stat-value" style="color: #f59e0b;">${med}</div><div class="exec-stat-label">Medium</div></div>
      <div class="exec-stat-box"><div class="exec-stat-value" style="color: #38bdf8;">${low}</div><div class="exec-stat-label">Low / Info</div></div>
    `;
  },

  updateTopology(step, isCompromised = false, moduleName = 'idor') {
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
    document.getElementById('code-vulnerable').textContent = diffData.vulnerable || '// No vulnerable code available';
    document.getElementById('code-secure').textContent = diffData.secure || '// No remediation available';
  },

  showReportModal(content, onDownload) {
    let modal = document.getElementById('report-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'report-modal';
      modal.className = 'report-modal';
      modal.innerHTML = `
        <div class="report-modal-content">
          <div class="report-modal-header">
            <h3 style="color: #00f0ff; font-size: 14px; font-weight: 700;">RAVEN Security Audit Report</h3>
            <button id="modal-close" class="btn btn-sm btn-outline">Close</button>
          </div>
          <div class="report-modal-body" id="modal-body"></div>
          <div class="report-modal-footer">
            <button id="modal-dl-md" class="btn btn-sm btn-primary">Download Markdown</button>
            <button id="modal-dl-json" class="btn btn-sm btn-secondary">Download JSON</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);

      modal.querySelector('#modal-close').addEventListener('click', () => {
        modal.classList.add('hidden');
      });
    }

    modal.querySelector('#modal-body').textContent = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    modal.classList.remove('hidden');

    modal.querySelector('#modal-dl-md').onclick = () => onDownload('markdown');
    modal.querySelector('#modal-dl-json').onclick = () => onDownload('json');
  },
};

window.UI = UI;
