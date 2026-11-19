// RAVEN API client for interacting with the backend server.

const RavenAPI = {
  async runFullAttack() {
    const res = await fetch('/api/demo/run', { method: 'POST' });
    return await res.json();
  },

  async runModule(moduleName = 'all') {
    const res = await fetch('/api/demo/modules/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ module: moduleName }),
    });
    return await res.json();
  },

  async runStep(stepNumber) {
    const res = await fetch('/api/demo/step', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step: stepNumber }),
    });
    return await res.json();
  },

  async resetDemo() {
    const res = await fetch('/api/demo/reset', { method: 'POST' });
    return await res.json();
  },

  async togglePatch(isVulnerable) {
    const res = await fetch('/api/demo/patch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_vulnerable: isVulnerable }),
    });
    return await res.json();
  },

  async setMode(mode) {
    const res = await fetch('/api/demo/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    });
    return await res.json();
  },

  async getEvidence() {
    const res = await fetch('/api/demo/evidence');
    return await res.json();
  },

  async getFindings() {
    const res = await fetch('/api/demo/findings');
    return await res.json();
  },

  async getHint(level) {
    const res = await fetch(`/api/demo/hints?level=${level}`);
    return await res.json();
  },

  async getStudentHint(tier, sessionId = 'default') {
    const res = await fetch(`/api/demo/student/hint?tier=${tier}&session_id=${sessionId}`);
    return await res.json();
  },

  async getExplanation() {
    const res = await fetch('/api/demo/explain');
    return await res.json();
  },

  async getRemediation() {
    const res = await fetch('/api/demo/remediation');
    return await res.json();
  },

  async getReport(format = 'json') {
    const res = await fetch(`/api/demo/report?format=${format}`);
    if (format === 'markdown') {
      return await res.text();
    }
    return await res.json();
  },
};

window.RavenAPI = RavenAPI;
