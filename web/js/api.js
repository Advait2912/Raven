// RAVEN API client for interacting with the backend server.

const RavenAPI = {
  async runFullAttack() {
    const res = await fetch('/api/demo/run', { method: 'POST' });
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

  async getEvidence() {
    const res = await fetch('/api/demo/evidence');
    return await res.json();
  },

  async getHint(level) {
    const res = await fetch(`/api/demo/hints?level=${level}`);
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
};

window.RavenAPI = RavenAPI;
