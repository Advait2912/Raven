// Main application controller for RAVEN Dashboard.

document.addEventListener('DOMContentLoaded', () => {
  let currentStep = 0;
  let isVulnerable = true;
  const trafficHistory = { 1: null, 2: null, 3: null };

  // Button Elements
  const btnRunFull = document.getElementById('btn-run-full');
  const btnStepNext = document.getElementById('btn-step-next');
  const btnTogglePatch = document.getElementById('btn-toggle-patch');
  const btnReset = document.getElementById('btn-reset');
  const stepIndicator = document.getElementById('step-indicator');
  const patchStatusPill = document.getElementById('patch-status');

  // Traffic Tab switching
  ['1', '2', '3'].forEach(num => {
    document.getElementById(`tab-step-${num}`).addEventListener('click', (e) => {
      document.querySelectorAll('.panel-inspector .tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      const stepData = trafficHistory[num];
      UI.renderTraffic(stepData?.req, stepData?.res);
    });
  });

  // Tutor Tab switching
  const tabHints = document.getElementById('tab-hints');
  const tabExplain = document.getElementById('tab-explain');
  const tabPatch = document.getElementById('tab-patch');
  const hintCard = document.getElementById('tutor-body').querySelector('.hint-stepper');
  const explainCard = document.getElementById('explain-card');
  const patchCard = document.getElementById('patch-card');

  function showTutorTab(tab) {
    [tabHints, tabExplain, tabPatch].forEach(t => t.classList.remove('active'));
    [hintCard, explainCard, patchCard].forEach(c => c.classList.add('hidden'));

    if (tab === 'hints') { tabHints.classList.add('active'); hintCard.classList.remove('hidden'); }
    if (tab === 'explain') { tabExplain.classList.add('active'); explainCard.classList.remove('hidden'); loadExplanation(); }
    if (tab === 'patch') { tabPatch.classList.add('active'); patchCard.classList.remove('hidden'); loadRemediation(); }
  }

  tabHints.addEventListener('click', () => showTutorTab('hints'));
  tabExplain.addEventListener('click', () => showTutorTab('explain'));
  tabPatch.addEventListener('click', () => showTutorTab('patch'));

  // Progressive Hint Buttons
  [1, 2, 3].forEach(lvl => {
    document.getElementById(`hint-${lvl}`).addEventListener('click', async (e) => {
      document.querySelectorAll('.hint-buttons .btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      const hint = await RavenAPI.getHint(lvl);
      document.getElementById('hint-title').textContent = hint.title;
      document.getElementById('hint-text').textContent = hint.content;
    });
  });

  async function loadExplanation() {
    const data = await RavenAPI.getExplanation();
    document.getElementById('ai-text').textContent = data.explanation || 'No explanation available.';
    if (data.model_used) {
      document.getElementById('ai-model-tag').textContent = `Model: ${data.model_used}`;
    }
  }

  async function loadRemediation() {
    const diff = await RavenAPI.getRemediation();
    UI.renderRemediationDiff(diff);
  }

  // Execute Next Step
  btnStepNext.addEventListener('click', async () => {
    if (currentStep >= 3) currentStep = 0;
    currentStep += 1;
    stepIndicator.textContent = `Step ${currentStep} of 3: In Progress`;

    const res = await RavenAPI.runStep(currentStep);
    trafficHistory[currentStep] = { req: res.request, res: res.response };

    // Update inspector to current step
    document.querySelectorAll('.panel-inspector .tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`tab-step-${currentStep}`).classList.add('active');
    UI.renderTraffic(res.request, res.response);

    // Refresh evidence
    const evData = await RavenAPI.getEvidence();
    UI.renderEvidence(evData.evidence);

    if (currentStep === 3) {
      UI.renderFinding(res.finding, !isVulnerable);
      UI.updateTopology(3, res.confirmed);
      stepIndicator.textContent = res.confirmed ? 'Step 3: Confirmed IDOR!' : 'Step 3: Access Blocked (Safe)';
    } else {
      UI.updateTopology(currentStep, false);
    }
  });

  // Run Full Attack
  btnRunFull.addEventListener('click', async () => {
    stepIndicator.textContent = 'Executing full scenario...';
    const res = await RavenAPI.runFullAttack();
    const result = res.result;

    currentStep = 3;
    stepIndicator.textContent = result.success ? 'Attack Finished: IDOR Confirmed!' : 'Attack Finished: Blocked (Safe)';
    UI.renderEvidence(result.evidence);
    UI.renderFinding(result.findings && result.findings.length > 0 ? result.findings[0] : null, !isVulnerable);
    UI.updateTopology(3, result.success);

    // Populate traffic history
    if (result.evidence && result.evidence.length >= 2) {
      trafficHistory[2] = { req: { method: 'GET', path: '/api/orders/101', headers: result.evidence[0].request_headers }, res: { status: result.evidence[0].response_status, body: result.evidence[0].response_body } };
      trafficHistory[3] = { req: { method: 'GET', path: '/api/orders/102', headers: result.evidence[1].request_headers }, res: { status: result.evidence[1].response_status, body: result.evidence[1].response_body } };
      UI.renderTraffic(trafficHistory[3].req, trafficHistory[3].res);
      document.querySelectorAll('.panel-inspector .tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById('tab-step-3').classList.add('active');
    }
  });

  // Toggle Target Remediation Patch
  btnTogglePatch.addEventListener('click', async () => {
    isVulnerable = !isVulnerable;
    await RavenAPI.togglePatch(isVulnerable);
    if (isVulnerable) {
      patchStatusPill.innerHTML = '<span class="dot red"></span> Mode: Vulnerable';
      btnTogglePatch.innerHTML = '<span class="btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span> Patch Target';
    } else {
      patchStatusPill.innerHTML = '<span class="dot green"></span> Mode: Patched & Secure';
      btnTogglePatch.innerHTML = '<span class="btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg></span> Unpatch Target';
    }
  });

  // Reset Button
  btnReset.addEventListener('click', async () => {
    currentStep = 0;
    isVulnerable = true;
    patchStatusPill.innerHTML = '<span class="dot red"></span> Mode: Vulnerable';
    btnTogglePatch.innerHTML = '<span class="btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span> Patch Target';
    trafficHistory[1] = null;
    trafficHistory[2] = null;
    trafficHistory[3] = null;
    await RavenAPI.resetDemo();
    stepIndicator.textContent = 'Step 0 of 3: Ready';
    UI.renderTraffic(null, null);
    UI.renderEvidence([]);
    UI.renderFinding(null);
    UI.updateTopology(0, false);
  });
});
