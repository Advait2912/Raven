// Main application controller for RAVEN Dashboard.

document.addEventListener('DOMContentLoaded', () => {
  let currentStep = 0;
  let isVulnerable = true;
  let activeModule = 'all';
  let activeMode = 'student';
  let allEvidenceList = [];
  const trafficHistory = { 1: null, 2: null, 3: null };

  // Header & Controls Elements
  const btnRunFull = document.getElementById('btn-run-full');
  const btnStepNext = document.getElementById('btn-step-next');
  const btnTogglePatch = document.getElementById('btn-toggle-patch');
  const btnExportReport = document.getElementById('btn-export-report');
  const btnReset = document.getElementById('btn-reset');
  const stepIndicator = document.getElementById('step-indicator');
  const patchStatusPill = document.getElementById('patch-status');
  const runBtnText = document.getElementById('run-btn-text');

  // Mode Switcher Elements
  const btnModeStudent = document.getElementById('mode-student');
  const btnModePro = document.getElementById('mode-professional');
  const replayBanner = document.getElementById('replay-banner');
  const studentTopologyView = document.getElementById('student-topology-view');
  const proSummaryView = document.getElementById('pro-summary-view');
  const panel1Title = document.getElementById('panel-1-title');

  // Module Bar Elements
  const moduleChips = document.querySelectorAll('.module-chip');

  // Traffic Tabs
  const trafficTabsContainer = document.getElementById('traffic-tabs');

  // Tutor Tabs
  const tabHints = document.getElementById('tab-hints');
  const tabExplain = document.getElementById('tab-explain');
  const tabPatch = document.getElementById('tab-patch');
  const hintCard = document.getElementById('tutor-body').querySelector('.hint-stepper');
  const explainCard = document.getElementById('explain-card');
  const patchCard = document.getElementById('patch-card');

  // 1. Mode Switching Logic
  function setDashboardMode(mode) {
    activeMode = mode;
    RavenAPI.setMode(mode);

    if (mode === 'student') {
      btnModeStudent.classList.add('active');
      btnModePro.classList.remove('active');
      replayBanner.classList.remove('hidden');
      studentTopologyView.classList.remove('hidden');
      proSummaryView.classList.add('hidden');
      btnStepNext.classList.remove('hidden');
      panel1Title.textContent = 'Target Topology & Execution Stepper';
    } else {
      btnModePro.classList.add('active');
      btnModeStudent.classList.remove('active');
      replayBanner.classList.add('hidden');
      studentTopologyView.classList.add('hidden');
      proSummaryView.classList.remove('hidden');
      btnStepNext.classList.add('hidden');
      panel1Title.textContent = 'Executive Risk Summary & Scope Gate';
    }
  }

  btnModeStudent.addEventListener('click', () => setDashboardMode('student'));
  btnModePro.addEventListener('click', () => setDashboardMode('professional'));

  // 2. Module Selection Logic
  moduleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      moduleChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      activeModule = chip.dataset.mod;
      runBtnText.textContent = activeModule === 'all' ? 'Run Assessment Suite' : `Run ${chip.querySelector('span').textContent}`;
    });
  });

  // 3. Traffic Inspector Evidence Click Callback
  function inspectEvidenceItem(ev) {
    const req = {
      method: ev.request_method,
      path: ev.request_path,
      headers: ev.request_headers,
      body: ev.request_body,
    };
    const res = {
      status: ev.response_status,
      headers: ev.response_headers,
      body: ev.response_body,
    };
    UI.renderTraffic(req, res);
  }

  // 4. Tutor Tabs Switching
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

  // 5. Progressive Hint Buttons
  [1, 2, 3].forEach(lvl => {
    document.getElementById(`hint-${lvl}`).addEventListener('click', async (e) => {
      document.querySelectorAll('.hint-buttons .btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      const hint = await RavenAPI.getStudentHint(lvl);
      document.getElementById('hint-title').textContent = hint.title || `Tier ${lvl} Guidance`;
      document.getElementById('hint-text').textContent = hint.content || hint.reason;
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

  // 6. Execute Next Step (Student Guided Stepper)
  btnStepNext.addEventListener('click', async () => {
    if (currentStep >= 3) currentStep = 0;
    currentStep += 1;
    stepIndicator.textContent = `Step ${currentStep} of 3: In Progress`;

    const res = await RavenAPI.runStep(currentStep);
    trafficHistory[currentStep] = { req: res.request, res: res.response };

    // Update inspector
    document.querySelectorAll('.panel-inspector .tab-btn').forEach(b => b.classList.remove('active'));
    const activeTab = document.getElementById(`tab-step-${currentStep}`);
    if (activeTab) activeTab.classList.add('active');
    UI.renderTraffic(res.request, res.response);

    // Refresh evidence
    const evData = await RavenAPI.getEvidence();
    allEvidenceList = evData.evidence || [];
    UI.renderEvidence(allEvidenceList, inspectEvidenceItem);

    if (currentStep === 3) {
      const findingsList = res.finding ? [res.finding] : [];
      UI.renderFindingsList(findingsList, !isVulnerable);
      UI.renderExecutiveSummary(findingsList);
      UI.updateTopology(3, res.confirmed);
      stepIndicator.textContent = res.confirmed ? 'Step 3: Confirmed IDOR!' : 'Step 3: Access Blocked (Safe)';
    } else {
      UI.updateTopology(currentStep, false);
    }
  });

  // 7. Run Assessment (Selected Module or All Modules)
  btnRunFull.addEventListener('click', async () => {
    stepIndicator.textContent = `Running ${activeModule.toUpperCase()}...`;
    btnRunFull.disabled = true;

    try {
      const data = await RavenAPI.runModule(activeModule);
      allEvidenceList = data.evidence || [];

      // Render Evidence with click inspector callback
      UI.renderEvidence(allEvidenceList, inspectEvidenceItem);

      // Render Findings List & Executive Summary
      const findingsList = data.findings || [];
      UI.renderFindingsList(findingsList, !isVulnerable);
      UI.renderExecutiveSummary(findingsList);

      // Render first evidence item in traffic inspector
      if (allEvidenceList.length > 0) {
        inspectEvidenceItem(allEvidenceList[allEvidenceList.length - 1]);
      }

      // Update Topology
      const hasConfirmed = findingsList.some(f => f.status === 'CONFIRMED' || f.confirmed);
      UI.updateTopology(3, hasConfirmed, activeModule);

      stepIndicator.textContent = hasConfirmed
        ? `Assessment Completed: ${findingsList.length} Finding(s)`
        : 'Assessment Completed: Clean / Remediated';

      // Automatically preload AI explanation if on explain tab
      if (tabExplain.classList.contains('active')) {
        loadExplanation();
      }
    } finally {
      btnRunFull.disabled = false;
    }
  });

  // 8. Toggle Target Remediation Patch
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

  // 9. Export Report Handler
  btnExportReport.addEventListener('click', async () => {
    const mdReport = await RavenAPI.getReport('markdown');
    UI.showReportModal(mdReport, async (format) => {
      const content = format === 'markdown' ? mdReport : JSON.stringify(await RavenAPI.getReport('json'), null, 2);
      const blob = new Blob([content], { type: format === 'markdown' ? 'text/markdown' : 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `raven_audit_report_${Date.now()}.${format === 'markdown' ? 'md' : 'json'}`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });

  // 10. Reset Dashboard State
  btnReset.addEventListener('click', async () => {
    currentStep = 0;
    isVulnerable = true;
    allEvidenceList = [];
    patchStatusPill.innerHTML = '<span class="dot red"></span> Mode: Vulnerable';
    btnTogglePatch.innerHTML = '<span class="btn-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span> Patch Target';
    trafficHistory[1] = null;
    trafficHistory[2] = null;
    trafficHistory[3] = null;
    await RavenAPI.resetDemo();
    stepIndicator.textContent = 'Ready';
    UI.renderTraffic(null, null);
    UI.renderEvidence([], inspectEvidenceItem);
    UI.renderFindingsList([], false);
    UI.renderExecutiveSummary([]);
    UI.updateTopology(0, false);
  });
});
