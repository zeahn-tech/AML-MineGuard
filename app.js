// ============================================
// MINEGUARD APP — MAIN LOGIC
// v5 — Multilingual + Push Notifications
// ============================================

// ---- SPLASH SCREEN ----
// Authentication gate: the worker workspace is AUTHENTICATED surface. The
// splash hides the shell while the session + membership resolve; the gate
// (auth-gate.js) decides between the welcome/auth screen and the workspace.
// Safety-reference content (glossary/PPE/first aid/emergency procedures) is
// public-by-design and also reachable from the gate note; tenant data is not.
function dismissSplash(entry) {
  try {
    const splash = document.getElementById('splash');
    if (splash) { splash.classList.add('fade-out'); setTimeout(() => { splash.style.display = 'none'; }, 500); }
    if (entry === 'workspace') {
      const app = document.getElementById('app');
      if (app) app.classList.remove('hidden');
      initApp();
    }
  } catch(e) {
    console.error('Init error:', e);
    const splash = document.getElementById('splash');
    if (splash) splash.style.display = 'none';
  }
}

function resolveEntry() {
  function finish(destination) {
    if (destination === 'AUTH_REQUIRED') {
      dismissSplash('gate');
      if (window.MG_GATE) MG_GATE.showGate();
    } else if (destination === 'NO_ORGANIZATION') {
      // Authenticated with no membership: show the workspace shell (public
      // reference tabs work) but surface onboarding guidance via the gate.
      dismissSplash('workspace');
      if (window.MG_GATE) { MG_GATE.showGate(); MG_GATE.showGateMsg(t ? t('gateNoOrg') : 'No organization has been assigned to your account yet. Ask your administrator for an invitation, or create your own organization.', 'info'); }
    } else if (destination === 'COMPANY_ADMIN' || destination === 'GOVERNMENT_WORKSPACE') {
      // Session 21 — workspace switching: an admin may intentionally work in
      // the Worker Workspace. The preference is a UI choice only — the role
      // in the database never changes, and every admin surface still gates
      // on the server-side role (worker/admin.html rejects non-admins).
      try {
        if (sessionStorage.getItem('mg_workspace') === 'worker') {
          dismissSplash('workspace');
          return;
        }
      } catch (e) { /* storage unavailable: default admin routing */ }
      dismissSplash('workspace');
      window.location.replace('admin.html');
    } else if (destination === 'SELECT_ORGANIZATION') {
      dismissSplash('workspace');
      if (window.MG_GATE) { MG_GATE.showGate(); MG_GATE.showGateMsg(t ? t('gateSelectOrg') : 'You belong to more than one organization. Open the account menu to choose which one to work in.', 'info'); }
    } else if (destination === 'VERIFY_FAILED') {
      // Session verification failed (connection/server) — do NOT claim the user
      // is signed out or orgless. Gate stays with a retry message (added by the
      // caller); the splash is dismissed so the user can see the state.
      dismissSplash('gate');
    } else {
      dismissSplash('workspace');
    }
  }
  if (!(window.MG_GATE && window.MG_AUTH && window.MG_CONFIG)) { finish('AUTH_REQUIRED'); return; }
  MG_GATE.resolveDestination(MG_AUTH).then(finish).catch(function (err) {
    // Verification failure ≠ signed-out: the user may hold a valid session and
    // an organization. Show the gate with a clear retry message instead of
    // pretending they need to sign in again.
    console.warn('[MineGuard] destination verification failed:', err && err.message);
    finish('VERIFY_FAILED');
    if (window.MG_GATE) MG_GATE.showGateMsg('Signed in, but we could not verify your organization access. Please retry in a moment.', 'info');
  });
}

window.addEventListener('load', () => { setTimeout(resolveEntry, 900); });
setTimeout(resolveEntry, 3500);

// ---- APP INIT ----
let connectivityRefreshBound = false;

function initApp() {
  applyLanguageToDOM();
  renderGlossary();
  renderPPE();
  renderPPEChecklist();
  renderEmergencyContacts();
  renderFirstAid();
  renderLetterFilter();
  setDailyTip();
  updateGlossaryCount();
  checkOnlineStatus();
  setJSADate();
  renderNotificationWidget();
  checkNotificationStatus();
  initSOSSystem();
  // Show Firebase sync status
  if (window.MG && window.MG.online) {
    updateSyncBanner('synced');
  } else {
    updateSyncBanner('offline');
  }
  bindConnectivityRefreshHandlers();
}

function bindConnectivityRefreshHandlers() {
  if (connectivityRefreshBound) return;
  connectivityRefreshBound = true;
  window.addEventListener('mg-connectivity-change', async function() {
    if (window.MG && window.MG.online) {
      updateSyncBanner('synced');
      try {
        await Promise.allSettled([
          typeof fetchNotices === 'function' ? fetchNotices().then(() => renderNoticesTab()) : Promise.resolve(),
          typeof renderPastIncidents === 'function' ? Promise.resolve(renderPastIncidents()) : Promise.resolve(),
          typeof initSOSSystem === 'function' ? Promise.resolve(initSOSSystem()) : Promise.resolve()
        ]);
      } catch (e) {
        console.warn('[MineGuard] Connectivity refresh failed:', e.message);
      }
    } else {
      updateSyncBanner('offline');
    }
  });
}

// ============================================
// EMERGENCY SOS SYSTEM
// ============================================

window.MG_SOS = window.MG_SOS || {
  tone: null,
  toneContext: null,
  timer: null,
};

const SOS_CHANNEL_NAME = 'mineguard-sos-state';
let sosBroadcastChannel = null;
let sosChannelBound = false;
let sosCloudUnsub = null;
let lastEmergencySOSSignature = '';
let lastEmergencyNotificationSignature = '';

function escapeHtml(value) {
  return String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function getSOSState() {
  try {
    return JSON.parse(localStorage.getItem('mineguard_sos_state') || 'null');
  } catch (e) {
    return null;
  }
}

function saveSOSState(state) {
  localStorage.setItem('mineguard_sos_state', JSON.stringify(state));
  lastEmergencySOSSignature = getEmergencySOSSignature(state);
  broadcastSOSState(state);
  window.dispatchEvent(new Event('storage'));
}

function getEmergencySOSSignature(state) {
  if (!state) return 'none';
  const acknowledgements = Array.isArray(state.acknowledgements) ? state.acknowledgements.join('|') : '';
  return [
    state._id || '',
    state.active ? '1' : '0',
    state.startedAt || 0,
    state.updatedAt || 0,
    acknowledgements,
  ].join('::');
}

function syncEmergencySOSState(state, options) {
  if (!state) return false;
  const sig = getEmergencySOSSignature(state);
  if (sig === lastEmergencySOSSignature) {
    if (state.active) {
      renderEmergencyOverlay(state);
    }
    return false;
  }
  lastEmergencySOSSignature = sig;
  localStorage.setItem('mineguard_sos_state', JSON.stringify(state));
  broadcastSOSState(state);
  if (state.active) {
    renderEmergencyOverlay(state);
    if (!options || options.notify !== false) {
      showEmergencyNotification(state);
    }
  } else {
    hideEmergencyOverlay();
  }
  return true;
}

function broadcastSOSState(state) {
  try {
    if (typeof BroadcastChannel === 'undefined') return;
    if (!sosBroadcastChannel) {
      sosBroadcastChannel = new BroadcastChannel(SOS_CHANNEL_NAME);
    }
    sosBroadcastChannel.postMessage({
      type: 'sos-state',
      state: state || null,
      timestamp: Date.now()
    });
  } catch (e) {
    console.warn('[SOS] Broadcast failed:', e.message);
  }
}

function setupSOSBroadcastListener() {
  if (sosChannelBound || typeof BroadcastChannel === 'undefined') return;
  sosChannelBound = true;
  try {
    sosBroadcastChannel = new BroadcastChannel(SOS_CHANNEL_NAME);
    sosBroadcastChannel.onmessage = function(event) {
      const payload = event && event.data ? event.data : null;
      if (!payload || payload.type !== 'sos-state') return;
      const state = payload.state || null;
      if (state && state.active) {
        renderEmergencyOverlay(state);
        showEmergencyNotification(state);
      } else {
        hideEmergencyOverlay();
      }
    };
  } catch (e) {
    console.warn('[SOS] Broadcast channel unavailable:', e.message);
  }
}

function getWorkerDeviceId() {
  let id = localStorage.getItem('mg_worker_device_id');
  if (!id) {
    id = 'worker-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    localStorage.setItem('mg_worker_device_id', id);
  }
  return id;
}

function registerWorkerDevice() {
  const deviceId = getWorkerDeviceId();
  const registered = JSON.parse(localStorage.getItem('mineguard_sos_registered_workers') || '[]');
  if (!registered.includes(deviceId)) {
    registered.push(deviceId);
    localStorage.setItem('mineguard_sos_registered_workers', JSON.stringify(registered));
  }
}

function getRegisteredWorkerCount() {
  try {
    const registered = JSON.parse(localStorage.getItem('mineguard_sos_registered_workers') || '[]');
    return Math.max(1, registered.length || 1);
  } catch (e) {
    return 1;
  }
}

function startEmergencyTone() {
  if (window.MG_SOS.toneContext) return;
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(780, ctx.currentTime);
    osc.frequency.linearRampToValueAtTime(1080, ctx.currentTime + 0.35);
    gain.gain.setValueAtTime(0.001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.28, ctx.currentTime + 0.05);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    ctx.resume().catch(() => {});
    window.MG_SOS.toneContext = ctx;
    window.MG_SOS.tone = { osc, gain };
    window.MG_SOS.timer = setInterval(() => {
      if (!window.MG_SOS.toneContext) return;
      const freq = window.MG_SOS.toneContext.currentTime % 2 < 1 ? 780 : 1120;
      window.MG_SOS.tone?.osc.frequency.setValueAtTime(freq, window.MG_SOS.toneContext.currentTime);
    }, 500);
  } catch (e) {
    console.warn('[SOS] Audio alarm unavailable:', e.message);
  }
}

function stopEmergencyTone() {
  if (window.MG_SOS.tone?.osc) {
    try { window.MG_SOS.tone.osc.stop(); } catch (e) {}
  }
  if (window.MG_SOS.timer) {
    clearInterval(window.MG_SOS.timer);
    window.MG_SOS.timer = null;
  }
  if (window.MG_SOS.toneContext) {
    try { window.MG_SOS.toneContext.close(); } catch (e) {}
  }
  window.MG_SOS.toneContext = null;
  window.MG_SOS.tone = null;
}

function updateEmergencyTitle(state) {
  if (!state || !state.active) {
    document.title = 'MineGuard';
    return;
  }
  const base = '🚨 EMERGENCY ALERT';
  document.title = document.title.includes(base) ? document.title : base;
}

async function showEmergencyNotification(state) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const signature = getEmergencySOSSignature(state);
  if (signature === lastEmergencyNotificationSignature) return;
  lastEmergencyNotificationSignature = signature;

  const title = '🚨 Emergency SOS Active';
  const options = {
    body: state.message || 'A site-wide emergency alert has been activated.',
    tag: 'mineguard-sos-' + (state._id || state.startedAt || 'active'),
    requireInteraction: true,
    renotify: true,
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
    vibrate: [500, 200, 500, 200, 800],
    actions: [
      { action: 'open', title: 'Open Alert' },
      { action: 'ack', title: 'Acknowledge' }
    ],
    data: { url: './index.html?tab=emergency' }
  };

  try {
    if (navigator.vibrate) navigator.vibrate([500, 200, 500, 200, 800]);
    if ('serviceWorker' in navigator) {
      const reg = await navigator.serviceWorker.ready;
      if (reg && reg.showNotification) {
        await reg.showNotification(title, options);
        return;
      }
    }
    new Notification(title, options);
  } catch (e) {
    console.warn('[SOS] Push notification failed:', e.message);
  }
}

function renderEmergencyOverlay(state) {
  if (!state || !state.active) {
    hideEmergencyOverlay();
    return;
  }

  const overlay = document.getElementById('emergencyOverlay');
  if (!overlay) return;

  const now = new Date();
  const category = state.category || 'Other';
  const activatedBy = state.activatedBy || 'Safety Officer';
  const contactNumber = state.contactNumber || '+231 770 000 000';
  const assemblyPoint = state.assemblyPoint || state.site || 'Proceed to the designated assembly point';
  overlay.innerHTML = `
    <div class="emergency-screen">
      <div class="emergency-screen-shell">
        <div class="emergency-screen-icon">🚨</div>
        <div class="emergency-screen-label">Emergency Alert</div>
        <div class="emergency-screen-title">EMERGENCY ALERT</div>
        <div class="emergency-screen-message">${escapeHtml(state.message || 'Emergency alert activated. Stop all work immediately and proceed to the assembly point.')}</div>
        <div class="emergency-screen-meta">
          <div class="emergency-screen-meta-card">
            <div class="emergency-screen-meta-label">Current Time</div>
            <div class="emergency-screen-meta-value">${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
          </div>
          <div class="emergency-screen-meta-card">
            <div class="emergency-screen-meta-label">Alert Type</div>
            <div class="emergency-screen-meta-value">${escapeHtml(category)}</div>
          </div>
          <div class="emergency-screen-meta-card">
            <div class="emergency-screen-meta-label">Activated By</div>
            <div class="emergency-screen-meta-value">${escapeHtml(activatedBy)}</div>
          </div>
          <div class="emergency-screen-meta-card">
            <div class="emergency-screen-meta-label">Status</div>
            <div class="emergency-screen-meta-value">SOS ACTIVE</div>
          </div>
        </div>
        <div class="emergency-screen-list">
          <h4>Worker Actions</h4>
          <div class="emergency-screen-action-grid">
            <div class="emergency-screen-action-item">
              <div class="emergency-screen-action-label">Emergency Contact Number</div>
              <div class="emergency-screen-action-value">${escapeHtml(contactNumber)}</div>
            </div>
            <div class="emergency-screen-action-item">
              <div class="emergency-screen-action-label">Assembly Point</div>
              <div class="emergency-screen-action-value">${escapeHtml(assemblyPoint)}</div>
            </div>
          </div>
        </div>
        <div class="emergency-screen-actions">
          <button class="emergency-hero-btn" onclick="acknowledgeEmergency()">I have received this alert.</button>
          <div class="emergency-screen-status">SOS ACTIVE</div>
        </div>
        <div class="emergency-screen-list">
          <h4>Worker Instructions</h4>
          <ul>
            <li>STOP ALL WORK IMMEDIATELY</li>
            <li>Proceed to your designated Emergency Assembly Point.</li>
            <li>Follow all instructions from the Safety Officer.</li>
            <li>Do not return until the emergency has been officially cleared.</li>
          </ul>
        </div>
        <div class="emergency-screen-list">
          <h4>Emergency Contacts</h4>
          <ul>
            <li>Site Control: 911</li>
            <li>Safety Office: +231 770 000 000</li>
            <li>Medical Team: +231 770 000 111</li>
          </ul>
        </div>
        <div class="emergency-screen-ack">Acknowledge this alert to dismiss your local screen. The Emergency SOS remains active until an authorized administrator clears it.</div>
      </div>
    </div>`;
  overlay.style.display = 'flex';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';
  document.body.classList.add('mg-sos-locked');
  startEmergencyTone();
  updateEmergencyTitle(state);
}

function hideEmergencyOverlay() {
  const overlay = document.getElementById('emergencyOverlay');
  if (overlay) overlay.style.display = 'none';
  document.body.classList.remove('mg-sos-locked');
  stopEmergencyTone();
}

function acknowledgeEmergency() {
  const state = getSOSState();
  if (!state || !state.active) {
    hideEmergencyOverlay();
    return;
  }
  const deviceId = getWorkerDeviceId();
  const acknowledgements = Array.isArray(state.acknowledgements) ? state.acknowledgements : [];
  if (!acknowledgements.includes(deviceId)) {
    acknowledgements.push(deviceId);
    state.acknowledgements = acknowledgements;
    saveSOSState(state);
    if (state._id && typeof updateEmergencySOSCloud === 'function') {
      updateEmergencySOSCloud(state._id, {
        acknowledgements,
        acknowledgedWorkers: acknowledgements.length,
        lastAcknowledgedAt: Date.now()
      }).catch(e => console.warn('[SOS] Cloud acknowledgement update failed:', e.message));
    }
  }
  hideEmergencyOverlay();
}

function initSOSSystem() {
  registerWorkerDevice();
  setupSOSBroadcastListener();
  if (!sosCloudUnsub && typeof subscribeEmergencySOS === 'function') {
    sosCloudUnsub = subscribeEmergencySOS(function(cloudState) {
      if (!cloudState) return;
      const current = getSOSState() || {};
      const merged = {
        ...current,
        ...cloudState,
        acknowledgements: Array.isArray(cloudState.acknowledgements)
          ? cloudState.acknowledgements
          : (current.acknowledgements || [])
      };
      syncEmergencySOSState(merged, { notify: true });
    });
  }
  const state = getSOSState();
  if (state && state.active) {
    syncEmergencySOSState(state, { notify: false });
  } else {
    hideEmergencyOverlay();
  }
}

window.addEventListener('storage', () => {
  initSOSSystem();
});

window.addEventListener('message', event => {
  const data = event && event.data ? event.data : null;
  if (!data || typeof data !== 'object') return;
  if (data.type === 'sos-state' && data.state) {
    syncEmergencySOSState(data.state, { notify: true });
  }
  if (data.type === 'open-tab' && data.tab === 'emergency') {
    const tabButton = document.querySelector('[data-tab="emergency"]');
    if (typeof showTab === 'function') {
      showTab('emergency', tabButton);
    }
  }
});

window.addEventListener('sos-change', () => {
  initSOSSystem();
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) initSOSSystem();
});

// ============================================
// LANGUAGE SWITCHING
// ============================================

function applyLanguageToDOM() {
  // Offline badge
  checkOnlineStatus();

  // Nav labels
  const navMap = {
    'nav-home': 'navHome',
    'nav-glossary': 'navGlossary',
    'nav-ppe': 'navPPE',
    'nav-jsa': 'navJSA',
    'nav-report': 'navReport',
    'nav-sos': 'navSOS',
  };
  Object.entries(navMap).forEach(([id, key]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = t(key);
  });

  // Hero section
  const heroTitle = document.getElementById('heroTitle');
  if (heroTitle) heroTitle.innerHTML = t('heroTitle');
  const heroSub = document.getElementById('heroSub');
  if (heroSub) heroSub.textContent = t('heroSub');

  // Quick access labels
  setTextById('qc-glossary-label', t('navGlossary'));
  setTextById('qc-ppe-label', t('navPPE'));
  setTextById('qc-jsa-label', t('jsaTool'));
  setTextById('qc-jsa-count', t('jsaRisk'));
  setTextById('qc-emergency-label', t('emergency'));
  setTextById('qc-emergency-count', t('tapNow'));

  const quickAccess = document.getElementById('quickAccessTitle');
  if (quickAccess) quickAccess.textContent = t('quickAccess');

  const adminLink = document.getElementById('adminLinkText');
  if (adminLink) adminLink.textContent = t('adminDashboard');

  const tipLabel = document.getElementById('tipLabel');
  if (tipLabel) tipLabel.textContent = t('safetyTipLabel');

  setTextById('statTermsDefined', t('termsDefined'));
  setTextById('statPPEItems', t('ppeItemsLabel'));
  setTextById('statOffline', t('offlineReady'));

  // Glossary tab
  setTextById('glossaryTabTitle', t('glossaryTitle'));
  setTextById('glossaryTabSub', t('glossarySub'));
  const glossarySearch = document.getElementById('glossarySearch');
  if (glossarySearch) glossarySearch.placeholder = t('searchPlaceholder');

  // PPE tab
  setTextById('ppeTabTitle', t('ppeTitle'));
  setTextById('ppeTabSub', t('ppeSub'));

  // JSA tab
  setTextById('jsaTabTitle', t('jsaTitle'));
  setTextById('jsaTabSub', t('jsaSub'));
  setPlaceholder('jsa-worker', t('workerNamePlaceholder'));
  setPlaceholder('jsa-task', t('taskPlaceholder'));
  setPlaceholder('jsa-location', t('locationPlaceholder'));
  setPlaceholder('jsa-supervisor', t('supervisorPlaceholder'));
  setLabelText('label-jsa-worker', t('workerName'));
  setLabelText('label-jsa-task', t('taskDesc'));
  setLabelText('label-jsa-location', t('locationArea'));
  setLabelText('label-jsa-date', t('date'));
  setLabelText('label-jsa-supervisor', t('supervisorName'));
  setTextById('jsaHazardTitle', t('hazardId'));
  setTextById('jsaPPETitle', t('ppeRequired'));
  setTextById('btnAddHazard', t('addHazard'));
  setTextById('btnSaveJSA', t('saveJSA'));
  setTextById('btnClearJSA', t('clearForm'));

  // Incident tab
  setTextById('incTabTitle', t('incidentTitle'));
  setTextById('incTabSub', t('incidentSub'));
  setTextById('incReporterTitle', t('reporterInfo'));
  setLabelText('label-inc-name', t('fullName'));
  setLabelText('label-inc-badge', t('employeeId'));
  setLabelText('label-inc-dept', t('department'));
  setPlaceholder('inc-name', t('fullNamePlaceholder'));
  setPlaceholder('inc-badge', t('employeePlaceholder'));
  setPlaceholder('inc-dept', t('deptPlaceholder'));
  setTextById('incDetailsTitle', t('incidentDetails'));
  setLabelText('label-inc-datetime', t('dateTime'));
  setLabelText('label-inc-location', t('incidentLocation'));
  setLabelText('label-inc-type', t('incidentType'));
  setLabelText('label-inc-severity', t('severity'));
  setPlaceholder('inc-location', t('incidentLocationPlaceholder'));
  updateIncidentTypeOptions();
  updateSeverityButtons();
  setTextById('incWhatTitle', t('whatHappened'));
  setLabelText('label-inc-description', t('describeIncident'));
  setPlaceholder('inc-description', t('describePlaceholder'));
  setLabelText('label-inc-action', t('immediateAction'));
  setPlaceholder('inc-action', t('actionPlaceholder'));
  setTextById('incPhotoTitle', t('photoEvidence'));
  setTextById('incPhotoHint', t('photoHint'));
  setTextById('btnTakePhoto', t('takePhoto'));
  setTextById('labelOpensCamera', t('opensCamera'));
  setTextById('btnChoosePhoto', t('choosePhoto'));
  setTextById('labelFromGallery', t('fromGallery'));
  setTextById('incWitnessTitle', t('witnesses'));
  setPlaceholder('inc-witnesses', t('witnessesPlaceholder'));
  setTextById('btnSubmitIncident', t('submitReport'));
  setTextById('btnClearIncident', t('clearBtn'));

  // Emergency tab
  setTextById('emergencyTabTitle', t('emergencyTitle'));
  setTextById('emergencyTabSub', t('emergencySub'));
  setTextById('emergencyActionsTitle', t('immediateActions'));
  setInnerHTML('emergencyStep1', t('step1'));
  setInnerHTML('emergencyStep2', t('step2'));
  setInnerHTML('emergencyStep3', t('step3'));
  setInnerHTML('emergencyStep4', t('step4'));
  setInnerHTML('emergencyStep5', t('step5'));
  setTextById('emergencyContactsTitle', t('emergencyContacts'));
  setTextById('btnAddContact', t('addSiteContact'));
  setPlaceholder('contactName', t('contactNamePlaceholder'));
  setPlaceholder('contactNumber', t('contactNumberPlaceholder'));
  setTextById('btnSaveContact', t('save'));
  setTextById('btnCancelContact', t('cancel'));
  setTextById('firstAidTitle', t('firstAidGuide'));

  // Notification widget
  setTextById('notifWidgetTitle', t('notifTitle'));
  setTextById('notifWidgetSub', t('notifSub'));
  renderNotificationWidget();
}

function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
function setInnerHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}
function setPlaceholder(id, text) {
  const el = document.getElementById(id);
  if (el) el.placeholder = text;
}
function setLabelText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function updateIncidentTypeOptions() {
  const sel = document.getElementById('inc-type');
  if (!sel) return;
  const opts = [
    ['', t('selectType')],
    ['near_miss', t('nearMiss')],
    ['hazard', t('hazardObs')],
    ['injury', t('injury')],
    ['property', t('property')],
    ['environmental', t('environmental')],
    ['security', t('security')],
    ['fire', t('fire')],
  ];
  const cur = sel.value;
  sel.innerHTML = opts.map(([v, label]) =>
    `<option value="${v}"${cur===v?' selected':''}>${label}</option>`
  ).join('');
}

function updateSeverityButtons() {
  const btns = [
    ['low', t('sevLow')],
    ['medium', t('sevMedium')],
    ['high', t('sevHigh')],
    ['critical', t('sevCritical')],
  ];
  btns.forEach(([sev, label]) => {
    const btn = document.querySelector(`.sev-btn[data-sev="${sev}"]`);
    if (btn) btn.textContent = label;
  });
}

function switchLanguage(lang) {
  setLanguage(lang);
  // Update toggle button states
  document.querySelectorAll('.lang-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === lang);
  });
  // Re-render all dynamic content
  applyLanguageToDOM();
  renderGlossary(document.getElementById('glossarySearch')?.value || '');
  renderLetterFilter();
  renderPPE();
  renderPPEChecklist();
  renderEmergencyContacts();
  renderFirstAid();
  setDailyTip();
  updateGlossaryCount();
  renderSavedJSAs();
  renderPastIncidents();
  renderNotificationWidget();
}

// ---- TABS ----
function showTab(tabId, btn) {
  document.querySelectorAll('.tab-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + tabId).classList.add('active');
  if (btn) btn.classList.add('active');
  document.querySelector('.main-content').scrollTop = 0;
}

// ---- ONLINE STATUS ----
function checkOnlineStatus() {
  const badge = document.getElementById('offlineBadge');
  if (!badge) return;
  function update() {
    if (navigator.onLine) {
      badge.textContent = t('onlineLabel');
      badge.classList.add('online');
    } else {
      badge.textContent = t('offlineLabel');
      badge.classList.remove('online');
    }
  }
  update();
  window.addEventListener('online', update);
  window.addEventListener('offline', update);
}

// ---- DAILY TIP ----
function setDailyTip() {
  const tips = getSafetyTips();
  const day = new Date().getDay();
  const tip = tips[day % tips.length];
  const el = document.getElementById('dailyTip');
  if (el) el.textContent = tip;
}

// ---- GLOSSARY ----
let activeFilter = 'ALL';

function getGlossarySource() {
  return window.currentLang === 'fr' ? window.GLOSSARY_TERMS_FR : GLOSSARY_TERMS;
}

function renderGlossary(filter = '') {
  const list = document.getElementById('glossaryList');
  const lower = filter.toLowerCase();
  const source = getGlossarySource();

  let filtered = source.filter(item => {
    const matchText = item.term.toLowerCase().includes(lower) ||
                      item.definition.toLowerCase().includes(lower) ||
                      item.short.toLowerCase().includes(lower);
    const matchLetter = activeFilter === 'ALL' || item.term[0].toUpperCase() === activeFilter;
    return matchText && matchLetter;
  });

  filtered.sort((a, b) => a.term.localeCompare(b.term));

  if (filtered.length === 0) {
    list.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-muted);">${t('noTermsFound')} "${escapeHtml(filter)}"</div>`;
    return;
  }

  list.innerHTML = filtered.map((item, i) => `
    <div class="glossary-item" id="gitem-${i}">
      <div class="glossary-term" onclick="toggleGlossary('gitem-${i}')">
        <div class="term-left">
          <div class="term-letter">${item.term[0].toUpperCase()}</div>
          <div>
            <div class="term-name">${item.term}</div>
            <div class="term-short">${item.short}</div>
          </div>
        </div>
        <span class="term-arrow">▼</span>
      </div>
      <div class="glossary-def">
        <div class="def-text">${item.definition}</div>
        <span class="def-category">${item.category}</span>
      </div>
    </div>
  `).join('');
}

function toggleGlossary(id) {
  document.getElementById(id).classList.toggle('open');
}

function filterGlossary(value) {
  activeFilter = 'ALL';
  document.querySelectorAll('.letter-btn').forEach(b => b.classList.remove('active'));
  const allBtn = document.querySelector('.letter-btn[data-letter="ALL"]');
  if (allBtn) allBtn.classList.add('active');
  renderGlossary(value);
}

function renderLetterFilter() {
  const source = getGlossarySource();
  const letters = ['ALL', ...new Set(source.map(t => t.term[0].toUpperCase()).sort())];
  const container = document.getElementById('letterFilter');
  container.innerHTML = letters.map(l => `
    <button class="letter-btn ${l === activeFilter ? 'active' : ''}" data-letter="${l}" onclick="filterByLetter('${l}', this)">${l}</button>
  `).join('');
}

function filterByLetter(letter, btn) {
  activeFilter = letter;
  document.querySelectorAll('.letter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const search = document.getElementById('glossarySearch');
  if (search) search.value = '';
  renderGlossary('');
}

function updateGlossaryCount() {
  const count = getGlossarySource().length;
  const glossaryCount = document.getElementById('glossaryCount');
  if (glossaryCount) glossaryCount.textContent = `${count} ${t('glossaryCount')}`;
  const glossaryStat = document.getElementById('glossaryStat');
  if (glossaryStat) glossaryStat.textContent = count;
}

// ---- PPE ----
function renderPPE() {
  const list = document.getElementById('ppeList');
  const items = getPPEItems();
  list.innerHTML = items.map(item => `
    <div class="ppe-card">
      <div class="ppe-emoji">${item.emoji}</div>
      <div class="ppe-info">
        <div class="ppe-name">${item.name}</div>
        <div class="ppe-desc">${item.description}</div>
        <div class="ppe-when">📍 ${item.when}</div>
        <span class="ppe-mandatory ${item.mandatory === 'always' ? 'always' : 'task'}">
          ${item.mandatory === 'always' ? t('alwaysRequired') : t('taskSpecific')}
        </span>
      </div>
    </div>
  `).join('');
}

function renderPPEChecklist() {
  const container = document.getElementById('ppeChecklist');
  const items = getPPEItems();
  container.innerHTML = items.map((item, i) => `
    <div class="ppe-check-item" id="pcheck-${i}" onclick="togglePPECheck('pcheck-${i}')">
      <input type="checkbox" />
      <span>${item.emoji} ${item.name.split(' ')[0]}</span>
    </div>
  `).join('');
}

function togglePPECheck(id) {
  const el = document.getElementById(id);
  el.classList.toggle('checked');
  el.querySelector('input').checked = el.classList.contains('checked');
}

// ---- JSA ----
function setJSADate() {
  const today = new Date().toISOString().split('T')[0];
  const el = document.getElementById('jsa-date');
  if (el) el.value = today;
}

function addHazardRow() {
  const container = document.getElementById('hazardRows');
  const row = document.createElement('div');
  row.className = 'hazard-row';
  row.innerHTML = `
    <input type="text" placeholder="${t('hazardPlaceholder')}" class="hazard-input" />
    <select class="risk-select">
      <option value="">${t('riskLevel')}</option>
      <option value="low">${t('riskLow')}</option>
      <option value="medium">${t('riskMedium')}</option>
      <option value="high">${t('riskHigh')}</option>
      <option value="critical">${t('riskCritical')}</option>
    </select>
    <input type="text" placeholder="${t('controlMeasure')}" class="control-input" />
    <button onclick="this.parentElement.remove()" style="background:rgba(230,57,70,0.1);color:var(--accent-red);border:1px solid rgba(230,57,70,0.2);border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px;">${t('removeBtn')}</button>
  `;
  container.appendChild(row);
}

async function submitJSA() {
  const worker = document.getElementById('jsa-worker').value.trim();
  const task = document.getElementById('jsa-task').value.trim();
  const location = document.getElementById('jsa-location').value.trim();
  if (!worker || !task || !location) {
    alert(t('fillRequired').replace('Name, Location, Incident Type, and Description', 'Worker Name, Task, and Location'));
    return;
  }
  const hazards = [];
  document.querySelectorAll('.hazard-row').forEach(row => {
    const hazard = row.querySelector('.hazard-input').value.trim();
    const risk = row.querySelector('.risk-select').value;
    const control = row.querySelector('.control-input').value.trim();
    if (hazard) hazards.push({ hazard, risk, control });
  });
  const ppeSelected = [...document.querySelectorAll('.ppe-check-item.checked')]
    .map(el => el.querySelector('span').textContent.trim());
  // Persist worker identity so we can filter "my records" on this device
  localStorage.setItem('mg_worker_name', worker);

  const jsa = {
    worker, task, location,
    date: document.getElementById('jsa-date').value,
    supervisor: document.getElementById('jsa-supervisor').value.trim(),
    hazards, ppeSelected,
    savedAt: new Date().toLocaleString(),
    lang: window.currentLang
  };
  // Save to Firebase + localStorage fallback
  await saveJSAToCloud(jsa);
  const confirmEl = document.getElementById('jsaConfirm');
  if (confirmEl) {
    confirmEl.textContent = t('jsaSaved');
    confirmEl.classList.remove('hidden');
    setTimeout(() => confirmEl.classList.add('hidden'), 3000);
  }
  clearJSAForm();
  renderSavedJSAs();
}

// Internal form reset — no confirm dialog (called after successful save)
function clearJSAForm() {
  document.getElementById('jsa-worker').value = '';
  document.getElementById('jsa-task').value = '';
  document.getElementById('jsa-location').value = '';
  document.getElementById('jsa-supervisor').value = '';
  setJSADate();
  document.getElementById('hazardRows').innerHTML = `
    <div class="hazard-row">
      <input type="text" placeholder="${t('hazardPlaceholder')}" class="hazard-input" />
      <select class="risk-select">
        <option value="">${t('riskLevel')}</option>
        <option value="low">${t('riskLow')}</option>
        <option value="medium">${t('riskMedium')}</option>
        <option value="high">${t('riskHigh')}</option>
        <option value="critical">${t('riskCritical')}</option>
      </select>
      <input type="text" placeholder="${t('controlMeasure')}" class="control-input" />
    </div>
  `;
  document.querySelectorAll('.ppe-check-item.checked').forEach(el => {
    el.classList.remove('checked');
    el.querySelector('input').checked = false;
  });
}

// Manual clear — asks confirmation (triggered by "Clear Form" button)
function clearJSA() {
  if (!window.confirm(t('clearJSAConfirm'))) return;
  clearJSAForm();
}

function renderSavedJSAs() {
  const workerName = (localStorage.getItem('mg_worker_name') || '').trim().toLowerCase();
  const all  = JSON.parse(localStorage.getItem('mineguard_jsas') || '[]');
  const saved = all.filter(j =>
    !j.deleted &&
    (!workerName || (j.worker || '').trim().toLowerCase() === workerName)
  );

  const container = document.getElementById('savedJSAs');
  if (!container) return;
  if (saved.length === 0) { container.innerHTML = ''; return; }

  const riskColor = { low:'#2ec4b6', medium:'#f5c518', high:'#e63946', critical:'#e63946' };
  const riskBg    = { low:'rgba(46,196,182,0.12)', medium:'rgba(245,197,24,0.12)', high:'rgba(230,57,70,0.12)', critical:'rgba(230,57,70,0.15)' };
  const riskIcon  = { low:'\u{1F7E2}', medium:'\u26A0\uFE0F', high:'\u{1F534}', critical:'\u26D4' };

  function buildJSACard(j) {
    const keyEnc = encodeURIComponent(JSON.stringify({ savedAt: j.savedAt, worker: j.worker, task: j.task }));

    const hazardHtml = (j.hazards && j.hazards.length)
      ? j.hazards.map(function(h) {
          const risk = (h.risk || '').toLowerCase();
          const col  = riskColor[risk] || '#9099b0';
          const bg   = riskBg[risk]   || 'rgba(144,153,176,0.1)';
          const ico  = riskIcon[risk] || '\u26AA';
          return [
            '<div style="background:var(--bg-card2);border:1px solid var(--border);',
            'border-radius:8px;padding:9px 12px;display:flex;align-items:flex-start;',
            'justify-content:space-between;gap:8px;">',
            '<div style="flex:1;min-width:0;">',
            '<div style="font-size:13px;font-weight:700;color:var(--text-primary);margin-bottom:',
            h.control ? '4px' : '0', ';">\u26A0\uFE0F ', (h.hazard || ''), '</div>',
            h.control ? ('<div style="font-size:11px;color:var(--accent-green);">\uD83D\uDEE1\uFE0F ' + h.control + '</div>') : '',
            '</div>',
            risk ? ('<span style="font-size:10px;font-weight:800;white-space:nowrap;padding:3px 9px;' +
              'border-radius:20px;flex-shrink:0;color:' + col + ';background:' + bg +
              ';border:1px solid ' + col + ';">' + ico + ' ' + risk.toUpperCase() + '</span>') : '',
            '</div>'
          ].join('');
        }).join('')
      : '';

    const ppeHtml = (j.ppeSelected && j.ppeSelected.length)
      ? '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:10px;">' +
        j.ppeSelected.map(function(p) {
          return '<span style="font-size:11px;background:var(--bg-card2);border:1px solid var(--border);' +
            'border-radius:16px;padding:3px 9px;color:var(--text-secondary);">' + p + '</span>';
        }).join('') + '</div>'
      : '';

    return [
      '<div class="saved-jsa-card" style="margin-bottom:14px;position:relative;">',
      '<button onclick="workerDeleteJSA(decodeURIComponent(\'' + keyEnc + '\'))"',
      ' style="position:absolute;top:12px;right:12px;background:rgba(230,57,70,0.1);',
      'color:var(--accent-red);border:1px solid rgba(230,57,70,0.3);border-radius:8px;',
      'padding:5px 11px;font-size:11px;font-weight:700;cursor:pointer;z-index:2;"',
      ' onmouseover="this.style.background=\'rgba(230,57,70,0.22)\'"',
      ' onmouseout="this.style.background=\'rgba(230,57,70,0.1)\'">&#128465; Delete</button>',
      '<div style="font-family:\'Barlow Condensed\',sans-serif;font-size:19px;',
      'font-weight:800;color:var(--text-primary);line-height:1.2;margin-bottom:7px;',
      'padding-right:82px;">', j.task, '</div>',
      '<div style="font-size:12px;color:var(--text-secondary);display:flex;',
      'flex-wrap:wrap;gap:10px;margin-bottom:', hazardHtml ? '10px' : '0', ';">',
      '<span>\uD83D\uDC77 ', j.worker, '</span>',
      '<span>\uD83D\uDCCD ', j.location, '</span>',
      '<span>\uD83D\uDCC5 ', j.date, '</span>',
      j.supervisor ? ('<span>\uD83E\uDDD1\u200D\uD83D\uDCBC ' + j.supervisor + '</span>') : '',
      '</div>',
      hazardHtml ? ('<div style="display:flex;flex-direction:column;gap:6px;margin-top:10px;">' + hazardHtml + '</div>') : '',
      ppeHtml,
      '</div>'
    ].join('');
  }

  const header = '<h3 style="font-family:\'Barlow Condensed\',sans-serif;font-size:15px;font-weight:700;' +
    'color:var(--text-secondary);letter-spacing:2px;text-transform:uppercase;' +
    'margin-bottom:12px;padding:0 0 8px;border-bottom:1px solid var(--border);">' +
    '\uD83D\uDCCB ' + t('savedJSAsTitle') + '</h3>';

  container.innerHTML = header + saved.map(buildJSACard).join('');
}


/**
 * Worker-initiated JSA delete.
 * Removes from localStorage immediately and soft-deletes in Firestore.
 */
async function workerDeleteJSA(keyEncoded) {
  if (!confirm('Delete this JSA from your records? This cannot be undone.')) return;

  let key;
  try { key = JSON.parse(decodeURIComponent(keyEncoded)); } catch(e) { return; }

  const all   = JSON.parse(localStorage.getItem('mineguard_jsas') || '[]');
  const match = all.find(j =>
    j.savedAt === key.savedAt && j.worker === key.worker && j.task === key.task
  );

  if (!match) { renderSavedJSAs(); return; }

  // Remove from local storage immediately
  const remaining = all.filter(j => j !== match);
  localStorage.setItem('mineguard_jsas', JSON.stringify(remaining));
  renderSavedJSAs();

  // Soft-delete in Firestore (fire-and-forget — offline is fine)
  if (typeof softDeleteJSA === 'function') {
    const id = match._id || match.savedAt;
    softDeleteJSA(id, localStorage.getItem('mg_worker_name') || 'worker').catch(() => {});
  }
}

// ---- EMERGENCY ----
function renderEmergencyContacts() {
  const stored = JSON.parse(localStorage.getItem('mineguard_contacts') || '[]');
  const base = getEmergencyContacts();
  const all = [...base, ...stored];
  const container = document.getElementById('emergencyContacts');
  container.innerHTML = all.map(c => `
    <div class="contact-card">
      <div class="contact-info">
        <div class="contact-name">${escapeHtml(c.name)}</div>
        <div class="contact-num">${escapeHtml(c.number)}</div>
      </div>
      <a class="contact-call" href="tel:${c.number.replace(/\D/g, '')}">📞 ${window.currentLang === 'fr' ? 'Appeler' : 'Call'}</a>
    </div>
  `).join('');
}

function showAddContact() { document.getElementById('addContactForm').classList.remove('hidden'); }
function hideAddContact() {
  document.getElementById('addContactForm').classList.add('hidden');
  document.getElementById('contactName').value = '';
  document.getElementById('contactNumber').value = '';
}
function saveContact() {
  const name = document.getElementById('contactName').value.trim();
  const number = document.getElementById('contactNumber').value.trim();
  if (!name || !number) { alert(t('enterBothFields')); return; }
  const saved = JSON.parse(localStorage.getItem('mineguard_contacts') || '[]');
  saved.push({ name, number });
  localStorage.setItem('mineguard_contacts', JSON.stringify(saved));
  hideAddContact();
  renderEmergencyContacts();
}

// ---- FIRST AID ----
function renderFirstAid() {
  const list = document.getElementById('firstAidList');
  const guides = getFirstAidGuides();
  list.innerHTML = guides.map((guide, i) => `
    <div class="first-aid-card" id="fa-${i}">
      <div class="fa-header" onclick="toggleFA('fa-${i}')">
        <div class="fa-title">${guide.emoji} ${guide.title}</div>
        <span class="fa-arrow">▼</span>
      </div>
      <div class="fa-steps">
        <ol>${guide.steps.map(s => `<li>${s}</li>`).join('')}</ol>
      </div>
    </div>
  `).join('');
}

function toggleFA(id) { document.getElementById(id).classList.toggle('open'); }

// ============================================
// PUSH NOTIFICATIONS MODULE
// ============================================

let notificationTimer = null;

function renderNotificationWidget() {
  const widget = document.getElementById('notifWidget');
  if (!widget) return;

  if (!('Notification' in window)) {
    widget.innerHTML = `
      <div class="notif-widget notif-unsupported">
        <div class="notif-icon">🔔</div>
        <div class="notif-info">
          <div class="notif-title">${t('notifTitle')}</div>
          <div class="notif-sub" style="color:var(--text-muted);">Not supported in this browser</div>
        </div>
      </div>`;
    return;
  }

  const perm = Notification.permission;
  const isEnabled = perm === 'granted' && localStorage.getItem('mg_notif_enabled') === 'true';

  widget.innerHTML = `
    <div class="notif-widget ${isEnabled ? 'notif-on' : ''}">
      <div class="notif-icon">${isEnabled ? '🔔' : '🔕'}</div>
      <div class="notif-info">
        <div class="notif-title">${t('notifTitle')}</div>
        <div class="notif-sub">${t('notifSub')}</div>
      </div>
      <div class="notif-action">
        ${perm === 'denied'
          ? `<span class="notif-status blocked">${t('notifBlocked')}</span>`
          : isEnabled
            ? `<button class="notif-toggle on" onclick="disableNotifications()">${t('notifEnabled')}</button>`
            : `<button class="notif-toggle off" onclick="enableNotifications()">${t('enableNotif')}</button>`
        }
      </div>
    </div>`;
}

async function enableNotifications() {
  if (!('Notification' in window)) return;
  try {
    const permission = await Notification.requestPermission();
    if (permission === 'granted') {
      localStorage.setItem('mg_notif_enabled', 'true');
      scheduleNotifications();
      // Fire a test notification immediately
      sendSafetyTipNotification(true);
      // Session 21: register this browser for Web Push (server-side store).
      // In-app notifications stay authoritative; failure never blocks the UI.
      if (window.MG_PUSH) { window.MG_PUSH.subscribe(); }
    }
    renderNotificationWidget();
  } catch(e) {
    console.error('Notification error:', e);
  }
}

function disableNotifications() {
  localStorage.setItem('mg_notif_enabled', 'false');
  if (notificationTimer) { clearTimeout(notificationTimer); notificationTimer = null; }
  // Session 21: drop this browser's push registration (own rows only, server-side).
  if (window.MG_PUSH) { window.MG_PUSH.unsubscribe(); }
  renderNotificationWidget();
}

function checkNotificationStatus() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted' && localStorage.getItem('mg_notif_enabled') === 'true') {
    scheduleNotifications();
  }
}

function scheduleNotifications() {
  if (notificationTimer) clearTimeout(notificationTimer);
  const now = new Date();
  const next7am = new Date(now);
  next7am.setHours(7, 0, 0, 0);
  if (next7am <= now) next7am.setDate(next7am.getDate() + 1);
  const msUntil7am = next7am - now;
  notificationTimer = setTimeout(() => {
    sendSafetyTipNotification(false);
    // Re-schedule for the next day
    notificationTimer = setInterval(() => sendSafetyTipNotification(false), 24 * 60 * 60 * 1000);
  }, msUntil7am);
}

function sendSafetyTipNotification(isTest) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  if (localStorage.getItem('mg_notif_enabled') !== 'true') return;
  const tips = getSafetyTips();
  const tip = tips[new Date().getDay() % tips.length];
  const title = isTest
    ? (window.currentLang === 'fr' ? '✅ Notifications activées !' : '✅ Notifications enabled!')
    : t('notifDailyTitle');
  const body = isTest
    ? (window.currentLang === 'fr' ? 'Vous recevrez des conseils de sécurité quotidiens à 7h00.' : 'You will receive daily safety tips at 7:00 AM.')
    : tip;
  try {
    new Notification(title, {
      body,
      icon: 'icons/icon-192.png',
      badge: 'icons/icon-192.png',
      tag: 'mineguard-safety-tip',
      renotify: true,
    });
  } catch(e) {
    console.warn('Notification failed:', e);
  }
}

// ---- SERVICE WORKER REGISTRATION ----
async function registerEmergencyBackgroundDelivery() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const reg = await navigator.serviceWorker.ready;
    if (!reg || !('periodicSync' in reg)) return;
    if ('permissions' in navigator) {
      try {
        const perm = await navigator.permissions.query({ name: 'periodic-background-sync' });
        if (perm && perm.state === 'denied') return;
      } catch (e) {}
    }
    await reg.periodicSync.register('mineguard-sos-poll', { minInterval: 60 * 1000 });
  } catch (e) {
    console.warn('[MineGuard] Emergency background delivery not available:', e.message);
  }
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .then(reg => {
        console.log('[MineGuard] SW registered, scope:', reg.scope);
        registerEmergencyBackgroundDelivery();
      })
      .catch(err => console.log('[MineGuard] SW failed:', err));
  });
}

// ---- LOAD SAVED DATA ON START ----
window.addEventListener('load', () => {
  setTimeout(() => {
    renderSavedJSAs();
    renderPastIncidents();
  }, 2200);
});



// ============================================
// INCIDENT REPORTING MODULE
// ============================================

let incidentPhotos = [];

function setIncidentSubmitState(isSubmitting, label) {
  const btn = document.getElementById('btnSubmitIncident');
  if (!btn) return;
  btn.disabled = !!isSubmitting;
  btn.textContent = label || (isSubmitting ? '⏳ Submitting...' : '📤 Submit Report');
}

async function compressIncidentPhoto(file) {
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('Unable to read image file.'));
    reader.readAsDataURL(file);
  });

  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      try {
        const maxSize = 1280;
        const scale = Math.min(1, maxSize / Math.max(img.width || 1, img.height || 1));
        const canvas = document.createElement('canvas');
        canvas.width = Math.max(1, Math.round((img.width || 1) * scale));
        canvas.height = Math.max(1, Math.round((img.height || 1) * scale));

        const ctx = canvas.getContext('2d');
        if (!ctx) {
          resolve(dataUrl);
          return;
        }

        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const compressed = canvas.toDataURL('image/jpeg', 0.72);
        resolve(compressed);
      } catch (err) {
        resolve(dataUrl);
      }
    };
    img.onerror = () => resolve(dataUrl);
    img.src = dataUrl;
  });
}

function setIncidentDateTime() {
  const now = new Date();
  const local = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const el = document.getElementById('inc-datetime');
  if (el) el.value = local;
}

function setSeverity(level, btn) {
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
  document.getElementById('inc-severity').value = level;
}

async function handlePhotos(input) {
  const newFiles = Array.from(input.files);
  const remaining = 3 - incidentPhotos.length;
  const filesToAdd = newFiles.slice(0, remaining);
  const compressed = await Promise.all(filesToAdd.map(file => compressIncidentPhoto(file)));
  compressed.forEach(src => {
    if (src && incidentPhotos.length < 3) {
      incidentPhotos.push(src);
    }
  });
  renderPhotoPreviews();
  input.value = '';
}

function renderPhotoPreviews() {
  const preview = document.getElementById('photoPreviewRow');
  const countEl = document.getElementById('photoCount');
  preview.innerHTML = incidentPhotos.map((src, i) => `
    <div class="preview-thumb">
      <img src="${escapeHtml(src)}" alt="Photo ${i+1}" />
      <button type="button" class="remove-photo" onclick="removePhoto(${i})">✕</button>
    </div>
  `).join('');
  if (countEl) {
    countEl.textContent = incidentPhotos.length > 0
      ? `📷 ${incidentPhotos.length}/3 ${t('photoAttached')}`
      : '';
  }
}

function removePhoto(idx) {
  incidentPhotos.splice(idx, 1);
  renderPhotoPreviews();
}

async function submitIncident() {
  setIncidentSubmitState(true);
  const name = document.getElementById('inc-name').value.trim();
  const location = document.getElementById('inc-location').value.trim();
  const type = document.getElementById('inc-type').value;
  const description = document.getElementById('inc-description').value.trim();
  if (!name || !location || !type || !description) {
    alert(t('fillRequired'));
    setIncidentSubmitState(false);
    return;
  }
  // Persist worker identity
  localStorage.setItem('mg_worker_name', name);

  const incident = {
    name,
    badge: document.getElementById('inc-badge').value.trim(),
    dept: document.getElementById('inc-dept').value.trim(),
    datetime: document.getElementById('inc-datetime').value,
    location, type,
    severity: document.getElementById('inc-severity').value || 'low',
    description,
    action: document.getElementById('inc-action').value.trim(),
    witnesses: document.getElementById('inc-witnesses').value.trim(),
    photos: incidentPhotos.filter(Boolean),
    status: 'open',
    savedAt: new Date().toLocaleString(),
    lang: window.currentLang
  };
  try {
    // Save to Firebase + localStorage fallback
    await saveIncidentToCloud(incident);
    const confirmEl = document.getElementById('incidentConfirm');
    if (confirmEl) {
      confirmEl.textContent = t('incidentSaved');
      confirmEl.classList.remove('hidden');
      setTimeout(() => confirmEl.classList.add('hidden'), 3500);
    }
    clearIncident();
    renderPastIncidents();
  } catch (err) {
    console.error('[MineGuard] Incident submit failed:', err);
    alert(err && err.message ? err.message : 'Unable to submit the incident report right now.');
  } finally {
    setIncidentSubmitState(false);
  }
}

function clearIncident() {
  ['inc-name','inc-badge','inc-dept','inc-location','inc-description','inc-action','inc-witnesses'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  document.getElementById('inc-type').value = '';
  document.getElementById('inc-severity').value = '';
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('selected'));
  document.getElementById('photoPreviewRow').innerHTML = '';
  const pi1 = document.getElementById('photoCamera');
  const pi2 = document.getElementById('photoGallery');
  if (pi1) pi1.value = '';
  if (pi2) pi2.value = '';
  incidentPhotos = [];
  setIncidentDateTime();
}

function renderPastIncidents() {
  const workerName = (localStorage.getItem('mg_worker_name') || '').trim().toLowerCase();
  const all  = JSON.parse(localStorage.getItem('mineguard_incidents') || '[]');
  const saved = all.filter(function(inc) {
    return !inc.deleted &&
      (!workerName || (inc.name || '').trim().toLowerCase() === workerName);
  });

  const container = document.getElementById('pastIncidents');
  if (!container) return;
  if (!saved.length) { container.innerHTML = ''; return; }

  const sevColor = { low:'var(--accent-green)', medium:'var(--accent-orange)', high:'var(--accent-red)', critical:'#ff4444' };
  const sevBg    = { low:'rgba(46,196,182,0.12)', medium:'rgba(255,140,0,0.12)', high:'rgba(230,57,70,0.12)', critical:'rgba(255,68,68,0.15)' };
  const statusColor = { open:'var(--accent-orange)', reviewing:'#4361ee', resolved:'var(--accent-green)' };
  const statusLabel = { open:'\uD83D\uDFE0 Open', reviewing:'\uD83D\uDD35 Under Review', resolved:'\u2705 Resolved' };
  const typeMap = {
    near_miss: t('nearMiss'), hazard: t('hazardObs'), injury: t('injury'),
    property: t('property'), environmental: t('environmental'),
    fire: t('fire'), security: t('security')
  };

  function buildIncCard(inc) {
    const sev    = (inc.severity || 'low').toLowerCase();
    const status = inc.status || 'open';
    const keyEnc = encodeURIComponent(JSON.stringify({ savedAt: inc.savedAt, name: inc.name, type: inc.type }));
    const desc   = inc.description || '';
    return [
      '<div class="saved-jsa-card" style="margin-bottom:14px;position:relative;">',
      '<button onclick="workerDeleteIncident(decodeURIComponent(\'' + keyEnc + '\'))"',
      ' style="position:absolute;top:12px;right:12px;background:rgba(230,57,70,0.1);',
      'color:var(--accent-red);border:1px solid rgba(230,57,70,0.3);border-radius:8px;',
      'padding:5px 11px;font-size:11px;font-weight:700;cursor:pointer;z-index:2;"',
      ' onmouseover="this.style.background=\'rgba(230,57,70,0.22)\'"',
      ' onmouseout="this.style.background=\'rgba(230,57,70,0.1)\'">&#128465; Delete</button>',
      '<div style="font-family:\'Barlow Condensed\',sans-serif;font-size:18px;',
      'font-weight:800;color:var(--text-primary);padding-right:82px;margin-bottom:6px;">',
      (typeMap[inc.type] || inc.type), '</div>',
      '<div style="font-size:12px;color:var(--text-secondary);display:flex;',
      'flex-wrap:wrap;gap:10px;margin-bottom:8px;">',
      '<span>\uD83D\uDCCD ', inc.location, '</span>',
      '<span>\uD83D\uDD52 ', inc.savedAt, '</span>',
      '</div>',
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">',
      '<span style="font-size:10px;font-weight:800;padding:3px 10px;border-radius:20px;',
      'color:', (sevColor[sev] || 'var(--text-muted)'), ';',
      'background:', (sevBg[sev] || 'rgba(144,153,176,0.1)'), ';',
      'border:1px solid ', (sevColor[sev] || 'var(--border)'), ';">',
      sev.toUpperCase(), '</span>',
      '<span style="font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;',
      'color:', (statusColor[status] || 'var(--text-muted)'), ';',
      'background:rgba(0,0,0,0.15);border:1px solid rgba(255,255,255,0.08);">',
      (statusLabel[status] || status), '</span>',
      '</div>',
      '<div style="font-size:12px;color:var(--text-muted);line-height:1.55;">',
      desc.substring(0, 100), (desc.length > 100 ? '\u2026' : ''),
      '</div>',
      (inc.photos && inc.photos.length
        ? ('<div style="margin-top:7px;font-size:11px;color:var(--accent-green);">' +
          '\uD83D\uDCF7 ' + inc.photos.length + ' ' + t('photoAttached') + '</div>')
        : ''),
      '</div>'
    ].join('');
  }

  const header = '<h3 style="font-family:\'Barlow Condensed\',sans-serif;font-size:16px;font-weight:700;' +
    'color:var(--text-secondary);letter-spacing:2px;text-transform:uppercase;' +
    'margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);">' +
    t('myReports') + '</h3>';

  container.innerHTML = header + saved.slice(0, 10).map(buildIncCard).join('');
}

/**
 * Worker-initiated incident delete.
 * Removes from localStorage immediately and soft-deletes in Firestore.
 * @param {string} keyJson — already-decoded JSON string
 */
async function workerDeleteIncident(keyJson) {
  if (!confirm('Delete this incident report from your records? This cannot be undone.')) return;

  let key;
  try { key = JSON.parse(keyJson); } catch(e) { return; }

  const all   = JSON.parse(localStorage.getItem('mineguard_incidents') || '[]');
  const match = all.find(inc =>
    inc.savedAt === key.savedAt && inc.name === key.name && inc.type === key.type
  );

  if (!match) { renderPastIncidents(); return; }

  // Remove from localStorage immediately — re-render shows updated list
  const remaining = all.filter(inc => inc !== match);
  localStorage.setItem('mineguard_incidents', JSON.stringify(remaining));
  renderPastIncidents();

  // Soft-delete in Firestore (fire-and-forget — works offline too)
  if (typeof softDeleteIncident === 'function') {
    const id = match._id || match.savedAt;
    softDeleteIncident(id, localStorage.getItem('mg_worker_name') || 'worker')
      .catch(e => console.warn('[MineGuard Worker] Incident cloud delete failed:', e.message));
  }
}
const _origInit = initApp;
window.initApp = function() {
  _origInit();
  setIncidentDateTime();
  renderPastIncidents();
  // Initialise Safety Notices system (notices.js)
  if (typeof initNotices === 'function') {
    initNotices().then(() => {
      // Update quick-access notices count
      const el = document.getElementById('qcNoticeCount');
      if (el) {
        const count = (window.MG_NOTICES && window.MG_NOTICES.all)
          ? window.MG_NOTICES.all.filter(n => !n.deleted).length
          : 0;
        const unread = (window.MG_NOTICES && window.MG_NOTICES.unreadCount) || 0;
        el.textContent = unread > 0 ? `${unread} unread` : `${count} notices`;
      }
    });
  }
};
