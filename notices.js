// ============================================================
// MINEGUARD — SAFETY NOTICES MODULE
// notices.js — Worker-facing notice center + emergency overlay
// Reads from Firestore COL_NOTICES via firebase.js functions
// ============================================================

// ── State ────────────────────────────────────────────────────
window.MG_NOTICES = window.MG_NOTICES || {
  all:          [],   // all non-deleted notices fetched from cloud/local
  unreadCount:  0,
  lastSynced:   null,
  _pollTimer:   null,
  _emergency:   null, // currently displayed emergency notice
};

const COL_NOTICES_KEY  = 'mineguard_notices';        // localStorage key
const READ_KEY         = 'mineguard_notices_read';   // set of read IDs
const ACK_KEY          = 'mineguard_notices_ack';    // set of acknowledged IDs

// ── Severity config ──────────────────────────────────────────
const SEV = {
  info:     { label:'INFO',     color:'#4361ee', bg:'rgba(67,97,238,0.12)',  border:'rgba(67,97,238,0.3)',  icon:'ℹ️' },
  warning:  { label:'WARNING',  color:'#f5c518', bg:'rgba(245,197,24,0.12)', border:'rgba(245,197,24,0.3)', icon:'⚠️' },
  critical: { label:'CRITICAL', color:'#e63946', bg:'rgba(230,57,70,0.15)',  border:'rgba(230,57,70,0.4)',  icon:'🚨' },
  resolved: { label:'RESOLVED', color:'#2ec4b6', bg:'rgba(46,196,182,0.12)', border:'rgba(46,196,182,0.3)', icon:'✅' },
};

// ── localStorage helpers ──────────────────────────────────────
function getReadIds()  { try { return new Set(JSON.parse(localStorage.getItem(READ_KEY) || '[]')); } catch(e) { return new Set(); } }
function getAckIds()   { try { return new Set(JSON.parse(localStorage.getItem(ACK_KEY)  || '[]')); } catch(e) { return new Set(); } }
function markReadLocal(id)  { const s=getReadIds();  s.add(id); localStorage.setItem(READ_KEY, JSON.stringify([...s])); }
function markAckLocal(id)   { const s=getAckIds();   s.add(id); localStorage.setItem(ACK_KEY,  JSON.stringify([...s])); }
function saveNoticesLocal(notices) { localStorage.setItem(COL_NOTICES_KEY, JSON.stringify(notices)); }
function loadNoticesLocal()        { try { return JSON.parse(localStorage.getItem(COL_NOTICES_KEY) || '[]'); } catch(e) { return []; } }

// ── Merge read/ack status into notice list ────────────────────
function applyLocalStatus(notices) {
  const readIds = getReadIds();
  const ackIds  = getAckIds();
  return notices.map(n => ({
    ...n,
    read:         readIds.has(n._id || n.noticeId),
    acknowledged: ackIds.has(n._id || n.noticeId),
  }));
}

// ── Filter out expired notices ────────────────────────────────
function filterActive(notices) {
  const now = Date.now();
  return notices.filter(n => {
    if (!n.expires) return true;
    return new Date(n.expires).getTime() > now;
  });
}

// ── Fetch notices from Firestore / localStorage ───────────────
async function fetchNotices() {
  let notices = [];
  try {
    notices = await fetchNoticesFromCloud();
    if (!Array.isArray(notices)) {
      notices = loadNoticesLocal();
    }
  } catch(e) {
    console.warn('[Notices] Fetch failed, using local:', e.message);
    notices = loadNoticesLocal();
  }

  notices = filterActive(notices);
  notices = applyLocalStatus(notices);
  // Sort: pinned first, then by createdAt desc
  notices.sort((a,b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  window.MG_NOTICES.all = notices;
  window.MG_NOTICES.lastSynced = new Date().toLocaleString();
  window.MG_NOTICES.unreadCount = notices.filter(n => !n.read && !n.deleted).length;

  saveNoticesLocal(notices);
  return notices;
}

// ── Called from firebase.js (added below) ────────────────────
// Phase 05 cutover: reverse-map a Supabase safety_notices row to the legacy
// render shape (field parity with the old Firestore docs — no UI changes).
function _mgSupabaseNoticeToLegacy(r) {
  return {
    _id: r.id,
    supabase_id: r.id,
    client_id: r.client_id || undefined,
    title: r.title,
    message: r.message,
    type: r.notice_type || 'info',
    workZone: r.work_zone_text || '',
    createdBy: r.created_by_text || 'Safety Officer',
    pinned: r.pinned === true,
    expires: r.expires_at || null,
    createdAt: r.created_at ? new Date(r.created_at).getTime() : Date.now(),
    deleted: false,
    site_id: r.site_id || null,
    read: false
  };
}

async function _mgGetOrgId() {
  const auth = window.MG_AUTH;
  if (!auth || !auth.getSession || !auth.getSession()) return null;
  try {
    const rows = await auth.fetchMyMemberships();
    return rows && rows.length ? rows[0].organization_id : null;
  } catch (e) { return null; }
}

async function fetchNoticesFromCloud() {
  // Phase 05 cutover: signed-in users read Supabase safety_notices (RLS).
  const auth = window.MG_AUTH;
  if (auth && auth.fetchSafetyNotices && auth.getSession && auth.getSession()) {
    try {
      const orgId = await _mgGetOrgId();
      if (orgId) {
        const [rows, acks] = await Promise.all([
          auth.fetchSafetyNotices(orgId),
          auth.fetchMyNoticeAcks ? auth.fetchMyNoticeAcks(orgId) : Promise.resolve([])
        ]);
        const ackedSet = new Set((acks || []).map(a => a.notice_id));
        const legacy = (rows || []).map(_mgSupabaseNoticeToLegacy)
          .map(n => { if (ackedSet.has(n.supabase_id)) n.read = true; return n; });
        saveNoticesLocal(legacy);
        return legacy;
      }
    } catch (e) {
      console.warn('[Notices] Supabase fetch failed, using local cache:', e.message);
      return loadNoticesLocal();
    }
  }
  if (typeof restQuery !== 'function') return loadNoticesLocal();
  try {
    const docs = await restQuery('notices', 200);
    return docs.filter(d => !d.deleted);
  } catch (e) {
    console.warn('[Notices] Cloud fetch failed, using local cache:', e.message);
    return loadNoticesLocal();
  }
}

// ── Save a new notice to Firestore + localStorage ─────────────
async function saveNoticeToCloud(notice) {
  const full = { ...notice, createdAt: Date.now(), deleted: false };
  // Optimistic local save
  const local = loadNoticesLocal();
  local.unshift(full);
  saveNoticesLocal(local);

  // Phase 05 cutover: signed-in users write Supabase safety_notices ONLY.
  const auth = window.MG_AUTH;
  if (auth && auth.createSafetyNotice && auth.getSession && auth.getSession()) {
    try {
      const orgId = await _mgGetOrgId();
      if (orgId) {
        await auth.createSafetyNotice(orgId, {
          client_id: window.MG_STORE ? window.MG_STORE.newClientId('notice') : null,
          title: full.title,
          message: full.message,
          notice_type: (full.type === 'critical' || full.type === 'warning') ? full.type : 'info',
          work_zone: full.workZone || null,
          created_by_text: full.createdBy || null
        });
        await fetchNoticesFromCloud();  // refresh from the authoritative store
        return full.client_id || null;
      }
    } catch (e) {
      console.error('[Notices] Supabase save failed:', e.message);
    }
  }

  if (window.MG && window.MG.online && typeof restAdd === 'function') {
    try {
      const ref = await restAdd('notices', full);
      // back-patch _id
      const local2 = loadNoticesLocal();
      const match = local2.find(n => n.createdAt === full.createdAt && n.title === full.title);
      if (match && ref) match._id = ref;
      saveNoticesLocal(local2);
      return ref;
    } catch(e) {
      console.error('[Notices] Cloud save failed:', e.message);
    }
  }
  return null;
}

// ── Soft-delete a notice ──────────────────────────────────────
async function deleteNoticeCloud(id) {
  const local = loadNoticesLocal();
  const item  = local.find(n => n._id === id || n.noticeId === id);
  if (item) { item.deleted = true; saveNoticesLocal(local); }
  // Phase 05 cutover: signed-in users soft-delete in Supabase via the
  // notices.delete-gated RPC (direct PATCH is blocked by the SELECT-policy
  // re-check — see scripts/verify-phase05.mjs finding F3).
  const auth = window.MG_AUTH;
  if (auth && auth.deleteSafetyNotice && auth.getSession && auth.getSession()
      && item && item.supabase_id) {
    try { await auth.deleteSafetyNotice(item.supabase_id); return; } catch (e) {
      console.warn('[Notices] Supabase delete failed:', e.message);
    }
  }
  if (window.MG && window.MG.online && typeof restUpdate === 'function' && id) {
    try { await restUpdate('notices', id, { deleted: true }); } catch(e) {}
  }
}

// ── Mark a notice read (local + optional cloud update) ────────
async function markNoticeRead(id) {
  markReadLocal(id);
  window.MG_NOTICES.all.forEach(n => { if ((n._id||n.noticeId) === id) n.read = true; });
  window.MG_NOTICES.unreadCount = window.MG_NOTICES.all.filter(n => !n.read).length;
  updateNoticesBadge();
  if (window.MG && window.MG.online && typeof restUpdate === 'function' && id) {
    try { await restUpdate('notices', id, { readCount: (window.MG_NOTICES.all.find(n=>(n._id||n.noticeId)===id)||{}).readCount + 1 || 1 }); } catch(e) {}
  }
}

// ── Acknowledge an emergency notice ──────────────────────────
async function acknowledgeNotice(id) {
  markAckLocal(id);
  const notice = window.MG_NOTICES.all.find(n => (n._id||n.noticeId) === id);
  if (notice) notice.acknowledged = true;
  // Phase 05 cutover: signed-in users ack via the per-user safety_notice_acks
  // row (unique(notice,user) makes re-acks idempotent) — no racy counters.
  const auth = window.MG_AUTH;
  if (auth && auth.ackSafetyNotice && auth.getSession && auth.getSession() && notice && notice.supabase_id) {
    try {
      const orgId = await _mgGetOrgId();
      if (orgId) await auth.ackSafetyNotice(notice.supabase_id, orgId, notice.client_id || null);
    } catch (e) { console.warn('[Notices] Supabase ack failed:', e.message); }
  } else if (window.MG && window.MG.online && typeof restUpdate === 'function' && id) {
    try { await restUpdate('notices', id, { ackCount: ((window.MG_NOTICES.all.find(n=>(n._id||n.noticeId)===id)||{}).ackCount || 0) + 1 }); } catch(e) {}
  }
  dismissEmergencyOverlay();
}

// ── Unread badge on nav ───────────────────────────────────────
function updateNoticesBadge() {
  const badge = document.getElementById('noticeNavBadge');
  const count = window.MG_NOTICES.unreadCount;
  if (!badge) return;
  badge.textContent  = count > 0 ? (count > 9 ? '9+' : count) : '';
  badge.style.display = count > 0 ? 'flex' : 'none';
}

// ── Polling — refreshes every 30 seconds when online ─────────
function startNoticesPolling() {
  if (window.MG_NOTICES._pollTimer) return;
  window.MG_NOTICES._pollTimer = setInterval(async () => {
    await fetchNotices();
    renderNoticesTab();
    updateNoticesBadge();
    checkForEmergencies();
  }, 30000);
}
function stopNoticesPolling() {
  if (window.MG_NOTICES._pollTimer) {
    clearInterval(window.MG_NOTICES._pollTimer);
    window.MG_NOTICES._pollTimer = null;
  }
}

// ── Emergency overlay ─────────────────────────────────────────
function checkForEmergencies() {
  const ackIds = getAckIds();
  const emergency = window.MG_NOTICES.all.find(n =>
    n.type === 'critical' && !n.deleted && !ackIds.has(n._id || n.noticeId)
  );
  if (emergency && (emergency._id || emergency.noticeId)) {
    showEmergencyOverlay(emergency);
  }
}

function showEmergencyOverlay(notice) {
  const id = notice._id || notice.noticeId || '';
  if (!id) return;
  const ackIds = getAckIds();
  if (ackIds.has(id)) return;
  if (window.MG_NOTICES._emergency === id) return;
  window.MG_NOTICES._emergency = id;

  // Vibrate (if supported)
  if (navigator.vibrate) navigator.vibrate([400,200,400,200,400]);

  let overlay = document.getElementById('emergencyOverlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'emergencyOverlay';
    document.body.appendChild(overlay);
  }
  overlay.innerHTML = `
    <div class="em-overlay-inner">
      <div class="em-pulse-ring"></div>
      <div class="em-icon">🚨</div>
      <div class="em-label">Emergency Alert</div>
      <div class="em-title">${escapeHtml(notice.title)}</div>
      <div class="em-body">${escapeHtml(notice.message)}</div>
      <div class="em-meta">
        Issued by <strong style="color:rgba(255,255,255,0.6);">${escapeHtml(notice.createdBy || 'Safety Officer')}</strong>
        &nbsp;·&nbsp; ${formatTime(notice.createdAt)}
        ${notice.workZone ? `&nbsp;·&nbsp; 📍 ${escapeHtml(notice.workZone)}` : ''}
      </div>
      <button class="em-ack-btn" onclick="acknowledgeNotice('${escapeHtml(id)}')">
        ✅ I Acknowledge — Tap to Dismiss
      </button>
      <div class="em-sub">This alert remains visible until acknowledged</div>
    </div>`;
  overlay.style.display = 'flex';
  document.body.classList.add('em-lock');
}

function dismissEmergencyOverlay() {
  const overlay = document.getElementById('emergencyOverlay');
  if (overlay) { overlay.style.display = 'none'; }
  document.body.classList.remove('em-lock');
  window.MG_NOTICES._emergency = null;
}

// ── Push notification ─────────────────────────────────────────
function sendNoticePushNotification(notice) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const sev = SEV[notice.type] || SEV.info;
  try {
    new Notification(`${sev.icon} ${notice.title}`, {
      body:    notice.message.substring(0, 120),
      icon:    'icons/icon-192.png',
      badge:   'icons/icon-192.png',
      tag:     'mg-notice-' + (notice._id || Date.now()),
      renotify: true,
    });
  } catch(e) { console.warn('[Notices] Push notification failed:', e.message); }
}

// ── RENDER NOTICES TAB ────────────────────────────────────────
let noticeFilter  = 'all';   // all | info | warning | critical | resolved
let noticeSearch  = '';
let noticeSortAsc = false;

function renderNoticesTab() {
  const container = document.getElementById('noticesList');
  if (!container) return;

  updateLastSynced();

  let notices = [...window.MG_NOTICES.all].filter(n => !n.deleted);

  // Apply filter
  if (noticeFilter !== 'all') notices = notices.filter(n => n.type === noticeFilter);

  // Apply search
  if (noticeSearch.trim()) {
    const q = noticeSearch.toLowerCase();
    notices = notices.filter(n =>
      (n.title||'').toLowerCase().includes(q) ||
      (n.message||'').toLowerCase().includes(q) ||
      (n.createdBy||'').toLowerCase().includes(q)
    );
  }

  // Apply sort
  if (noticeSortAsc) notices.reverse();

  if (notices.length === 0) {
    container.innerHTML = `
      <div class="notices-empty">
        <div style="font-size:42px;margin-bottom:12px;">📋</div>
        <div style="font-size:15px;font-weight:700;color:var(--text-primary);margin-bottom:6px;">No Notices</div>
        <div style="font-size:13px;color:var(--text-muted);">${noticeFilter !== 'all' ? 'No ' + escapeHtml(noticeFilter) + ' notices found.' : 'No safety notices at this time.'}</div>
      </div>`;
    return;
  }

  container.innerHTML = notices.map(n => renderNoticeCard(n)).join('');
}

function renderNoticeCard(n) {
  const id      = n._id || n.noticeId || '';
  const sev     = SEV[n.type] || SEV.info;
  const read    = n.read;
  const ack     = n.acknowledged;
  const pin     = n.pinned;
  const expired = n.expires && new Date(n.expires).getTime() < Date.now();
  const preview = escapeHtml((n.message || '').replace(/\n/g, ' ').substring(0, 130));
  const hasMore = (n.message || '').length > 130;
  const expDate = n.expires
    ? new Date(n.expires).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})
    : '';
  const timeStr = formatTime(n.createdAt);

  return `
  <div class="notice-card ${read ? 'nc-read' : 'nc-unread'} nc-${n.type||'info'} ${pin ? 'nc-pinned' : ''}"
       onclick="openNoticeDetail('${escapeHtml(id)}')" role="button" tabindex="0">
    <div class="nc-inner">
      ${pin ? '<div class="nc-pin-flag">📌 PINNED NOTICE</div>' : ''}
      <div class="nc-header">
        <span class="nc-sev-badge"
              style="background:${sev.bg};color:${sev.color};border-color:${sev.border};">
          ${sev.icon} ${sev.label}
        </span>
        <div class="nc-meta-right">
          ${!read ? '<span class="nc-unread-dot" title="Unread"></span>' : ''}
          ${expired ? '<span class="nc-expired-tag">EXPIRED</span>' : ''}
          ${ack     ? '<span class="nc-ack-tag">✅ ACK</span>'      : ''}
        </div>
      </div>
      <div class="nc-title">${escapeHtml(n.title || 'Untitled Notice')}</div>
      <div class="nc-body">${preview}${hasMore ? '<span style="color:var(--text-muted)"> … read more</span>' : ''}</div>
      <div class="nc-footer">
        <span>👤 ${escapeHtml(n.createdBy || 'Safety Officer')}</span>
        <span style="margin-left:auto;">🕒 ${timeStr}</span>
        ${n.attachments && n.attachments.length
          ? `<span>📎 ${n.attachments.length} file${n.attachments.length > 1 ? 's' : ''}</span>`
          : ''}
      </div>
      ${expDate ? `<div class="nc-expires">⏳ Expires ${expDate}</div>` : ''}
    </div>
  </div>`;
}


function openNoticeDetail(id) {
  const notice = window.MG_NOTICES.all.find(n => (n._id||n.noticeId) === id);
  if (!notice) return;
  if (!notice.read) markNoticeRead(id);

  const sev   = SEV[notice.type] || SEV.info;
  const modal = document.getElementById('noticeModal');
  const body  = document.getElementById('noticeModalBody');
  if (!modal || !body) return;

  const expStr = notice.expires
    ? new Date(notice.expires).toLocaleString([],{weekday:'short',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})
    : null;

  body.innerHTML = `
    <div class="nm-sev-bar" style="background:${sev.color};"></div>
    <div class="nm-inner">

      <div class="nm-badge-row">
        <span class="nc-sev-badge"
              style="background:${sev.bg};color:${sev.color};border-color:${sev.border};font-size:12px;padding:5px 13px;">
          ${sev.icon} ${sev.label}
        </span>
        ${notice.pinned ? '<span style="font-size:12px;color:var(--accent-yellow);font-weight:700;">📌 Pinned</span>' : ''}
      </div>

      <h2 class="nm-title">${escapeHtml(notice.title || 'Notice')}</h2>

      <div class="nm-meta">
        <span>👤 ${escapeHtml(notice.createdBy || 'Safety Officer')}</span>
        <span>🕒 ${formatTime(notice.createdAt)}</span>
        ${notice.department ? `<span>🏭 ${escapeHtml(notice.department)}</span>` : ''}
        ${notice.workZone   ? `<span>📍 ${escapeHtml(notice.workZone)}</span>`   : ''}
        ${notice.target && notice.target !== 'all' ? `<span>🎯 ${escapeHtml(notice.target)}</span>` : ''}
      </div>

      <div class="nm-body">${escapeHtml(notice.message || '').replace(/\n/g, '<br/>')}</div>

      ${expStr ? `<div class="nm-expires">⏳ Expires ${expStr}</div>` : ''}

      ${notice.attachments && notice.attachments.length ? `
        <div class="nm-attachments">
          <div class="nm-att-label">📎 Attachments (${notice.attachments.length})</div>
          ${notice.attachments.map(a => `
            <div class="nm-att-item">📄 ${escapeHtml(a.name || String(a))}</div>`
          ).join('')}
        </div>` : ''}

      ${notice.type === 'critical' && !notice.acknowledged ? `
        <button class="nm-ack-btn" onclick="acknowledgeNotice('${escapeHtml(id)}');closeNoticeModal();">
          ✅ ACKNOWLEDGE — I HAVE READ THIS ALERT
        </button>` : ''}

    </div>`;

  modal.style.display = 'flex';
  renderNoticesTab();
  updateNoticesBadge();
}


function closeNoticeModal() {
  const modal = document.getElementById('noticeModal');
  if (modal) modal.style.display = 'none';
}

function updateLastSynced() {
  const el = document.getElementById('noticesLastSynced');
  if (!el) return;
  const ts = window.MG_NOTICES.lastSynced;
  const online = window.MG && window.MG.online;
  const dotColor = online ? '#2ec4b6' : '#ff8c00';
  el.innerHTML = `
    <span class="notices-sync-dot" style="background:${dotColor};"></span>
    <span>${ts ? 'Synced ' + escapeHtml(ts) : (online ? 'Syncing...' : 'Offline')}</span>`;
}

function setNoticeFilter(f, btn) {
  noticeFilter = f;
  document.querySelectorAll('.notice-filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderNoticesTab();
}

function searchNotices(val) {
  noticeSearch = val;
  renderNoticesTab();
}

function toggleNoticeSort() {
  noticeSortAsc = !noticeSortAsc;
  const btn = document.getElementById('noticeSortBtn');
  if (btn) btn.textContent = noticeSortAsc ? '↑ Oldest' : '↓ Newest';
  renderNoticesTab();
}

// ── Init called from app.js initApp() ─────────────────────────
async function initNotices() {
  await fetchNotices();
  renderNoticesTab();
  updateNoticesBadge();
  checkForEmergencies();
  startNoticesPolling();
  // Subscribe to real-time updates if online
  if (typeof subscribeNotices === 'function') {
    subscribeNotices(function(docs) {
      const active = filterActive(docs.filter(d => !d.deleted));
      window.MG_NOTICES.all = applyLocalStatus(active);
      window.MG_NOTICES.all.sort((a,b) => {
        if (a.pinned && !b.pinned) return -1;
        if (!a.pinned && b.pinned) return 1;
        return (b.createdAt||0) - (a.createdAt||0);
      });
      window.MG_NOTICES.unreadCount = window.MG_NOTICES.all.filter(n=>!n.read).length;
      saveNoticesLocal(window.MG_NOTICES.all);
      window.MG_NOTICES.lastSynced = new Date().toLocaleString();
      renderNoticesTab();
      updateNoticesBadge();
      checkForEmergencies();
      // Push notification for any newly added critical/warning
      docs.filter(d => !d.deleted && (d.type==='critical'||d.type==='warning')).forEach(n => {
        const prevIds = new Set(loadNoticesLocal().map(x => x._id||x.noticeId));
        if (!prevIds.has(n._id)) sendNoticePushNotification(n);
      });
    });
  }
}

// ── Utilities ─────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(typeof ts === 'number' ? ts : ts);
  if (isNaN(d)) return '';
  const now  = new Date();
  const diff = now - d;
  if (diff < 60000)    return 'Just now';
  if (diff < 3600000)  return Math.floor(diff/60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff/3600000) + 'h ago';
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}
