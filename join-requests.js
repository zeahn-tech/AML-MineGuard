// ============================================================
// MINEGUARD — Worker Join Requests (session 21)
// join-requests.js — onboarding "Join an Existing Organization"
// + admin review card + notification bell.
//
// Architecture notes:
//   * Discovery  : organization_search_joinable() server TVF — only ACTIVE
//                  orgs that opted in (settings.allow_worker_join_requests),
//                  minimum public fields (id/name/type/county). No RLS bypass:
//                  the TVF exposes nothing else.
//   * Requests   : organization_request_join(org_id) — the requested role is
//                  SERVER-SET ('worker'); duplicate-pending and already-member
//                  guards are server-side; admin notification rows are written
//                  by the RPC.
//   * Review     : organization_review_join_request(id, approve, reason) —
//                  require_org_admin-gated; atomic row-lock + status re-check;
//                  approval upserts the ACTIVE worker membership via the same
//                  organization_members rows used by invitations.
//   * Notifications: my_notifications / mark_notification_read (own rows only,
//                  RLS-enforced). Push remains an additional delivery channel
//                  via the existing SW push handler; never authoritative.
// UMD: browser uses window.MG_JOIN; admin.html + index.html include it after
// supabase-auth.js.
// ============================================================
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.MG_JOIN = factory();
  }
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function auth() { return (typeof window !== "undefined") ? window.MG_AUTH : null; }

  function friendlyError(err) {
    var msg = (err && err.message) || "";
    if (/already a member/i.test(msg)) return "You are already a member of this organization.";
    if (/pending request/i.test(msg)) return "You already have a pending request for this organization.";
    if (/not accepting join requests/i.test(msg)) return "This organization is not accepting join requests right now.";
    if (/authentication required/i.test(msg)) return "Your session has expired. Please sign in again.";
    return "We could not complete that action. Please try again or contact your administrator.";
  }

  // ------------------------------------------------------------------
  // Onboarding: "Join an Existing Organization" (login screen / gate)
  // ------------------------------------------------------------------
  var searchTimer = null;
  var lastQuery = null;

  function showJoinForm() {
    var opts = document.getElementById("loginOnboardOptions");
    var createForm = document.getElementById("loginCreateOrgForm");
    var form = document.getElementById("loginJoinOrgForm");
    if (opts) opts.style.display = "none";
    if (createForm) createForm.style.display = "none";
    if (form) form.style.display = "block";
    search();
  }

  function searchDebounced() {
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(search, 250);
  }

  function search() {
    var a = auth();
    if (!a || !a.searchJoinableOrgs) return;
    var input = document.getElementById("loginJoinQuery");
    var box = document.getElementById("loginJoinResults");
    if (!box) return;
    var q = (input && input.value || "").trim();
    if (q === lastQuery && box.dataset.loaded === "1") return;
    lastQuery = q;
    box.dataset.loaded = "1";
    a.searchJoinableOrgs(q).then(function (rows) {
      var list = Array.isArray(rows) ? rows : (rows && rows.data) || [];
      box.dataset.loaded = "";
      if (!list.length) {
        box.innerHTML = '<div style="font-size:12px;color:#9aa0b4;padding:6px 0;line-height:1.6;">' +
          (q
            ? 'No organizations matching “' + esc(q) + '” currently accept join requests.'
            : 'No organizations currently accept join requests. Ask your company administrator to enable them, or use an invitation.') +
          '</div>';
        return;
      }
      box.innerHTML = list.map(function (o) {
        var type = String(o.org_type || "").replace(/_/g, " ");
        var meta = type + (o.county ? " · " + esc(o.county) : "");
        return '<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 10px;border:1px solid rgba(255,255,255,0.09);border-radius:10px;margin-bottom:6px;background:rgba(255,255,255,0.02);">' +
          '<div style="min-width:0;">' +
          '<div style="font-size:13px;font-weight:700;color:#e8eaf0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(o.name) + '</div>' +
          '<div style="font-size:11px;color:#9aa0b4;text-transform:capitalize;">' + esc(meta) + '</div></div>' +
          '<button type="button" data-join-org="' + esc(o.id) + '" style="flex-shrink:0;margin:0;padding:8px 12px;font-size:12px;font-weight:700;border:none;border-radius:8px;background:linear-gradient(135deg,#4361ee,#3a51b8);color:#fff;cursor:pointer;">Request to Join</button>' +
          '</div>';
      }).join("");
      Array.prototype.forEach.call(box.querySelectorAll("[data-join-org]"), function (btn) {
        btn.addEventListener("click", function () { requestJoin(btn.getAttribute("data-join-org"), btn); });
      });
    }).catch(function (err) {
      box.dataset.loaded = "";
      box.innerHTML = "";
      showError((err && err.message) || "Search failed. Please retry.");
    });
  }

  function showError(msg) {
    var e = document.getElementById("loginJoinError");
    if (e) { e.textContent = msg || ""; e.style.display = msg ? "block" : "none"; }
  }

  function requestJoin(orgId, btn) {
    var a = auth();
    if (!a || !orgId) return;
    if (btn) { btn.disabled = true; btn.textContent = "Submitting…"; }
    showError("");
    a.requestJoinOrg(orgId).then(function () {
      var box = document.getElementById("loginJoinResults");
      if (box) {
        box.innerHTML = '<div style="font-size:13px;color:#2ec4b6;line-height:1.7;padding:8px 2px;">' +
          '✅ <b>Request submitted.</b> The organization administrator has been notified and will review it. ' +
          'You will be notified once a decision is made.</div>';
      }
    }).catch(function (err) {
      if (btn) { btn.disabled = false; btn.textContent = "Request to Join"; }
      showError(friendlyError(err));
    });
  }

  // ------------------------------------------------------------------
  // Admin: notification bell (topbar) + join-request review card
  // ------------------------------------------------------------------
  var BELL_ID = "mgJoinBell";
  var POLL_MS = 60000;
  var pollTimer = null;
  var unreadCache = 0;

  function isOrgAdminState() {
    // org-admin.js exposes its loaded state; when unavailable (e.g. worker app),
    // notifications still render — RLS scopes rows server-side.
    var st = root.OrgAdmin && root.OrgAdmin._state;
    return !!(st && st.orgId && st.canManagePeople);
  }

  function ensureBell() {
    var host = document.querySelector(".topbar-right");
    if (!host || document.getElementById(BELL_ID)) return null;
    var bell = document.createElement("button");
    bell.id = BELL_ID;
    bell.title = "Notifications";
    bell.style.cssText = "position:relative;background:transparent;border:1px solid rgba(255,255,255,0.12);" +
      "border-radius:8px;padding:6px 10px;cursor:pointer;font-size:15px;line-height:1;";
    bell.textContent = "🔔";
    var badge = document.createElement("span");
    badge.id = BELL_ID + "Badge";
    badge.style.cssText = "display:none;position:absolute;top:-6px;right:-6px;min-width:17px;height:17px;" +
      "border-radius:9px;background:#e63946;color:#fff;font-size:10px;font-weight:800;" +
      "align-items:center;justify-content:center;padding:0 4px;";
    bell.appendChild(badge);
    bell.addEventListener("click", function () { openPanel(); });
    host.insertBefore(bell, host.firstChild);
    return bell;
  }

  function refreshUnread() {
    var a = auth();
    var badge = document.getElementById(BELL_ID + "Badge");
    if (!a || !a.fetchMyNotifications || !badge) return;
    a.fetchMyNotifications(true).then(function (rows) {
      var list = Array.isArray(rows) ? rows : (rows && rows.data) || [];
      unreadCache = list.length;
      badge.style.display = unreadCache > 0 ? "flex" : "none";
      badge.textContent = unreadCache > 9 ? "9+" : String(unreadCache);
      renderPanel();
    }).catch(function () { /* offline: keep last state */ });
  }

  var panelEl = null;
  function ensurePanel() {
    if (panelEl && document.body.contains(panelEl)) return panelEl;
    panelEl = document.createElement("div");
    panelEl.id = "mgNotifPanel";
    panelEl.style.cssText = "display:none;position:fixed;top:64px;right:18px;z-index:6000;width:min(380px,92vw);" +
      "max-height:70vh;overflow-y:auto;background:#1a1d2e;border:1px solid rgba(255,255,255,0.12);" +
      "border-radius:14px;box-shadow:0 18px 48px rgba(0,0,0,0.5);padding:14px;";
    document.body.appendChild(panelEl);
    document.addEventListener("click", function (e) {
      if (panelEl.style.display === "block" && !panelEl.contains(e.target) &&
          !(e.target.closest && e.target.closest("#" + BELL_ID))) {
        panelEl.style.display = "none";
      }
    });
    return panelEl;
  }

  function openPanel() {
    var p = ensurePanel();
    p.style.display = p.style.display === "block" ? "none" : "block";
    renderPanel();
  }

  function renderPanel() {
    var p = ensurePanel();
    if (p.style.display !== "block") return;
    var a = auth();
    if (!a || !a.fetchMyNotifications) { p.innerHTML = ""; return; }
    a.fetchMyNotifications(false).then(function (rows) {
      var list = Array.isArray(rows) ? rows : (rows && rows.data) || [];
      if (!list.length) {
        p.innerHTML = '<div style="font-size:12px;color:#9aa0b4;text-align:center;padding:14px 0;">No notifications yet.</div>';
        return;
      }
      p.innerHTML = '<div style="font-size:12px;font-weight:800;letter-spacing:1px;color:#f5c518;margin-bottom:10px;">NOTIFICATIONS</div>' +
        list.map(function (n) {
          var unread = !n.read_at;
          var reqId = n.metadata && n.metadata.request_id;
          var action = "";
          if (n.kind === "join_request_received" && reqId && isOrgAdminState()) {
            action = '<button type="button" data-review-req="' + esc(reqId) + '" style="margin-top:8px;width:auto;padding:7px 12px;font-size:12px;font-weight:700;border:none;border-radius:8px;background:linear-gradient(135deg,#f5c518,#e8a800);color:#000;cursor:pointer;">Review Request</button>';
          }
          return '<div style="padding:10px;border-radius:10px;margin-bottom:8px;background:' +
            (unread ? "rgba(245,197,24,0.06)" : "rgba(255,255,255,0.02)") + ';border:1px solid rgba(255,255,255,0.07);">' +
            '<div style="font-size:13px;font-weight:' + (unread ? "700" : "600") + ';color:#e8eaf0;">' +
            (unread ? "● " : "") + esc(n.title) + '</div>' +
            (n.body ? '<div style="font-size:12px;color:#9aa0b4;line-height:1.6;margin-top:3px;">' + esc(n.body) + '</div>' : "") +
            '<div style="font-size:10px;color:#6d7288;margin-top:5px;">' + esc(new Date(n.created_at).toLocaleString()) + '</div>' +
            action + '</div>';
        }).join("");
      Array.prototype.forEach.call(p.querySelectorAll("[data-review-req]"), function (btn) {
        btn.addEventListener("click", function () {
          p.style.display = "none";
          reviewFlow(btn.getAttribute("data-review-req"));
        });
      });
      // mark visible unread rows as read (fire-and-forget)
      list.filter(function (n) { return !n.read_at; }).slice(0, 20).forEach(function (n) {
        if (a.markNotificationRead) a.markNotificationRead(n.id).catch(function () {});
      });
      unreadCache = 0;
      var badge = document.getElementById(BELL_ID + "Badge");
      if (badge) badge.style.display = "none";
    }).catch(function () {});
  }

  // ------------------------------------------------------------------
  // Admin review card (rendered into the Organization panel)
  // ------------------------------------------------------------------
  function renderAdminCard(hostId) {
    var host = document.getElementById(hostId);
    var a = auth();
    if (!host || !a || !a.listJoinRequests) return;
    var st = root.OrgAdmin && root.OrgAdmin._state;
    if (!st || !st.orgId || !st.canManagePeople) return;
    a.listJoinRequests(st.orgId).then(function (rows) {
      var list = (Array.isArray(rows) ? rows : (rows && rows.data) || [])
        .filter(function (r) { return r.status === "pending"; });
      if (!list.length) { host.innerHTML = ""; return; }
      host.innerHTML =
        '<div style="background:rgba(245,197,24,0.05);border:1px solid rgba(245,197,24,0.25);border-radius:12px;padding:14px;margin-bottom:14px;">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">' +
        '<h3 style="margin:0;font-size:15px;color:#f5c518;">👥 Worker Join Requests (' + list.length + ')</h3>' +
        '</div>' +
        list.map(function (r) {
          return '<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:11px;margin-bottom:8px;">' +
            '<div style="font-size:13px;font-weight:700;color:#e8eaf0;">' + esc(r.email || "Worker") + '</div>' +
            '<div style="font-size:11px;color:#9aa0b4;margin-top:2px;">Requested access: Worker · Submitted ' +
            esc(new Date(r.created_at).toLocaleDateString()) + '</div>' +
            '<div style="display:flex;gap:8px;margin-top:9px;">' +
            '<button type="button" data-approve="' + esc(r.id) + '" style="flex:1;padding:8px;border:none;border-radius:8px;background:linear-gradient(135deg,#2ec4b6,#1d9a8e);color:#fff;font-weight:700;font-size:12px;cursor:pointer;">✔ Approve</button>' +
            '<button type="button" data-reject="' + esc(r.id) + '" style="flex:1;padding:8px;border:none;border-radius:8px;background:rgba(230,57,70,0.12);color:#e63946;border:1px solid rgba(230,57,70,0.35);font-weight:700;font-size:12px;cursor:pointer;">✕ Reject</button>' +
            '</div></div>';
        }).join("") +
        '</div>';
      Array.prototype.forEach.call(host.querySelectorAll("[data-approve]"), function (b) {
        b.addEventListener("click", function () { reviewFlow(b.getAttribute("data-approve"), true, b); });
      });
      Array.prototype.forEach.call(host.querySelectorAll("[data-reject]"), function (b) {
        b.addEventListener("click", function () { reviewFlow(b.getAttribute("data-reject"), false, b); });
      });
    }).catch(function () { host.innerHTML = ""; });
  }

  function reviewFlow(requestId, approve, btn) {
    var a = auth();
    if (!a || !requestId) return;
    if (approve === undefined) { approve = true; } // bell "Review" → default approve prompt
    var reason = null;
    if (approve === false) {
      reason = window.prompt("Rejection reason (optional, shared with admins only):");
      if (reason === null) return; // cancelled
    }
    if (btn) { btn.disabled = true; }
    a.reviewJoinRequest(requestId, approve === true, reason).then(function (res) {
      var out = Array.isArray(res) ? res[0] : res;
      if (btn && btn.closest) {
        var card = btn.closest("div[style*='background:rgba(255,255,255,0.03)']") || btn.parentElement;
        if (card && card.parentElement) card.remove();
      }
      if (root.OrgAdmin && root.OrgAdmin.refresh) { try { root.OrgAdmin.refresh(); } catch (e) {} }
      alert(out === "approved" || approve === true
        ? "Worker approved successfully."
        : "Worker request rejected.");
    }).catch(function (err) {
      if (btn) { btn.disabled = false; }
      var msg = (err && err.message) || "";
      alert(/already been processed/i.test(msg)
        ? "This request has already been processed."
        : "Review failed: " + friendlyError(err));
    });
  }

  // ------------------------------------------------------------------
  // Org opt-in toggle (settings card helper)
  // ------------------------------------------------------------------
  function renderOptInToggle(hostId) {
    var host = document.getElementById(hostId);
    var st = root.OrgAdmin && root.OrgAdmin._state;
    if (!host || !st || !st.org) return;
    var settings = st.org.settings || {};
    var enabled = settings.allow_worker_join_requests === true ||
      String(settings.allow_worker_join_requests) === "true";
    host.innerHTML =
      '<label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;color:var(--text2);">' +
      '<input type="checkbox" id="mgJoinOptIn" ' + (enabled ? "checked" : "") +
      ' style="width:16px;height:16px;accent-color:var(--yellow,#f5c518);" /> ' +
      'Allow workers to request to join this organization</label>';
    var cb = document.getElementById("mgJoinOptIn");
    if (cb) {
      cb.addEventListener("change", function () {
        var a = auth();
        if (!a || !a.orgUpdateSettings) return;
        var next = Object.assign({}, settings, { allow_worker_join_requests: cb.checked });
        cb.disabled = true;
        a.orgUpdateSettings(st.orgId, next, null).then(function () {
          cb.disabled = false;
          if (st.org) st.org.settings = next;
        }).catch(function () { cb.disabled = false; cb.checked = !cb.checked; });
      });
    }
  }

  // ------------------------------------------------------------------
  // Boot (auto-wire on page load; safe on both index.html and admin.html)
  // ------------------------------------------------------------------
  function boot() {
    if (!auth()) return;
    // Bell only where a signed-in session can exist and a topbar exists.
    function wire() {
      var s = null;
      try { s = JSON.parse(localStorage.getItem("mg_auth_session") || "null"); } catch (e) {}
      if (!s || !s.user) return;
      if (ensureBell()) refreshUnread();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(refreshUnread, POLL_MS);
    }
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
    else wire();
  }
  boot();

  return {
    showJoinForm: showJoinForm,
    searchDebounced: searchDebounced,
    search: search,
    requestJoin: requestJoin,
    renderAdminCard: renderAdminCard,
    renderOptInToggle: renderOptInToggle,
    refreshUnread: refreshUnread,
    openPanel: openPanel,
    reviewFlow: reviewFlow
  };
});
