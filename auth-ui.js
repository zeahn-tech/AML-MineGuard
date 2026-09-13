// ============================================================
// MINEGUARD — Worker-app auth UI (index.html)
// Injects an account chip into .header-right and an auth modal.
// Purely additive: does not touch app.js data flows. Signing in
// is OPTIONAL for workers in Phase 02; report/JSA flows keep
// working exactly as before when signed out.
// ============================================================
(function () {
  "use strict";

  function tr(key) {
    try {
      if (window.t) return t(key);
      var en = window.TRANSLATIONS && window.TRANSLATIONS.en;
      return (en && en[key]) || key;
    } catch (e) { return key; }
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function el(id) { return document.getElementById(id); }
  function ready(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }
  function hasSession() {
    try { return !!JSON.parse(localStorage.getItem("mg_auth_session") || "null"); } catch (e) { return false; }
  }

  var CHIP_ID = "mgAuthChip";
  var MODAL_ID = "mgAuthModal";
  var busy = false;
  var mode = "signin"; // signin | signup

  var STYLES = [
    "#" + CHIP_ID + "{display:inline-flex;align-items:center;gap:4px;background:rgba(255,255,255,0.05);border:1px solid var(--border);border-radius:18px;padding:4px 10px;font-size:11px;font-weight:700;color:var(--text-secondary);cursor:pointer;letter-spacing:0.3px;max-width:130px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;}",
    "#" + CHIP_ID + ".signed-in{color:var(--accent-green);border-color:rgba(46,196,182,0.3);}",
    "#" + MODAL_ID + "{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.82);z-index:9000;align-items:flex-end;justify-content:center;backdrop-filter:blur(4px);}",
    "#" + MODAL_ID + ".open{display:flex;}",
    ".mg-auth-sheet{background:var(--bg-card);border:1px solid var(--border);border-radius:20px 20px 0 0;width:100%;max-width:480px;padding:20px 18px 26px;position:relative;max-height:92vh;overflow-y:auto;}",
    ".mg-auth-title{font-family:'Barlow Condensed',sans-serif;font-size:24px;font-weight:800;letter-spacing:1px;margin-bottom:2px;}",
    ".mg-auth-sub{font-size:12px;color:var(--text-muted);margin-bottom:12px;word-break:break-all;}",
    ".mg-auth-label{display:block;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text-secondary);margin:10px 0 5px;}",
    ".mg-auth-input{width:100%;background:var(--bg-card2);border:1px solid var(--border);border-radius:10px;color:var(--text-primary);padding:11px 12px;font-family:'Barlow',sans-serif;font-size:14px;outline:none;}",
    ".mg-auth-input:focus{border-color:rgba(245,197,24,0.4);}",
    ".mg-auth-btn{width:100%;margin-top:14px;background:linear-gradient(135deg,#f5c518,#e8a800);color:#000;border:none;border-radius:12px;font-family:'Barlow Condensed',sans-serif;font-size:17px;font-weight:800;letter-spacing:1.5px;padding:13px;cursor:pointer;}",
    ".mg-auth-btn:disabled{opacity:0.5;}",
    ".mg-auth-toggle{margin-top:12px;text-align:center;font-size:12px;color:var(--text-muted);}",
    ".mg-auth-toggle a{color:var(--accent-yellow);cursor:pointer;text-decoration:none;font-weight:700;}",
    ".mg-auth-error{display:none;margin-top:10px;font-size:12px;color:var(--accent-red);line-height:1.5;word-break:break-word;}",
    ".mg-auth-info{display:none;margin-top:10px;font-size:12px;color:var(--accent-green);line-height:1.5;}",
    ".mg-auth-close{position:absolute;top:12px;right:14px;background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;}",
    ".mg-auth-role{font-size:12px;color:var(--text-secondary);margin-top:12px;line-height:1.6;word-break:break-all;}",
    ".mg-auth-signout{margin-top:12px;width:100%;background:rgba(230,57,70,0.14);color:var(--accent-red);border:1px solid rgba(230,57,70,0.35);border-radius:10px;padding:11px;font-weight:800;letter-spacing:1px;font-size:13px;cursor:pointer;}"
  ].join("\n");

  function injectStyles() {
    if (el("mg-auth-styles")) return;
    var s = document.createElement("style");
    s.id = "mg-auth-styles";
    s.textContent = STYLES;
    document.head.appendChild(s);
  }

  function buildChip() {
    if (el(CHIP_ID)) return;
    var host = document.querySelector(".header-right");
    if (!host) return;
    var btn = document.createElement("button");
    btn.id = CHIP_ID;
    btn.type = "button";
    btn.addEventListener("click", openModal);
    host.insertBefore(btn, host.firstChild);
  }

  function buildModal() {
    if (el(MODAL_ID)) return;
    var m = document.createElement("div");
    m.id = MODAL_ID;
    m.innerHTML =
      '<div class="mg-auth-sheet">' +
      '<button class="mg-auth-close" data-close="1" aria-label="Close">✕</button>' +
      '<div class="mg-auth-title" id="mgAuthTitle"></div>' +
      '<div class="mg-auth-sub" id="mgAuthSub"></div>' +
      '<form id="mgAuthForm" novalidate>' +
      '<label class="mg-auth-label" for="mgAuthEmail">' + esc(tr("authEmail")) + '</label>' +
      '<input class="mg-auth-input" type="email" id="mgAuthEmail" autocomplete="email" required />' +
      '<label class="mg-auth-label" for="mgAuthPassword">' + esc(tr("authPassword")) + '</label>' +
      '<input class="mg-auth-input" type="password" id="mgAuthPassword" required />' +
      '<button class="mg-auth-btn" type="submit" id="mgAuthSubmit"></button>' +
      '</form>' +
      '<div class="mg-auth-toggle" id="mgAuthToggle"></div>' +
      '<div class="mg-auth-error" id="mgAuthError"></div>' +
      '<div class="mg-auth-role" id="mgAuthRole" style="display:none;"></div>' +
      '<div id="mgAuthJoinStatus" style="display:none;font-size:12px;color:#9aa0b4;line-height:1.6;margin:10px 0 0;"></div>' +
      '<button class="mg-auth-signout" id="mgAuthAdminLink" style="display:none;background:rgba(245,197,24,0.12);color:var(--accent-yellow,#f5c518);border:1.5px solid rgba(245,197,24,0.4);">🛠️ Admin Dashboard</button>' +
      '<button class="mg-auth-signout" id="mgAuthWorkerLink" style="display:none;background:rgba(46,196,182,0.1);color:#2ec4b6;border:1.5px solid rgba(46,196,182,0.35);">⛏️ Worker Workspace</button>' +
      '<button class="mg-auth-signout" id="mgAuthSignOut" style="display:none;">🚪 ' + esc(tr("authSignOut")) + '</button>' +
      '</div>';
    document.body.appendChild(m);
    m.addEventListener("click", function (e) {
      if (e.target === m || (e.target.getAttribute && e.target.getAttribute("data-close"))) closeModal();
    });
    el("mgAuthForm").addEventListener("submit", function (e) { e.preventDefault(); submitForm(); });
    el("mgAuthToggle").addEventListener("click", function (e) {
      if (e.target.tagName === "A") { mode = mode === "signin" ? "signup" : "signin"; renderModeUI(); }
    });
    el("mgAuthSignOut").addEventListener("click", function () {
      if (busy) return;
      busy = true;
      MG_AUTH.signOut().then(function () {
      busy = false; closeModal(); renderChip();
      // Clear the workspace preference with the session.
      try { sessionStorage.removeItem("mg_workspace"); } catch (e) {}
      // Return to the authentication gate; protected state is hidden again.
      if (window.MG_GATE) MG_GATE.showGate();
    });
    });
    // Session 21 — workspace switching (UI choice only; never changes roles).
    el("mgAuthAdminLink").addEventListener("click", function () {
      try { sessionStorage.setItem("mg_workspace", "admin"); } catch (e) {}
      window.location.href = "admin.html";
    });
    el("mgAuthWorkerLink").addEventListener("click", function () {
      try { sessionStorage.setItem("mg_workspace", "worker"); } catch (e) {}
      window.location.href = "index.html";
    });
  }

  function renderModeUI() {
    el("mgAuthSub").textContent = tr(mode === "signin" ? "authSignInSub" : "authSignUpSub");
    el("mgAuthSubmit").textContent = tr(mode === "signin" ? "authSignIn" : "authSignUp");
    el("mgAuthPassword").autocomplete = mode === "signin" ? "current-password" : "new-password";
    el("mgAuthToggle").innerHTML = mode === "signin"
      ? tr("authNoAccount") + ' <a href="#">' + esc(tr("authCreateOne")) + '</a>'
      : tr("authHaveAccount") + ' <a href="#">' + esc(tr("authSignInLink")) + '</a>';
    el("mgAuthError").style.display = "none";
  }

  function showError(msg) {
    var e = el("mgAuthError");
    if (e) { e.textContent = msg; e.style.display = "block"; }
  }

  function submitForm() {
    if (busy) return;
    var email = (el("mgAuthEmail").value || "").trim();
    var pw = el("mgAuthPassword").value || "";
    if (!email || pw.length < 6) { showError(tr("authValidation")); return; }
    busy = true;
    el("mgAuthSubmit").disabled = true;
    var p = mode === "signin" ? MG_AUTH.signInWithPassword(email, pw) : MG_AUTH.signUp(email, pw);
    p.then(function (res) {
      busy = false;
      el("mgAuthSubmit").disabled = false;
      if (res.session) {
        closeModal();
        renderChip();
        // Authentication gate: after sign-in/sign-up, route to the resolved
        // destination instead of silently remaining on the same screen.
        routeAfterAuth();
      } else {
        showError(tr("authConfirmEmail"));
      }
    }).catch(function (err) {
      busy = false;
      el("mgAuthSubmit").disabled = false;
      showError((err && err.message) || tr("authFailed"));
    });
  }

  // Route to the destination resolved from CURRENT server-side memberships
  // (the gate resolver in auth-gate.js is the single source of truth).
  function routeAfterAuth() {
    if (!(window.MG_GATE && window.MG_AUTH)) return;
    window.MG_GATE.resolveDestination(MG_AUTH).catch(function (err) {
      // Verification failed (connection/server) — NOT the same as being
      // orgless. Say so; the user keeps their session and can retry.
      if (window.MG_GATE) {
        MG_GATE.showGate();
        MG_GATE.showGateMsg("Signed in, but we could not verify your organization access (" + ((err && err.message) || "connection issue") + "). Please retry in a moment.", "info");
      }
    }).then(function (dest) {
      if (!dest) return; // already handled by the catch above
      if (dest === "COMPANY_ADMIN" || dest === "GOVERNMENT_WORKSPACE") {
        // Session 21 — respect an intentional Worker-Workspace session choice;
        // the default remains the admin console.
        var ws = null;
        try { ws = sessionStorage.getItem("mg_workspace"); } catch (e) {}
        if (ws === "worker") {
          if (window.MG_GATE) MG_GATE.hideGate();
          var app = document.getElementById("app");
          if (app) app.classList.remove("hidden");
        } else {
          window.location.replace("admin.html");
        }
      } else if (dest === "AUTH_REQUIRED") {
        if (window.MG_GATE) MG_GATE.showGate();
      } else if (dest === "NO_ORGANIZATION" || dest === "SELECT_ORGANIZATION") {
        // Stay on the workspace (reference tabs usable); surface guidance.
        if (window.MG_GATE) {
          MG_GATE.showGate();
          MG_GATE.showGateMsg(
            dest === "NO_ORGANIZATION"
              ? (window.t ? t("gateNoOrg") : "No organization has been assigned to your account yet. Ask your administrator for an invitation, or create your own organization.")
              : (window.t ? t("gateSelectOrg") : "You belong to more than one organization. Open the account menu to choose which one to work in."),
            "info");
          // Session 21 — make onboarding actionable: Create / Join buttons
          // (the "Set organization" path) instead of text-only guidance.
          if (dest === "NO_ORGANIZATION" && MG_GATE.showGateActions) MG_GATE.showGateActions();
        }
      } else {
        // WORKER_WORKSPACE: hide the gate, reveal the authenticated shell.
        if (window.MG_GATE) MG_GATE.hideGate();
        var app = document.getElementById("app");
        if (app) app.classList.remove("hidden");
      }
    });
  }

  function renderChip() {
    var chip = el(CHIP_ID);
    if (!chip) return;
    var s = null;
    try { s = JSON.parse(localStorage.getItem("mg_auth_session") || "null"); } catch (e) {}
    if (s && s.user) {
      chip.classList.add("signed-in");
      chip.textContent = "👤 " + esc(s.user.email || tr("authSignedIn"));
    } else {
      chip.classList.remove("signed-in");
      chip.textContent = "🔐 " + tr("authSignIn");
    }
    if (el(MODAL_ID)) renderSignedPanel();
  }

  function renderSignedPanel() {
    var role = el("mgAuthRole");
    var signOutBtn = el("mgAuthSignOut");
    var form = el("mgAuthForm");
    var toggle = el("mgAuthToggle");
    var sub = el("mgAuthSub");
    var title = el("mgAuthTitle");
    var adminLink = el("mgAuthAdminLink");
    var workerLink = el("mgAuthWorkerLink");
    var joinStatus = el("mgAuthJoinStatus");
    if (!role || !signOutBtn) return;
    if (adminLink) adminLink.style.display = "none";
    if (workerLink) workerLink.style.display = "none";
    if (joinStatus) { joinStatus.style.display = "none"; joinStatus.textContent = ""; }
    var s = null;
    try { s = JSON.parse(localStorage.getItem("mg_auth_session") || "null"); } catch (e) {}
    if (!s || !s.user) {
      role.style.display = "none";
      signOutBtn.style.display = "none";
      form.style.display = "block";
      toggle.style.display = "block";
      title.innerHTML = "Mine<span style=\"color:var(--accent-yellow)\">Guard</span>";
      renderModeUI();
      return;
    }
    // Signed in: show account + membership, hide form controls
    form.style.display = "none";
    toggle.style.display = "none";
    el("mgAuthError").style.display = "none";
    signOutBtn.style.display = "block";
    title.innerHTML = "Mine<span style=\"color:var(--accent-yellow)\">Guard</span>";
    sub.textContent = s.user.email || tr("authSignedIn");
    role.style.display = "block";
    role.textContent = tr("authChecking") + "…";
    MG_AUTH.fetchMyMemberships().then(function (memberships) {
      var active = (memberships || []).filter(function (m) { return m.status === "active"; });
      if (!active.length) {
        role.textContent = tr("authNoOrg");
        // Session 21 — surface pending join-request outcomes for orgless users.
        if (joinStatus && MG_AUTH.myJoinRequests) {
          MG_AUTH.myJoinRequests().then(function (r) {
            var rows = Array.isArray(r) ? r : (r && r.data) || [];
            if (!rows.length) return;
            var last = rows[0];
            var line = last.status === "pending"
              ? "⏳ Join request to “" + (last.org_name || "organization") + "” is pending review."
              : last.status === "approved"
                ? "✅ Your request to join “" + (last.org_name || "organization") + "” was approved — sign out and back in to refresh access."
                : "❌ Your request to join “" + (last.org_name || "organization") + "” was not approved.";
            joinStatus.textContent = line;
            joinStatus.style.display = "block";
          }).catch(function () {});
        }
        return;
      }
      var isAdmin = active.some(function (m) { return m.role === "owner" || m.role === "admin"; });
      if (isAdmin) {
        // Admins can use both workspaces; the current page is highlighted away.
        var onAdminPage = /admin\.html/i.test(window.location.pathname);
        if (adminLink && !onAdminPage) adminLink.style.display = "block";
        if (workerLink && onAdminPage) workerLink.style.display = "block";
      }
      var m = active[0];
      MG_AUTH.fetchOrganization(m.organization_id).then(function (org) {
        var roleName = {
          owner: tr("authRoleOwner"), admin: tr("authRoleAdmin"),
          safety_manager: tr("authRoleSafetyManager"), safety_officer: tr("authRoleSafetyOfficer"),
          site_manager: tr("authRoleSiteManager"), supervisor: tr("authRoleSupervisor"),
          worker: tr("authRoleWorker"), contractor: tr("authRoleContractor"),
          member: tr("authRoleMember"),
          // Phase 11 — government roles (English labels; EN/FR keys optional)
          national_regulatory_admin: "National Regulatory Administrator",
          government_safety_inspector: "Government Safety Inspector",
          government_compliance_officer: "Government Compliance Officer",
          government_analyst: "Government Analyst"
        }[m.role] || m.role;
        role.textContent = (org ? org.name + " · " : "") + roleName;
      }).catch(function () {
        role.textContent = tr("authNoOrg");
      });
    }).catch(function () {
      role.textContent = tr("authNoOrg");
    });
  }

  function openModal(mode) {
    if (typeof MG_AUTH === "undefined" || !window.MG_CONFIG) { return; }
    if (!el(MODAL_ID)) buildModal();
    // Honor the requested mode (signin/signup) — the auth-gate "Create Account"
    // button must land directly on the sign-UP form, not sign-in + hidden toggle.
    mode = (mode === "signup") ? "signup" : "signin";
    renderSignedPanel();
    el(MODAL_ID).classList.add("open");
    var email = el("mgAuthEmail");
    if (email && formVisible()) email.focus();
  }

  function formVisible() {
    var f = el("mgAuthForm");
    return f && f.style.display !== "none";
  }

  function closeModal() {
    var m = el(MODAL_ID);
    if (m) m.classList.remove("open");
  }

  ready(function () {
    if (typeof MG_AUTH === "undefined" || !window.MG_CONFIG) return;
    injectStyles();
    buildChip();
    buildModal();
    renderChip();
    MG_AUTH.onAuthChange(function () { renderChip(); });
    window.addEventListener("storage", function (e) {
      if (e.key === "mg_auth_session") renderChip();
    });
    // Public hook so the auth-gate (and other surfaces) can open the modal in
    // an explicit mode instead of simulating a chip click.
    window.MG_AUTH_UI = { open: openModal, close: closeModal };
  });
})();
