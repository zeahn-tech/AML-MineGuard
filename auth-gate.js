// ============================================================
// MINEGUARD — Authentication gate + entry routing (worker app)
//
// Establishes the gate: AUTHENTICATION → SESSION VALIDATION →
// ORGANIZATION RESOLUTION → ROLE RESOLUTION → AUTHORIZED WORKSPACE.
//
// Screen classification (AUTHENTICATION_GATE_AND_ENTRY_ROUTING.md §2):
//   PUBLIC      — splash/branding, language switcher, safety reference
//                 content (glossary, PPE, first aid, emergency procedures):
//                 public-by-design safety information with no tenant data.
//   AUTHENTICATED — the worker workspace (reports, JSAs, SOS activation,
//                 notice acks): writes tenant-scoped records through the
//                 Phase 10 sync engine; requires a session + active membership.
//   PROTECTED   — admin.html (owner/admin), gov-admin.js, platform RPCs:
//                 already gated server-side; UI gates are NOT the boundary.
//
// The UI gate is UX only. Supabase Auth + RLS remain the security
// boundary: with no session, every tenant read/write returns nothing.
// Local safety-reference content and the offline queue stay functional
// (public + private-outbox data is per-device, never shared).
//
// Exposes window.MG_GATE: { resolveDestination, showGate, hideGate }.
// ============================================================
(function () {
  "use strict";

  function tr(key) {
    try { if (window.t) return t(key); } catch (e) {}
    var en = window.TRANSLATIONS && window.TRANSLATIONS.en;
    return (en && en[key]) || key;
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // ---- destination resolver (single source of entry-routing truth) --------
  // Resolves the post-authentication destination from CURRENT server-side
  // state (membership rows visible under the session's RLS). Never trusts
  // client-stored role/organization values.
  //
  // Returns one of:
  //   AUTH_REQUIRED     — no valid session
  //   NO_ORGANIZATION   — authenticated, no active membership (onboarding)
  //   SELECT_ORGANIZATION — multiple active memberships (switcher)
  //   WORKER_WORKSPACE  — one active membership (any role) → workspace
  //   COMPANY_ADMIN     — active owner/admin membership → admin console
  //   GOVERNMENT_WORKSPACE — active government role
  function resolveDestination(auth) {
    if (!auth || !auth.ensureSession) return Promise.resolve("AUTH_REQUIRED");
    return auth.ensureSession().then(function (session) {
      if (!session) return "AUTH_REQUIRED";
      return auth.fetchMyMemberships().then(function (mems) {
        var active = (mems || []).filter(function (m) { return m.status === "active"; });
        if (!active.length) return "NO_ORGANIZATION";
        var GOV_ROLES = ["national_regulatory_admin", "government_safety_inspector",
          "government_compliance_officer", "government_analyst"];
        var gov = active.find(function (m) { return GOV_ROLES.indexOf(m.role) >= 0; });
        if (gov && active.length === 1) return "GOVERNMENT_WORKSPACE";
        var admin = active.find(function (m) { return m.role === "owner" || m.role === "admin"; });
        var multi = active.length > 1;
        if (admin && !multi) return "COMPANY_ADMIN";
        if (multi) return "SELECT_ORGANIZATION";
        return "WORKER_WORKSPACE";
      });
    }).catch(function () { return "AUTH_REQUIRED"; });
  }

  // ---- gate UI (reuses splash visual identity) ----------------------------
  var GATE_ID = "authGate";

  function injectStyles() {
    if (document.getElementById("mg-gate-styles")) return;
    var s = document.createElement("style");
    s.id = "mg-gate-styles";
    s.textContent = [
      "#" + GATE_ID + "{position:fixed;inset:0;z-index:8000;background:linear-gradient(160deg,#12141f 0%,#1a1d2e 60%,#232741 100%);display:flex;align-items:center;justify-content:center;padding:20px;}",
      "#" + GATE_ID + ".hidden{display:none;}",
      ".mg-gate-card{width:100%;max-width:420px;text-align:center;}",
      ".mg-gate-brand{font-family:'Barlow Condensed',sans-serif;font-size:42px;font-weight:800;letter-spacing:2px;color:#f5c518;margin:18px 0 4px;}",
      ".mg-gate-brand span{color:#e8eaf0;}",
      ".mg-gate-tag{font-size:13px;color:#9aa0b4;line-height:1.7;margin-bottom:22px;}",
      ".mg-gate-btn{display:block;width:100%;margin:10px 0;background:linear-gradient(135deg,#f5c518,#e8a800);color:#000;border:none;border-radius:12px;font-family:'Barlow Condensed',sans-serif;font-size:18px;font-weight:800;letter-spacing:1.5px;padding:14px;cursor:pointer;}",
      ".mg-gate-btn.secondary{background:transparent;color:#f5c518;border:1.5px solid rgba(245,197,24,0.55);}",
      ".mg-gate-btn.ghost{background:transparent;color:#9aa0b4;border:1px solid rgba(154,160,180,0.3);font-size:14px;padding:11px;}",
      ".mg-gate-btn:disabled{opacity:0.55;cursor:wait;}",
      ".mg-gate-note{margin-top:16px;font-size:12px;color:#6d7288;line-height:1.6;}",
      ".mg-gate-msg{display:none;margin:12px 0;font-size:13px;color:#e63946;line-height:1.6;}",
      ".mg-gate-msg.info{color:#2ec4b6;}",
      ".mg-gate-status{font-size:12px;color:#6d7288;margin-top:14px;letter-spacing:1px;}"
    ].join("\n");
    document.head.appendChild(s);
  }

  function ensureGate() {
    injectStyles();
    var g = document.getElementById(GATE_ID);
    if (g) return g;
    g = document.createElement("div");
    g.id = GATE_ID;
    g.className = "hidden";
    g.innerHTML =
      '<div class="mg-gate-card">' +
      '  <div class="mg-gate-brand">MINE<span>GUARD</span></div>' +
      '  <div class="mg-gate-tag">Protecting Mining Operations.<br>Protecting People.<br>Protecting Liberia\u2019s Resources.</div>' +
      '  <div class="mg-gate-msg" id="mgGateMsg"></div>' +
      '  <button class="mg-gate-btn" id="mgGateSignIn">\u{1F510} ' + esc(tr("authSignIn") || "Sign In") + '</button>' +
      '  <button class="mg-gate-btn secondary" id="mgGateSignUp">' + esc(tr("authSignUp") || "Create Account") + '</button>' +
      '  <button class="mg-gate-btn ghost" id="mgGateInvite">' + esc(tr("gateAcceptInvite") || "Accept Invitation") + '</button>' +
      '  <button class="mg-gate-btn ghost" id="mgGateForgot" style="margin-top:4px;">' + esc(tr("gateForgot") || "Forgot Password?") + '</button>' +
      '  <div id="mgGateOnboard" style="display:none;margin-top:14px;">' +
      '    <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:#f5c518;margin-bottom:8px;">SET YOUR ORGANIZATION</div>' +
      '    <button class="mg-gate-btn" id="mgGateCreateOrg">\u{1F3D7} Create a New Organization</button>' +
      '    <button class="mg-gate-btn secondary" id="mgGateJoinOrg">\u{1F465} Join an Existing Organization</button>' +
      '    <div style="font-size:11px;color:#6d7288;line-height:1.6;margin-top:6px;">Both options open the admin console onboarding — you remain signed in.</div>' +
      '  </div>' +
      '  <div class="mg-gate-note">Safety reference guides remain available offline.<br>Sign in to report incidents, file JSAs, and receive your organization\u2019s notices.</div>' +
      '  <div class="mg-gate-status" id="mgGateStatus"></div>' +
      '</div>';
    document.body.appendChild(g);
    // Wire the buttons to the existing auth-ui modal (single sign-in surface)
    g.querySelector("#mgGateSignIn").addEventListener("click", function () {
      var chip = document.getElementById("mgAuthChip");
      if (chip) chip.click();
      else openAuthModal();
    });
    g.querySelector("#mgGateSignUp").addEventListener("click", function () {
      openAuthModal("signup");
    });
    g.querySelector("#mgGateForgot").addEventListener("click", function () {
      showGateMsg((window.t && t("gateForgotSent")) || "Password reset is not available yet. Contact your organization administrator.", "info");
    });
    g.querySelector("#mgGateInvite").addEventListener("click", function () {
      openAuthModal("signin", (window.t && t("gateInviteHint")) || "Sign in with the invited email, then use the invitation link your administrator sent you.");
    });
    return g;
  }

  function openAuthModal(mode, note) {
    // Prefer the explicit-mode hook (auth-ui exposes MG_AUTH_UI.open(mode));
    // fall back to the chip (sign-in) for stale cached auth-ui.js.
    if (window.MG_AUTH_UI && typeof window.MG_AUTH_UI.open === "function") {
      window.MG_AUTH_UI.open(mode === "signup" ? "signup" : "signin");
    } else {
      var chip = document.getElementById("mgAuthChip");
      if (chip) chip.click();
    }
    if (note) showGateMsg(note, "info");
  }

  function showGateMsg(msg, kind) {
    var m = document.getElementById("mgGateMsg");
    if (!m) return;
    m.textContent = msg;
    m.className = "mg-gate-msg" + (kind === "info" ? " info" : "");
    m.style.display = "block";
  }

  function showGate(statusText) {
    var g = ensureGate();
    g.classList.remove("hidden");
    var app = document.getElementById("app");
    if (app) app.classList.add("hidden");
    var st = document.getElementById("mgGateStatus");
    if (st) st.textContent = statusText || "";
    setOnboardActions(false);
  }

  // Session 21 — NO_ORGANIZATION needs ACTIONABLE onboarding, not just text.
  // Renders Create / Join buttons (wired to the same surfaces the admin
  // sign-in screen uses) inside the gate until hidden again.
  function setOnboardActions(show) {
    var g = ensureGate();
    var host = document.getElementById("mgGateOnboard");
    if (!host) return;
    host.style.display = show ? "block" : "none";
    if (!show) return;
    var createBtn = document.getElementById("mgGateCreateOrg");
    var joinBtn = document.getElementById("mgGateJoinOrg");
    if (createBtn && !createBtn.dataset.wired) {
      createBtn.dataset.wired = "1";
      createBtn.addEventListener("click", function () {
        window.location.href = "admin.html?onboard=create";
      });
    }
    if (joinBtn && !joinBtn.dataset.wired) {
      joinBtn.dataset.wired = "1";
      joinBtn.addEventListener("click", function () {
        window.location.href = "admin.html?onboard=join";
      });
    }
  }

  function hideGate() {
    var g = document.getElementById(GATE_ID);
    if (g) g.classList.add("hidden");
    setOnboardActions(false);
  }

  window.MG_GATE = {
    resolveDestination: resolveDestination,
    showGate: showGate,
    hideGate: hideGate,
    showGateMsg: showGateMsg,
    showGateActions: function () { setOnboardActions(true); }
  };
})();
