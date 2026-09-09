// ============================================================
// MINEGUARD — Government Regulatory Command Center (Phase 11)
// Renders the "Government" panel of admin.html for regulator
// users (members of a government-scoped organization):
//   * onboarding: one-shot claim of the first open regulator org
//     (bootstrap_first_regulator_admin) for brand-new users
//   * grants: org-wide + site-scoped authorizations issued by
//     the regulator org (issue / revoke), the explicit records
//     behind every cross-org read (GOVERNMENT_PLATFORM §2)
//   * command center: national overview + drill-down over the
//     granted orgs ONLY (incidents, inspections, CAPAs, emergency
//     events) — every read RLS-bounded by the grant intersection;
//     no grant = zero rows, never blanket access
// All writes go through SECURITY DEFINER RPCs in supabase-auth.js
// (regulatorIssueGrant / regulatorRevokeGrant /
// regulatorUpdateUserRole). The DATABASE enforces every
// authorization — this UI only mirrors what RPCs/RLS allow.
//
// Exposes window.GovAdmin: { render(), refresh() }
// ============================================================
(function () {
  "use strict";

  var GOV_ROLE_NAMES = {
    national_regulatory_admin: "National Regulatory Administrator",
    government_safety_inspector: "Government Safety Inspector",
    government_compliance_officer: "Government Compliance Officer",
    government_analyst: "Government Analyst"
  };

  var state = {
    loaded: false,
    orgId: null,          // regulator org of the signed-in user (or bootstrap-claimed)
    org: null,            // regulator org row
    role: null,           // government role code in that org
    grants: [],           // grants issued by this regulator org
    myGrants: [],         // active grants where I am the regulator user (TVF)
    grantedOrgs: [],      // distinct target orgs across my grants (rows cache)
    selectedOrgId: null,  // command-center drill-down target
    selectedSiteId: "all",
    sites: [],            // sites of selected target org (grant-scoped read)
    stats: null,          // aggregate stats of selected org
    incidents: [],        // recent incidents (grant scope, capped)
    emergency: [],        // recent emergency events (grant scope, capped)
    isGovAdmin: false     // national_regulatory_admin (may issue/revoke)
  };

  // ---------- helpers ----------
  function el(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d) ? "—" : d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  }
  function fmtDateTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d) ? "—" : d.toLocaleString();
  }
  function statusLine(msg, isErr) {
    var box = el("govStatus");
    if (box) {
      box.textContent = msg || "";
      box.style.color = isErr ? "var(--red)" : "var(--green)";
    }
  }

  // ---------- state resolution ----------
  function resolveRegulatorContext() {
    state.orgId = null; state.org = null; state.role = null;
    state.isGovAdmin = false;
    state.myGrants = [];
    state.grantedOrgs = [];
    var s = window.MG_AUTH && MG_AUTH.getSession && MG_AUTH.getSession();
    if (!s || !s.access_token) return Promise.resolve(false);
    return MG_AUTH.fetchMyMemberships().then(function (rows) {
      var gov = (rows || []).filter(function (m) { return GOV_ROLE_NAMES[m.role]; });
      if (!gov.length) return false;
      // one regulator org per user for Phase 11 surfaces
      var m = gov[0];
      state.orgId = m.organization_id;
      state.role = m.role;
      state.isGovAdmin = m.role === "national_regulatory_admin";
      return MG_AUTH.fetchOrganization(state.orgId).then(function (org) {
        state.org = org || null;
        return true;
      });
    }).catch(function () { return false; });
  }

  function loadGrants() {
    state.grants = [];
    state.myGrants = [];
    state.grantedOrgs = [];
    if (!state.orgId) return Promise.resolve();
    return MG_AUTH.fetchIssuedGrants(state.orgId).then(function (rows) {
      state.grants = (rows || []).filter(function (g) { return g.status === "active" || g.status === "revoked"; });
    }).then(function () {
      return MG_AUTH.fetchMyGovernmentGrants().then(function (rows) {
        state.myGrants = rows || [];
        var orgIds = {};
        state.myGrants.forEach(function (g) { if (g.target_org_id) orgIds[g.target_org_id] = true; });
        state.grantedOrgs = Object.keys(orgIds);
        if (!state.selectedOrgId && state.grantedOrgs.length) {
          state.selectedOrgId = state.grantedOrgs[0];
        }
      });
    }).catch(function () { /* keep empty state */ });
  }

  // ---------- command-center data (all RLS grant-scoped) ----------
  function loadGrantScopedData() {
    state.sites = []; state.stats = null; state.incidents = []; state.emergency = [];
    if (!state.selectedOrgId) return Promise.resolve();
    var orgQ = "organization_id=eq." + state.selectedOrgId;

    var sitesGet = MG_AUTH.fetchOrgSites(state.selectedOrgId)
      .then(function (rows) { state.sites = rows || []; })
      .catch(function () { state.sites = []; });

    var incidentsGet = MG_AUTH.fetchIncidentsGrantScoped(state.selectedOrgId, state.selectedSiteId)
      .catch(function () { return []; });

    var emergencyGet = MG_AUTH.fetchEmergencyGrantScoped(state.selectedOrgId, state.selectedSiteId)
      .catch(function () { return []; });

    return Promise.all([sitesGet, incidentsGet, emergencyGet]).then(function (res) {
      state.incidents = res[1] || [];
      state.emergency = res[2] || [];
      state.stats = {
        incidents: state.incidents.length,
        critical: state.incidents.filter(function (r) { return r.severity === "critical" || r.severity === "high"; }).length,
        openCapas: null, // Phase 12 aggregate server view; not client-computed per non-negotiable #7
        activeEmergency: state.emergency.filter(function (r) { return r.status === "ACTIVATED" || r.status === "ACKNOWLEDGED" || r.status === "RESPONDING"; }).length,
        emergency: state.emergency.length
      };
    });
  }

  // ---------- rendering ----------
  function render() {
    var root = el("govAdminRoot");
    if (!root) return;
    if (!window.MG_AUTH || !MG_AUTH.getSession || !MG_AUTH.getSession()) {
      root.innerHTML = emptyState("Sign in to use the government command center.");
      return;
    }
    resolveRegulatorContext().then(function (isRegulator) {
      if (!isRegulator) {
        // not a regulator user: offer one-shot bootstrap for brand-new users
        root.innerHTML =
          '<div class="empty-state">' +
          '<div class="empty-icon">🏛️</div>' +
          '<div class="empty-text">This panel is for government regulator users.<br>' +
          'If you are the first government user and belong to no organization yet, you can claim the open regulator organization.</div>' +
          '<button id="govBootstrapBtn" style="margin-top:12px;background:var(--yellow);color:#111;border:0;border-radius:8px;padding:10px 18px;font-weight:700;cursor:pointer;">Claim Regulator Organization</button>' +
          '</div>';
        var btn = el("govBootstrapBtn");
        if (btn) btn.onclick = onBootstrap;
        return;
      }
      loadGrants().then(function () { return loadGrantScopedData(); }).then(renderPanel);
    });
  }

  function emptyState(msg) {
    return '<div class="empty-state"><div class="empty-icon">🏛️</div><div class="empty-text">' + esc(msg) + "</div></div>";
  }

  function onBootstrap() {
    MG_AUTH.bootstrapFirstRegulatorAdmin().then(function (orgId) {
      statusLine("Regulator organization claimed.");
      return resolveRegulatorContext().then(function () { return loadGrants(); }).then(renderPanel);
    }).catch(function (err) {
      statusLine((err && err.message) || "Bootstrap failed.", true);
    });
  }

  function grantRowHtml(g) {
    var statusColor = g.status === "active" ? "var(--green)" : "var(--text3)";
    return "<tr>" +
      "<td>" + esc(g.target_org_id ? (state.orgNameCache[g.target_org_id] || shortId(g.target_org_id)) : "—") + "</td>" +
      "<td>" + (g.site_id ? esc(shortId(g.site_id)) : '<span style="color:var(--text3);">Org-wide</span>') + "</td>" +
      "<td>" + esc(g.scope || "—") + "</td>" +
      "<td>" + esc(GOV_ROLE_NAMES[g.regulator_role] || g.regulator_role || "—") + "</td>" +
      '<td style="color:' + statusColor + ';font-weight:600;">' + esc(g.status) + "</td>" +
      "<td>" + esc(fmtDate(g.expires_at)) + "</td>" +
      "<td>" + (state.isGovAdmin && g.status === "active"
        ? '<button class="gov-extend" data-grant="' + esc(g.id) + '" data-expires="' + esc(g.expires_at || "") + '">Extend</button> ' +
          '<button class="gov-revoke" data-grant="' + esc(g.id) + '">Revoke</button>'
        : "—") + "</td>" +
      "</tr>";
  }

  function shortId(id) { return String(id || "").substring(0, 8) + "…"; }

  function renderPanel() {
    var root = el("govAdminRoot");
    if (!root) return;

    // resolve org names for display (best effort, grant-scoped SELECT on organizations)
    state.orgNameCache = {};
    var nameFetch = state.grantedOrgs.length
      ? Promise.all(state.grantedOrgs.map(function (oid) {
          return MG_AUTH.fetchOrganization(oid).then(function (o) {
            if (o && o.id) state.orgNameCache[o.id] = o.name;
          }).catch(function () {});
        }))
      : Promise.resolve();
    nameFetch.then(function () {
      var h = "";

      h += '<div id="govStatus" style="margin-bottom:10px;font-size:13px;font-weight:600;"></div>';

      // Regulator org header
      h += '<div class="card-block" style="margin-bottom:20px;">';
      h += '<div class="card-block-title">🏛️ ' + esc(state.org ? state.org.name : "Regulator Organization") + "</div>";
      h += '<div style="color:var(--text2);font-size:13px;">Signed in as <strong>' + esc(GOV_ROLE_NAMES[state.role] || state.role) + "</strong>" +
        (state.isGovAdmin ? " — may issue and revoke grants" : " — read-only within granted scope") + "</div>";
      h += "</div>";

      // Onboarding nudge: brand-new regulator org with no grants
      if (!state.grants.length) {
        h += '<div class="card-block" style="margin-bottom:20px;">';
        h += '<div class="card-block-title">Issue the first authorization</div>';
        h += '<div style="color:var(--text2);font-size:13px;margin-bottom:10px;">No grants yet. A government grant is the explicit record behind every cross-org read — without one, a regulator user sees zero rows of any mining company.</div>';
        h += "</div>";
      }

      // Issue grant form (admin only) — includes optional expiry (Phase 12)
      if (state.isGovAdmin) {
        h += '<div class="card-block" style="margin-bottom:20px;">';
        h += '<div class="card-block-title">➕ Issue Government Grant</div>';
        h += '<div class="gov-form-row">';
        h += '<input id="govGrantTarget" class="nc-form-input" placeholder="Target organization UUID" style="flex:2;">';
        h += '<input id="govGrantSite" class="nc-form-input" placeholder="Site UUID (optional — blank = org-wide)" style="flex:2;">';
        h += '<input id="govGrantScope" class="nc-form-input" placeholder="Scope label (e.g. compliance monitoring)" style="flex:2;">';
        h += '<input id="govGrantExpires" type="datetime-local" class="nc-form-input" style="flex:2;">';
        h += '<button id="govIssueBtn" class="gov-btn">Issue Grant</button>';
        h += "</div>";
        h += '<div style="color:var(--text3);font-size:11px;margin-top:6px;">The regulator user must already be an active government member of this regulator org. Expiry is optional — blank = no expiry.</div>';
        h += "</div>";
      }

      // Grants table
      h += '<div class="card-block" style="margin-bottom:20px;">';
      h += '<div class="card-block-title">📜 Government Grants (' + state.grants.length + ")</div>";
      if (state.grants.length) {
        h += '<table class="data-table"><thead><tr><th>Target Org</th><th>Site</th><th>Scope</th><th>Regulator Role</th><th>Status</th><th>Expires</th><th></th></tr></thead><tbody>';
        state.grants.forEach(function (g) { h += grantRowHtml(g); });
        h += "</tbody></table>";
      } else {
        h += '<div style="color:var(--text3);font-size:13px;">No grants issued by this regulator org.</div>';
      }
      h += "</div>";

      // National overview — server-side aggregate over ALL active grants (Phase 12)
      if (state.grantedOrgs.length && state.isGovAdmin) {
        h += '<div class="card-block" style="margin-bottom:20px;">';
        h += '<div class="card-block-title">🌐 National Overview (server-side roll-up, all active grants)</div>';
        h += '<div id="govNational">' + esc(state.nationalError || "Loading…") + "</div>";
        h += "</div>";
      }

      // Command center (visible when the user holds active grants)
      h += '<div class="card-block" style="margin-bottom:20px;">';
      h += '<div class="card-block-title">📊 National Command Center (granted scope)</div>';
      if (state.grantedOrgs.length) {
        h += '<div class="gov-form-row" style="margin-bottom:12px;">';
        h += '<select id="govOrgSel" class="nc-form-select" style="flex:2;">';
        state.grantedOrgs.forEach(function (oid) {
          h += '<option value="' + esc(oid) + '"' + (oid === state.selectedOrgId ? " selected" : "") + ">" + esc(state.orgNameCache[oid] || shortId(oid)) + "</option>";
        });
        h += "</select>";
        h += '<select id="govSiteSel" class="nc-form-select" style="flex:2;">';
        h += '<option value="all">All sites (grant scope)</option>';
        (state.sites || []).forEach(function (s) {
          h += '<option value="' + esc(s.id) + '"' + (s.id === state.selectedSiteId ? " selected" : "") + ">" + esc(s.name || shortId(s.id)) + "</option>";
        });
        h += "</select>";
        h += '<button id="govRefreshBtn" class="gov-btn">Refresh</button>';
        h += "</div>";
        var st = state.stats || {};
        h += '<div class="gov-stats">';
        h += statCard(st.incidents || 0, "Incidents (latest 50)", "var(--yellow)");
        h += statCard(st.critical || 0, "High / Critical", "var(--red)");
        h += statCard(st.emergency || 0, "Emergency Events", "var(--orange)");
        h += statCard(st.activeEmergency || 0, "Active Emergencies", "var(--red)");
        h += "</div>";

        if (state.emergency.length) {
          h += '<div class="card-block-title" style="margin:14px 0 8px;">🚨 Recent Emergency Events</div>';
          h += '<table class="data-table"><thead><tr><th>Category</th><th>Status</th><th>Started</th><th>Assembly Point</th></tr></thead><tbody>';
          state.emergency.slice(0, 10).forEach(function (e) {
            h += "<tr><td>" + esc(e.category || "—") + '</td><td style="color:var(--red);font-weight:600;">' + esc(e.status || "—") + "</td><td>" + esc(fmtDateTime(e.started_at)) + "</td><td>" + esc(e.assembly_point || "—") + "</td></tr>";
          });
          h += "</tbody></table>";
        }

        if (state.incidents.length) {
          h += '<div class="card-block-title" style="margin:14px 0 8px;">📸 Recent Incidents</div>';
          h += '<table class="data-table"><thead><tr><th>Type</th><th>Severity</th><th>Status</th><th>Date</th><th>Location</th><th>Reporter</th></tr></thead><tbody>';
          state.incidents.slice(0, 10).forEach(function (r) {
            var sevColor = r.severity === "critical" || r.severity === "high" ? "var(--red)" : "var(--yellow)";
            h += "<tr><td>" + esc(r.incident_type || "—") + '</td><td style="color:' + sevColor + ';font-weight:600;">' + esc(r.severity || "—") + "</td><td>" + esc(r.status || "—") + "</td><td>" + esc(fmtDate(r.incident_datetime || r.created_at)) + "</td><td>" + esc(r.location_text || "—") + "</td><td>" + esc(r.reported_by_name || "—") + "</td></tr>";
          });
          h += "</tbody></table>";
        }
      } else {
        h += '<div style="color:var(--text3);font-size:13px;">You hold no active grants yet — the command center fills in once a grant covers an organization. This is the isolation guarantee: no grant, zero rows.</div>';
      }
      h += "</div>";

      root.innerHTML = h;
      wire();
    });
  }

  function statCard(n, label, color) {
    return '<div class="gov-stat-card"><div class="gov-stat-num" style="color:' + color + ';">' + n + '</div><div class="gov-stat-label">' + esc(label) + "</div></div>";
  }

  // ---------- actions ----------
  function wire() {
    var issue = el("govIssueBtn");
    if (issue) issue.onclick = onIssueGrant;
    var refresh = el("govRefreshBtn");
    if (refresh) refresh.onclick = function () {
      state.selectedOrgId = el("govOrgSel") ? el("govOrgSel").value : state.selectedOrgId;
      state.selectedSiteId = el("govSiteSel") ? el("govSiteSel").value : "all";
      refresh();
    };
    var orgSel = el("govOrgSel");
    if (orgSel) orgSel.onchange = function () {
      state.selectedOrgId = orgSel.value;
      state.selectedSiteId = "all";
      refresh();
    };
    var siteSel = el("govSiteSel");
    if (siteSel) siteSel.onchange = function () {
      state.selectedSiteId = siteSel.value;
      loadGrantScopedData().then(renderPanel);
    };
    document.querySelectorAll(".gov-revoke").forEach(function (b) {
      b.onclick = function () { onRevokeGrant(b.getAttribute("data-grant")); };
    });
    document.querySelectorAll(".gov-extend").forEach(function (b) {
      b.onclick = function () { onExtendGrant(b.getAttribute("data-grant"), b.getAttribute("data-expires")); };
    });
    if (el("govNational") && state.isGovAdmin && state.grantedOrgs.length) {
      MG_AUTH.fetchNationalOverview().then(function (rows) {
        var box = el("govNational");
        if (!box) return;
        state.nationalError = null;
        var r = (Array.isArray(rows) ? rows[0] : rows) || {};
        box.innerHTML = '<div class="gov-stats">' +
          statCard(r.orgs_granted || 0, "Organizations Granted", "var(--yellow)") +
          statCard(r.sites_granted || 0, "Sites Granted", "var(--green)") +
          statCard(r.active_grants || 0, "Active Grants", "var(--green)") +
          statCard(r.open_incidents || 0, "Open Incidents", "var(--yellow)") +
          statCard(r.critical_incidents || 0, "Critical Incidents", "var(--red)") +
          statCard(r.active_emergencies || 0, "Active Emergencies", "var(--red)") +
          "</div>";
      }).catch(function (err) {
        state.nationalError = (err && err.message) || "National overview unavailable.";
        var box = el("govNational");
        if (box) box.textContent = state.nationalError;
      });
    }
  }

  function onIssueGrant() {
    var target = el("govGrantTarget").value.trim();
    if (!target) { statusLine("Enter the target organization UUID.", true); return; }
    var site = el("govGrantSite").value.trim() || null;
    var scope = el("govGrantScope").value.trim() || "compliance monitoring";
    var expiresRaw = el("govGrantExpires") ? el("govGrantExpires").value.trim() : "";
    var expiresAt = expiresRaw ? new Date(expiresRaw).toISOString() : null;
    if (expiresAt && isNaN(Date.parse(expiresAt))) { statusLine("Invalid expiry date.", true); return; }
    MG_AUTH.regulatorIssueGrant(target, { siteId: site, scope: scope, expiresAt: expiresAt }).then(function () {
      statusLine("Grant issued.");
      el("govGrantTarget").value = ""; el("govGrantSite").value = ""; el("govGrantScope").value = "";
      if (el("govGrantExpires")) el("govGrantExpires").value = "";
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Issue grant failed.", true); });
  }

  function onExtendGrant(grantId, currentExpires) {
    if (!grantId) return;
    var input = prompt(
      "New expiry for this grant (ISO or yyyy-mm-dd hh:mm, blank = remove expiry):",
      currentExpires ? String(currentExpires).replace("T", " ").slice(0, 16) : ""
    );
    if (input === null) return;
    var trimmed = input.trim();
    var expiresAt = null;
    if (trimmed) {
      var parsed = new Date(trimmed.replace(" ", "T"));
      if (isNaN(parsed.getTime())) { statusLine("Invalid expiry date.", true); return; }
      expiresAt = parsed.toISOString();
    }
    MG_AUTH.regulatorExtendGrant(grantId, expiresAt).then(function () {
      statusLine(expiresAt ? "Grant expiry updated." : "Grant expiry removed (now non-expiring).");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Extend failed.", true); });
  }

  function onRevokeGrant(grantId) {
    if (!grantId || !confirm("Revoke this government grant? Access is lost immediately.")) return;
    MG_AUTH.regulatorRevokeGrant(grantId).then(function () {
      statusLine("Grant revoked.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Revoke failed.", true); });
  }

  function refresh() {
    loadGrants().then(function () { return loadGrantScopedData(); }).then(renderPanel);
  }

  window.GovAdmin = { render: render, refresh: refresh };
})();
