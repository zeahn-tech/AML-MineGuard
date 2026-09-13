// ============================================================
// MINEGUARD — Supabase Auth client (plain fetch, no SDK)
// GoTrue REST + PostgREST over HTTPS. Session tokens are stored
// in localStorage (PWA standard; passwords are NEVER stored).
// RLS is the security boundary for every data read/write.
//
// Exposes window.MG_AUTH:
//   signUp(email, password)
//   signInWithPassword(email, password)
//   signOut()
//   getUser()                          -> user | null
//   ensureSession()                    -> session | null (refresh if expiring)
//   getSession()
//   fetchMyMemberships()               -> [{organization_id, role, status, ...}]
//   fetchOrganization(id)              -> org row | null
//   fetchEffectiveRole(orgId)          -> role code | null (Phase 03 RBAC RPC)
//   hasOrgPermission(orgId, perm)      -> boolean (Phase 03 RBAC RPC)
//   fetchMyPermissions(orgId)          -> [permission codes] (Phase 03 RBAC RPC)
//   fetchSiteEffectiveRole(orgId, siteId)   -> role | null (Phase 04)
//   hasSitePermission(orgId, siteId, perm)  -> boolean (Phase 04)
//   fetchOrgSites(orgId)               -> [sites] (Phase 04)
//   fetchOrgMembers(orgId)             -> [{user_id,email,role,status}] (Phase 04 RPC)
//   fetchSiteMembers(orgId) / fetchUnits(orgId) / fetchWorkers(orgId) / fetchInvites(orgId)
//   orgAddMember / orgUpdateMemberRole / orgRemoveMember / orgSendInvite(->token)
//   orgAcceptInvite(token) / orgRevokeInvite / siteAssignMember / siteRemoveMember
//   orgCreateUnit / orgUpdateUnit / orgRemoveUnit / workerAdd / workerUpdate / workerRemove
//   onAuthChange(cb)                   -> unsubscribe
// ============================================================
(function () {
  "use strict";

  var CFG = window.MG_CONFIG || {};
  var BASE = (CFG.supabaseUrl || "").replace(/\/+$/, "");
  var ANON = CFG.supabaseAnonKey || "";
  var SESSION_KEY = "mg_auth_session"; // {access_token, refresh_token, expires_at, user}
  var SESSION_MARGIN_MS = 60 * 1000;

  function http(path, opts) {
    opts = opts || {};
    var headers = {
      apikey: ANON,
      "Content-Type": "application/json",
      Accept: "application/json"
    };
    if (opts.token) headers.Authorization = "Bearer " + opts.token;
    var init = { method: opts.method || "GET", headers: headers };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    return fetch(BASE + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
        if (!res.ok) {
          var msg = (data && (data.error_description || data.error || data.message || data.msg))
            || ("Request failed (HTTP " + res.status + ")");
          if (typeof data === "object" && data && data.code === "PGRST301") {
            msg = "Access denied by database security policy";
          }
          var err = new Error(msg);
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function readSession() {
    try {
      var raw = localStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }
  function writeSession(s) {
    if (!s) { localStorage.removeItem(SESSION_KEY); return; }
    localStorage.setItem(SESSION_KEY, JSON.stringify(s));
  }
  function notify(session) {
    try {
      window.dispatchEvent(new CustomEvent("mg-auth-change", { detail: { session: session } }));
    } catch (e) { /* older browsers */ }
  }

  function storeTokenResponse(resp, userOverride) {
    if (!resp || !resp.access_token) return null;
    var session = {
      access_token: resp.access_token,
      refresh_token: resp.refresh_token,
      expires_at: Date.now() + (resp.expires_in || 3600) * 1000,
      user: resp.user || userOverride || null
    };
    writeSession(session);
    return session;
  }

  function signUp(email, password) {
    return http("/auth/v1/signup", {
      method: "POST",
      body: { email: email, password: password }
    }).then(function (resp) {
      // Email confirmation may be required; session may be null then.
      var session = storeTokenResponse(resp);
      notify(session);
      return { user: resp.user || (session && session.user) || null, session: session };
    });
  }

  function signInWithPassword(email, password) {
    return http("/auth/v1/token?grant_type=password", {
      method: "POST",
      body: { email: email, password: password }
    }).then(function (resp) {
      var session = storeTokenResponse(resp);
      notify(session);
      return { user: resp.user || null, session: session };
    });
  }

  function refreshSession() {
    var stored = readSession();
    if (!stored || !stored.refresh_token) return Promise.resolve(null);
    return http("/auth/v1/token?grant_type=refresh_token", {
      method: "POST",
      body: { refresh_token: stored.refresh_token }
    }).then(function (resp) {
      var session = storeTokenResponse(resp);
      notify(session);
      return session;
    }).catch(function () {
      writeSession(null);
      notify(null);
      return null;
    });
  }

  function getSession() {
    var s = readSession();
    if (!s) return null;
    // Normalize user in case only the token response cached it
    if (!s.user && s.user_id) s.user = { id: s.user_id };
    return s;
  }

  // Returns a usable session (refresh if expired/missing user), or null.
  function ensureSession() {
    var s = readSession();
    if (!s || !s.access_token) return Promise.resolve(null);
    if (!s.expires_at || s.expires_at - SESSION_MARGIN_MS > Date.now()) {
      return Promise.resolve(s);
    }
    return refreshSession();
  }

  function getUser() {
    var s = getSession();
    if (!s) return Promise.resolve(null);
    if (s.user) return Promise.resolve(s.user);
    return http("/auth/v1/user", { token: s.access_token }).then(function (u) {
      s.user = u; writeSession(s);
      return u;
    }).catch(function () { return null; });
  }

  function signOut() {
    var s = readSession();
    var p = s && s.access_token
      ? http("/auth/v1/logout", { method: "POST", token: s.access_token }).catch(function () { return null; })
      : Promise.resolve(null);
    return p.then(function () {
      writeSession(null);
      // Clear the selected-organization UI preference (never a security
      // boundary, but must not leak across accounts on a shared device).
      try { localStorage.removeItem("mg_selected_org"); } catch (e) {}
      notify(null);
      return true;
    });
  }

  function pgHeaders(token) {
    return { apikey: ANON, Authorization: "Bearer " + token, Accept: "application/json", "Content-Type": "application/json" };
  }

  function fetchMyMemberships() {
    var s = getSession();
    if (!s || !s.access_token) return Promise.resolve([]);
    function once() {
      return fetch(BASE + "/rest/v1/organization_members?select=organization_id,user_id,role,status&order=organization_id.asc", {
        headers: pgHeaders(s.access_token)
      }).then(function (res) {
        if (!res.ok) {
          // A failed verification must NOT be reported as "no memberships":
          // every caller would misroute a signed-in owner to the orgless
          // onboarding state. Distinguish error from genuinely-zero rows.
          var err = new Error("Could not verify organization memberships (HTTP " + res.status + ")");
          err.httpStatus = res.status;
          err.transient = res.status >= 500 || res.status === 429;
          throw err;
        }
        return res.json();
      }).then(function (rows) {
        return Array.isArray(rows) && s.user ? rows.filter(function (r) { return r.user_id === s.user.id; }) : [];
      });
    }
    // One automatic retry for transient server failures, then surface the error.
    return once().catch(function (err) {
      if (err && err.transient) {
        return new Promise(function (resolve) { setTimeout(resolve, 800); }).then(once);
      }
      throw err;
    });
  }

  function fetchOrganization(id) {
    var s = getSession();
    if (!s || !s.access_token || !id) return Promise.resolve(null);
    return fetch(BASE + "/rest/v1/organizations?select=id,slug,name,org_type,status&id=eq." + encodeURIComponent(id), {
      headers: pgHeaders(s.access_token)
    }).then(function (res) { return res.json(); })
      .then(function (rows) { return Array.isArray(rows) && rows.length ? rows[0] : null; })
      .catch(function () { return null; });
  }

  // First-owner onboarding: claim an active mining_company org that has no
  // active members yet (Phase 02 bootstrap; SECURITY DEFINER server-side).
  // Returns the claimed organization id.
  function bootstrapFirstOwner() {
    var s = getSession();
    if (!s || !s.access_token) return Promise.reject(new Error("Not signed in"));
    return fetch(BASE + "/rest/v1/rpc/bootstrap_first_owner", {
      method: "POST",
      headers: pgHeaders(s.access_token)
    }).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        if (!res.ok) {
          var msg = (data && (data.message || data.msg || data.error))
            || ("Organization setup failed (HTTP " + res.status + ")");
          throw new Error(msg);
        }
        return data; // claimed organization id
      });
    });
  }

  // Phase 03 RBAC: server-resolved role/permission queries (RLS-adjacent
  // SECURITY DEFINER RPCs — the DB is the source of truth; the UI only mirrors
  // what these return, never the reverse).
  function fetchEffectiveRole(orgId) {
    var s = getSession();
    if (!s || !s.access_token || !orgId) return Promise.resolve(null);
    return fetch(BASE + "/rest/v1/rpc/auth_user_effective_role", {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify({ p_organization_id: orgId })
    }).then(function (res) { return res.json(); })
      .catch(function () { return null; });
  }

  function hasOrgPermission(orgId, permission) {
    var s = getSession();
    if (!s || !s.access_token || !orgId || !permission) return Promise.resolve(false);
    return fetch(BASE + "/rest/v1/rpc/auth_user_has_permission", {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify({ p_organization_id: orgId, p_permission: permission })
    }).then(function (res) { return res.json(); })
      .then(function (v) { return v === true; })
      .catch(function () { return false; });
  }

  function fetchMyPermissions(orgId) {
    var s = getSession();
    if (!s || !s.access_token || !orgId) return Promise.resolve([]);
    return fetch(BASE + "/rest/v1/rpc/auth_user_permissions", {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify({ p_organization_id: orgId })
    }).then(function (res) { return res.json(); })
      .then(function (rows) { return Array.isArray(rows) ? rows : []; })
      .catch(function () { return []; });
  }

  // ---- Phase 04: generic RPC + PostgREST GET helpers ----------------------
  // SECURITY DEFINER RPCs carry their own authorization checks server-side;
  // table reads are RLS-filtered. The client never filters by trust.
  function rpc(name, args) {
    var s = getSession();
    if (!s || !s.access_token) return Promise.reject(new Error("Not signed in"));
    return fetch(BASE + "/rest/v1/rpc/" + name, {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify(args || {})
    }).then(function (res) {
      if (res.status === 204) return null; // void RPC
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
        if (!res.ok) {
          var msg = (data && (data.message || data.msg || data.error))
            || ("Request failed (HTTP " + res.status + ")");
          var err = new Error(msg);
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  function pgGet(path) {
    var s = getSession();
    if (!s || !s.access_token) return Promise.resolve([]);
    return fetch(BASE + "/rest/v1" + path, { headers: pgHeaders(s.access_token) })
      .then(function (res) { return res.json(); })
      .then(function (rows) { return Array.isArray(rows) ? rows : []; })
      .catch(function () { return []; });
  }

  // ---- Phase 04: site hierarchy + org administration reads ----------------
  function fetchOrgSites(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/sites?select=id,name,location,county,status&organization_id=eq." + encodeURIComponent(orgId) + "&order=name.asc");
  }

  // Org member list WITH emails (org_list_members is SECURITY DEFINER and
  // raises for non-members; the caller must be an org member to read it).
  function fetchOrgMembers(orgId) {
    if (!orgId) return Promise.resolve([]);
    return rpc("org_list_members", { p_organization_id: orgId })
      .then(function (rows) { return Array.isArray(rows) ? rows : []; })
      .catch(function () { return []; });
  }

  function fetchSiteMembers(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/site_members?select=site_id,user_id,role,status,created_at&organization_id=eq." + encodeURIComponent(orgId) + "&order=created_at.asc");
  }

  function fetchUnits(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/organizational_units?select=id,site_id,parent_id,unit_type,name,code,status&organization_id=eq." + encodeURIComponent(orgId) + "&order=name.asc");
  }

  function fetchWorkers(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/workers?select=id,site_id,department_id,team_id,user_id,employee_id,full_name,classification,contact_phone,status&organization_id=eq." + encodeURIComponent(orgId) + "&order=full_name.asc");
  }

  function fetchInvites(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/org_invites?select=id,email,role,site_id,status,expires_at,created_at&organization_id=eq." + encodeURIComponent(orgId) + "&order=created_at.desc");
  }

  function fetchSiteEffectiveRole(orgId, siteId) {
    if (!orgId || !siteId) return Promise.resolve(null);
    return rpc("auth_user_site_effective_role", { p_organization_id: orgId, p_site_id: siteId })
      .then(function (v) { return v || null; })
      .catch(function () { return null; });
  }

  function hasSitePermission(orgId, siteId, permission) {
    if (!orgId || !siteId || !permission) return Promise.resolve(false);
    return rpc("auth_user_has_site_permission", { p_organization_id: orgId, p_site_id: siteId, p_permission: permission })
      .then(function (v) { return v === true; })
      .catch(function () { return false; });
  }

  // ---- Phase 04: org-admin member management ------------------------------
  function orgAddMember(orgId, userId, role) {
    return rpc("org_add_member", { p_organization_id: orgId, p_user_id: userId, p_role: role });
  }
  function orgUpdateMemberRole(orgId, userId, role) {
    return rpc("org_update_member_role", { p_organization_id: orgId, p_user_id: userId, p_role: role });
  }
  function orgRemoveMember(orgId, userId) {
    return rpc("org_remove_member", { p_organization_id: orgId, p_user_id: userId });
  }

  // ---- Phase 04: invites ---------------------------------------------------
  // orgSendInvite resolves to the invite token (the shareable secret).
  function orgSendInvite(orgId, email, role, siteId) {
    return rpc("org_send_invite", { p_organization_id: orgId, p_email: email, p_role: role, p_site_id: siteId || null });
  }
  function orgAcceptInvite(token) {
    return rpc("org_accept_invite", { p_token: token });
  }
  function orgRevokeInvite(orgId, inviteId) {
    return rpc("org_revoke_invite", { p_organization_id: orgId, p_invite_id: inviteId });
  }

  // ---- Phase 04: site members ---------------------------------------------
  function siteAssignMember(orgId, siteId, userId, role) {
    return rpc("site_assign_member", { p_organization_id: orgId, p_site_id: siteId, p_user_id: userId, p_role: role });
  }
  function siteRemoveMember(orgId, siteId, userId) {
    return rpc("site_remove_member", { p_organization_id: orgId, p_site_id: siteId, p_user_id: userId });
  }

  // ---- Session 21: worker join requests + notifications --------------------
  // The requested role is decided server-side ('worker'); clients only pass
  // the organization id resolved through organization_search_joinable.
  function searchJoinableOrgs(query) {
    return rpc("organization_search_joinable", { p_query: query || null });
  }
  function requestJoinOrg(orgId) {
    return rpc("organization_request_join", { p_organization_id: orgId });
  }
  function myJoinRequests() {
    return rpc("my_join_requests", {});
  }
  function listJoinRequests(orgId) {
    return rpc("organization_join_requests_list", { p_organization_id: orgId });
  }
  function reviewJoinRequest(requestId, approve, rejectionReason) {
    return rpc("organization_review_join_request", {
      p_request_id: requestId, p_approve: approve === true,
      p_rejection_reason: rejectionReason || null
    });
  }
  function fetchMyNotifications(unreadOnly) {
    return rpc("my_notifications", { p_unread_only: unreadOnly === true });
  }
  function markNotificationRead(notificationId) {
    return rpc("mark_notification_read", { p_notification_id: notificationId });
  }

  // ---- Session 21: push subscription registration (additional channel) ----
  function registerPushSubscription(endpoint, p256dh, authKey, userAgent) {
    return rpc("register_push_subscription", {
      p_endpoint: endpoint, p_p256dh: p256dh, p_auth: authKey,
      p_user_agent: userAgent || null
    });
  }
  function deregisterPushSubscription(endpoint) {
    return rpc("deregister_push_subscription", { p_endpoint: endpoint });
  }

  // ---- Phase 04: hierarchy + worker registry -------------------------------
  function orgCreateUnit(orgId, siteId, parentId, unitType, name, code) {
    return rpc("org_create_unit", { p_organization_id: orgId, p_site_id: siteId, p_parent_id: parentId || null, p_unit_type: unitType, p_name: name, p_code: code || null });
  }
  function orgUpdateUnit(unitId, name, code, status) {
    return rpc("org_update_unit", { p_unit_id: unitId, p_name: name || null, p_code: code || null, p_status: status || null });
  }
  function orgRemoveUnit(unitId) {
    return rpc("org_remove_unit", { p_unit_id: unitId });
  }
  function workerAdd(orgId, data) {
    return rpc("worker_add", {
      p_organization_id: orgId, p_site_id: (data && data.site_id) || null,
      p_department_id: (data && data.department_id) || null, p_team_id: (data && data.team_id) || null,
      p_user_id: (data && data.user_id) || null, p_employee_id: (data && data.employee_id) || null,
      p_full_name: (data && data.full_name) || "", p_classification: (data && data.classification) || "employee",
      p_contact_phone: (data && data.contact_phone) || null
    });
  }
  function workerUpdate(workerId, data) {
    return rpc("worker_update", {
      p_worker_id: workerId, p_site_id: (data && data.site_id) || null,
      p_department_id: (data && data.department_id) || null, p_team_id: (data && data.team_id) || null,
      p_employee_id: (data && data.employee_id) || null, p_full_name: (data && data.full_name) || null,
      p_classification: (data && data.classification) || null, p_contact_phone: (data && data.contact_phone) || null,
      p_status: (data && data.status) || null
    });
  }
  function workerRemove(workerId) {
    return rpc("worker_remove", { p_worker_id: workerId });
  }

  function onAuthChange(cb) {
    var fn = function (e) { try { cb(e.detail && e.detail.session); } catch (err) {} };
    window.addEventListener("mg-auth-change", fn);
    return function () { window.removeEventListener("mg-auth-change", fn); };
  }

  // Security hygiene: legacy plaintext admin password must never persist.
  try {
    if (localStorage.getItem("mg_admin_pass")) localStorage.removeItem("mg_admin_pass");
  } catch (e) { /* ignore */ }

  // ---- Phase 11: government regulator surfaces -----------------------------
  // All authorization is server-side: bootstrap is one-shot per user (any
  // active membership disqualifies); grant issue/revoke re-check regulator
  // admin rights; reads are RLS-bounded by government_grants scope.
  function bootstrapFirstRegulatorAdmin() {
    return rpc("bootstrap_first_regulator_admin", {});
  }

  // Regulator claim state for the Government panel (session 20). SECURITY
  // DEFINER TVF; returns [] for members (not eligible) and for signed-out
  // users. Rows carry { state, organization_id, name, county, org_status }.
  function regulatorClaimStatus() {
    return rpc("regulator_claim_status", {});
  }
  function regulatorRevokeGrant(grantId) {
    return rpc("regulator_revoke_grant", { p_grant_id: grantId });
  }
  function regulatorUpdateUserRole(regulatorOrgId, userId, newRole) {
    return rpc("regulator_update_user_role", {
      p_regulator_org_id: regulatorOrgId, p_user_id: userId, p_new_role: newRole
    });
  }
  function fetchMyGovernmentGrants() {
    // SECURITY DEFINER TVF: active grants where I am the regulator user.
    return rpc("current_user_active_government_grants", {})
      .then(function (rows) { return Array.isArray(rows) ? rows : []; });
  }
  function fetchIssuedGrants(regulatorOrgId) {
    // RLS: regulator-org members read grants issued by their org.
    return pgGet("/government_grants?select=id,regulator_user_id,target_org_id,site_id,scope,regulator_role,status,issued_at,expires_at&regulator_org_id=eq." + encodeURIComponent(regulatorOrgId) + "&order=issued_at.desc");
  }
  function fetchIncidentsGrantScoped(orgId, siteId) {
    // RLS: visible only where the caller's active grant covers (org, site).
    var q = "/incidents?select=id,site_id,incident_type,severity,status,incident_datetime,location_text,reported_by_name,created_at&organization_id=eq." + encodeURIComponent(orgId) + "&deleted=eq.false&order=created_at.desc&limit=50";
    if (siteId && siteId !== "all") q += "&site_id=eq." + encodeURIComponent(siteId);
    return pgGet(q);
  }
  function fetchEmergencyGrantScoped(orgId, siteId) {
    var q = "/emergency_events?select=id,site_id,category,severity,status,started_at,deactivated_at,assembly_point&organization_id=eq." + encodeURIComponent(orgId) + "&deleted=eq.false&order=started_at.desc&limit=50";
    if (siteId && siteId !== "all") q += "&site_id=eq." + encodeURIComponent(siteId);
    return pgGet(q);
  }

  // ---- Phase 12: SaaS + enterprise administration --------------------------
  // Site management (sites.create/update/delete permission codes; the RPCs
  // re-check server-side — the client gates are UX only).
  function siteCreate(orgId, name, location, county) {
    return rpc("site_create", { p_organization_id: orgId, p_name: name, p_location: location || null, p_county: county || null });
  }
  function siteUpdate(siteId, name, location, county) {
    return rpc("site_update", { p_site_id: siteId, p_name: name || null, p_location: location || null, p_county: county || null });
  }
  function siteRemove(siteId) {
    return rpc("site_remove", { p_site_id: siteId });
  }
  // Org settings/branding (settings.manage server-side).
  function orgUpdateSettings(orgId, settings, branding) {
    return rpc("org_update_settings", { p_organization_id: orgId, p_settings: settings || null, p_branding: branding || null });
  }
  // Plans/subscriptions (modeled only — billing not wired).
  function fetchPlans() {
    return pgGet("/plans?select=code,name,max_sites,max_users,features&order=sort_order.asc");
  }
  function fetchOrgSubscription(orgId) {
    return pgGet("/subscriptions?select=id,plan_code,status,current_period_start,current_period_end&organization_id=eq." + encodeURIComponent(orgId) + "&status=in.(active,trialing)&limit=1");
  }
  function orgUpdateSubscription(orgId, planCode) {
    return rpc("org_update_subscription", { p_organization_id: orgId, p_plan_code: planCode });
  }
  // Grant expiry administration (Phase 11 gap): 5-arg issue + extend.
  function regulatorIssueGrant(targetOrgId, opts) {
    var o = opts || {};
    return rpc("regulator_issue_grant", {
      p_target_org_id: targetOrgId,
      p_site_id: o.siteId || null,
      p_scope: o.scope || null,
      p_regulator_user_id: o.regulatorUserId || null,
      p_expires_at: o.expiresAt || null
    });
  }
  function regulatorExtendGrant(grantId, expiresAt) {
    return rpc("regulator_extend_grant", { p_grant_id: grantId, p_expires_at: expiresAt || null });
  }
  // Platform administration (platform-scope membership server-side).
  function bootstrapFirstPlatformAdmin() {
    return rpc("bootstrap_first_platform_admin", {});
  }
  function platformListOrganizations() {
    return rpc("platform_list_organizations", {})
      .then(function (rows) { return Array.isArray(rows) ? rows : []; });
  }
  function platformUpdateOrganizationStatus(orgId, newStatus) {
    return rpc("platform_update_organization_status", { p_organization_id: orgId, p_new_status: newStatus });
  }
  // Server-side national roll-up over ACTIVE grants (documented formulas).
  function fetchNationalOverview() {
    return rpc("gov_national_overview", {});
  }

  // ---- Phase 05 cutover: safety notices + safety-domain org reads ---------
  // Fresh-start directive (ADR-014): these reads/writes ARE the production
  // data path now — RLS scopes everything to the caller's org.
  function fetchSafetyNotices(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/safety_notices?select=id,site_id,client_id,title,message,notice_type,work_zone_text,created_by_text,pinned,expires_at,created_at&organization_id=eq." + encodeURIComponent(orgId) + "&deleted=eq.false&order=created_at.desc&limit=100");
  }
  function createSafetyNotice(orgId, n) {
    var s = getSession();
    if (!s || !s.access_token) return Promise.reject(new Error("Not signed in"));
    return fetch(BASE + "/rest/v1/safety_notices", {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify({
        organization_id: orgId,
        site_id: n.site_id || null,
        client_id: n.client_id || null,
        title: n.title,
        message: n.message,
        notice_type: n.notice_type || "info",
        work_zone_text: n.work_zone || n.work_zone_text || null,
        created_by_text: n.created_by_text || null,
        lang: n.lang || "en",
        pinned: n.pinned === true,
        expires_at: n.expires_at || null
      })
    }).then(function (res) {
      if (res.status === 201) return null;
      return res.text().then(function (t) { throw new Error("notice create " + res.status + ": " + t.slice(0, 160)); });
    });
  }
  // Phase 05 cutover: soft-delete via SECURITY DEFINER RPC — a direct PATCH
  // {deleted:true} is impossible (PostgREST re-checks the SELECT policy
  // deleted=false on the returning row → 42501; Phase 07-class finding).
  function deleteSafetyNotice(noticeId) {
    return rpc("notice_soft_delete", { p_notice_id: noticeId });
  }
  function updateSafetyNotice(noticeId, patch) {
    var s = getSession();
    if (!s || !s.access_token) return Promise.reject(new Error("Not signed in"));
    return fetch(BASE + "/rest/v1/safety_notices?id=eq." + encodeURIComponent(noticeId), {
      method: "PATCH",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify(patch)
    }).then(function (res) {
      if (res.status === 204) return true;
      throw new Error("notice update " + res.status);
    });
  }
  function ackSafetyNotice(noticeId, orgId, clientId) {
    var s = getSession();
    if (!s || !s.access_token) return Promise.reject(new Error("Not signed in"));
    return fetch(BASE + "/rest/v1/safety_notice_acks", {
      method: "POST",
      headers: pgHeaders(s.access_token),
      body: JSON.stringify({ notice_id: noticeId, organization_id: orgId, client_id: clientId || null })
    }).then(function (res) {
      if (res.status === 201) return true;      // first ack
      if (res.status === 409) return true;      // idempotent re-ack (unique)
      return res.text().then(function (t) { throw new Error("ack " + res.status + ": " + t.slice(0, 120)); });
    });
  }
  function fetchMyNoticeAcks(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/safety_notice_acks?select=notice_id,acked_at&organization_id=eq." + encodeURIComponent(orgId));
  }
  // Org-wide safety-domain reads for the admin dashboard (RLS-scoped).
  function fetchIncidentsOrg(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/incidents?select=id,site_id,client_id,incident_type,severity,status,incident_datetime,location_text,reported_by_name,badge,dept_text,description,immediate_action,witnesses_text,saved_at,created_at,deleted&organization_id=eq." + encodeURIComponent(orgId) + "&order=created_at.desc&limit=200");
  }
  function fetchJsasOrg(orgId) {
    if (!orgId) return Promise.resolve([]);
    return pgGet("/jsas?select=id,site_id,client_id,task,worker_text,supervisor_text,location_text,date,status,ppe,saved_at,created_at,deleted&organization_id=eq." + encodeURIComponent(orgId) + "&order=created_at.desc&limit=200");
  }

  // Organization lifecycle (session 18): self-service creation + ownership
  // transfer. Both are SECURITY DEFINER server-side; ownership/role/status are
  // ALWAYS derived from auth.uid() — the client only passes name/type/county.
  function createOrganization(name, orgType, county) {
    var args = { p_name: name };
    if (orgType) args.p_org_type = orgType;
    if (county) args.p_county = county;
    return rpc("create_organization", args).then(function (data) {
      // PostgREST returns a jsonb object {organization_id, slug}
      return data && data.organization_id ? data : { organization_id: data };
    });
  }

  function orgTransferOwnership(orgId, newOwnerUserId) {
    return rpc("org_transfer_ownership", {
      p_organization_id: orgId,
      p_new_owner_user_id: newOwnerUserId
    });
  }

  // Selected-organization UI preference (NOT a security boundary — every data
  // read/write is revalidated server-side by RLS; the id is only a hint).
  var ORG_PREF_KEY = "mg_selected_org";
  function getSelectedOrgId() {
    try { return localStorage.getItem(ORG_PREF_KEY) || null; } catch (e) { return null; }
  }
  function setSelectedOrgId(orgId) {
    try {
      if (orgId) localStorage.setItem(ORG_PREF_KEY, orgId);
      else localStorage.removeItem(ORG_PREF_KEY);
    } catch (e) { /* storage unavailable */ }
    try { window.dispatchEvent(new CustomEvent("mg-org-change", { detail: { organization_id: orgId || null } })); }
    catch (e) { /* older browsers */ }
  }

  // Resolve the effective organization: validates the stored preference against
  // CURRENT active memberships (server truth); falls back to the first active
  // owner/admin membership, then the first active membership. Returns null when
  // the user has no active membership (never grants access to anything).
  function resolveActiveOrg() {
    return fetchMyMemberships().then(function (mems) {
      var active = (mems || []).filter(function (m) { return m.status === "active"; });
      if (!active.length) { setSelectedOrgId(null); return null; }
      var pref = getSelectedOrgId();
      var chosen = pref && active.find(function (m) { return m.organization_id === pref; });
      if (!chosen) {
        chosen = active.find(function (m) { return m.role === "owner" || m.role === "admin"; }) || active[0];
        setSelectedOrgId(chosen.organization_id);
      }
      return chosen;
    });
    // NOTE: verification errors now PROPAGATE (previously swallowed → null,
    // which misrouted signed-in owners to the orgless onboarding state).
    // Callers distinguish "genuinely orgless" (null) from "verify failed"
    // (rejected promise) and must surface the difference to the user.
  }

  window.MG_AUTH = {
    signUp: signUp,
    signInWithPassword: signInWithPassword,
    signOut: signOut,
    getUser: getUser,
    getSession: getSession,
    ensureSession: ensureSession,
    fetchMyMemberships: fetchMyMemberships,
    fetchOrganization: fetchOrganization,
    fetchEffectiveRole: fetchEffectiveRole,
    hasOrgPermission: hasOrgPermission,
    fetchMyPermissions: fetchMyPermissions,
    bootstrapFirstOwner: bootstrapFirstOwner,
    createOrganization: createOrganization,
    orgTransferOwnership: orgTransferOwnership,
    getSelectedOrgId: getSelectedOrgId,
    setSelectedOrgId: setSelectedOrgId,
    resolveActiveOrg: resolveActiveOrg,
    fetchSiteEffectiveRole: fetchSiteEffectiveRole,
    hasSitePermission: hasSitePermission,
    fetchOrgSites: fetchOrgSites,
    fetchOrgMembers: fetchOrgMembers,
    fetchSiteMembers: fetchSiteMembers,
    fetchUnits: fetchUnits,
    fetchWorkers: fetchWorkers,
    fetchInvites: fetchInvites,
    orgAddMember: orgAddMember,
    orgUpdateMemberRole: orgUpdateMemberRole,
    orgRemoveMember: orgRemoveMember,
    orgSendInvite: orgSendInvite,
    orgAcceptInvite: orgAcceptInvite,
    orgRevokeInvite: orgRevokeInvite,
    siteAssignMember: siteAssignMember,
    siteRemoveMember: siteRemoveMember,
    searchJoinableOrgs: searchJoinableOrgs,
    requestJoinOrg: requestJoinOrg,
    myJoinRequests: myJoinRequests,
    listJoinRequests: listJoinRequests,
    reviewJoinRequest: reviewJoinRequest,
    fetchMyNotifications: fetchMyNotifications,
    markNotificationRead: markNotificationRead,
    registerPushSubscription: registerPushSubscription,
    deregisterPushSubscription: deregisterPushSubscription,
    orgCreateUnit: orgCreateUnit,
    orgUpdateUnit: orgUpdateUnit,
    orgRemoveUnit: orgRemoveUnit,
    workerAdd: workerAdd,
    workerUpdate: workerUpdate,
    workerRemove: workerRemove,
    bootstrapFirstRegulatorAdmin: bootstrapFirstRegulatorAdmin,
    regulatorClaimStatus: regulatorClaimStatus,
    regulatorIssueGrant: regulatorIssueGrant,
    regulatorRevokeGrant: regulatorRevokeGrant,
    regulatorUpdateUserRole: regulatorUpdateUserRole,
    fetchMyGovernmentGrants: fetchMyGovernmentGrants,
    fetchIssuedGrants: fetchIssuedGrants,
    fetchIncidentsGrantScoped: fetchIncidentsGrantScoped,
    fetchEmergencyGrantScoped: fetchEmergencyGrantScoped,
    siteCreate: siteCreate,
    siteUpdate: siteUpdate,
    siteRemove: siteRemove,
    orgUpdateSettings: orgUpdateSettings,
    fetchPlans: fetchPlans,
    fetchOrgSubscription: fetchOrgSubscription,
    orgUpdateSubscription: orgUpdateSubscription,
    regulatorExtendGrant: regulatorExtendGrant,
    bootstrapFirstPlatformAdmin: bootstrapFirstPlatformAdmin,
    platformListOrganizations: platformListOrganizations,
    platformUpdateOrganizationStatus: platformUpdateOrganizationStatus,
    fetchNationalOverview: fetchNationalOverview,
    // ---- Phase 05 cutover: safety notices + safety-domain reads ----------
    fetchSafetyNotices: fetchSafetyNotices,
    createSafetyNotice: createSafetyNotice,
    updateSafetyNotice: updateSafetyNotice,
    deleteSafetyNotice: deleteSafetyNotice,
    ackSafetyNotice: ackSafetyNotice,
    fetchMyNoticeAcks: fetchMyNoticeAcks,
    fetchIncidentsOrg: fetchIncidentsOrg,
    fetchJsasOrg: fetchJsasOrg,
    onAuthChange: onAuthChange
  };
})();
