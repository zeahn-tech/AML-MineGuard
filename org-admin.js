// ============================================================
// MINEGUARD — Organization administration (Phase 04)
// Powers the "Organization" panel of admin.html:
//   * hierarchy: sites, departments/teams/work zones
//   * people: org members, site members, worker registry
//   * onboarding: email invites (token shared in-app until a
//     mail provider is wired in Phase 09/13)
// All writes go through the SECURITY DEFINER RPCs in
// supabase-auth.js (orgAddMember / orgSendInvite / siteAssignMember
// / orgCreateUnit / workerAdd …). The DATABASE enforces every
// authorization — this UI only mirrors what RPCs/RLS allow, never
// the reverse.
//
// Exposes window.OrgAdmin: { render(), refresh() }
// ============================================================
(function () {
  "use strict";

  var ROLE_CODES = ["admin", "safety_manager", "safety_officer", "site_manager",
    "supervisor", "worker", "contractor", "member"];
  var ROLE_NAMES = {
    owner: "Owner", admin: "Administrator", safety_manager: "Safety Manager",
    safety_officer: "Safety Officer", site_manager: "Site Manager",
    supervisor: "Supervisor", worker: "Worker", contractor: "Contractor", member: "Member"
  };
  var UNIT_TYPES = { department: "Department", team: "Team", work_zone: "Work Zone" };

  var state = {
    orgId: null,
    org: null,
    sites: [],
    members: [],
    siteMembers: [],
    units: [],
    workers: [],
    invites: [],
    perms: [],
    canManagePeople: false,   // org owner/admin
    canManageSites: false,    // org owner/admin (site assignment)
    canManageUnits: false,    // owner/admin/safety_manager create; +update for others
    canCreateUnits: false,
    canManageWorkers: false,
    canCreateSites: false,    // sites.create (Phase 12)
    canUpdateSites: false,    // sites.update (Phase 12)
    canDeleteSites: false,    // sites.delete (Phase 12)
    canManageSettings: false, // settings.manage (Phase 12)
    canManageBilling: false,  // billing.manage (Phase 12)
    subscription: null,       // active subscription row (Phase 12)
    plan: null                // plan row for the subscription (Phase 12)
  };

  function el(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function fmtDate(ts) {
    if (!ts) return "—";
    var d = new Date(ts);
    return isNaN(d) ? "—" : d.toLocaleDateString();
  }
  function hasPerm(code) { return state.perms.indexOf(code) !== -1; }
  function roleName(r) { return ROLE_NAMES[r] || r; }
  function siteName(id) {
    var s = state.sites.find(function (x) { return x.id === id; });
    return s ? s.name : "—";
  }
  function unitName(id) {
    var u = state.units.find(function (x) { return x.id === id; });
    return u ? u.name : "—";
  }
  function memberEmail(userId) {
    var m = state.members.find(function (x) { return x.user_id === userId; });
    return m ? m.email : "—";
  }
  function unitLabel(u) {
    var label = (UNIT_TYPES[u.unit_type] || u.unit_type) + " · " + u.name;
    if (u.code) label += " (" + u.code + ")";
    return label;
  }

  function statusLine(msg, isErr) {
    var s = el("orgAdminStatus");
    if (!s) return;
    s.textContent = msg || "";
    s.style.display = msg ? "block" : "none";
    s.style.color = isErr ? "var(--red)" : "var(--green)";
  }

  function setBusy(busy, btnId) {
    var b = el(btnId);
    if (b) b.disabled = busy;
  }

  // ---- data loading --------------------------------------------------------
  function pickOrg() {
    return MG_AUTH.fetchMyMemberships().then(function (mems) {
      var list = mems || [];
      if (!list.length) return null;
      // Prefer the first active owner/admin membership (dashboard entry already
      // guarantees at least one exists).
      var admin = list.find(function (m) { return m.status === "active" && (m.role === "owner" || m.role === "admin"); });
      return (admin || list[0]).organization_id;
    }).catch(function () { return null; });
  }

  function load(orgId) {
    if (!orgId) return Promise.reject(new Error("No organization"));
    state.orgId = orgId;
    return Promise.all([
      MG_AUTH.fetchOrganization(orgId),
      MG_AUTH.fetchOrgSites(orgId),
      MG_AUTH.fetchOrgMembers(orgId),
      MG_AUTH.fetchSiteMembers(orgId),
      MG_AUTH.fetchUnits(orgId),
      MG_AUTH.fetchWorkers(orgId),
      MG_AUTH.fetchInvites(orgId),
      MG_AUTH.fetchMyPermissions(orgId),
      MG_AUTH.fetchEffectiveRole(orgId),
      MG_AUTH.fetchOrgSubscription(orgId).catch(function () { return []; })
    ]).then(function (r) {
      state.org = r[0]; state.sites = r[1]; state.members = r[2];
      state.siteMembers = r[3]; state.units = r[4]; state.workers = r[5];
      state.invites = r[6]; state.perms = r[7];
      var role = r[8];
      state.canManagePeople = role === "owner" || role === "admin";
      state.canManageSites = role === "owner" || role === "admin";
      state.canCreateUnits = state.canManagePeople || hasPerm("organizational_units.create");
      state.canManageUnits = state.canManagePeople || hasPerm("organizational_units.update");
      state.canManageWorkers = state.canManagePeople || hasPerm("workers.manage");
      // Phase 12 permissions (server-resolved; the client only mirrors them).
      state.canCreateSites = hasPerm("sites.create");
      state.canUpdateSites = hasPerm("sites.update");
      state.canDeleteSites = hasPerm("sites.delete");
      state.canManageSettings = hasPerm("settings.manage");
      state.canManageBilling = hasPerm("billing.manage");
      var sub = Array.isArray(r[9]) && r[9].length ? r[9][0] : null;
      state.subscription = sub;
      state.plan = null;
      if (sub) {
        return MG_AUTH.fetchPlans().then(function (plans) {
          state.plan = (plans || []).find(function (p) { return p.code === sub.plan_code; }) || null;
        }).catch(function () {});
      }
    });
  }

  // ---- rendering -----------------------------------------------------------
  function render() {
    var root = el("orgAdminRoot");
    if (!root) return;
    root.innerHTML = '<div style="color:var(--text2);padding:24px;">Loading organization…</div>';
    pickOrg().then(function (orgId) {
      if (!orgId) { root.innerHTML = '<div style="color:var(--red);padding:24px;">No organization membership found.</div>'; return; }
      return load(orgId).then(function () {
        root.innerHTML = buildHtml();
        bindEvents();
      });
    }).catch(function (err) {
      root.innerHTML = '<div style="color:var(--red);padding:24px;">Failed to load organization: ' + esc(err && err.message || err) + '</div>';
    });
  }

  function buildHtml() {
    var org = state.org || {};
    var h = [];
    h.push('<div class="section-hdr"><h3>🏢 ' + esc(org.name || "Organization") + '</h3><span style="font-size:12px;color:var(--text2);">' +
      esc(org.org_type || "") + (org.county ? " · " + esc(org.county) : "") + '</span></div>');
    h.push('<div id="orgAdminStatus" style="display:none;margin-bottom:12px;font-size:13px;font-weight:600;"></div>');

    // --- Plan & settings (Phase 12: SaaS + enterprise administration) ---
    h.push('<div class="card-block" style="margin-bottom:20px;">');
    h.push('<div class="settings-group-title">⚙️ Plan &amp; Organization Settings</div>');
    var sub = state.subscription;
    var plan = state.plan;
    if (sub) {
      var limits = [];
      if (plan && plan.max_sites != null) limits.push("max " + plan.max_sites + " sites");
      if (plan && plan.max_users != null) limits.push("max " + plan.max_users + " users");
      h.push('<div style="font-size:13px;color:var(--text2);margin:10px 0;">Plan: <strong style="color:var(--yellow);">' +
        esc(plan ? plan.name : sub.plan_code) + '</strong> · status <strong>' + esc(sub.status) + '</strong>' +
        (limits.length ? " · " + esc(limits.join(", ")) : "") +
        ' <span style="color:var(--text3);">(billing integration is a later phase — plan changes are recorded, not charged)</span></div>');
    } else {
      h.push('<div style="font-size:13px;color:var(--text2);margin:10px 0;">No active subscription found.</div>');
    }
    if (state.canManageBilling) {
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;margin:0 0 12px;align-items:center;">');
      h.push('<label class="nc-form-label" style="font-size:10px;">Change plan</label>');
      h.push('<select id="sub-plan" class="nc-form-select">' +
        (state.planOptions || []).map(function (p) {
          return '<option value="' + esc(p.code) + '"' + (sub && p.code === sub.plan_code ? " selected" : "") + ">" + esc(p.name) + "</option>";
        }).join("") + '</select>');
      h.push('<button class="filter-btn" id="sub-save" style="background:rgba(245,197,24,0.12);color:var(--yellow);border-color:rgba(245,197,24,0.35);">Save Plan</button>');
      h.push('</div>');
    }
    if (state.canManageSettings) {
      var st = (state.org && state.org.settings) || {};
      var br = (state.org && state.org.branding) || {};
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;margin:6px 0;align-items:flex-end;">');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Display name</label><input id="os-name" class="nc-form-input" style="width:180px;" value="' + esc(br.name || org.name || "") + '" /></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Brand color</label><input id="os-color" type="color" class="nc-form-input" style="width:52px;padding:2px;" value="' + esc(br.primary_color || "#f5c518") + '" /></div>');
      h.push('<button class="filter-btn" id="os-save" style="background:rgba(46,196,182,0.12);color:var(--green);border-color:rgba(46,196,182,0.35);">Save Settings</button>');
      h.push('</div>');
    } else if (!state.canManageBilling) {
      h.push('<div style="font-size:12px;color:var(--text3);">Plan and settings changes require Owner or Administrator permissions.</div>');
    }
    h.push('</div>');

    // --- People & access ---
    h.push('<div class="card-block" style="margin-bottom:20px;">');
    h.push('<div class="settings-group-title">👥 Members &amp; Access</div>');
    if (state.canManagePeople) {
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 16px;">');
      h.push('<input type="email" id="oi-email" class="nc-form-input" style="flex:1;min-width:180px;" placeholder="person@company.com" />');
      h.push('<select id="oi-role" class="nc-form-select">' + ROLE_CODES.map(function (c) {
        return '<option value="' + c + '">' + ROLE_NAMES[c] + '</option>';
      }).join("") + '</select>');
      h.push('<select id="oi-site" class="nc-form-select"><option value="">Org-wide (no site)</option>' +
        state.sites.map(function (s) { return '<option value="' + s.id + '">' + esc(s.name) + '</option>'; }).join("") + '</select>');
      h.push('<button class="filter-btn" id="oi-send" style="background:rgba(245,197,24,0.12);color:var(--yellow);border-color:rgba(245,197,24,0.35);">📨 Invite</button>');
      h.push('</div>');
      h.push('<div id="oi-token" style="display:none;margin-bottom:12px;font-size:12px;line-height:1.7;color:var(--text2);background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:10px;">' +
        'Invite created. Share this one-time token with the person (email delivery is wired up in a later phase):<br/>' +
        '<code id="oi-token-val" style="color:var(--yellow);word-break:break-all;"></code></div>');
    } else {
      h.push('<p style="font-size:12px;color:var(--text2);margin:8px 0 12px;">Member management requires an Owner or Administrator role.</p>');
    }
    h.push('<table class="data-table"><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Site</th>' +
      (state.canManagePeople ? '<th style="width:150px;">Actions</th>' : '') + '</tr></thead><tbody>');
    var seen = {};
    state.members.forEach(function (m) {
      var mySiteRoles = state.siteMembers.filter(function (sm) { return sm.user_id === m.user_id && sm.status === "active"; });
      h.push('<tr><td>' + esc(m.email || m.user_id) + '</td>' +
        '<td>' + esc(roleName(m.role)) + '</td>' +
        '<td>' + esc(m.status) + '</td>' +
        '<td>' + (mySiteRoles.length ? mySiteRoles.map(function (sm) { return esc(siteName(sm.site_id)) + " (" + esc(roleName(sm.role)) + ")"; }).join(", ") : "—") + '</td>');
      if (state.canManagePeople && m.role !== "owner") {
        h.push('<td style="display:flex;gap:6px;">' +
          '<select class="nc-form-select om-role" data-uid="' + m.user_id + '" style="padding:4px 6px;font-size:12px;">' +
          ['admin','safety_manager','safety_officer','site_manager','supervisor','worker','contractor','member'].map(function (c) {
            return '<option value="' + c + '"' + (c === m.role ? " selected" : "") + '>' + ROLE_NAMES[c] + '</option>';
          }).join("") + '</select>' +
          '<button class="filter-btn om-save" data-uid="' + m.user_id + '" style="font-size:11px;padding:4px 8px;">Save</button>' +
          '<button class="filter-btn om-remove" data-uid="' + m.user_id + '" style="font-size:11px;padding:4px 8px;color:var(--red);border-color:rgba(230,57,70,0.4);">Remove</button></td>');
      } else if (state.canManagePeople && m.role === "owner") {
        h.push('<td style="font-size:11px;color:var(--yellow);">Protected</td>');
      } else {
        h.push('<td>—</td>');
      }
      h.push('</tr>');
      seen[m.user_id] = true;
    });
    if (!state.members.length) h.push('<tr><td colspan="6" style="color:var(--text3);">No members yet.</td></tr>');
    h.push('</tbody></table>');
    h.push('</div>');

    // --- Pending invites ---
    if (state.canManagePeople && state.invites.length) {
      h.push('<div class="card-block" style="margin-bottom:20px;">');
      h.push('<div class="settings-group-title">📨 Pending Invites</div>');
      h.push('<table class="data-table"><thead><tr><th>Email</th><th>Role</th><th>Site</th><th>Expires</th><th></th></tr></thead><tbody>');
      state.invites.filter(function (i) { return i.status === "pending"; }).forEach(function (i) {
        h.push('<tr><td>' + esc(i.email) + '</td><td>' + esc(roleName(i.role)) + '</td><td>' +
          (i.site_id ? esc(siteName(i.site_id)) : "Org-wide") + '</td><td>' + esc(fmtDate(i.expires_at)) + '</td>' +
          '<td><button class="filter-btn oi-revoke" data-id="' + i.id + '" style="font-size:11px;padding:4px 8px;color:var(--red);border-color:rgba(230,57,70,0.4);">Revoke</button></td></tr>');
      });
      h.push('</tbody></table></div>');
    }

    // --- Sites & structure ---
    h.push('<div class="card-block" style="margin-bottom:20px;">');
    h.push('<div class="settings-group-title">🏗️ Sites &amp; Structure</div>');
    h.push('<table class="data-table" style="margin-bottom:14px;"><thead><tr><th>Site</th><th>Location</th><th>County</th><th>Status</th><th>Departments / Teams / Work Zones</th></tr></thead><tbody>');
    state.sites.forEach(function (s) {
      var units = state.units.filter(function (u) { return u.site_id === s.id && u.status !== "deleted"; });
      h.push('<tr><td>' + esc(s.name) + '</td><td>' + esc(s.location || "—") + '</td><td>' + esc(s.county || "—") + '</td><td>' + esc(s.status) + '</td><td>');
      if (units.length) {
        var byParent = {};
        units.forEach(function (u) { (byParent[u.parent_id || ""] = byParent[u.parent_id || ""] || []).push(u); });
        function walk(parentKey, depth) {
          (byParent[parentKey] || []).forEach(function (u) {
            h.push('<div style="padding-left:' + (depth * 16) + 'px;font-size:13px;">' + esc(unitLabel(u)) + '</div>');
            walk(u.id, depth + 1);
          });
        }
        walk("", 0);
      } else {
        h.push('<span style="color:var(--text3);font-size:12px;">No units yet</span>');
      }
      h.push('</td></tr>');
    });
    if (!state.sites.length) h.push('<tr><td colspan="5" style="color:var(--text3);">No sites.</td></tr>');
    h.push('</tbody></table>');
    // --- Phase 12: site create / remove (RPC-gated, server-side permission) ---
    if (state.canCreateSites) {
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px;">');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">New site name *</label><input id="sm-name" class="nc-form-input" style="width:170px;" placeholder="e.g. Tokadeh Mine" /></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Location</label><input id="sm-loc" class="nc-form-input" style="width:150px;" placeholder="Location" /></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">County</label><input id="sm-county" class="nc-form-input" style="width:120px;" placeholder="County" /></div>');
      h.push('<button class="filter-btn" id="sm-create" style="background:rgba(46,196,182,0.12);color:var(--green);border-color:rgba(46,196,182,0.35);">+ Add Site</button>');
      h.push('</div>');
    }
    if (state.canDeleteSites && state.sites.length) {
      h.push('<div style="font-size:11px;color:var(--text3);">Site removal is a soft delete — safety records are preserved. Select a site:</div>');
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:6px 0;">');
      h.push('<select id="sm-remove" class="nc-form-select">' +
        state.sites.filter(function (s) { return s.status !== "deleted"; }).map(function (s) {
          return '<option value="' + s.id + '">' + esc(s.name) + '</option>';
        }).join("") + '</select>');
      h.push('<button class="filter-btn" id="sm-remove-btn" style="color:var(--red);border-color:rgba(230,57,70,0.4);">🗑️ Remove Site</button>');
      h.push('</div>');
    }
    if (state.canManageUnits) {
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;">');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Type</label><select id="ou-type" class="nc-form-select"><option value="department">Department</option><option value="team">Team</option><option value="work_zone">Work Zone</option></select></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Site</label><select id="ou-site" class="nc-form-select">' +
        state.sites.map(function (s) { return '<option value="' + s.id + '">' + esc(s.name) + '</option>'; }).join("") + '</select></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Parent (optional)</label><select id="ou-parent" class="nc-form-select"><option value="">—</option>' +
        state.units.filter(function (u) { return u.status !== "deleted" && u.unit_type !== "work_zone"; }).map(function (u) {
          return '<option value="' + u.id + '" data-site="' + u.site_id + '">' + esc(unitLabel(u)) + '</option>';
        }).join("") + '</select></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Name</label><input id="ou-name" class="nc-form-input" style="width:170px;" placeholder="e.g. Mining Operations" /></div>');
      h.push('<button class="filter-btn" id="ou-create" style="background:rgba(46,196,182,0.12);color:var(--green);border-color:rgba(46,196,182,0.35);">+ Add Unit</button>');
      h.push('</div>');
    }
    h.push('</div>');

    // --- Worker registry ---
    h.push('<div class="card-block">');
    h.push('<div class="settings-group-title">👷 Worker Registry</div>');
    if (state.canManageWorkers) {
      h.push('<div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 14px;align-items:flex-end;">');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Full name *</label><input id="w-name" class="nc-form-input" style="width:170px;" placeholder="Worker name" /></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Employee ID</label><input id="w-eid" class="nc-form-input" style="width:120px;" placeholder="Badge #" /></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Site</label><select id="w-site" class="nc-form-select"><option value="">—</option>' +
        state.sites.map(function (s) { return '<option value="' + s.id + '">' + esc(s.name) + '</option>'; }).join("") + '</select></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Department</label><select id="w-dept" class="nc-form-select"><option value="">—</option>' +
        state.units.filter(function (u) { return u.unit_type === "department" && u.status !== "deleted"; }).map(function (u) {
          return '<option value="' + u.id + '">' + esc(u.name) + '</option>';
        }).join("") + '</select></div>');
      h.push('<div><label class="nc-form-label" style="font-size:10px;">Classification</label><select id="w-class" class="nc-form-select"><option value="employee">Employee</option><option value="contractor">Contractor</option><option value="other">Other</option></select></div>');
      h.push('<button class="filter-btn" id="w-add" style="background:rgba(46,196,182,0.12);color:var(--green);border-color:rgba(46,196,182,0.35);">+ Add Worker</button>');
      h.push('</div>');
    } else {
      h.push('<p style="font-size:12px;color:var(--text2);margin:8px 0 12px;">Worker registry management requires an Owner, Administrator or Safety Manager role.</p>');
    }
    h.push('<table class="data-table"><thead><tr><th>Name</th><th>Employee ID</th><th>Site</th><th>Department</th><th>Classification</th><th>Status</th>' +
      (state.canManageWorkers ? '<th style="width:90px;"></th>' : '') + '</tr></thead><tbody>');
    state.workers.filter(function (w) { return w.status !== "deleted"; }).forEach(function (w) {
      h.push('<tr><td>' + esc(w.full_name) + '</td><td>' + esc(w.employee_id || "—") + '</td><td>' +
        (w.site_id ? esc(siteName(w.site_id)) : "—") + '</td><td>' + (w.department_id ? esc(unitName(w.department_id)) : "—") + '</td>' +
        '<td>' + esc(w.classification) + '</td><td>' + esc(w.status) + '</td>');
      if (state.canManageWorkers) {
        h.push('<td><button class="filter-btn w-remove" data-id="' + w.id + '" data-name="' + esc(w.full_name) + '" style="font-size:11px;padding:4px 8px;color:var(--red);border-color:rgba(230,57,70,0.4);">Remove</button></td>');
      }
      h.push('</tr>');
    });
    if (!state.workers.length) h.push('<tr><td colspan="7" style="color:var(--text3);">No workers registered yet.</td></tr>');
    h.push('</tbody></table></div>');

    return h.join("");
  }

  // ---- events --------------------------------------------------------------
  function bindEvents() {
    var send = el("oi-send");
    if (send) send.addEventListener("click", onInvite);
    var revokes = document.querySelectorAll(".oi-revoke");
    Array.prototype.forEach.call(revokes, function (b) {
      b.addEventListener("click", function () { onRevokeInvite(b.getAttribute("data-id")); });
    });
    var saves = document.querySelectorAll(".om-save");
    Array.prototype.forEach.call(saves, function (b) {
      b.addEventListener("click", function () {
        var uid = b.getAttribute("data-uid");
        var sel = document.querySelector('.om-role[data-uid="' + uid + '"]');
        onChangeMemberRole(uid, sel && sel.value);
      });
    });
    var removes = document.querySelectorAll(".om-remove");
    Array.prototype.forEach.call(removes, function (b) {
      b.addEventListener("click", function () { onRemoveMember(b.getAttribute("data-uid")); });
    });
    var unitCreate = el("ou-create");
    if (unitCreate) unitCreate.addEventListener("click", onAddUnit);
    var wAdd = el("w-add");
    if (wAdd) wAdd.addEventListener("click", onAddWorker);
    var wRemoves = document.querySelectorAll(".w-remove");
    Array.prototype.forEach.call(wRemoves, function (b) {
      b.addEventListener("click", function () { onRemoveWorker(b.getAttribute("data-id"), b.getAttribute("data-name")); });
    });
    // --- Phase 12 bindings ---
    var smCreate = el("sm-create");
    if (smCreate) smCreate.addEventListener("click", onAddSite);
    var smRemove = el("sm-remove-btn");
    if (smRemove) smRemove.addEventListener("click", onRemoveSite);
    var osSave = el("os-save");
    if (osSave) osSave.addEventListener("click", onSaveSettings);
    var subSave = el("sub-save");
    if (subSave) subSave.addEventListener("click", onSavePlan);
  }

  // ---- Phase 12 actions ----------------------------------------------------
  function onAddSite() {
    var name = el("sm-name").value.trim();
    if (!name) { statusLine("Enter a site name.", true); return; }
    MG_AUTH.siteCreate(state.orgId, name, el("sm-loc").value.trim() || null, el("sm-county").value.trim() || null)
      .then(function () {
        statusLine("Site created.");
        el("sm-name").value = ""; el("sm-loc").value = ""; el("sm-county").value = "";
        refresh();
      }).catch(function (err) { statusLine((err && err.message) || "Create site failed.", true); });
  }

  function onRemoveSite() {
    var siteId = el("sm-remove").value;
    var s = state.sites.find(function (x) { return x.id === siteId; });
    if (!confirm("Remove site \"" + (s ? s.name : siteId) + "\"?\n\nThis is a soft delete — all safety records are preserved.")) return;
    MG_AUTH.siteRemove(siteId).then(function () {
      statusLine("Site removed (soft delete).");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Remove site failed.", true); });
  }

  function onSaveSettings() {
    var name = el("os-name").value.trim();
    var color = el("os-color").value;
    var branding = { name: name || (state.org && state.org.name) || null, primary_color: color };
    MG_AUTH.orgUpdateSettings(state.orgId, null, branding).then(function () {
      statusLine("Organization settings saved.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Save settings failed.", true); });
  }

  function onSavePlan() {
    var code = el("sub-plan").value;
    if (!code) return;
    if (!confirm("Change the organization plan to \"" + code + "\"?\n\nRecorded immediately; billing integration comes later.")) return;
    MG_AUTH.orgUpdateSubscription(state.orgId, code).then(function () {
      statusLine("Plan updated.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Plan change failed.", true); });
  }

  function onInvite() {
    var email = el("oi-email").value.trim();
    var role = el("oi-role").value;
    var siteId = el("oi-site").value || null;
    if (!email) { statusLine("Enter an email address to invite.", true); return; }
    setBusy(true, "oi-send");
    MG_AUTH.orgSendInvite(state.orgId, email, role, siteId).then(function (token) {
      setBusy(false, "oi-send");
      var box = el("oi-token");
      if (box) { box.style.display = "block"; el("oi-token-val").textContent = token || ""; }
      statusLine("Invite created for " + email + ".");
      el("oi-email").value = "";
      refresh();
    }).catch(function (err) {
      setBusy(false, "oi-send");
      statusLine((err && err.message) || "Invite failed.", true);
    });
  }

  function onRevokeInvite(inviteId) {
    if (!confirm("Revoke this pending invite?")) return;
    MG_AUTH.orgRevokeInvite(state.orgId, inviteId).then(function () {
      statusLine("Invite revoked.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Revoke failed.", true); });
  }

  function onChangeMemberRole(userId, role) {
    if (!role || !confirm("Change this member's role?")) return;
    MG_AUTH.orgUpdateMemberRole(state.orgId, userId, role).then(function () {
      statusLine("Role updated.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Role change failed.", true); });
  }

  function onRemoveMember(userId) {
    if (!confirm("Remove this member from the organization?\n\nThey will keep any site memberships? No — site memberships are withdrawn too.")) return;
    MG_AUTH.orgRemoveMember(state.orgId, userId).then(function () {
      statusLine("Member removed.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Remove failed.", true); });
  }

  function onAddUnit() {
    var type = el("ou-type").value;
    var siteId = el("ou-site").value;
    var parentId = el("ou-parent").value || null;
    var name = el("ou-name").value.trim();
    if (!name) { statusLine("Enter a unit name.", true); return; }
    if (parentId) {
      var parentOpt = document.querySelector('#ou-parent option[value="' + parentId + '"]');
      var parentSite = parentOpt && parentOpt.getAttribute("data-site");
      if (parentSite && parentSite !== siteId) { statusLine("Parent unit belongs to a different site.", true); return; }
    }
    MG_AUTH.orgCreateUnit(state.orgId, siteId, parentId, type, name, null).then(function () {
      statusLine("Unit added.");
      el("ou-name").value = "";
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Create unit failed.", true); });
  }

  function onAddWorker() {
    var name = el("w-name").value.trim();
    if (!name) { statusLine("Enter the worker's full name.", true); return; }
    MG_AUTH.workerAdd(state.orgId, {
      site_id: el("w-site").value || null,
      department_id: el("w-dept").value || null,
      employee_id: el("w-eid").value.trim() || null,
      full_name: name,
      classification: el("w-class").value
    }).then(function () {
      statusLine("Worker added to the registry.");
      el("w-name").value = ""; el("w-eid").value = "";
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Add worker failed.", true); });
  }

  function onRemoveWorker(workerId, name) {
    if (!confirm("Remove " + name + " from the worker registry? (soft delete)")) return;
    MG_AUTH.workerRemove(workerId).then(function () {
      statusLine("Worker removed.");
      refresh();
    }).catch(function (err) { statusLine((err && err.message) || "Remove failed.", true); });
  }

  function refresh() {
    if (state.orgId) {
      load(state.orgId).then(function () {
        var root = el("orgAdminRoot");
        if (root) { root.innerHTML = buildHtml(); bindEvents(); }
      }).catch(function (err) { statusLine((err && err.message) || "Refresh failed.", true); });
    } else {
      render();
    }
  }

  window.OrgAdmin = { render: render, refresh: refresh };
})();