// ============================================================
// MINEGUARD — Offline Sync Engine (Phase 10)
//
// Implements OFFLINE_SYNC_ARCHITECTURE.md §2.2–§2.7:
//   * outbox queue drained FIFO, EMERGENCY priority first
//   * exponential backoff + max-attempt cap; failures surfaced
//     (never silent)
//   * client_id idempotency: retries cannot duplicate rows —
//     server unique indexes (Phase 07–09 client_id columns) turn
//     a duplicate POST into 409 → treated as already-synced
//   * conflict handling: updates compare server updated_at vs
//     local updated_at; never silently overwrite safety data
//   * per-record sync states: pending → syncing → synced |
//     error | conflict (records store)
//   * attachment sync: photo blobs → incident-evidence storage
//     (X-Upsert idempotent) → incident_evidence rows
//   * connectivity heartbeat + reconnect drain
//
// Payload adapters map the legacy app's form shapes (incident,
// jsa, SOS activation) to the Phase 07–09 target columns — a
// client-side subset of the Phase 05 mapper.
//
// UMD: browser exposes window.MG_SYNC; Node probes require() the
// module and inject {store, transport, auth} to run the real
// engine against the live project (scripts/verify-phase10.mjs).
// ============================================================
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.MG_SYNC = factory();
  }
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  // `root` is NOT a parameter of this factory — rebind it for the same
  // environment resolution the UMD wrapper used (window in browsers,
  // globalThis in Node probes).
  var root = typeof self !== "undefined" ? self : globalThis;

  var MAX_ATTEMPTS = 8;
  var BACKOFF_BASE_MS = 2000;
  var BACKOFF_CAP_MS = 60000;
  var EMERGENCY_ENTITIES = ["emergency_events", "emergency_acknowledgements"];

  // ---- payload adapters (legacy app shape → target columns) --------------
  // Mirrors scripts/phase05-map.mjs field mapping for client-generated rows.
  var ADAPTERS = {
    incidents: function (src, ctx) {
      var severity = String(src.severity || "low").toLowerCase();
      if (["low", "medium", "high", "critical"].indexOf(severity) < 0) severity = "low";
      var status = String(src.status || "SUBMITTED").toUpperCase();
      if (status === "OPEN") status = "SUBMITTED";
      if (status === "RESOLVED") status = "RESOLVED";
      return {
        organization_id: ctx.organization_id,
        site_id: ctx.site_id || null,
        client_id: src.client_id,
        reported_by_name: src.name || src.reported_by_name || null,
        badge: src.badge || null,
        dept_text: src.dept || null,
        incident_type: src.type || src.incident_type || "other",
        severity: severity,
        status: status,
        incident_datetime: src.datetime ? new Date(src.datetime).toISOString() : null,
        location_text: src.location || src.location_text || null,
        description: src.description || "",
        immediate_action: src.action || null,
        witnesses_text: Array.isArray(src.witnesses) ? src.witnesses.join("; ") : (src.witnesses || null),
        lang: src.lang || "en",
        saved_at: src.savedAt ? new Date(src.savedAt).toISOString() : null,
        site_notice_scope: src.site_notice_scope === true,
        deleted: false
      };
    },
    jsas: function (src, ctx) {
      return {
        organization_id: ctx.organization_id,
        site_id: ctx.site_id || null,
        client_id: src.client_id,
        reported_by_name: src.worker || src.reported_by_name || null,
        worker_text: src.worker || null,
        supervisor_text: src.supervisor || null,
        task: src.task || "Untitled task",
        location_text: src.location || src.location_text || null,
        date: src.date || null,
        lang: src.lang || "en",
        ppe: Array.isArray(src.ppeSelected) ? src.ppeSelected : (Array.isArray(src.ppe) ? src.ppe : []),
        status: "SUBMITTED",
        deleted: false
      };
    },
    emergency_events: function (src, ctx) {
      var active = src.active === true;
      var closed = !active || src.deactivatedAt != null || src.endedBy != null;
      return {
        organization_id: ctx.organization_id,
        site_id: ctx.site_id || null,
        client_id: src.client_id,
        category: src.category || null,
        message: src.message || null,
        contact_number: src.contactNumber || null,
        assembly_point: src.assemblyPoint || null,
        activated_by_text: src.activatedBy || null,
        ended_by_text: src.endedBy || null,
        started_at: src.startedAt ? new Date(src.startedAt).toISOString() : null,
        deactivated_at: src.deactivatedAt ? new Date(src.deactivatedAt).toISOString() : null,
        duration_seconds: typeof src.durationSeconds === "number" ? src.durationSeconds : null,
        status: active ? "ACTIVATED" : (closed ? "RESOLVED" : "ACTIVATED"),
        notified_workers_legacy: typeof src.notifiedWorkers === "number" ? src.notifiedWorkers : null,
        deleted: false
      };
    },
    emergency_acknowledgements: function (src, ctx) {
      return {
        event_id: src.event_id,
        note: src.note || null,
        channel: src.channel || "app",
        client_id: src.client_id
      };
    }
  };

  // ---- PostgREST transport (session token; RLS is the boundary) ----------
  function postgrestTransport(opts) {
    var cfg = opts || {};
    function base() {
      return (cfg.url || (root.MG_CONFIG && root.MG_CONFIG.supabaseUrl) || "").replace(/\/+$/, "");
    }
    function anon() {
      return cfg.anonKey || (root.MG_CONFIG && root.MG_CONFIG.supabaseAnonKey) || "";
    }
    function token() {
      if (cfg.token) return cfg.token;
      if (root.MG_AUTH && root.MG_AUTH.getSession) {
        var s = root.MG_AUTH.getSession();
        return s && s.access_token ? s.access_token : null;
      }
      return null;
    }
    function headers(extra) {
      var h = { apikey: anon(), "Content-Type": "application/json", Accept: "application/json" };
      var t = token();
      if (t) h.Authorization = "Bearer " + t;
      if (extra) Object.assign(h, extra);
      return h;
    }
    // INSERT without Prefer (Phase 07 finding: return=representation +
    // RLS re-checks SELECT on RETURNING → 42501).
    function insert(entity, payload) {
      return fetch(base() + "/rest/v1/" + entity, {
        method: "POST", headers: headers(), body: JSON.stringify(payload)
      }).then(function (r) {
        return r.text().then(function (text) { return { status: r.status, body: text }; });
      });
    }
    function selectByClientId(entity, clientId) {
      return fetch(base() + "/rest/v1/" + entity + "?client_id=eq." + encodeURIComponent(clientId) + "&select=id,updated_at,status", {
        headers: headers()
      }).then(function (r) { return r.json().then(function (d) { return { status: r.status, rows: d }; }); });
    }
    function update(entity, clientId, payload) {
      return fetch(base() + "/rest/v1/" + entity + "?client_id=eq." + encodeURIComponent(clientId), {
        method: "PATCH", headers: headers(), body: JSON.stringify(payload)
      }).then(function (r) {
        return r.text().then(function (text) { return { status: r.status, body: text }; });
      });
    }
    function ping() {
      return fetch(base() + "/rest/v1/", { headers: headers() })
        .then(function () { return true; })
        .catch(function () { return false; });
    }
    return { insert: insert, selectByClientId: selectByClientId, update: update, ping: ping };
  }

  // ---- engine ------------------------------------------------------------
  function createEngine(opts) {
    var store = (opts && opts.store) || null;
    var transport = (opts && opts.transport) || postgrestTransport(opts);
    var auth = (opts && opts.auth) || (root.MG_AUTH || null);
    var listeners = [];
    var contextCache = null;   // {organization_id, site_id, user_id}
    var draining = false;
    var lastSummary = { pending: 0, syncing: 0, synced: 0, error: 0, conflict: 0 };
    var heartbeatTimer = null;

    function emit() {
      listeners.forEach(function (fn) { try { fn(lastSummary); } catch (e) {} });
      try {
        root.dispatchEvent(new CustomEvent("mg-sync-change", { detail: lastSummary }));
      } catch (e) { /* older browsers */ }
    }
    function onChange(fn) {
      listeners.push(fn);
      return function () {
        var i = listeners.indexOf(fn);
        if (i >= 0) listeners.splice(i, 1);
      };
    }

    // Resolve org/site scope from memberships (RLS-filtered reads).
    function resolveContext(force) {
      if (contextCache && !force) return Promise.resolve(contextCache);
      function read(path) {
        var url = ((opts && opts.url) || (root.MG_CONFIG && root.MG_CONFIG.supabaseUrl) || "").replace(/\/+$/, "");
        var anonKey = (opts && opts.anonKey) || (root.MG_CONFIG && root.MG_CONFIG.supabaseAnonKey) || "";
        var t = null;
        if (opts && opts.token) t = opts.token;
        else if (auth && auth.getSession) { var s = auth.getSession(); t = s && s.access_token; }
        if (!t) return Promise.resolve(null);
        return fetch(url + path, {
          headers: { apikey: anonKey, Authorization: "Bearer " + t, Accept: "application/json" }
        }).then(function (r) { return r.json(); }).catch(function () { return null; });
      }
      return read("/rest/v1/organization_members?select=organization_id,user_id,role,status&status=eq.active&order=created_at.asc")
        .then(function (members) {
          if (!Array.isArray(members) || !members.length) return null;
          var org = members[0];
          return read("/rest/v1/site_members?select=site_id,organization_id,status&status=eq.active&organization_id=eq." + encodeURIComponent(org.organization_id) + "&order=created_at.asc")
            .then(function (sites) {
              var siteId = null;
              if (Array.isArray(sites) && sites.length) siteId = sites[0].site_id || null;
              contextCache = { organization_id: org.organization_id, site_id: siteId, user_id: org.user_id };
              return contextCache;
            });
        })
        .catch(function () { return null; });
    }

    function adapterFor(entity) { return ADAPTERS[entity] || null; }

    function stateOf(m) {
      return m.state || (m.attempts > 0 ? "syncing" : "pending");
    }

    function backoffMs(m) {
      var n = Math.min(Math.pow(2, m.attempts), BACKOFF_CAP_MS / BACKOFF_BASE_MS);
      return Math.min(BACKOFF_BASE_MS * n, BACKOFF_CAP_MS);
    }

    // Dedupe on (entity, client_id, op): a retry tap never queues twice.
    function enqueue(entity, op, payload, opts2) {
      var o = opts2 || {};
      if (!store) return Promise.reject(new Error("MG_SYNC: no store configured"));
      var priority = o.priority || (EMERGENCY_ENTITIES.indexOf(entity) >= 0 ? 100 : 0);
      var nowIso = new Date().toISOString();
      return store.outboxAll().then(function (rows) {
        var existing = (rows || []).find(function (r) {
          return r.entity === entity && r.client_id === payload.client_id && r.op === op;
        });
        var m;
        if (existing) {
          m = Object.assign({}, existing, { payload: payload, updated_at: nowIso, state: "pending", error: null });
          return store.outboxPut(m).then(function () { return m; });
        }
        m = {
          id: store.newClientId ? store.newClientId("outbox") : Math.random().toString(36).slice(2),
          entity: entity,
          op: op || "insert",
          client_id: payload.client_id,
          payload: payload,
          priority: priority,
          attempts: 0,
          next_attempt_at: nowIso,
          state: "pending",
          error: null,
          created_at: nowIso,
          updated_at: nowIso
        };
        return store.outboxAdd(m).then(function () { return m; });
      }).then(function (m) {
        refreshSummary();
        kick();
        return m;
      });
    }

    // One mutation: insert/update with idempotency + conflict handling.
    function executeMutation(m) {
      var adapter = adapterFor(m.entity);
      if (!adapter) {
        m.state = "error"; m.error = "no adapter for " + m.entity;
        return store.outboxPut(m).then(function () { return { ok: false }; });
      }
      // Mark syncing + persist before the network call (crash-safe).
      m.state = "syncing";
      return store.outboxPut(m).then(function () {
        if (m.op === "insert") {
          return transport.insert(m.entity, m.payload).then(function (r) {
            if (r.status === 201) {
              // re-select by client_id to capture the server id (no Prefer)
              return transport.selectByClientId(m.entity, m.client_id).then(function (sel) {
                var row = Array.isArray(sel.rows) && sel.rows.length ? sel.rows[0] : null;
                return { ok: true, serverRow: row, status: 201 };
              });
            }
            if (r.status === 409 || r.status === 400) {
              // duplicate client_id (unique index) → already synced; treat
              // as success. Verify the row exists to be safe.
              return transport.selectByClientId(m.entity, m.client_id).then(function (sel) {
                var row = Array.isArray(sel.rows) && sel.rows.length ? sel.rows[0] : null;
                if (row) return { ok: true, serverRow: row, status: 409 };
                // 400 not caused by dup? surface as retryable error
                return { ok: false, status: r.status, body: r.body };
              });
            }
            return { ok: false, status: r.status, body: r.body };
          });
        }
        if (m.op === "update" || m.op === "soft_delete") {
          // conflict check first: never silently overwrite newer server data
          return transport.selectByClientId(m.entity, m.client_id).then(function (sel) {
            var serverRow = Array.isArray(sel.rows) && sel.rows.length ? sel.rows[0] : null;
            if (!serverRow) return { ok: false, status: 404, body: "row not found" };
            var serverTs = serverRow.updated_at ? Date.parse(serverRow.updated_at) : 0;
            var localTs = m.payload.updated_at ? Date.parse(m.payload.updated_at) : 0;
            if (serverTs > localTs) {
              m.state = "conflict"; m.error = "server row is newer (updated_at) — not overwritten";
              return store.outboxPut(m).then(function () { return { ok: false, conflict: true }; });
            }
            var body = Object.assign({}, m.payload);
            if (m.op === "soft_delete") Object.assign(body, { deleted: true, deleted_at: new Date().toISOString() });
            return transport.update(m.entity, m.client_id, body).then(function (r) {
              if (r.status === 204 || r.status === 200) return { ok: true, serverRow: serverRow, status: r.status };
              return { ok: false, status: r.status, body: r.body };
            });
          });
        }
        m.state = "error"; m.error = "unsupported op " + m.op;
        return store.outboxPut(m).then(function () { return { ok: false }; });
      });
    }

    // Drain the queue: emergency priority first, then FIFO by created_at.
    // Respects backoff (next_attempt_at). Stops on network failure (whole
    // batch retries later per-mutation backoff).
    function drain() {
      if (draining) return Promise.resolve();
      draining = true;
      return store.outboxAll().then(function (rows) {
        var now = new Date();
        var ready = (rows || []).filter(function (m) {
          return m.state !== "error" && m.state !== "conflict"
            && (!m.next_attempt_at || new Date(m.next_attempt_at) <= now);
        });
        ready.sort(function (a, b) {
          if (b.priority !== a.priority) return b.priority - a.priority;
          return String(a.created_at).localeCompare(String(b.created_at));
        });
        var chain = Promise.resolve();
        var networkDown = false;
        ready.forEach(function (m) {
          chain = chain.then(function () {
            if (networkDown) return null;
            return executeMutation(m).then(function (res) {
              if (res && res.ok) {
                // synced: move to records with sync_state, drop from outbox
                var rec = {
                  client_id: m.client_id,
                  entity: m.entity,
                  data: m.payload,
                  sync_state: "synced",
                  server_id: (res.serverRow && res.serverRow.id) || null,
                  updated_at: m.payload.updated_at || m.updated_at,
                  updated_by: null,
                  synced_at: new Date().toISOString()
                };
                return store.recordPut(rec).then(function () { return store.outboxRemove(m.id); });
              }
              if (res && res.conflict) return null;
              // retryable? network/5xx/429 → backoff; authz 4xx → error
              var status = res ? res.status : 0;
              if (!res || status === 0 || status >= 500 || status === 429 || status === 404) {
                m.attempts = (m.attempts || 0) + 1;
                m.next_attempt_at = new Date(Date.now() + backoffMs(m)).toISOString();
                if (m.attempts >= MAX_ATTEMPTS) {
                  m.state = "error"; m.error = "max attempts reached (" + status + ")";
                } else {
                  m.state = "pending";
                }
                m.last_error = res && res.body ? String(res.body).slice(0, 200) : ("HTTP " + status);
                if (status === 0) networkDown = true;
                return store.outboxPut(m);
              }
              // 4xx (authz/validation) — surface, don't retry blindly
              m.state = "error"; m.error = String((res && res.body) || ("HTTP " + status)).slice(0, 200);
              return store.outboxPut(m);
            }).catch(function (err) {
              // transport threw (network down, DNS, fetch abort) — apply
              // backoff + mark the batch as network-down; never strand a
              // mutation in 'syncing' without a retry budget.
              m.attempts = (m.attempts || 0) + 1;
              m.next_attempt_at = new Date(Date.now() + backoffMs(m)).toISOString();
              if (m.attempts >= MAX_ATTEMPTS) {
                m.state = "error"; m.error = "max attempts reached (network)";
              } else {
                m.state = "pending";
              }
              m.last_error = String((err && err.message) || err).slice(0, 200);
              networkDown = true;
              return store.outboxPut(m);
            });
          });
        });
        return chain;
      }).then(function () {
        refreshSummary();
        emit();
        draining = false;
      }).catch(function (e) {
        draining = false;
        refreshSummary();
        emit();
      });
    }

    // Upload pending attachments for a synced incident row (storage + evidence).
    function syncAttachments(entity, clientId, serverId, ctx) {
      return store.attachmentsByClient(clientId).then(function (atts) {
        if (!atts || !atts.length) return Promise.resolve();
        var url = ((opts && opts.url) || (root.MG_CONFIG && root.MG_CONFIG.supabaseUrl) || "").replace(/\/+$/, "");
        var anonKey = (opts && opts.anonKey) || (root.MG_CONFIG && root.MG_CONFIG.supabaseAnonKey) || "";
        function token() {
          if (opts && opts.token) return opts.token;
          if (auth && auth.getSession) { var s = auth.getSession(); return s && s.access_token; }
          return null;
        }
        var chain = Promise.resolve();
        atts.forEach(function (att) {
          chain = chain.then(function () {
            // X-Upsert: idempotent overwrite on retry
            var path = "organizations/" + ctx.organization_id + "/sites/" + (ctx.site_id || "unassigned") +
              "/incidents/" + clientId + "/" + (att.filename || "photo.jpg");
            return fetch(url + "/storage/v1/object/incident-evidence/" + path, {
              method: "POST",
              headers: {
                apikey: anonKey,
                Authorization: "Bearer " + token(),
                "Content-Type": att.content_type || "image/jpeg",
                "X-Upsert": "true"
              },
              body: att.blob
            }).then(function (r) {
              if (r.status !== 200 && r.status !== 201) {
                return store.attachmentPut(Object.assign({}, att, { sync_state: "error" }));
              }
              return store.attachmentPut(Object.assign({}, att, { sync_state: "synced", storage_path: path })).then(function () {
                return transport.insert("incident_evidence", {
                  incident_id: serverId,
                  storage_path: path,
                  kind: att.kind || "photo",
                  content_type: att.content_type || "image/jpeg",
                  size_bytes: att.blob ? att.blob.size : null,
                  captured_at: att.captured_at || new Date().toISOString()
                });
              });
            });
          });
        });
        return chain;
      });
    }

    function refreshSummary() {
      return store.outboxAll().then(function (rows) {
        var summary = { pending: 0, syncing: 0, synced: 0, error: 0, conflict: 0 };
        (rows || []).forEach(function (m) {
          var st = m.state || "pending";
          if (summary[st] !== undefined) summary[st] += 1; else summary.pending += 1;
        });
        lastSummary = summary;
        return summary;
      }).catch(function () { return lastSummary; });
    }

    function getStatus() {
      return refreshSummary().then(function (s) {
        return Object.assign({}, s, { context: contextCache, online: !!(root.MG && root.MG.online) });
      });
    }

    function kick() {
      // debounce: let the current call stack settle before draining
      setTimeout(function () {
        if (root.MG && root.MG.online) drain();
        else drain(); // drain is idempotent; transport failures back off
      }, 50);
    }

    function startHeartbeat(intervalMs) {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(function () {
        if (root.MG && root.MG.online === false) return;
        transport.ping().then(function (ok) {
          if (ok && root.MG && root.MG.online === false) { /* offline → online */ }
          if (ok) drain();
        });
      }, intervalMs || 30000);
    }

    function wireConnectivity() {
      function onOnline() { if (root.MG) root.MG.online = true; kick(); }
      root.addEventListener("online", onOnline);
      root.addEventListener("mg-connectivity-change", function (e) {
        if (e.detail && e.detail.online) kick();
      });
      return function () {
        root.removeEventListener("online", onOnline);
        if (heartbeatTimer) clearInterval(heartbeatTimer);
      };
    }

    function init() {
      resolveContext(false).then(function () {
        refreshSummary().then(emit);
        if (root.MG && root.MG.online !== false) kick();
      });
    }

    // convenience: adapt + enqueue a legacy-format payload
    function submit(entity, op, srcPayload, opts2) {
      return resolveContext().then(function (ctx) {
        if (!ctx || !ctx.organization_id) {
          return Promise.reject(new Error("MG_SYNC: no org context (sign in first)"));
        }
        var adapter = adapterFor(entity);
        var clientId = srcPayload.client_id || (store.newClientId ? store.newClientId() : null);
        var adapted = adapter
          ? adapter(Object.assign({}, srcPayload, { client_id: clientId }), ctx)
          : Object.assign({}, srcPayload, { client_id: clientId });
        adapted.updated_at = new Date().toISOString();
        return enqueue(entity, op || "insert", adapted, opts2).then(function (m) {
          return { client_id: clientId, mutation: m, context: ctx };
        });
      });
    }

    return {
      init: init,
      enqueue: enqueue,
      submit: submit,
      drain: drain,
      onChange: onChange,
      getStatus: getStatus,
      resolveContext: resolveContext,
      adapterFor: adapterFor,
      syncAttachments: syncAttachments,
      startHeartbeat: startHeartbeat,
      wireConnectivity: wireConnectivity,
      adapters: ADAPTERS,
      constants: { MAX_ATTEMPTS: MAX_ATTEMPTS, BACKOFF_BASE_MS: BACKOFF_BASE_MS, BACKOFF_CAP_MS: BACKOFF_CAP_MS },
      _state: function () { return lastSummary; }
    };
  }

  return { createEngine: createEngine, postgrestTransport: postgrestTransport, adapters: ADAPTERS };
});