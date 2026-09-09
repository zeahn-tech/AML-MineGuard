// ============================================================
// MINEGUARD — Offline Store (Phase 10: offline-first sync)
//
// IndexedDB-backed local database replacing localStorage-as-database
// (OFFLINE_SYNC_ARCHITECTURE.md §2.1):
//   outbox      — pending mutations (create/update/soft-delete)
//   records     — cached per-domain rows keyed by client_id
//                 (per-record sync state: pending/syncing/synced/
//                  error/conflict)
//   attachments — pending photo/video blobs + metadata
//   kv          — settings/preferences ONLY (never credentials,
//                 never authoritative data)
//
// Legacy localStorage datasets (mineguard_incidents/jsas/notices/
// sos_state) are migrated once into `records` with a stable
// clientId backfill (§2.8) — non-destructive: localStorage keys
// are left in place for the legacy Firebase readers.
//
// UMD: browser sets window.MG_STORE; Node probes may
// require() the module and inject a store object implementing the
// same async interface (used by scripts/verify-phase10.mjs).
// ============================================================
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();          // Node probe: factory returns class/interface
  } else {
    root.MG_STORE = factory();           // browser: window.MG_STORE
  }
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  var DB_NAME = "mineguard-offline-v1";
  var DB_VERSION = 1;
  var MIGRATION_KEY = "phase10.migration_v1";
  var LEGACY_KEYS = {
    incidents: "mineguard_incidents",
    jsas: "mineguard_jsas",
    notices: "mineguard_notices",
    emergency: "mineguard_sos_state"
  };

  // ---- stable client id (idempotency key) --------------------------------
  function newClientId(prefix) {
    var id = "";
    try {
      if (crypto && crypto.randomUUID) id = crypto.randomUUID();
    } catch (e) { /* fall through */ }
    if (!id) {
      id = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
        var r = (Math.random() * 16) | 0;
        var v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      });
    }
    return (prefix ? prefix + "-" : "") + id;
  }

  // deterministic stable id for a legacy record without one
  function legacyClientId(entity, rec) {
    var seed = (rec && (rec._id || rec.noticeId || rec.savedAt || rec.createdAt || rec.startedAt))
      || (entity + ":" + Math.random().toString(36).slice(2));
    var h = 0;
    for (var i = 0; i < String(seed).length; i++) {
      h = ((h << 5) - h + String(seed).charCodeAt(i)) | 0;
    }
    return "legacy-" + entity + "-" + Math.abs(h).toString(36);
  }

  // ---- IndexedDB implementation -----------------------------------------
  function openDb() {
    return new Promise(function (resolve, reject) {
      if (typeof indexedDB === "undefined") {
        reject(new Error("IndexedDB unavailable in this environment"));
        return;
      }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = req.result;
        if (!db.objectStoreNames.contains("outbox")) {
          var outbox = db.createObjectStore("outbox", { keyPath: "id" });
          outbox.createIndex("by_state", "state", { unique: false });
          outbox.createIndex("by_priority_created", ["priority", "created_at"], { unique: false });
        }
        if (!db.objectStoreNames.contains("records")) {
          var recs = db.createObjectStore("records", { keyPath: "client_id" });
          recs.createIndex("by_entity", "entity", { unique: false });
          recs.createIndex("by_sync_state", "sync_state", { unique: false });
        }
        if (!db.objectStoreNames.contains("attachments")) {
          var att = db.createObjectStore("attachments", { keyPath: "id" });
          att.createIndex("by_client_id", "client_id", { unique: false });
        }
        if (!db.objectStoreNames.contains("kv")) {
          db.createObjectStore("kv", { keyPath: "key" });
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function tx(db, storeName, mode, fn) {
    return new Promise(function (resolve, reject) {
      var t = db.transaction(storeName, mode);
      var out = fn(t.objectStore(storeName));
      t.oncomplete = function () { resolve(out && out.result !== undefined ? out.result : undefined); };
      t.onerror = function () { reject(t.error); };
      t.onabort = function () { reject(t.error || new Error("transaction aborted")); };
    });
  }

  var IndexedDBStore = function () {
    var dbPromise = null;
    function db() {
      if (!dbPromise) dbPromise = openDb();
      return dbPromise;
    }
    return {
      name: "indexeddb",
      kvGet: function (key) {
        return db().then(function (d) {
          return tx(d, "kv", "readonly", function (s) { return s.get(key); }).then(function (r) {
            return r ? r.value : undefined;
          });
        });
      },
      kvSet: function (key, value) {
        return db().then(function (d) {
          return tx(d, "kv", "readwrite", function (s) { return s.put({ key: key, value: value }); });
        });
      },
      outboxAdd: function (m) {
        return db().then(function (d) {
          return tx(d, "outbox", "readwrite", function (s) { return s.add(m); });
        });
      },
      outboxPut: function (m) {
        return db().then(function (d) {
          return tx(d, "outbox", "readwrite", function (s) { return s.put(m); });
        });
      },
      outboxRemove: function (id) {
        return db().then(function (d) {
          return tx(d, "outbox", "readwrite", function (s) { return s.delete(id); });
        });
      },
      outboxAll: function () {
        return db().then(function (d) {
          return tx(d, "outbox", "readonly", function (s) { return s.getAll(); }).then(function (rows) {
            return rows || [];
          });
        });
      },
      recordPut: function (rec) {
        return db().then(function (d) {
          return tx(d, "records", "readwrite", function (s) { return s.put(rec); });
        });
      },
      recordGet: function (clientId) {
        return db().then(function (d) {
          return tx(d, "records", "readonly", function (s) { return s.get(clientId); }).then(function (r) {
            return r || null;
          });
        });
      },
      recordsByEntity: function (entity) {
        return db().then(function (d) {
          return new Promise(function (resolve, reject) {
            var t = d.transaction("records", "readonly");
            var idx = t.objectStore("records").index("by_entity");
            var req = idx.getAll(entity);
            req.onsuccess = function () { resolve(req.result || []); };
            req.onerror = function () { reject(req.error); };
          });
        });
      },
      recordRemove: function (clientId) {
        return db().then(function (d) {
          return tx(d, "records", "readwrite", function (s) { return s.delete(clientId); });
        });
      },
      attachmentPut: function (a) {
        return db().then(function (d) {
          return tx(d, "attachments", "readwrite", function (s) { return s.put(a); });
        });
      },
      attachmentsByClient: function (clientId) {
        return db().then(function (d) {
          return new Promise(function (resolve, reject) {
            var t = d.transaction("attachments", "readonly");
            var idx = t.objectStore("attachments").index("by_client_id");
            var req = idx.getAll(clientId);
            req.onsuccess = function () { resolve(req.result || []); };
            req.onerror = function () { reject(req.error); };
          });
        });
      },
      attachmentRemove: function (id) {
        return db().then(function (d) {
          return tx(d, "attachments", "readwrite", function (s) { return s.delete(id); });
        });
      },
      clearAll: function () {
        return db().then(function (d) {
          return Promise.all(["outbox", "records", "attachments", "kv"].map(function (st) {
            return tx(d, st, "readwrite", function (s) { return s.clear(); });
          }));
        });
      }
    };
  };

  // ---- legacy localStorage migration (§2.8) ------------------------------
  // Idempotent: guarded by kv flag. Non-destructive: legacy keys remain for
  // the Firebase readers; backfilled records carry sync_state 'pending' so the
  // engine can offer to sync legacy device data once signed in.
  function migrateLocalStorage(store) {
    return store.kvGet(MIGRATION_KEY).then(function (done) {
      if (done) return { migrated: false, records: 0 };
      var put = [];
      Object.keys(LEGACY_KEYS).forEach(function (entity) {
        var key = LEGACY_KEYS[entity];
        var raw = null;
        try { raw = JSON.parse(localStorage.getItem(key) || "null"); } catch (e) { raw = null; }
        if (!raw) return;
        var list = Array.isArray(raw) ? raw : [raw];
        list.forEach(function (rec) {
          if (!rec || typeof rec !== "object") return;
          var clientId = rec.client_id || rec.clientId || legacyClientId(entity, rec);
          put.push({
            client_id: clientId,
            entity: entity,
            data: rec,
            sync_state: "pending",
            updated_at: rec.updatedAt || rec.updated_at || rec.savedAt || rec.createdAt || new Date().toISOString(),
            updated_by: null,
            synced_at: null,
            migrated: true
          });
        });
      });
      var chain = Promise.resolve();
      put.forEach(function (rec) {
        chain = chain.then(function () { return store.recordPut(rec); });
      });
      return chain.then(function () {
        return store.kvSet(MIGRATION_KEY, { at: new Date().toISOString(), records: put.length });
      }).then(function () {
        return { migrated: true, records: put.length };
      });
    });
  }

  return {
    newClientId: newClientId,
    legacyClientId: legacyClientId,
    IndexedDBStore: IndexedDBStore,
    migrateLocalStorage: migrateLocalStorage,
    createDefault: function () { return IndexedDBStore(); }
  };
});