// ============================================
// MINEGUARD SERVICE WORKER v9
// Fixes: added admin.html, aml-logo, icons,
//        activate/cache-cleanup, skipWaiting,
//        offline navigation fallback
// ============================================

const CACHE_NAME = 'mineguard-v13';
const FIREBASE_PROJECT_ID = 'aml-mineguard';
const FIREBASE_API_KEY = 'AIzaSyCPqKNe7zyTfBqLT6Gh7Cx2-f7jSf1gvTg';
const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents`;
const SOS_COLLECTION = 'emergency_sos';

const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './admin.html',
  './style.css',
  './app.js',
  './data.js',
  './lang.js',
  './firebase.js',
  './notices.js',
  './config.js',
  './supabase-auth.js',
  './auth-gate.js',
  './auth-ui.js',
  './org-admin.js',
  './gov-admin.js',
  './offline-store.js',
  './sync-engine.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/aml-logo.jpg',
];

async function fetchLatestSOSState() {
  try {
    const url = `${FIRESTORE_BASE}:runQuery?key=${FIREBASE_API_KEY}`;
    const body = JSON.stringify({
      structuredQuery: {
        from: [{ collectionId: SOS_COLLECTION }],
        orderBy: [{ field: { fieldPath: 'createdAt' }, direction: 'DESCENDING' }],
        limit: 10
      }
    });
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body
    });
    if (!resp.ok) return null;
    const results = await resp.json();
    if (!Array.isArray(results)) return null;
    const doc = results.find(r => r.document && !r.document.fields?.deleted?.booleanValue) || null;
    if (!doc || !doc.document) return null;
    const fields = doc.document.fields || {};
    const unpack = value => {
      if (!value || typeof value !== 'object') return null;
      if ('nullValue' in value) return null;
      if ('booleanValue' in value) return value.booleanValue;
      if ('integerValue' in value) return parseInt(value.integerValue, 10);
      if ('doubleValue' in value) return value.doubleValue;
      if ('stringValue' in value) return value.stringValue;
      if ('arrayValue' in value) return (value.arrayValue.values || []).map(unpack);
      if ('mapValue' in value) return Object.fromEntries(Object.entries(value.mapValue.fields || {}).map(([k, v]) => [k, unpack(v)]));
      return null;
    };
    const state = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, unpack(v)]));
    state._id = doc.document.name.split('/').pop();
    return state;
  } catch (e) {
    console.warn('[SW] SOS fetch failed:', e.message);
    return null;
  }
}

async function showSosNotification(state) {
  if (!state || !state.active) return;
  const title = '🚨 Emergency SOS Active';
  const options = {
    body: state.message || 'An emergency alert has been activated. Open MineGuard immediately.',
    icon: './icons/icon-192.png',
    badge: './icons/icon-192.png',
    tag: 'mineguard-sos-' + (state._id || state.startedAt || 'active'),
    renotify: true,
    requireInteraction: true,
    vibrate: [500, 200, 500, 200, 800],
    actions: [
      { action: 'open', title: 'Open Alert' },
      { action: 'ack', title: 'Acknowledge' }
    ],
    data: { url: './index.html?tab=emergency' }
  };
  await self.registration.showNotification(title, options);
}

async function pollEmergencySOSAndNotify() {
  const state = await fetchLatestSOSState();
  if (!state) return;
  if (!state.active) return;
  await showSosNotification(state);
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  clients.forEach(client => {
    client.postMessage({ type: 'sos-state', state });
  });
}

// ---- INSTALL ----
self.addEventListener('install', event => {
  console.log('[MineGuard SW v10] Installing...');
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      // Add files one by one — one failure won't block the rest
      return Promise.allSettled(
        ASSETS_TO_CACHE.map(url =>
          cache.add(url).catch(err =>
            console.warn('[SW v9] Could not cache:', url, err.message)
          )
        )
      );
    }).then(() => {
      console.log('[MineGuard SW v10] Assets cached');
    })
  );
  // Take control immediately without waiting for old SW to unload
  self.skipWaiting();
});

// ---- ACTIVATE ----
self.addEventListener('activate', event => {
  console.log('[MineGuard SW v10] Activating, cleaning old caches...');
  event.waitUntil(
    caches.keys().then(cacheNames =>
      Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME)
          .map(name => {
            console.log('[MineGuard SW v10] Deleting old cache:', name);
            return caches.delete(name);
          })
      )
    )
  );
  // Immediately claim all open clients
  self.clients.claim();
});

self.addEventListener('periodicsync', event => {
  if (event.tag === 'mineguard-sos-poll') {
    event.waitUntil(pollEmergencySOSAndNotify());
  }
});

self.addEventListener('sync', event => {
  if (event.tag === 'mineguard-sos-poll') {
    event.waitUntil(pollEmergencySOSAndNotify());
  }
  if (event.tag === 'mineguard-sync-drain') {
    // Best-effort: tell open clients the network is back so the
    // sync engine can drain its outbox (Phase 10).
    event.waitUntil(
      self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
        clients.forEach(c => c.postMessage({ type: 'sync-drain' }));
      })
    );
  }
});

// Phase 10 — offline sync queue messaging. Pages post 'sync-enqueue' after
// a write so the SW can register a background sync tag; the SW answers with
// 'sync-drain' so clients drain their outboxes when connectivity returns.
self.addEventListener('message', event => {
  if (!event.data) return;
  if (event.data.type === 'sync-enqueue') {
    if ('sync' in self.registration) {
      self.registration.sync.register('mineguard-sync-drain').catch(() => {});
    }
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      clients.forEach(c => c.postMessage({ type: 'sync-drain' }));
    });
  }
});

self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { body: event.data ? event.data.text() : '' };
  }
  if (!data || !data.title) return;
  event.waitUntil(self.registration.showNotification(data.title, {
    body: data.body || '',
    icon: './icons/icon-192.png',
    badge: './icons/icon-192.png',
    requireInteraction: true,
    vibrate: [500, 200, 500, 200, 800],
    data: data.data || {}
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification && event.notification.data && event.notification.data.url) || './index.html?tab=emergency';
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of clients) {
      if ('focus' in client) {
        await client.focus();
        try { client.postMessage({ type: 'open-tab', tab: 'emergency' }); } catch (e) {}
        return;
      }
    }
    await self.clients.openWindow(targetUrl);
  })());
});

// ---- FETCH ----
self.addEventListener('fetch', event => {
  // Only handle GET requests
  if (event.request.method !== 'GET') return;
  // Skip non-http requests (chrome-extension etc.)
  if (!event.request.url.startsWith('http')) return;
  // Skip Firestore API calls — always go to network
  if (event.request.url.includes('firestore.googleapis.com')) return;
  // Skip Google Fonts — they have their own cache headers
  if (event.request.url.includes('fonts.googleapis.com') ||
      event.request.url.includes('fonts.gstatic.com')) return;

  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      // Serve from cache if available
      if (cachedResponse) return cachedResponse;

      // Otherwise try network
      return fetch(event.request).then(networkResponse => {
        // Cache valid same-origin responses for future offline use
        if (
          networkResponse &&
          networkResponse.status === 200 &&
          networkResponse.type !== 'opaque'
        ) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      }).catch(() => {
        // Network failed — serve offline fallback for page navigations
        if (event.request.mode === 'navigate') {
          // admin.html requested offline — serve from cache
          if (event.request.url.includes('admin.html')) {
            return caches.match('./admin.html').then(r => r || caches.match('./index.html'));
          }
          return caches.match('./index.html');
        }
        // For images that fail offline, return a transparent 1×1 pixel
        if (event.request.destination === 'image') {
          return new Response(
            '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>',
            { headers: { 'Content-Type': 'image/svg+xml' } }
          );
        }
        return new Response('Offline', { status: 503 });
      });
    })
  );
});
