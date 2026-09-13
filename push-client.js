// ============================================================
// MINEGUARD — Web Push subscription client (session 21)
// push-client.js — subscribes the browser to Web Push and registers the
// subscription with the server (push_subscriptions via
// register_push_subscription / deregister_push_subscription).
//
// Architecture notes:
//   * In-app notifications (notifications table + bell) remain the
//     AUTHORITATIVE channel; this module is an additional delivery mechanism.
//     Failure here must never block join requests or approvals.
//   * No VAPID key is shipped yet: without one, browsers cannot create a push
//     subscription, so the module degrades to a no-op (server-side store and
//     SW push handler are already live; when a VAPID key is provisioned in
//     config.js (VAPID_PUBLIC_KEY), delivery needs no further schema work).
//   * Auth: the server derives the user from auth.uid(); the client never
//     sends a user id.
// UMD: window.MG_PUSH; included after supabase-auth.js on both pages.
// ============================================================
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.MG_PUSH = factory();
  }
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  function config() { return (typeof window !== "undefined") ? window.MG_CONFIG : null; }
  function auth() { return (typeof window !== "undefined") ? window.MG_AUTH : null; }

  function vapidKey() {
    var c = config();
    return c && c.VAPID_PUBLIC_KEY ? String(c.VAPID_PUBLIC_KEY) : null;
  }

  function supported() {
    return typeof window !== "undefined" &&
      "serviceWorker" in navigator &&
      "PushManager" in window &&
      "Notification" in window;
  }

  function urlBase64ToUint8Array(base64String) {
    var padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    var base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
    var raw = atob(base64);
    var arr = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  }

  // Subscribe (or refresh) the current browser profile for the signed-in user.
  // Resolves true when subscribed; false when unavailable/not configured —
  // NEVER rejects for expected environmental reasons (permission denied,
  // no VAPID key, unsupported browser). Unexpected errors are swallowed with
  // a console warning: push must not break the flows it decorates.
  async function subscribe() {
    try {
      if (!supported()) return false;
      var key = vapidKey();
      if (!key) return false; // push sender not provisioned yet — graceful no-op
      if (Notification.permission !== "granted") {
        var perm = await Notification.requestPermission();
        if (perm !== "granted") return false;
      }
      var reg = await navigator.serviceWorker.ready;
      var existing = await reg.pushManager.getSubscription();
      var sub = existing || await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(key)
      });
      var j = sub.toJSON();
      if (!j.endpoint || !j.keys || !j.keys.p256dh || !j.keys.auth) return false;
      var a = auth();
      if (!a || !a.registerPushSubscription) return false;
      await a.registerPushSubscription(j.endpoint, j.keys.p256dh, j.keys.auth, navigator.userAgent);
      return true;
    } catch (e) {
      console.warn("[MineGuard] push subscribe skipped:", e && e.message);
      return false;
    }
  }

  // Remove this browser profile's registration (e.g. on disable/sign-out).
  async function unsubscribe() {
    try {
      if (!supported()) return false;
      var reg = await navigator.serviceWorker.ready;
      var sub = await reg.pushManager.getSubscription();
      var a = auth();
      if (a && a.deregisterPushSubscription && sub && sub.endpoint) {
        await a.deregisterPushSubscription(sub.endpoint).catch(function () {});
      }
      if (sub) await sub.unsubscribe();
      return true;
    } catch (e) {
      console.warn("[MineGuard] push unsubscribe skipped:", e && e.message);
      return false;
    }
  }

  return { subscribe: subscribe, unsubscribe: unsubscribe, supported: supported };
});
