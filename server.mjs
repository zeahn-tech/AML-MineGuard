// ============================================================
// MINEGUARD — static dev server (development/preview only)
// Serves the vanilla HTML/CSS/JS app from the repository root.
// Dependency-free (node:http). NOT for production use.
//
// Usage:  node server.mjs [-p <port>] [-H <host>]
// The Freebuff preview injects `-p <port> -H 0.0.0.0`; the
// PORT environment variable is honored as a fallback.
// ============================================================

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = fileURLToPath(new URL(".", import.meta.url));

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
  ".apk": "application/vnd.android.package-archive",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".woff2": "font/woff2",
};

function parseArgs(argv) {
  let port = 3000;
  let host = "0.0.0.0";
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-p" || arg === "--port") port = Number(argv[++i]);
    else if (arg === "-H" || arg === "--host") host = argv[++i];
    else if (arg.startsWith("--port=")) port = Number(arg.split("=")[1]);
    else if (arg.startsWith("--host=")) host = arg.split("=")[1];
  }
  if (process.env.PORT) {
    const envPort = Number(process.env.PORT);
    if (Number.isFinite(envPort) && envPort > 0) port = envPort;
  }
  if (!Number.isFinite(port) || port <= 0) port = 3000;
  return { port, host: host || "0.0.0.0" };
}

export function createRequestHandler(root = ROOT) {
  const rootResolved = resolve(root);
  return async function handler(req, res) {
    try {
      if (req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(405, { Allow: "GET, HEAD" });
        res.end("Method Not Allowed");
        return;
      }

      let pathname;
      try {
        pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
      } catch {
        res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Bad Request");
        return;
      }
      if (pathname.includes("\0")) {
        res.writeHead(400);
        res.end("Bad Request");
        return;
      }
      if (pathname.endsWith("/")) pathname += "index.html";
      if (pathname === "" || pathname === "/") pathname = "/index.html";

      // Resolve and verify containment inside the repo root.
      const fileResolved = resolve(join(rootResolved, pathname));
      const inside =
        fileResolved === rootResolved ||
        fileResolved.startsWith(rootResolved + sep);
      if (!inside) {
        res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Forbidden");
        return;
      }
      // Reject hidden files/dirs and any traversal via dot segments
      // (covers "/.git/config", "/..", "/%2e%2e/..." after decoding).
      const fileName = fileResolved.split(sep).pop() || "";
      const hasDotSegment = pathname.split("/").some(seg => seg.startsWith("."));
      if (hasDotSegment || fileName.startsWith(".")) {
        res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Forbidden");
        return;
      }

      const body = await readFile(fileResolved);
      res.writeHead(200, {
        "Content-Type": MIME[extname(fileName).toLowerCase()] || "application/octet-stream",
        "Cache-Control": "no-store",
      });
      res.end(req.method === "HEAD" ? undefined : body);
    } catch (err) {
      if (err && err.code === "ENOENT") {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Not Found");
      } else {
        console.error("[MineGuard dev server]", err);
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Internal Server Error");
      }
    }
  };
}

// Listen only when run directly (`node server.mjs`), so the handler can be
// imported for tests without binding a port.
const isMain =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMain) {
  const { port, host } = parseArgs(process.argv.slice(2));
  createServer(createRequestHandler()).listen(port, host, () => {
    console.log(`[MineGuard] dev server running at http://${host}:${port} (serving ${ROOT})`);
  });
}
