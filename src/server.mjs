import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handleAdminApiRequest } from "./admin-api.mjs";
import { APP_VERSION, PROJECT_ROOT, ensureStorageDirs, loadConfig } from "./config.mjs";
import { AuditLogger, SnapshotStore } from "./harness.mjs";
import { HttpError, sendJson } from "./http-utils.mjs";
import { createMcpHandler } from "./mcp.mjs";
import { OAuthManager, getBaseUrl, handleOAuthRequest } from "./oauth.mjs";
import { TaskStore } from "./store.mjs";

let cachedLogoSvg = null;
try {
  cachedLogoSvg = fs.readFileSync(path.join(PROJECT_ROOT, "assets", "logo.svg"));
} catch {
  cachedLogoSvg = null;
}

const BASE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version",
  "Access-Control-Expose-Headers":
    "Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate",
};

const OAUTH_CONSENT_PATH_RE = /^\/(?:u\/[^/]+\/)?oauth\/authorize\/?$/;

/**
 * Redact `/u/<key>` or `/mcp/u/<key>` segments before logging or reflecting paths.
 * @param {string} pathname
 * @returns {string}
 */
function redactKeySegments(pathname) {
  return String(pathname || "").replace(/(\/(?:mcp\/)?u\/)([^/]+)/g, "$1[redacted]");
}

/**
 * Parse incoming request URL with Host header validation.
 * @param {import("node:http").IncomingMessage} req
 * @param {string} fallbackHost
 * @returns {URL}
 */
function parseRequestUrl(req, fallbackHost) {
  try {
    const host = req.headers.host || fallbackHost;
    return new URL(req.url || "/", `http://${host}`);
  } catch {
    throw new HttpError(400, "Invalid request URL or Host header");
  }
}

/**
 * Unified error responder for HTTP servers.
 */
function sendUnhandledError(res, err) {
  if (res.headersSent) {
    res.end();
    return;
  }
  if (err instanceof HttpError) {
    sendJson(res, err.status, { error: "http_error", message: err.message }, err.headers);
    return;
  }
  sendJson(res, 500, {
    error: "internal_error",
    message: err?.message || "Unexpected server error",
  });
}

/**
 * Validate incoming Origin header per MCP Streamable HTTP DNS-rebinding defense.
 * Requests without an Origin header (server-to-server / CLI) are permitted.
 * Same-origin CSRF-protected `/oauth/authorize` form posts are permitted even behind tunnels without `PUBLIC_BASE_URL`.
 * @param {string} origin
 * @param {Record<string, any>} config
 * @param {import("node:http").IncomingMessage} [req]
 * @param {string} [pathname]
 * @returns {boolean}
 */
function isOriginAllowed(origin, config, req = null, pathname = "") {
  if (!origin) {
    return true;
  }
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return false;
  }
  if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]") {
    return true;
  }
  if (config.publicBaseUrl) {
    try {
      if (new URL(config.publicBaseUrl).origin === parsed.origin) {
        return true;
      }
    } catch {
      // Ignore invalid publicBaseUrl
    }
  }
  if (Array.isArray(config.allowedOrigins) && config.allowedOrigins.includes(parsed.origin)) {
    return true;
  }
  if (req && OAUTH_CONSENT_PATH_RE.test(pathname)) {
    try {
      const effectiveOrigin = new URL(getBaseUrl(req, config)).origin;
      if (effectiveOrigin === parsed.origin) {
        return true;
      }
    } catch {
      // Ignore malformed forwarded headers
    }
  }
  return false;
}

/**
 * Apply CORS headers on a ServerResponse before writeHead.
 * @param {import("node:http").ServerResponse} res
 * @param {string} [allowedOrigin]
 */
function applyCorsHeaders(res, allowedOrigin = "") {
  if (allowedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
    res.setHeader("Vary", "Origin");
  }
  for (const [key, value] of Object.entries(BASE_CORS_HEADERS)) {
    res.setHeader(key, value);
  }
}

/**
 * Enforce Origin validation and apply CORS headers on an incoming request.
 * Returns true if the request was rejected with 403, false if allowed.
 */
function enforceOrigin(req, res, config, pathname = "") {
  const origin = typeof req.headers.origin === "string" ? req.headers.origin.trim() : "";
  if (origin && !isOriginAllowed(origin, config, req, pathname)) {
    sendJson(res, 403, {
      error: "forbidden_origin",
      message: "Origin header is not allowed",
    });
    return true;
  }
  applyCorsHeaders(res, origin);
  return false;
}

/**
 * Create the Gemini Bridge HTTP server without binding until caller invokes `.listen()`.
 * @param {Record<string, any>} [configOrOverrides]
 */
export function createBridgeServer(configOrOverrides = {}) {
  const isFullConfig =
    configOrOverrides &&
    typeof configOrOverrides === "object" &&
    configOrOverrides.tasksDir &&
    configOrOverrides.filesRoot &&
    configOrOverrides.notesRoot &&
    configOrOverrides.reposRoot &&
    configOrOverrides.oauthStateFile &&
    (configOrOverrides.ownerPassphrase || configOrOverrides.accountKeys?.size > 0) &&
    configOrOverrides.adminToken;

  const config = isFullConfig
    ? (ensureStorageDirs(configOrOverrides), configOrOverrides)
    : loadConfig(configOrOverrides);

  const store = new TaskStore(config.tasksDir);
  const oauth = new OAuthManager(config.oauthStateFile, config);
  const audit = new AuditLogger(
    config.auditLogFile || path.join(config.dataDir || path.dirname(config.tasksDir), "audit.jsonl")
  );
  const snapshots = new SnapshotStore(
    config.snapshotsDir || path.join(config.dataDir || path.dirname(config.tasksDir), "snapshots"),
    { retentionPerFile: config.snapshotRetention }
  );
  const handleMcp = createMcpHandler({ store, oauth, config, audit, snapshots });
  const splitAdminPort = config.adminPort !== null && config.adminPort !== undefined;

  const server = http.createServer(async (req, res) => {
    if (process.env.NODE_ENV !== "test" && config.port !== 0) {
      res.on("finish", () => {
        const rawPath = String(req.url || "/").split("?")[0];
        console.log(`[http] ${req.method} ${redactKeySegments(rawPath)} -> ${res.statusCode}`);
      });
    }

    try {
      const url = parseRequestUrl(req, `${config.host}:${config.port}`);

      if (enforceOrigin(req, res, config, url.pathname)) {
        return;
      }

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      if (await handleOAuthRequest(req, res, url, config, oauth)) {
        return;
      }

      if (url.pathname === "/mcp") {
        await handleMcp(req, res);
        return;
      }

      const pathKeyMatch = url.pathname.match(/^\/mcp\/u\/([^/]+)\/?$/);
      if (pathKeyMatch) {
        let rawKey;
        try {
          rawKey = decodeURIComponent(pathKeyMatch[1]);
        } catch {
          sendJson(res, 403, { error: "forbidden", message: "Invalid or revoked MCP account key" });
          return;
        }
        await handleMcp(req, res, { pathKey: rawKey });
        return;
      }

      if (url.pathname.startsWith("/api/")) {
        if (splitAdminPort && url.pathname !== "/api/health") {
          sendJson(res, 403, {
            error: "admin_port_isolated",
            message: "Admin API is isolated to ADMIN_PORT on loopback",
          });
          return;
        }
        if (await handleAdminApiRequest(req, res, url, config, store)) {
          return;
        }
      }

      if (
        req.method === "GET" &&
        cachedLogoSvg &&
        (url.pathname === "/assets/logo.svg" ||
          url.pathname === "/logo.svg" ||
          url.pathname === "/favicon.ico")
      ) {
        res.writeHead(200, {
          "Content-Type": "image/svg+xml; charset=utf-8",
          "Content-Length": cachedLogoSvg.length,
          "Cache-Control": "public, max-age=3600",
        });
        res.end(cachedLogoSvg);
        return;
      }

      if (url.pathname === "/" && req.method === "GET") {
        sendJson(res, 200, {
          name: "gemini-handoff-mcp",
          version: APP_VERSION,
          icon: "/assets/logo.svg",
          mcp_endpoint: "/mcp",
          health_endpoint: "/api/health",
        });
        return;
      }

      sendJson(res, 404, { error: "not_found", path: redactKeySegments(url.pathname) });
    } catch (err) {
      sendUnhandledError(res, err);
    }
  });

  server.on("close", () => {
    handleMcp.stop?.();
  });

  let adminServer = null;
  if (splitAdminPort) {
    adminServer = http.createServer(async (req, res) => {
      try {
        const url = parseRequestUrl(req, `${config.adminHost}:${config.adminPort}`);
        if (enforceOrigin(req, res, config, url.pathname)) {
          return;
        }
        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }
        if (await handleAdminApiRequest(req, res, url, config, store)) {
          return;
        }
        sendJson(res, 404, { error: "not_found", path: redactKeySegments(url.pathname) });
      } catch (err) {
        sendUnhandledError(res, err);
      }
    });
  }

  return { server, adminServer, store, oauth, audit, snapshots, config };
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);

if (isMain) {
  const { server, adminServer, config } = createBridgeServer();
  server.listen(config.port, config.host, () => {
    const publicHint = config.publicBaseUrl ? ` (public: ${config.publicBaseUrl})` : "";
    console.log(
      `gemini-handoff-mcp listening on http://${config.host}:${config.port}${publicHint}`
    );
    console.log(`MCP endpoint: /mcp | Health endpoint: /api/health`);
  });

  if (adminServer) {
    adminServer.listen(config.adminPort, config.adminHost, () => {
      console.log(
        `gemini-handoff-mcp admin API listening on http://${config.adminHost}:${config.adminPort}`
      );
    });
  }

  const shutdown = () => {
    adminServer?.close();
    server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
