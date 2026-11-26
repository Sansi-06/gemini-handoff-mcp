import fs from "node:fs/promises";
import path from "node:path";
import { APP_VERSION, resolveTenantFilesRoot } from "./config.mjs";
import {
  HttpError,
  extractBearerToken,
  readJsonBody,
  readRawBody,
  sendJson,
  sendText,
} from "./http-utils.mjs";
import { isLikelyBinary, resolveSandboxedPath, timingSafeEqualStr } from "./security.mjs";

const ADMIN_MAX_BODY_BYTES = 2 * 1024 * 1024;
const JSON_MAX_BODY_BYTES = 3 * 1024 * 1024;

/**
 * Map sync bucket name to configured sandbox root directory.
 */
function resolveBucketRoot(bucket, config, account = "default") {
  switch (bucket) {
    case "files":
      return resolveTenantFilesRoot(config, account);
    case "notes":
      return config.notesRoot;
    case "repos":
      return config.reposRoot;
    default:
      return null;
  }
}

/**
 * Decode URL path segments cleanly after `/api/sync/<bucket>/`.
 */
function decodeRelativeSyncPath(rawSuffix) {
  if (!rawSuffix) {
    throw new HttpError(400, "Target relative path is required");
  }
  try {
    return rawSuffix
      .split("/")
      .map((seg) => decodeURIComponent(seg))
      .join("/");
  } catch {
    throw new HttpError(400, "Malformed URL encoding in sync path");
  }
}

/**
 * Map domain errors from TaskStore or sandbox checks into HTTP status codes.
 */
function mapErrorToHttp(err) {
  if (err instanceof HttpError) {
    throw err;
  }
  const msg = err?.message || String(err);
  if (msg.startsWith("Task not found") || msg.includes("does not exist")) {
    throw new HttpError(404, msg);
  }
  throw new HttpError(400, msg);
}

/**
 * Handle `/api/*` management and file sync requests.
 * Returns true if the request path started with `/api/`, false otherwise.
 *
 * @param {import("node:http").IncomingMessage} req
 * @param {import("node:http").ServerResponse} res
 * @param {URL} url
 * @param {Record<string, any>} config
 * @param {import("./store.mjs").TaskStore} store
 * @returns {Promise<boolean>}
 */
export async function handleAdminApiRequest(req, res, url, config, store) {
  const pathname = url.pathname;
  if (!pathname.startsWith("/api/")) {
    return false;
  }

  if (pathname === "/api/health" && req.method === "GET") {
    sendJson(res, 200, {
      ok: true,
      service: "gemini-handoff-mcp",
      version: APP_VERSION,
    });
    return true;
  }

  const token = extractBearerToken(req);
  if (!token || !timingSafeEqualStr(token, config.adminToken)) {
    sendJson(res, 401, {
      error: "unauthorized",
      message: "Valid ADMIN_TOKEN Bearer token is required",
    });
    return true;
  }

  if (pathname === "/api/tasks") {
    if (req.method === "GET") {
      const status = url.searchParams.get("status") || "all";
      const limit = Number(url.searchParams.get("limit") || 50);
      const tag = url.searchParams.get("tag") || "";
      const account = url.searchParams.get("account") || "";
      const tasks = await store.listTasks({ status, limit, tag, account });
      sendJson(res, 200, { count: tasks.length, tasks });
      return true;
    }

    if (req.method === "POST") {
      const body = await readJsonBody(req, JSON_MAX_BODY_BYTES);
      try {
        const task = await store.createTask(body);
        sendJson(res, 201, { task });
      } catch (err) {
        mapErrorToHttp(err);
      }
      return true;
    }

    sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "GET, POST" });
    return true;
  }

  const taskMatch = pathname.match(/^\/api\/tasks\/([^/]+)$/);
  if (taskMatch) {
    let taskId;
    try {
      taskId = decodeURIComponent(taskMatch[1]);
    } catch {
      throw new HttpError(400, "Invalid task ID encoding");
    }

    if (req.method === "GET") {
      try {
        const task = await store.getTask(taskId);
        sendJson(res, 200, { task });
      } catch (err) {
        mapErrorToHttp(err);
      }
      return true;
    }

    if (req.method === "DELETE") {
      try {
        const task = await store.archiveTask(taskId);
        sendJson(res, 200, { ok: true, task });
      } catch (err) {
        mapErrorToHttp(err);
      }
      return true;
    }

    sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "GET, DELETE" });
    return true;
  }

  const syncMatch = pathname.match(/^\/api\/sync\/([^/]+)\/(.+)$/);
  if (syncMatch) {
    const bucket = syncMatch[1];
    const account = url.searchParams.get("account") || "default";
    let bucketRoot;
    try {
      bucketRoot = resolveBucketRoot(bucket, config, account);
    } catch (err) {
      mapErrorToHttp(err);
    }
    if (!bucketRoot) {
      throw new HttpError(404, `Unknown sync bucket: ${bucket}`);
    }

    const relPath = decodeRelativeSyncPath(syncMatch[2]);

    if (req.method === "PUT") {
      const content = await readRawBody(req, ADMIN_MAX_BODY_BYTES);
      let resolved;
      try {
        resolved = await resolveSandboxedPath(bucketRoot, relPath, {
          allowRoot: false,
          mustExist: false,
        });
      } catch (err) {
        mapErrorToHttp(err);
      }

      await fs.mkdir(path.dirname(resolved.fullPath), { recursive: true });
      await fs.writeFile(resolved.fullPath, content, "utf8");
      const bytes = Buffer.byteLength(content, "utf8");
      sendJson(res, 200, {
        ok: true,
        bucket,
        path: resolved.relPath,
        bytes,
      });
      return true;
    }

    if (req.method === "GET") {
      let resolved;
      try {
        resolved = await resolveSandboxedPath(bucketRoot, relPath, {
          allowRoot: false,
          mustExist: true,
        });
      } catch (err) {
        mapErrorToHttp(err);
      }

      const stat = await fs.stat(resolved.fullPath);
      if (!stat.isFile()) {
        throw new HttpError(400, `Path is not a file: ${resolved.relPath}`);
      }

      const buf = await fs.readFile(resolved.fullPath);
      if (isLikelyBinary(buf)) {
        res.writeHead(200, {
          "Content-Type": "application/octet-stream",
          "Content-Length": buf.length,
        });
        res.end(buf);
      } else {
        sendText(res, 200, buf.toString("utf8"));
      }
      return true;
    }

    if (req.method === "DELETE") {
      let resolved;
      try {
        resolved = await resolveSandboxedPath(bucketRoot, relPath, {
          allowRoot: false,
          mustExist: true,
        });
      } catch (err) {
        mapErrorToHttp(err);
      }

      const stat = await fs.stat(resolved.fullPath);
      if (!stat.isFile()) {
        throw new HttpError(400, `Path is not a file: ${resolved.relPath}`);
      }

      await fs.unlink(resolved.fullPath);
      sendJson(res, 200, {
        ok: true,
        bucket,
        path: resolved.relPath,
      });
      return true;
    }

    sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "GET, PUT, DELETE" });
    return true;
  }

  sendJson(res, 404, { error: "not_found", message: `Unknown API route: ${pathname}` });
  return true;
}
