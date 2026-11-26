import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { normalizeSlashes } from "./http-utils.mjs";
import {
  isLikelyBinary,
  isSensitivePath,
  resolveSandboxedPath,
  sha256Hex,
} from "./security.mjs";
import { AsyncKeyLock, atomicWriteBuffer, atomicWriteFile } from "./store.mjs";

const MAX_AUDIT_LOG_BYTES = 5 * 1024 * 1024;
const SNAPSHOT_ID_RE = /^snap_\d{8}_\d{6}_[a-f0-9]{8}$/;
const SENSITIVE_KEY_RE = /(token|secret|passphrase|password|authorization|code_verifier|api_?key)/i;
const DEFAULT_ADVISORY_SUMMARY_CHARS = 2500;

/**
 * Error thrown when a harness guardrail policy blocks an operation.
 */
export class PolicyError extends Error {
  /**
   * @param {string} message
   * @param {string} [rule]
   */
  constructor(message, rule = "policy_denied") {
    super(message);
    this.name = "PolicyError";
    this.code = "POLICY_DENIED";
    this.rule = rule;
  }
}

/**
 * In-memory sliding window rate limiter with bounded key cleanup.
 */
export class SlidingWindowRateLimiter {
  /**
   * @param {{ maxRequests: number, windowMs: number, maxKeys?: number }} options
   */
  constructor({ maxRequests, windowMs, maxKeys = 2000 }) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this._buckets = new Map();
  }

  /**
   * Remove expired timestamps for a key and prune map if large.
   * @param {string} key
   * @param {number} now
   * @returns {number[]}
   */
  #getActive(key, now) {
    const cutoff = now - this.windowMs;
    const existing = this._buckets.get(key);
    if (!existing) {
      return [];
    }
    const active = existing.filter((ts) => ts > cutoff);
    if (active.length === 0) {
      this._buckets.delete(key);
    } else if (active.length !== existing.length) {
      this._buckets.set(key, active);
    }
    return active;
  }

  #pruneIfNeeded(now) {
    if (this._buckets.size < this.maxKeys) {
      return;
    }
    const cutoff = now - this.windowMs;
    for (const [key, list] of this._buckets) {
      const active = list.filter((ts) => ts > cutoff);
      if (active.length === 0) {
        this._buckets.delete(key);
      } else {
        this._buckets.set(key, active);
      }
    }
  }

  /**
   * Attempt to consume 1 quota unit for `key`.
   * @param {string} key
   * @returns {{ allowed: boolean, remaining: number, limit: number, retryAfterMs: number }}
   */
  consume(key) {
    if (!this.maxRequests || this.maxRequests <= 0) {
      return { allowed: true, remaining: Infinity, limit: 0, retryAfterMs: 0 };
    }
    const now = Date.now();
    this.#pruneIfNeeded(now);
    const active = this.#getActive(key, now);
    if (active.length >= this.maxRequests) {
      const oldest = active[0];
      return {
        allowed: false,
        remaining: 0,
        limit: this.maxRequests,
        retryAfterMs: Math.max(1000, oldest + this.windowMs - now),
      };
    }
    active.push(now);
    this._buckets.set(key, active);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - active.length),
      limit: this.maxRequests,
      retryAfterMs: 0,
    };
  }

  /**
   * Inspect current remaining quota without consuming a slot.
   * @param {string} key
   */
  peek(key) {
    if (!this.maxRequests || this.maxRequests <= 0) {
      return { remaining: Infinity, limit: 0, used: 0 };
    }
    const active = this.#getActive(key, Date.now());
    return {
      remaining: Math.max(0, this.maxRequests - active.length),
      limit: this.maxRequests,
      used: active.length,
    };
  }
}

/**
 * Recursively sanitize values before writing to audit logs so secrets and large payloads never leak.
 * @param {unknown} value
 * @param {number} [depth]
 */
export function sanitizeForAudit(value, depth = 0) {
  if (value === null || value === undefined) {
    return value;
  }
  if (depth > 4) {
    return "[max_depth]";
  }
  if (typeof value === "string") {
    if (value.length > 240) {
      return {
        _omitted: true,
        chars: value.length,
        bytes: Buffer.byteLength(value, "utf8"),
        sha256_prefix: sha256Hex(value).slice(0, 12),
        preview: `${value.slice(0, 80)}...`,
      };
    }
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    const sliced = value.slice(0, 20).map((item) => sanitizeForAudit(item, depth + 1));
    if (value.length > 20) {
      sliced.push(`[+${value.length - 20} more]`);
    }
    return sliced;
  }
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = sanitizeForAudit(v, depth + 1);
      }
    }
    return out;
  }
  return String(value);
}

/**
 * Append-only JSONL audit logger and live telemetry accumulator.
 */
export class AuditLogger {
  /**
   * @param {string} logFile
   */
  constructor(logFile) {
    this.logFile = logFile ? path.resolve(logFile) : "";
    this.startedAt = Date.now();
    this._writeQueue = Promise.resolve();
    this._metrics = {
      total_events: 0,
      ok: 0,
      error: 0,
      blocked: 0,
      by_action: {},
    };
  }

  /**
   * Append an audit entry and update live telemetry.
   * @param {{
   *   category: "mcp_tool" | "admin_api" | "oauth" | "mcp_resource" | "mcp_prompt",
   *   action: string,
   *   status: "ok" | "error" | "blocked",
   *   actor?: string,
   *   session_id?: string | null,
   *   trace_id?: string | null,
   *   duration_ms?: number,
   *   args?: unknown,
   *   result?: unknown,
   *   error?: string | null
   * }} entry
   */
  log(entry) {
    const record = {
      ts: new Date().toISOString(),
      trace_id: entry.trace_id || crypto.randomBytes(6).toString("hex"),
      category: entry.category,
      action: entry.action,
      status: entry.status,
      actor: entry.actor || "unknown",
      ...(entry.session_id ? { session_id: entry.session_id } : {}),
      ...(entry.duration_ms !== undefined ? { duration_ms: Math.max(0, Math.round(entry.duration_ms)) } : {}),
      ...(entry.args !== undefined ? { args: sanitizeForAudit(entry.args) } : {}),
      ...(entry.result !== undefined ? { result: sanitizeForAudit(entry.result) } : {}),
      ...(entry.error ? { error: String(entry.error).slice(0, 500) } : {}),
    };

    this._metrics.total_events += 1;
    if (record.status === "ok") {
      this._metrics.ok += 1;
    } else if (record.status === "blocked") {
      this._metrics.blocked += 1;
    } else {
      this._metrics.error += 1;
    }

    const bucketKey = `${record.category}:${record.action}`;
    if (!this._metrics.by_action[bucketKey]) {
      this._metrics.by_action[bucketKey] = {
        calls: 0,
        ok: 0,
        error: 0,
        blocked: 0,
        total_ms: 0,
      };
    }
    const stat = this._metrics.by_action[bucketKey];
    stat.calls += 1;
    if (record.status === "ok") {
      stat.ok += 1;
    } else if (record.status === "blocked") {
      stat.blocked += 1;
    } else {
      stat.error += 1;
    }
    if (typeof record.duration_ms === "number") {
      stat.total_ms += record.duration_ms;
    }

    if (!this.logFile) {
      return Promise.resolve();
    }

    const line = `${JSON.stringify(record)}\n`;
    this._writeQueue = this._writeQueue
      .catch(() => {})
      .then(async () => {
        await fs.mkdir(path.dirname(this.logFile), { recursive: true });
        try {
          const st = await fs.stat(this.logFile);
          if (st.size >= MAX_AUDIT_LOG_BYTES) {
            await fs.rename(this.logFile, `${this.logFile}.1`).catch(() => {});
          }
        } catch {
          // File does not exist yet.
        }
        await fs.appendFile(this.logFile, line, "utf8");
      });

    return this._writeQueue;
  }

  /**
   * Flush pending audit writes (useful before querying or shutting down).
   */
  async flush() {
    await this._writeQueue.catch(() => {});
  }

  /**
   * Query recent audit records newest-first.
   * @param {{ limit?: number, tool?: string, status?: string, actor?: string, category?: string }} [filters]
   */
  async query({ limit = 50, tool = "", status = "", actor = "", category = "" } = {}) {
    await this.flush();
    if (!this.logFile) {
      return [];
    }
    let raw;
    try {
      raw = await fs.readFile(this.logFile, "utf8");
    } catch (err) {
      if (err?.code === "ENOENT") {
        return [];
      }
      throw err;
    }

    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 50));
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const matches = [];

    for (let i = lines.length - 1; i >= 0 && matches.length < safeLimit; i -= 1) {
      try {
        const rec = JSON.parse(lines[i]);
        if (tool && rec.action !== tool) {
          continue;
        }
        if (status && rec.status !== status) {
          continue;
        }
        if (actor && rec.actor !== actor) {
          continue;
        }
        if (category && rec.category !== category) {
          continue;
        }
        matches.push(rec);
      } catch {
        // Skip malformed line.
      }
    }

    return matches;
  }

  /**
   * Return live in-memory telemetry summary.
   */
  getMetrics() {
    const byAction = {};
    for (const [k, v] of Object.entries(this._metrics.by_action)) {
      byAction[k] = {
        calls: v.calls,
        ok: v.ok,
        error: v.error,
        blocked: v.blocked,
        avg_ms: v.calls > 0 ? Math.round(v.total_ms / v.calls) : 0,
      };
    }
    return {
      uptime_seconds: Math.floor((Date.now() - this.startedAt) / 1000),
      total_events: this._metrics.total_events,
      ok: this._metrics.ok,
      error: this._metrics.error,
      blocked: this._metrics.blocked,
      by_action: byAction,
    };
  }
}

/**
 * Format compact UTC timestamp YYYYMMDD_HHMMSS for snapshot IDs.
 */
function formatSnapTimestamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}_` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`
  );
}

/**
 * Persistent pre-write snapshot store enabling deterministic rollback of FILES_ROOT mutations.
 */
export class SnapshotStore {
  /**
   * @param {string} snapshotsDir
   * @param {{ retentionPerFile?: number }} [options]
   */
  constructor(snapshotsDir, { retentionPerFile = 20 } = {}) {
    this.snapshotsDir = path.resolve(snapshotsDir);
    this.retentionPerFile = Math.max(0, Math.min(200, Number(retentionPerFile) ?? 20));
    this._lock = new AsyncKeyLock();
  }

  validateSnapshotId(snapshotId) {
    if (typeof snapshotId !== "string" || !SNAPSHOT_ID_RE.test(snapshotId)) {
      throw new Error("Invalid snapshot_id format");
    }
    return snapshotId;
  }

  #metaPath(snapshotId) {
    this.validateSnapshotId(snapshotId);
    return path.join(this.snapshotsDir, `${snapshotId}.meta.json`);
  }

  #blobPath(snapshotId) {
    this.validateSnapshotId(snapshotId);
    return path.join(this.snapshotsDir, `${snapshotId}.blob`);
  }

  /**
   * Capture a reversible snapshot of an existing file before mutation.
   * Returns snapshot metadata, or null if retentionPerFile === 0.
   */
  async capture({
    fullPath,
    relPath,
    reason = "overwrite",
    tool = "write_file",
    actor = "mcp",
    account = "default",
    taskId = null,
  }) {
    if (this.retentionPerFile === 0) {
      return null;
    }

    const cleanRel = normalizeSlashes(relPath);
    const cleanAccount = String(account || "default").trim().toLowerCase() || "default";
    return this._lock.withLock(`${cleanAccount}:${cleanRel}`, async () => {
      const buf = await fs.readFile(fullPath);
      const now = new Date();
      const id = `snap_${formatSnapTimestamp(now)}_${crypto.randomBytes(4).toString("hex")}`;
      const meta = {
        id,
        rel_path: cleanRel,
        sha256: sha256Hex(buf),
        bytes: buf.length,
        created_at: now.toISOString(),
        reason,
        tool,
        actor,
        account: cleanAccount,
        task_id: taskId || null,
      };

      await fs.mkdir(this.snapshotsDir, { recursive: true });
      await atomicWriteBuffer(this.#blobPath(id), buf);
      await atomicWriteFile(this.#metaPath(id), `${JSON.stringify(meta, null, 2)}\n`);
      await this.#pruneForPath(cleanRel, cleanAccount);
      return meta;
    });
  }

  async #pruneForPath(relPath, account = "") {
    const entries = await this.list({ path: relPath, account, limit: 500 });
    if (entries.length <= this.retentionPerFile) {
      return;
    }
    const toDelete = entries.slice(this.retentionPerFile);
    for (const snap of toDelete) {
      await fs.unlink(this.#metaPath(snap.id)).catch(() => {});
      await fs.unlink(this.#blobPath(snap.id)).catch(() => {});
    }
  }

  /**
   * List snapshot metadata sorted newest-first, optionally filtered by relative path and account.
   * @param {{ path?: string, limit?: number, account?: string }} [options]
   */
  async list({ path: filterPath = "", limit = 30, account = "" } = {}) {
    await fs.mkdir(this.snapshotsDir, { recursive: true });
    const dirents = await fs.readdir(this.snapshotsDir, { withFileTypes: true });
    const normalizedFilter = filterPath ? normalizeSlashes(filterPath).replace(/^\/+/, "") : "";
    const normalizedAccount = String(account || "").trim().toLowerCase();
    const results = [];

    for (const entry of dirents) {
      if (!entry.isFile() || !entry.name.endsWith(".meta.json")) {
        continue;
      }
      try {
        const raw = await fs.readFile(path.join(this.snapshotsDir, entry.name), "utf8");
        const meta = JSON.parse(raw);
        if (normalizedFilter && normalizeSlashes(meta.rel_path) !== normalizedFilter) {
          continue;
        }
        if (normalizedAccount && String(meta.account || "default").toLowerCase() !== normalizedAccount) {
          continue;
        }
        results.push(meta);
      } catch {
        // Ignore corrupt snapshot metadata.
      }
    }

    results.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const safeLimit = Math.max(1, Math.min(200, Number(limit) || 30));
    return results.slice(0, safeLimit);
  }

  /**
   * Load snapshot metadata and raw payload bytes.
   * @param {string} snapshotId
   */
  async get(snapshotId) {
    this.validateSnapshotId(snapshotId);
    let rawMeta;
    try {
      rawMeta = await fs.readFile(this.#metaPath(snapshotId), "utf8");
    } catch (err) {
      if (err?.code === "ENOENT") {
        throw new Error(`Snapshot not found: ${snapshotId}`);
      }
      throw err;
    }
    const meta = JSON.parse(rawMeta);
    const contentBuffer = await fs.readFile(this.#blobPath(snapshotId));
    return { meta, contentBuffer };
  }

  /**
   * Restore a snapshot back into FILES_ROOT, taking a pre_restore snapshot first so rollback is reversible.
   */
  async restore({
    snapshotId,
    filesRoot,
    config,
    actor = "mcp",
    account = "",
    taskId = null,
    fileLock = null,
  }) {
    const { meta, contentBuffer } = await this.get(snapshotId);
    const metaAccount = String(meta.account || "default").trim().toLowerCase() || "default";
    const callerAccount = String(account || "").trim().toLowerCase();
    if (callerAccount && metaAccount !== callerAccount) {
      throw new PolicyError(
        `Access denied: snapshot '${snapshotId}' belongs to another account`,
        "tenant_isolation_denied"
      );
    }
    const relPath = normalizeSlashes(meta.rel_path);

    checkWriteAllowed(relPath, config);

    const executeRestore = async () => {
      const resolved = await resolveSandboxedPath(filesRoot, relPath, {
        allowRoot: false,
        mustExist: false,
      });

      let preRestoreBackup = null;
      if (resolved.exists) {
        const st = await fs.stat(resolved.fullPath);
        if (st.isDirectory()) {
          throw new Error(`Cannot restore snapshot over directory: ${resolved.relPath}`);
        }
        preRestoreBackup = await this.capture({
          fullPath: resolved.fullPath,
          relPath: resolved.relPath,
          reason: `pre_restore:${snapshotId}`,
          tool: "restore_file_snapshot",
          actor,
          account: metaAccount,
          taskId,
        });
      }

      await atomicWriteBuffer(resolved.fullPath, contentBuffer);
      return {
        ok: true,
        restored_path: resolved.relPath,
        snapshot_id: snapshotId,
        restored_sha256: sha256Hex(contentBuffer),
        bytes: contentBuffer.length,
        pre_restore_backup_id: preRestoreBackup?.id || null,
      };
    };

    if (fileLock) {
      return fileLock.withLock(`${metaAccount}:${relPath}`, executeRestore);
    }
    return executeRestore();
  }

  /**
   * Count stored snapshots for status reporting.
   * @param {{ account?: string }} [options]
   */
  async count({ account = "" } = {}) {
    try {
      if (account) {
        return (await this.list({ account, limit: 200 })).length;
      }
      const dirents = await fs.readdir(this.snapshotsDir, { withFileTypes: true });
      return dirents.filter((d) => d.isFile() && d.name.endsWith(".meta.json")).length;
    } catch {
      return 0;
    }
  }
}

/**
 * Enforce global READ_ONLY_MODE, WRITE_ALLOWED_PREFIXES, and optional task-scoped write prefixes.
 * @param {string} relPath
 * @param {Record<string, any>} config
 * @param {{ taskContract?: Record<string, any> | null }} [options]
 */
export function checkWriteAllowed(relPath, config, { taskContract = null } = {}) {
  if (config?.readOnlyMode) {
    throw new PolicyError(
      "Harness is in READ_ONLY_MODE; file write, edit, and restore operations are disabled.",
      "read_only_mode"
    );
  }

  const normalized = normalizeSlashes(relPath).replace(/^\/+/, "");
  const matchesPrefix = (prefixes) =>
    prefixes.some((prefix) => normalized === prefix || normalized.startsWith(`${prefix}/`));

  const globalPrefixes = Array.isArray(config?.writeAllowedPrefixes)
    ? config.writeAllowedPrefixes
    : [];
  if (globalPrefixes.length > 0 && !matchesPrefix(globalPrefixes)) {
    throw new PolicyError(
      `Write path '${normalized}' is outside WRITE_ALLOWED_PREFIXES (${globalPrefixes.join(", ")}).`,
      "write_prefix_denied"
    );
  }

  const taskPrefixes = Array.isArray(taskContract?.allowed_write_prefixes)
    ? taskContract.allowed_write_prefixes
    : [];
  if (taskPrefixes.length > 0 && !matchesPrefix(taskPrefixes)) {
    throw new PolicyError(
      `Write path '${normalized}' is outside task allowed_write_prefixes (${taskPrefixes.join(", ")}).`,
      "task_write_prefix_denied"
    );
  }
}

/**
 * Resolve a path within a content bucket that may also expose admin-configured read-only virtual mounts.
 * Never leaks absolute host mount paths in errors.
 *
 * @param {string} rootDir
 * @param {Record<string, string> | undefined} mounts
 * @param {string} relPath
 * @param {{ allowRoot?: boolean, mustExist?: boolean }} [options]
 */
export async function resolveBucketPath(
  rootDir,
  mounts = {},
  relPath = ".",
  { allowRoot = false, mustExist = false } = {}
) {
  if (typeof relPath !== "string") {
    throw new Error("Path must be a string");
  }
  if (relPath.includes("\0")) {
    throw new Error("Invalid null byte in path");
  }

  const normalizedInput = normalizeSlashes(relPath);
  if (
    normalizedInput.startsWith("/") ||
    /^[a-zA-Z]:/.test(normalizedInput) ||
    path.isAbsolute(relPath)
  ) {
    throw new Error("Absolute paths are not allowed; use a path relative to sandbox root");
  }

  const mountMap = mounts && typeof mounts === "object" ? mounts : {};
  const mountKeys = Object.keys(mountMap);

  if (mountKeys.length > 0) {
    const cleanPosix = path.posix.normalize(normalizedInput || ".");
    if (cleanPosix === ".." || cleanPosix.startsWith("../")) {
      throw new Error("Path traversal outside sandbox root is forbidden");
    }
    if (cleanPosix !== "." && isSensitivePath(cleanPosix)) {
      throw new Error("Access to sensitive credential or environment files is blocked");
    }

    if (cleanPosix !== ".") {
      const slashIdx = cleanPosix.indexOf("/");
      const head = slashIdx === -1 ? cleanPosix : cleanPosix.slice(0, slashIdx);
      const tail = slashIdx === -1 ? "" : cleanPosix.slice(slashIdx + 1);

      if (Object.prototype.hasOwnProperty.call(mountMap, head)) {
        const mountRoot = mountMap[head];
        let mountStat;
        try {
          mountStat = await fs.stat(mountRoot);
        } catch {
          throw new Error(`Mounted workspace '${head}' is currently unavailable on host`);
        }
        if (!mountStat.isDirectory()) {
          throw new Error(`Mounted workspace '${head}' is not a directory on host`);
        }

        if (!tail && !allowRoot) {
          throw new Error(`Path is a mounted directory, not a file: ${head}`);
        }

        const inner = await resolveSandboxedPath(mountRoot, tail || ".", {
          allowRoot: true,
          mustExist,
        });

        return {
          fullPath: inner.fullPath,
          relPath: inner.relPath === "." ? head : `${head}/${inner.relPath}`,
          exists: inner.exists,
          mountAlias: head,
          mountRoot,
        };
      }
    }
  }

  const local = await resolveSandboxedPath(rootDir, relPath, { allowRoot, mustExist });
  return {
    ...local,
    mountAlias: null,
    mountRoot: path.resolve(rootDir),
  };
}

/**
 * Inspect configured virtual mounts for availability (host paths only included if `includeHostPath: true`).
 * @param {Record<string, string>} mounts
 * @param {{ includeHostPath?: boolean }} [options]
 */
export async function inspectMounts(mounts = {}, { includeHostPath = false } = {}) {
  const results = [];
  for (const [alias, hostDir] of Object.entries(mounts || {})) {
    let available = false;
    let error = null;
    try {
      const st = await fs.stat(hostDir);
      available = st.isDirectory();
      if (!available) {
        error = "Configured path is not a directory";
      }
    } catch (err) {
      error = err?.code === "ENOENT" ? "Directory not found" : err?.message || "Unavailable";
    }
    results.push({
      alias,
      mode: "read_only",
      available,
      ...(error ? { error } : {}),
      ...(includeHostPath ? { host_path: hostDir } : {}),
    });
  }
  return results;
}

/**
 * Resolve attached_files listed on a task so Gemini APP knows exact bucket, existence, size, lines, and sha256.
 * Supports optional explicit bucket prefix `files:a.md`, `notes:b.md`, `repos:app/src/a.js`, or auto-detection.
 * @param {string[]} attachedFiles
 * @param {Record<string, any>} config
 * @param {{ filesRoot?: string }} [options]
 */
export async function resolveTaskAttachmentManifest(attachedFiles = [], config, { filesRoot } = {}) {
  const manifest = [];
  const activeFilesRoot = filesRoot || config.filesRoot;
  const buckets = [
    { name: "files", root: activeFilesRoot, mounts: {}, tool: "read_file" },
    { name: "notes", root: config.notesRoot, mounts: config.noteMounts || {}, tool: "read_note" },
    { name: "repos", root: config.reposRoot, mounts: config.repoMounts || {}, tool: "read_repo_file" },
  ];

  for (const rawRef of attachedFiles) {
    const ref = String(rawRef || "").trim();
    if (!ref) {
      continue;
    }

    let explicitBucket = null;
    let relPath = ref;
    const prefixMatch = ref.match(/^(files|notes|repos):(.+)$/i);
    if (prefixMatch) {
      explicitBucket = prefixMatch[1].toLowerCase();
      relPath = prefixMatch[2].trim();
    }

    const candidates = explicitBucket
      ? buckets.filter((b) => b.name === explicitBucket)
      : buckets;

    let resolvedInfo = null;
    for (const bucket of candidates) {
      try {
        const res = await resolveBucketPath(bucket.root, bucket.mounts, relPath, {
          allowRoot: false,
          mustExist: true,
        });
        const st = await fs.stat(res.fullPath);
        if (!st.isFile()) {
          resolvedInfo = {
            ref,
            bucket: bucket.name,
            path: res.relPath,
            exists: true,
            type: "directory",
            recommended_tool:
              bucket.name === "files"
                ? "list_files"
                : bucket.name === "notes"
                  ? "list_notes"
                  : "list_repo_tree",
          };
          break;
        }
        let lines = null;
        let sha256 = null;
        let binary = false;
        if (st.size <= 5 * 1024 * 1024) {
          const buf = await fs.readFile(res.fullPath);
          binary = isLikelyBinary(buf);
          sha256 = sha256Hex(buf);
          if (!binary) {
            lines = buf.length === 0 ? 0 : buf.toString("utf8").split(/\r?\n/).length;
          }
        }
        resolvedInfo = {
          ref,
          bucket: bucket.name,
          path: res.relPath,
          exists: true,
          type: "file",
          bytes: st.size,
          lines,
          binary,
          sha256,
          recommended_tool: bucket.tool,
        };
        break;
      } catch {
        // Try next candidate bucket.
      }
    }

    if (resolvedInfo) {
      manifest.push(resolvedInfo);
    } else {
      manifest.push({
        ref,
        bucket: explicitBucket || "files",
        path: relPath,
        exists: false,
        recommended_tool:
          explicitBucket === "notes"
            ? "read_note"
            : explicitBucket === "repos"
              ? "read_repo_file"
              : "read_file",
      });
    }
  }

  return manifest;
}

/**
 * Check whether a Markdown document contains a heading or prominent section matching `sectionName`.
 * @param {string} markdown
 * @param {string} sectionName
 * @returns {boolean}
 */
function hasMarkdownSection(markdown, sectionName) {
  const needle = String(sectionName)
    .replace(/^#+\s*/, "")
    .replace(/[*_`]/g, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
  if (!needle) {
    return true;
  }

  const lines = String(markdown).split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      continue;
    }
    const headingMatch = trimmed.match(/^#{1,6}\s+(.+?)\s*#*$/);
    if (headingMatch) {
      const normalized = headingMatch[1]
        .replace(/[*_`]/g, "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
      if (normalized.includes(needle)) {
        return true;
      }
    }
    const boldMatch = trimmed.match(/^\*\*(.+?)\*\*:?$/);
    if (boldMatch) {
      const normalized = boldMatch[1].trim().toLowerCase().replace(/\s+/g, " ");
      if (normalized.includes(needle)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Verify a task deliverable against universal harness invariants and the task's contract.
 */
export async function verifyDeliverable({
  task,
  summary,
  content,
  artifacts = [],
  filesRoot,
  config,
}) {
  const cleanSummary = String(summary ?? "").trim();
  const cleanContent = String(content ?? "");
  const contract = task?.contract || {};
  const checks = [];
  const warnings = [];
  const artifactManifest = [];

  const summaryChars = cleanSummary.length;
  const contentChars = cleanContent.length;
  const contentLines = cleanContent ? cleanContent.split(/\r?\n/).length : 0;
  const contentSha256 = sha256Hex(cleanContent);

  // 1. Validate declared artifacts strictly against FILES_ROOT sandbox.
  const declaredArtifacts = Array.isArray(artifacts)
    ? [...new Set(artifacts.map((a) => String(a ?? "").trim()).filter(Boolean))]
    : [];

  for (const artPath of declaredArtifacts) {
    let resolved;
    try {
      resolved = await resolveSandboxedPath(filesRoot, artPath, {
        allowRoot: false,
        mustExist: false,
      });
    } catch (err) {
      throw new PolicyError(
        `Invalid artifact path '${artPath}': ${err.message}`,
        "invalid_artifact_path"
      );
    }

    if (
      Array.isArray(contract.allowed_write_prefixes) &&
      contract.allowed_write_prefixes.length > 0
    ) {
      const allowed = contract.allowed_write_prefixes.some(
        (prefix) => resolved.relPath === prefix || resolved.relPath.startsWith(`${prefix}/`)
      );
      checks.push({
        name: `artifact_prefix:${resolved.relPath}`,
        passed: allowed,
        detail: allowed
          ? "Within task allowed_write_prefixes"
          : `Outside allowed_write_prefixes (${contract.allowed_write_prefixes.join(", ")})`,
      });
    }

    let exists = false;
    let bytes = 0;
    let sha256 = null;
    if (resolved.exists) {
      const st = await fs.stat(resolved.fullPath);
      if (st.isFile()) {
        exists = true;
        bytes = st.size;
        const buf = await fs.readFile(resolved.fullPath);
        sha256 = sha256Hex(buf);
      }
    }

    artifactManifest.push({
      path: resolved.relPath,
      exists,
      bytes,
      sha256,
    });

    checks.push({
      name: `artifact_exists:${resolved.relPath}`,
      passed: exists,
      detail: exists
        ? `Verified on disk (${bytes} bytes, sha256=${sha256.slice(0, 12)})`
        : `Declared artifact '${resolved.relPath}' does not exist in FILES_ROOT`,
    });
    if (!exists) {
      warnings.push(`Declared artifact '${resolved.relPath}' was not found in FILES_ROOT.`);
    }
  }

  // 2. Check contract.expected_artifacts
  const expectedArtifacts = Array.isArray(contract.expected_artifacts)
    ? contract.expected_artifacts
    : [];
  for (const expPath of expectedArtifacts) {
    let resolved;
    try {
      resolved = await resolveSandboxedPath(filesRoot, expPath, {
        allowRoot: false,
        mustExist: false,
      });
    } catch (err) {
      checks.push({
        name: `expected_artifact:${expPath}`,
        passed: false,
        detail: `Invalid expected artifact path: ${err.message}`,
      });
      continue;
    }

    let exists = false;
    let bytes = 0;
    let sha256 = null;
    if (resolved.exists) {
      const st = await fs.stat(resolved.fullPath);
      if (st.isFile()) {
        exists = true;
        bytes = st.size;
        const buf = await fs.readFile(resolved.fullPath);
        sha256 = sha256Hex(buf);
      }
    }

    if (!artifactManifest.some((m) => m.path === resolved.relPath)) {
      artifactManifest.push({
        path: resolved.relPath,
        exists,
        bytes,
        sha256,
      });
    }

    checks.push({
      name: `expected_artifact:${resolved.relPath}`,
      passed: exists,
      detail: exists
        ? `Expected artifact verified (${bytes} bytes)`
        : `Expected artifact '${resolved.relPath}' is missing from FILES_ROOT`,
    });
    if (!exists) {
      warnings.push(`Expected artifact '${resolved.relPath}' is missing from FILES_ROOT.`);
    }
  }

  // 3. Check contract.required_sections
  const requiredSections = Array.isArray(contract.required_sections)
    ? contract.required_sections
    : [];
  for (const section of requiredSections) {
    const found = hasMarkdownSection(cleanContent, section);
    checks.push({
      name: `required_section:${section}`,
      passed: found,
      detail: found
        ? `Found section '${section}'`
        : `Missing required Markdown section '${section}'`,
    });
    if (!found) {
      warnings.push(`Missing required section heading: '${section}'.`);
    }
  }

  // 4. Check summary budget
  if (contract.max_summary_chars) {
    const ok = summaryChars <= contract.max_summary_chars;
    checks.push({
      name: "max_summary_chars",
      passed: ok,
      detail: `${summaryChars}/${contract.max_summary_chars} chars`,
    });
    if (!ok) {
      warnings.push(
        `Summary (${summaryChars} chars) exceeds contract limit (${contract.max_summary_chars} chars).`
      );
    }
  } else if (summaryChars > DEFAULT_ADVISORY_SUMMARY_CHARS) {
    warnings.push(
      `Summary is long (${summaryChars} chars > recommended ${DEFAULT_ADVISORY_SUMMARY_CHARS}); consider keeping summary compact for low-token Antigravity pickup.`
    );
  }

  // 5. Check min_content_chars
  if (contract.min_content_chars) {
    const ok = contentChars >= contract.min_content_chars;
    checks.push({
      name: "min_content_chars",
      passed: ok,
      detail: `${contentChars}/${contract.min_content_chars} chars`,
    });
    if (!ok) {
      warnings.push(
        `Content (${contentChars} chars) is shorter than contract minimum (${contract.min_content_chars} chars).`
      );
    }
  }

  const failedChecks = checks.filter((c) => !c.passed);
  const passed = failedChecks.length === 0;
  const strictFailed = Boolean(contract.strict_contract) && !passed;

  return {
    passed,
    strict_failed: strictFailed,
    verified_at: new Date().toISOString(),
    checks,
    warnings,
    artifact_manifest: artifactManifest,
    metrics: {
      summary_chars: summaryChars,
      content_chars: contentChars,
      content_lines: contentLines,
      content_sha256: contentSha256,
    },
  };
}

/**
 * Generate a compact unified-style diff preview between two UTF-8 strings.
 * @param {string} beforeText
 * @param {string} afterText
 * @param {string} relPath
 * @param {{ maxLines?: number }} [options]
 */
export function createUnifiedDiffPreview(beforeText, afterText, relPath, { maxLines = 40 } = {}) {
  const beforeLines = beforeText.split(/\r?\n/);
  const afterLines = afterText.split(/\r?\n/);

  let start = 0;
  while (
    start < beforeLines.length &&
    start < afterLines.length &&
    beforeLines[start] === afterLines[start]
  ) {
    start += 1;
  }

  let endBefore = beforeLines.length - 1;
  let endAfter = afterLines.length - 1;
  while (
    endBefore >= start &&
    endAfter >= start &&
    beforeLines[endBefore] === afterLines[endAfter]
  ) {
    endBefore -= 1;
    endAfter -= 1;
  }

  const out = [`--- a/${relPath}`, `+++ b/${relPath}`];
  const ctxStart = Math.max(0, start - 2);
  const ctxEndBefore = Math.min(beforeLines.length - 1, endBefore + 2);
  const ctxEndAfter = Math.min(afterLines.length - 1, endAfter + 2);

  out.push(
    `@@ -${ctxStart + 1},${Math.max(0, ctxEndBefore - ctxStart + 1)} +${ctxStart + 1},${Math.max(0, ctxEndAfter - ctxStart + 1)} @@`
  );

  const body = [];
  for (let i = ctxStart; i < start; i += 1) {
    body.push(` ${beforeLines[i]}`);
  }
  for (let i = start; i <= endBefore; i += 1) {
    body.push(`-${beforeLines[i]}`);
  }
  for (let i = start; i <= endAfter; i += 1) {
    body.push(`+${afterLines[i]}`);
  }
  for (let i = endBefore + 1; i <= ctxEndBefore; i += 1) {
    body.push(` ${beforeLines[i]}`);
  }

  if (body.length > maxLines) {
    out.push(...body.slice(0, maxLines), `...[${body.length - maxLines} more diff lines omitted]`);
  } else {
    out.push(...body);
  }

  return out.join("\n");
}
