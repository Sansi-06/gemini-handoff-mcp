import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { normalizeWritePrefixes } from "./config.mjs";
import { sha256Hex } from "./security.mjs";

const TASK_ID_RE = /^[a-zA-Z0-9_-]{3,80}$/;
const DEFAULT_LEASE_MINUTES = 60;
const MAX_EVENTS_PER_TASK = 100;
const MAX_CHECKPOINTS_PER_TASK = 50;

/**
 * Sleep helper used for bounded Windows rename retry.
 * @param {number} ms
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * In-process per-key async mutex to serialize read-modify-write operations.
 */
export class AsyncKeyLock {
  constructor() {
    this._chains = new Map();
  }

  /**
   * Execute `fn` exclusively for `key`.
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async withLock(key, fn) {
    const prev = this._chains.get(key) || Promise.resolve();
    let release;
    const next = new Promise((resolve) => {
      release = resolve;
    });
    const tail = prev.catch(() => {}).then(() => next);
    this._chains.set(key, tail);

    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
      if (this._chains.get(key) === tail) {
        this._chains.delete(key);
      }
    }
  }
}

/**
 * Write raw bytes atomically via a unique temporary sibling file and rename.
 * Retries transiently on Windows EPERM/EBUSY and cleans up temp file on error.
 * @param {string} targetPath
 * @param {Buffer | Uint8Array | string} data
 */
export async function atomicWriteBuffer(targetPath, data) {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  try {
    await fs.writeFile(tmpPath, data);
    let lastErr = null;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        await fs.rename(tmpPath, targetPath);
        return;
      } catch (err) {
        lastErr = err;
        if ((err?.code === "EPERM" || err?.code === "EBUSY") && attempt < 3) {
          await sleep(20 * (attempt + 1));
          continue;
        }
        throw err;
      }
    }
    throw lastErr;
  } catch (err) {
    await fs.unlink(tmpPath).catch(() => {});
    throw err;
  }
}

/**
 * Write a UTF-8 text file atomically via a unique temporary sibling file and rename.
 * @param {string} targetPath
 * @param {string} content
 */
export async function atomicWriteFile(targetPath, content) {
  await atomicWriteBuffer(targetPath, Buffer.from(String(content), "utf8"));
}

/**
 * Format UTC timestamp part YYYYMMDD_HHMMSS for human-sortable task IDs.
 * @param {Date} [date]
 * @returns {string}
 */
function formatTimestampId(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}_` +
    `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`
  );
}

/**
 * Normalize optional deliverable verification contract attached to a task.
 * @param {Record<string, any> | undefined | null} raw
 */
export function normalizeTaskContract(raw) {
  if (!raw || typeof raw !== "object") {
    return {
      required_sections: [],
      expected_artifacts: [],
      max_summary_chars: null,
      min_content_chars: null,
      allowed_write_prefixes: [],
      strict_contract: false,
    };
  }

  const toStringList = (val) =>
    Array.isArray(val)
      ? [...new Set(val.map((s) => String(s ?? "").trim()).filter(Boolean))]
      : [];

  const toOptionalPositiveInt = (val, max) => {
    if (val === undefined || val === null || val === "") {
      return null;
    }
    const n = Number(val);
    if (!Number.isFinite(n) || n <= 0) {
      return null;
    }
    return Math.min(max, Math.trunc(n));
  };

  return {
    required_sections: toStringList(raw.required_sections),
    expected_artifacts: toStringList(raw.expected_artifacts),
    max_summary_chars: toOptionalPositiveInt(raw.max_summary_chars, 50_000),
    min_content_chars: toOptionalPositiveInt(raw.min_content_chars, 1_000_000),
    allowed_write_prefixes: normalizeWritePrefixes(raw.allowed_write_prefixes),
    strict_contract: Boolean(raw.strict_contract),
  };
}

/**
 * Determine whether an active task lease has expired.
 * @param {Record<string, any>} task
 * @returns {boolean}
 */
export function isTaskLeaseStale(task) {
  if (task?.status !== "in_progress" || !task?.lease_expires_at) {
    return false;
  }
  const expiresMs = Date.parse(task.lease_expires_at);
  return Number.isFinite(expiresMs) && expiresMs < Date.now();
}

/**
 * Append a bounded audit event onto a task metadata object.
 */
function appendTaskEvent(task, type, actor, detail = null) {
  if (!Array.isArray(task.events)) {
    task.events = [];
  }
  task.events.push({
    ts: new Date().toISOString(),
    type,
    actor: actor || "system",
    ...(detail ? { detail } : {}),
  });
  if (task.events.length > MAX_EVENTS_PER_TASK) {
    task.events = task.events.slice(-MAX_EVENTS_PER_TASK);
  }
}

/**
 * Persistent file-backed task handoff queue between Antigravity and Gemini APP.
 */
export class TaskStore {
  /**
   * @param {string} tasksDir
   */
  constructor(tasksDir) {
    this.tasksDir = path.resolve(tasksDir);
    this._lock = new AsyncKeyLock();
  }

  /**
   * Validate task ID to prevent path traversal or invalid filenames.
   * @param {string} taskId
   * @returns {string}
   */
  validateTaskId(taskId) {
    if (typeof taskId !== "string" || !TASK_ID_RE.test(taskId)) {
      throw new Error("Invalid task_id format. Expected 3-80 alphanumeric, '_' or '-' characters.");
    }
    return taskId;
  }

  /**
   * @param {string} taskId
   * @returns {string}
   */
  #metaPath(taskId) {
    this.validateTaskId(taskId);
    return path.join(this.tasksDir, `${taskId}.json`);
  }

  /**
   * @param {string} taskId
   * @returns {string}
   */
  #resultPath(taskId) {
    this.validateTaskId(taskId);
    return path.join(this.tasksDir, `${taskId}.result.md`);
  }

  /**
   * @param {string} taskId
   */
  async #readMeta(taskId) {
    const filePath = this.#metaPath(taskId);
    let raw;
    try {
      raw = await fs.readFile(filePath, "utf8");
    } catch (err) {
      if (err?.code === "ENOENT") {
        throw new Error(`Task not found: ${taskId}`);
      }
      throw err;
    }
    const task = JSON.parse(raw);
    task.revision = Number.isInteger(task.revision) ? task.revision : 1;
    task.contract = normalizeTaskContract(task.contract);
    task.checkpoints = Array.isArray(task.checkpoints) ? task.checkpoints : [];
    task.events = Array.isArray(task.events) ? task.events : [];
    task.result_artifacts = Array.isArray(task.result_artifacts) ? task.result_artifacts : [];
    task.result_artifact_manifest = Array.isArray(task.result_artifact_manifest)
      ? task.result_artifact_manifest
      : [];
    return task;
  }

  /**
   * @param {Record<string, any>} task
   */
  async #writeMeta(task) {
    await atomicWriteFile(this.#metaPath(task.id), `${JSON.stringify(task, null, 2)}\n`);
  }

  /**
   * Create a new delegated task in the handoff queue.
   * @param {object} input
   * @param {{ actor?: string }} [options]
   */
  async createTask(input, { actor = "admin" } = {}) {
    const title = String(input?.title ?? "").trim();
    const objective = String(input?.objective ?? "").trim();
    if (!title || !objective) {
      throw new Error("Both 'title' and 'objective' are required to create a task");
    }

    const now = new Date();
    const id = `task_${formatTimestampId(now)}_${crypto.randomBytes(2).toString("hex")}`;
    const priority = ["low", "normal", "high"].includes(input?.priority)
      ? input.priority
      : "normal";

    const attachedFiles = Array.isArray(input?.attached_files)
      ? input.attached_files.map((item) => String(item).trim()).filter(Boolean)
      : [];

    const account = String(input?.account ?? "").trim().toLowerCase() || "default";
    const rawTags = Array.isArray(input?.tags)
      ? input.tags.map((item) => String(item).trim()).filter(Boolean)
      : [];
    const tags = [
      ...new Set([
        ...rawTags,
        ...(account !== "default" ? [`account:${account}`] : []),
      ]),
    ];

    const contract = normalizeTaskContract(input?.contract);

    const task = {
      id,
      revision: 1,
      account,
      title,
      objective,
      instructions: String(input?.instructions ?? "").trim(),
      output_format: String(
        input?.output_format ??
          "Structured Markdown with executive summary, key findings, evidence, and actionable next steps."
      ).trim(),
      context: String(input?.context ?? "").trim(),
      attached_files: attachedFiles,
      priority,
      tags,
      contract,
      status: "pending",
      progress_percent: 0,
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      claimed_at: null,
      claim_note: null,
      lease_expires_at: null,
      completed_at: null,
      archived_at: null,
      result_summary: null,
      result_sha256: null,
      result_bytes: null,
      result_artifacts: [],
      result_artifact_manifest: [],
      verification: null,
      checkpoints: [],
      events: [
        {
          ts: now.toISOString(),
          type: "created",
          actor,
          detail: { priority, attached_count: attachedFiles.length, strict_contract: contract.strict_contract },
        },
      ],
    };

    await this.#writeMeta(task);
    return task;
  }

  /**
   * Submit an architectural proposal, design specification, or research roadmap initiated in Gemini APP.
   * @param {object} input
   * @param {{ actor?: string, account?: string }} [options]
   */
  async createProposal(input, { actor = "gemini_app", account = "default" } = {}) {
    const title = String(input?.title ?? "").trim();
    const summary = String(input?.summary ?? "").trim();
    const planMarkdown = String(input?.plan_markdown ?? "").trim();
    if (!title || !summary || !planMarkdown) {
      throw new Error("Both 'title', 'summary', and 'plan_markdown' are required to propose a task");
    }

    const now = new Date();
    const id = `task_${formatTimestampId(now)}_${crypto.randomBytes(2).toString("hex")}`;
    const priority = ["low", "normal", "high"].includes(input?.priority)
      ? input.priority
      : "normal";

    const attachedFiles = Array.isArray(input?.attached_files)
      ? input.attached_files.map((item) => String(item).trim()).filter(Boolean)
      : [];

    const chosenAccount = String(account || input?.account || "default").trim().toLowerCase() || "default";
    const rawTags = Array.isArray(input?.tags) ? input.tags : [];
    const tags = [
      ...new Set([
        "proposal",
        "from_gemini",
        ...(chosenAccount !== "default" ? [`account:${chosenAccount}`] : []),
        ...rawTags.map((t) => String(t).trim()).filter(Boolean),
      ]),
    ];

    await atomicWriteFile(this.#resultPath(id), planMarkdown);

    const task = {
      id,
      revision: 1,
      account: chosenAccount,
      source: "gemini_app",
      title,
      objective: summary,
      instructions: String(
        input?.suggested_actions ?? "Review proposal and execute implementation in Antigravity."
      ).trim(),
      output_format: "Implementation Report and Code Deliverables",
      context: "",
      attached_files: attachedFiles,
      priority,
      tags,
      contract: normalizeTaskContract(null),
      status: "proposed",
      progress_percent: 0,
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      claimed_at: null,
      claim_note: null,
      lease_expires_at: null,
      completed_at: null,
      archived_at: null,
      result_summary: summary,
      result_sha256: sha256Hex(planMarkdown),
      result_bytes: Buffer.byteLength(planMarkdown, "utf8"),
      result_artifacts: attachedFiles,
      result_artifact_manifest: [],
      verification: null,
      checkpoints: [],
      events: [
        {
          ts: now.toISOString(),
          type: "proposed_by_gemini",
          actor,
          detail: { priority, attached_count: attachedFiles.length },
        },
      ],
    };

    await this.#writeMeta(task);
    return task;
  }

  /**
   * List tasks filtered by status, optional tag, and optional account, sorted newest first.
   * @param {{ status?: string, limit?: number, tag?: string, account?: string }} [options]
   */
  async listTasks({ status = "pending", limit = 20, tag = "", account = "" } = {}) {
    await fs.mkdir(this.tasksDir, { recursive: true });
    const entries = await fs.readdir(this.tasksDir, { withFileTypes: true });
    const tasks = [];
    const normalizedTag = String(tag || "").trim().toLowerCase();
    const normalizedAccount = String(account || "").trim().toLowerCase();

    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".json")) {
        continue;
      }
      try {
        const raw = await fs.readFile(path.join(this.tasksDir, entry.name), "utf8");
        const task = JSON.parse(raw);
        if (task.status === "deleted") {
          continue;
        }
        if (status && status !== "all" && task.status !== status) {
          continue;
        }
        const taskTags = Array.isArray(task.tags) ? task.tags : [];
        if (normalizedTag && !taskTags.some((t) => String(t).toLowerCase() === normalizedTag)) {
          continue;
        }
        if (normalizedAccount && normalizedAccount !== "all") {
          const taskAccount = String(task.account || "default").toLowerCase();
          if (taskAccount !== normalizedAccount) {
            continue;
          }
        }
        const contract = normalizeTaskContract(task.contract);
        const hasContract =
          contract.required_sections.length > 0 ||
          contract.expected_artifacts.length > 0 ||
          contract.max_summary_chars !== null ||
          contract.min_content_chars !== null ||
          contract.allowed_write_prefixes.length > 0;

        tasks.push({
          id: task.id,
          account: task.account || "default",
          revision: Number.isInteger(task.revision) ? task.revision : 1,
          title: task.title,
          status: task.status,
          priority: task.priority,
          tags: taskTags,
          attached_files: task.attached_files ?? [],
          progress_percent: task.progress_percent ?? null,
          lease_expires_at: task.lease_expires_at ?? null,
          lease_stale: isTaskLeaseStale(task),
          has_contract: hasContract,
          strict_contract: contract.strict_contract,
          verification_passed: task.verification ? Boolean(task.verification.passed) : null,
          created_at: task.created_at,
          updated_at: task.updated_at,
          completed_at: task.completed_at,
          result_summary: task.result_summary,
        });
      } catch {
        // Ignore malformed metadata files rather than crashing listing.
      }
    }

    tasks.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
    return tasks.slice(0, safeLimit);
  }

  /**
   * Compute aggregate queue statistics for harness diagnostics.
   * @param {{ account?: string }} [options]
   */
  async getQueueStats({ account = "" } = {}) {
    const all = await this.listTasks({ status: "all", limit: 100, account });
    const counts = {
      pending: 0,
      in_progress: 0,
      needs_input: 0,
      proposed: 0,
      completed: 0,
      failed: 0,
      archived: 0,
      stale_leases: 0,
      total: all.length,
    };
    for (const t of all) {
      if (Object.prototype.hasOwnProperty.call(counts, t.status)) {
        counts[t.status] += 1;
      }
      if (t.lease_stale) {
        counts.stale_leases += 1;
      }
    }
    return {
      counts,
      active_tasks: all
        .filter((t) => ["pending", "in_progress", "needs_input"].includes(t.status))
        .slice(0, 10)
        .map((t) => ({
          id: t.id,
          title: t.title,
          status: t.status,
          priority: t.priority,
          progress_percent: t.progress_percent,
          lease_stale: t.lease_stale,
        })),
    };
  }

  /**
   * Retrieve full task specification and markdown result (if available).
   * @param {string} taskId
   * @param {{ includeResultMarkdown?: boolean }} [options]
   */
  async getTask(taskId, { includeResultMarkdown = true } = {}) {
    const task = await this.#readMeta(taskId);
    let resultMarkdown = null;
    if (includeResultMarkdown) {
      try {
        resultMarkdown = await fs.readFile(this.#resultPath(taskId), "utf8");
      } catch (err) {
        if (err?.code !== "ENOENT") {
          throw err;
        }
      }
    }
    return {
      ...task,
      lease_stale: isTaskLeaseStale(task),
      result_markdown: resultMarkdown,
    };
  }

  /**
   * Claim a task and mark it in_progress with an active lease timestamp.
   * @param {string} taskId
   * @param {string} [note]
   * @param {{ actor?: string, force?: boolean, leaseMinutes?: number }} [options]
   */
  async claimTask(taskId, note = "", { actor = "mcp", force = false, leaseMinutes = DEFAULT_LEASE_MINUTES } = {}) {
    this.validateTaskId(taskId);
    return this._lock.withLock(taskId, async () => {
      const task = await this.#readMeta(taskId);
      if (task.status === "archived") {
        throw new Error(`Cannot claim archived task: ${taskId}`);
      }
      if (task.status === "completed" && !force) {
        throw new Error(
          `Task ${taskId} is already completed. Pass force=true or reopen via admin API to re-run it.`
        );
      }
      const nowMs = Date.now();
      const now = new Date(nowMs).toISOString();
      const safeLeaseMins = Math.max(5, Math.min(24 * 60, Math.trunc(Number(leaseMinutes) || DEFAULT_LEASE_MINUTES)));
      const prevStatus = task.status;

      task.status = "in_progress";
      task.claimed_at = task.claimed_at || now;
      task.lease_expires_at = new Date(nowMs + safeLeaseMins * 60 * 1000).toISOString();
      task.updated_at = now;
      task.revision += 1;
      if (note && String(note).trim()) {
        task.claim_note = String(note).trim();
      }
      appendTaskEvent(task, "claimed", actor, {
        from: prevStatus,
        note: task.claim_note || undefined,
        lease_minutes: safeLeaseMins,
      });

      await this.#writeMeta(task);
      return task;
    });
  }

  /**
   * Record incremental progress, request human/Antigravity input, or mark a task failed.
   * @param {string} taskId
   * @param {{
   *   note: string,
   *   status?: "in_progress" | "needs_input" | "failed",
   *   percent?: number,
   *   questions?: string[],
   *   partial_artifacts?: string[],
   *   actor?: string,
   *   leaseMinutes?: number
   * }} payload
   */
  async checkpointTask(
    taskId,
    {
      note,
      status = "in_progress",
      percent,
      questions = [],
      partial_artifacts = [],
      actor = "mcp",
      leaseMinutes = DEFAULT_LEASE_MINUTES,
    }
  ) {
    this.validateTaskId(taskId);
    const cleanNote = String(note ?? "").trim();
    if (!cleanNote) {
      throw new Error("Checkpoint 'progress_note' cannot be empty");
    }
    if (!["in_progress", "needs_input", "failed"].includes(status)) {
      throw new Error(`Invalid checkpoint status '${status}'. Expected in_progress, needs_input, or failed.`);
    }

    return this._lock.withLock(taskId, async () => {
      const task = await this.#readMeta(taskId);
      if (task.status === "archived" || task.status === "completed") {
        throw new Error(`Cannot checkpoint task in '${task.status}' state: ${taskId}`);
      }

      const nowMs = Date.now();
      const now = new Date(nowMs).toISOString();
      const cleanQuestions = Array.isArray(questions)
        ? questions.map((q) => String(q ?? "").trim()).filter(Boolean)
        : [];
      const cleanPartials = Array.isArray(partial_artifacts)
        ? partial_artifacts.map((a) => String(a ?? "").trim()).filter(Boolean)
        : [];

      let cleanPercent = task.progress_percent ?? null;
      if (percent !== undefined && percent !== null && percent !== "") {
        const num = Number(percent);
        if (Number.isFinite(num)) {
          cleanPercent = Math.max(0, Math.min(100, Math.trunc(num)));
        }
      }

      const checkpoint = {
        ts: now,
        status,
        note: cleanNote,
        percent: cleanPercent,
        questions: cleanQuestions,
        partial_artifacts: cleanPartials,
        actor,
      };

      task.status = status;
      task.progress_percent = cleanPercent;
      task.updated_at = now;
      task.revision += 1;
      if (status === "in_progress") {
        const safeLeaseMins = Math.max(5, Math.min(24 * 60, Math.trunc(Number(leaseMinutes) || DEFAULT_LEASE_MINUTES)));
        task.lease_expires_at = new Date(nowMs + safeLeaseMins * 60 * 1000).toISOString();
      } else {
        task.lease_expires_at = null;
      }

      task.checkpoints.push(checkpoint);
      if (task.checkpoints.length > MAX_CHECKPOINTS_PER_TASK) {
        task.checkpoints = task.checkpoints.slice(-MAX_CHECKPOINTS_PER_TASK);
      }

      appendTaskEvent(task, `checkpoint:${status}`, actor, {
        percent: cleanPercent,
        questions_count: cleanQuestions.length,
      });

      await this.#writeMeta(task);
      return { task, checkpoint };
    });
  }

  /**
   * Persist completed deliverable markdown, concise summary, and verification manifest.
   * @param {string} taskId
   * @param {{
   *   summary: string,
   *   content: string,
   *   artifacts?: string[],
   *   artifact_manifest?: Array<Record<string, any>>,
   *   verification?: Record<string, any> | null,
   *   actor?: string
   * }} payload
   */
  async submitTaskResult(
    taskId,
    { summary, content, artifacts = [], artifact_manifest = [], verification = null, actor = "mcp" }
  ) {
    this.validateTaskId(taskId);
    const cleanSummary = String(summary ?? "").trim();
    const cleanContent = String(content ?? "");
    if (!cleanSummary || !cleanContent.trim()) {
      throw new Error("Both 'summary' and 'content' are required when submitting task results");
    }

    return this._lock.withLock(taskId, async () => {
      const task = await this.#readMeta(taskId);
      if (task.status === "archived") {
        throw new Error(`Cannot submit result for archived task: ${taskId}`);
      }
      const now = new Date().toISOString();

      await atomicWriteFile(this.#resultPath(taskId), cleanContent);

      task.status = "completed";
      task.progress_percent = 100;
      task.lease_expires_at = null;
      task.completed_at = now;
      task.updated_at = now;
      task.revision += 1;
      task.result_summary = cleanSummary;
      task.result_sha256 = sha256Hex(cleanContent);
      task.result_bytes = Buffer.byteLength(cleanContent, "utf8");
      task.result_artifacts = Array.isArray(artifacts)
        ? artifacts.map((item) => String(item).trim()).filter(Boolean)
        : [];
      task.result_artifact_manifest = Array.isArray(artifact_manifest) ? artifact_manifest : [];
      task.verification = verification;

      appendTaskEvent(task, "completed", actor, {
        result_bytes: task.result_bytes,
        artifacts_count: task.result_artifacts.length,
        verification_passed: verification ? Boolean(verification.passed) : null,
      });

      await this.#writeMeta(task);
      return {
        ...task,
        result_file: `${taskId}.result.md`,
      };
    });
  }

  /**
   * Reopen a task (or answer a needs_input task) back to pending with operator feedback.
   * @param {string} taskId
   * @param {{ message?: string, actor?: string }} [options]
   */
  async reopenTask(taskId, { message = "", actor = "admin" } = {}) {
    this.validateTaskId(taskId);
    return this._lock.withLock(taskId, async () => {
      const task = await this.#readMeta(taskId);
      if (task.status === "archived") {
        throw new Error(`Cannot reopen archived task: ${taskId}`);
      }
      const now = new Date().toISOString();
      const prevStatus = task.status;
      const cleanMessage = String(message ?? "").trim();

      task.status = "pending";
      task.lease_expires_at = null;
      task.updated_at = now;
      task.revision += 1;
      if (cleanMessage) {
        const block = `[Operator follow-up ${now}]\n${cleanMessage}`;
        task.context = task.context ? `${task.context}\n\n${block}` : block;
      }

      appendTaskEvent(task, "reopened", actor, {
        from: prevStatus,
        has_message: Boolean(cleanMessage),
      });

      await this.#writeMeta(task);
      return task;
    });
  }

  /**
   * Archive a task without deleting its artifacts from disk.
   * @param {string} taskId
   * @param {{ actor?: string }} [options]
   */
  async archiveTask(taskId, { actor = "admin" } = {}) {
    this.validateTaskId(taskId);
    return this._lock.withLock(taskId, async () => {
      const task = await this.#readMeta(taskId);
      const now = new Date().toISOString();
      task.status = "archived";
      task.lease_expires_at = null;
      task.archived_at = now;
      task.updated_at = now;
      task.revision += 1;
      appendTaskEvent(task, "archived", actor);
      await this.#writeMeta(task);
      return task;
    });
  }
}
