import crypto from "node:crypto";
import { APP_VERSION, resolveAccountByPathKey } from "./config.mjs";
import { SlidingWindowRateLimiter } from "./harness.mjs";
import { readRawBody, sendJson, sendText } from "./http-utils.mjs";
import { getBaseUrl, verifyBearerToken } from "./oauth.mjs";
import { createToolRegistry } from "./tools.mjs";

const MCP_MAX_BODY_BYTES = 3 * 1024 * 1024;
const SUPPORTED_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_VERSION = "2025-11-25";
const DEFAULT_SESSION_TTL_MS = 20 * 60 * 1000;
const DEFAULT_ZERO_CALL_SESSION_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_SESSIONS = 256;

const SERVER_INSTRUCTIONS = [
  `You are connected to Gemini Handoff MCP v${APP_VERSION} (Deterministic Agent Harness connecting Antigravity / local IDEs and Gemini APP).`,
  "1. Call `get_workspace_status` for an instant map of active guardrails, queues, mounts, and buckets.",
  "2. For delegated tasks: call `get_task` (check `attachment_manifest` and `contract`), then `claim_task`. Use `checkpoint_task` to save progress or ask clarifying questions (`status='needs_input'`).",
  "3. When modifying existing files in FILES_ROOT, prefer `edit_file` with `expected_sha256` from `read_file` (or `dry_run=true`) instead of full rewrites; automatic pre-write snapshots enable rollback via `list_file_snapshots` / `restore_file_snapshot`.",
  "4. Finish with `submit_task_result` (concise high-signal `summary` + full Markdown `content` + verified `artifacts`) and inspect the returned `verification` report.",
  "5. NOTES_ROOT / NOTE_MOUNTS and REPOS_ROOT / REPO_MOUNTS are strictly read-only.",
].join(" ");

const MCP_RESOURCES = [
  {
    uri: "bridge://harness/status",
    name: "Harness & Workspace Status",
    description:
      "Live snapshot of Gemini Handoff guardrails, queue counts, available repos/mounts/notes/files, and telemetry.",
    mimeType: "application/json",
  },
  {
    uri: "bridge://tasks/queue",
    name: "Active Task Queue",
    description: "Current pending, in_progress, and needs_input tasks awaiting action.",
    mimeType: "application/json",
  },
];

const MCP_PROMPTS = [
  {
    name: "execute_task",
    description:
      "Deterministic step-by-step protocol to claim, research, verify, and submit a delegated Gemini Handoff task.",
    arguments: [
      {
        name: "task_id",
        description: "Task identifier to execute (optional; if omitted, lists pending tasks first).",
        required: false,
      },
    ],
  },
  {
    name: "workspace_briefing",
    description:
      "Inspect current Gemini Bridge harness guardrails, mounted repos/notes, and pending queue items.",
    arguments: [],
  },
];

/**
 * Create a JSON-RPC 2.0 error object.
 */
function rpcError(id, code, message, data) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {}),
    },
  };
}

/**
 * Create a JSON-RPC 2.0 success response object.
 */
function rpcResult(id, result) {
  return {
    jsonrpc: "2.0",
    id,
    result,
  };
}

/**
 * Negotiate MCP protocol version from request params or header.
 */
function negotiateVersion(requested) {
  if (typeof requested === "string" && SUPPORTED_VERSIONS.includes(requested)) {
    return requested;
  }
  return DEFAULT_VERSION;
}

/**
 * Build Streamable HTTP `/mcp` handler bound to TaskStore, OAuthManager, Harness components, and config.
 * @param {{
 *   store: import("./store.mjs").TaskStore,
 *   oauth: import("./oauth.mjs").OAuthManager,
 *   config: Record<string, any>,
 *   audit?: import("./harness.mjs").AuditLogger,
 *   snapshots?: import("./harness.mjs").SnapshotStore
 * }} deps
 */
export function createMcpHandler({ store, oauth, config, audit, snapshots }) {
  const sessions = new Map();
  const sessionTtlMs = config.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const zeroCallSessionTtlMs = config.zeroCallSessionTtlMs ?? DEFAULT_ZERO_CALL_SESSION_TTL_MS;
  const maxSessions = config.maxSessions ?? DEFAULT_MAX_SESSIONS;
  const toolRateLimiter = new SlidingWindowRateLimiter({
    maxRequests: config.maxToolCallsPerMinute ?? 120,
    windowMs: 60 * 1000,
  });
  const pathAuthFailureLimiter = new SlidingWindowRateLimiter({
    maxRequests: config.oauthMaxFailedAuth ?? 15,
    windowMs: 15 * 60 * 1000,
  });

  function pruneSessions() {
    const now = Date.now();
    const idleCutoff = now - sessionTtlMs;
    const zeroCallCutoff = now - zeroCallSessionTtlMs;
    for (const [id, rec] of sessions) {
      const cutoff = rec.toolCalls === 0 ? zeroCallCutoff : idleCutoff;
      if (rec.lastSeenAt < cutoff) {
        sessions.delete(id);
      }
    }
    while (sessions.size > maxSessions) {
      const oldestKey = sessions.keys().next().value;
      if (!oldestKey) {
        break;
      }
      sessions.delete(oldestKey);
    }
  }

  const sweepTimer = setInterval(pruneSessions, 60 * 1000);
  sweepTimer.unref?.();

  function getSessionSummary({ includeDetails = false, actorFilter = "" } = {}) {
    pruneSessions();
    if (!includeDetails) {
      let count = 0;
      for (const rec of sessions.values()) {
        if (!actorFilter || rec.actor === actorFilter) {
          count += 1;
        }
      }
      return { active_count: count };
    }
    const list = [];
    for (const [id, rec] of sessions) {
      if (actorFilter && rec.actor !== actorFilter) {
        continue;
      }
      list.push({
        session_id: id,
        actor: rec.actor,
        client_name: rec.clientName,
        protocol_version: rec.protocolVersion,
        tool_calls: rec.toolCalls,
        created_at: new Date(rec.createdAt).toISOString(),
        last_seen_at: new Date(rec.lastSeenAt).toISOString(),
      });
    }
    return {
      active_count: list.length,
      sessions: list.slice(-20),
    };
  }

  const registry = createToolRegistry({
    store,
    config,
    audit,
    snapshots,
    getSessionSummary,
  });

  /**
   * Process a single parsed JSON-RPC 2.0 request or notification.
   */
  async function handleMessage(msg, req, reqContext) {
    if (!msg || typeof msg !== "object" || Array.isArray(msg) || msg.jsonrpc !== "2.0") {
      return { response: rpcError(null, -32600, "Invalid JSON-RPC 2.0 request") };
    }

    const hasId = Object.prototype.hasOwnProperty.call(msg, "id");
    const method = msg.method;
    if (typeof method !== "string" || !method) {
      return {
        response: hasId ? rpcError(msg.id, -32600, "Missing JSON-RPC method") : null,
      };
    }

    // Notifications omit `id` and expect no JSON-RPC response body.
    if (!hasId) {
      return { response: null };
    }

    const params = msg.params ?? {};

    switch (method) {
      case "initialize": {
        pruneSessions();
        const version = negotiateVersion(params.protocolVersion);
        const sessionId = crypto.randomUUID();
        const now = Date.now();
        sessions.set(sessionId, {
          protocolVersion: version,
          actor: reqContext.actor,
          clientName: String(params?.clientInfo?.name || "unknown-mcp-client").slice(0, 100),
          createdAt: now,
          lastSeenAt: now,
          toolCalls: 0,
        });
        return {
          sessionId,
          protocolVersion: version,
          response: rpcResult(msg.id, {
            protocolVersion: version,
            capabilities: {
              tools: { listChanged: false },
              resources: { listChanged: false },
              prompts: { listChanged: false },
            },
            serverInfo: {
              name: "gemini-handoff-mcp",
              version: APP_VERSION,
              icons: [
                {
                  src: `${getBaseUrl(req, config)}/assets/logo.svg`,
                  mimeType: "image/svg+xml",
                  sizes: ["any"],
                },
              ],
            },
            instructions: SERVER_INSTRUCTIONS,
          }),
        };
      }

      case "ping":
        return { response: rpcResult(msg.id, {}) };

      case "tools/list":
        return { response: rpcResult(msg.id, { tools: registry.listTools() }) };

      case "tools/call": {
        if (typeof params.name !== "string" || !params.name) {
          return { response: rpcError(msg.id, -32602, "Invalid params: 'name' must be a string") };
        }
        if (
          params.arguments !== undefined &&
          (typeof params.arguments !== "object" ||
            params.arguments === null ||
            Array.isArray(params.arguments))
        ) {
          return {
            response: rpcError(msg.id, -32602, "Invalid params: 'arguments' must be an object"),
          };
        }

        const quota = toolRateLimiter.consume(reqContext.actor);
        if (!quota.allowed) {
          const retrySec = Math.ceil(quota.retryAfterMs / 1000);
          const errMsg = `Rate limit exceeded (${quota.limit} tool calls/min). Retry in ${retrySec}s.`;
          audit?.log({
            category: "mcp_tool",
            action: params.name,
            status: "blocked",
            actor: reqContext.actor,
            session_id: reqContext.sessionId,
            trace_id: reqContext.traceId,
            error: errMsg,
          });
          return {
            response: rpcResult(msg.id, {
              content: [{ type: "text", text: `Policy blocked (${params.name}): ${errMsg}` }],
              isError: true,
            }),
          };
        }

        if (reqContext.sessionRecord) {
          reqContext.sessionRecord.toolCalls += 1;
        }

        const toolResult = await registry.callTool(params.name, params.arguments ?? {}, {
          actor: reqContext.actor,
          account: reqContext.account,
          authMode: reqContext.authMode,
          sessionId: reqContext.sessionId,
          traceId: reqContext.traceId,
        });
        return {
          response: rpcResult(msg.id, {
            content: [{ type: "text", text: toolResult.text }],
            ...(toolResult.isError ? { isError: true } : {}),
          }),
        };
      }

      case "resources/list":
        return { response: rpcResult(msg.id, { resources: MCP_RESOURCES }) };

      case "resources/read": {
        const uri = params?.uri;
        if (typeof uri !== "string" || !uri) {
          return { response: rpcError(msg.id, -32602, "Invalid params: 'uri' must be a string") };
        }
        const startMs = Date.now();
        if (uri === "bridge://harness/status") {
          const isAdmin = reqContext.authMode === "admin";
          const scopedAccount = isAdmin || config?.tenantIsolation === false ? "" : reqContext.account;
          const status = await registry.buildWorkspaceStatus({
            includeHostPaths: false,
            includeAdminMeta: isAdmin,
            account: scopedAccount,
            actor: reqContext.actor,
          });
          audit?.log({
            category: "mcp_resource",
            action: uri,
            status: "ok",
            actor: reqContext.actor,
            session_id: reqContext.sessionId,
            duration_ms: Date.now() - startMs,
          });
          return {
            response: rpcResult(msg.id, {
              contents: [
                {
                  uri,
                  mimeType: "application/json",
                  text: JSON.stringify(status, null, 2),
                },
              ],
            }),
          };
        }
        if (uri === "bridge://tasks/queue") {
          const isAdmin = reqContext.authMode === "admin";
          const scopedAccount = isAdmin || config?.tenantIsolation === false ? "" : reqContext.account;
          const queue = await store.getQueueStats({ account: scopedAccount });
          audit?.log({
            category: "mcp_resource",
            action: uri,
            status: "ok",
            actor: reqContext.actor,
            session_id: reqContext.sessionId,
            duration_ms: Date.now() - startMs,
          });
          return {
            response: rpcResult(msg.id, {
              contents: [
                {
                  uri,
                  mimeType: "application/json",
                  text: JSON.stringify(queue, null, 2),
                },
              ],
            }),
          };
        }
        return { response: rpcError(msg.id, -32602, `Unknown resource URI: ${uri}`) };
      }

      case "prompts/list":
        return { response: rpcResult(msg.id, { prompts: MCP_PROMPTS }) };

      case "prompts/get": {
        const promptName = params?.name;
        const promptArgs = params?.arguments ?? {};
        if (promptName === "execute_task") {
          const taskId = String(promptArgs.task_id || "").trim();
          const step1 = taskId
            ? `1. Call get_task(task_id="${taskId}") and inspect its objective, contract, and attachment_manifest.`
            : `1. Call list_tasks(status="pending") to select a task, then call get_task(task_id) and inspect its contract and attachment_manifest.`;
          return {
            response: rpcResult(msg.id, {
              description: "Deterministic task execution workflow for Gemini Bridge",
              messages: [
                {
                  role: "user",
                  content: {
                    type: "text",
                    text: [
                      step1,
                      "2. Call claim_task(task_id) before starting deep work.",
                      "3. Read required context using read_file / search_files / list_notes / search_notes / read_note / list_repo_tree / read_repo_file / search_repo_code.",
                      "4. If the task is long or blocked, call checkpoint_task(task_id, progress_note, status='in_progress' | 'needs_input', questions=[...]).",
                      "5. When writing artifacts to FILES_ROOT, use write_file or edit_file (with expected_sha256 for safety).",
                      "6. Call submit_task_result(task_id, summary, content, artifacts) and verify all checks in the returned verification object pass.",
                    ].join("\n"),
                  },
                },
              ],
            }),
          };
        }
        if (promptName === "workspace_briefing") {
          return {
            response: rpcResult(msg.id, {
              description: "Inspect Gemini Bridge workspace state",
              messages: [
                {
                  role: "user",
                  content: {
                    type: "text",
                    text: "Call get_workspace_status() and summarize active guardrails, mounted repos/notes, and pending/in_progress/needs_input tasks.",
                  },
                },
              ],
            }),
          };
        }
        return { response: rpcError(msg.id, -32602, `Unknown prompt: ${promptName}`) };
      }

      default:
        return { response: rpcError(msg.id, -32601, `Method not found: ${method}`) };
    }
  }

  /**
   * Handle incoming HTTP request targeting `/mcp` or `/mcp/u/<key>`.
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:http").ServerResponse} res
   * @param {{ pathKey?: string }} [options]
   */
  async function handleMcpRequest(req, res, options = {}) {
    let auth;
    if (options.pathKey !== undefined) {
      const peerKey = String(req.socket?.remoteAddress || "unknown").slice(0, 64);
      const failStatus = pathAuthFailureLimiter.peek(peerKey);
      if (failStatus.limit > 0 && failStatus.remaining <= 0) {
        audit?.log({
          category: "mcp_auth",
          action: "path_key",
          status: "blocked",
          actor: peerKey,
          error: "Too many invalid MCP account key attempts",
        });
        sendJson(
          res,
          429,
          { error: "too_many_requests", message: "Too many invalid MCP account key attempts" },
          { "Retry-After": "900" }
        );
        return;
      }

      const matched = resolveAccountByPathKey(options.pathKey, config);
      if (!matched) {
        pathAuthFailureLimiter.consume(peerKey);
        audit?.log({
          category: "mcp_auth",
          action: "path_key",
          status: "blocked",
          actor: peerKey,
          error: "Invalid or revoked MCP account key",
        });
        sendJson(res, 403, {
          error: "forbidden",
          message: "Invalid or revoked MCP account key",
        });
        return;
      }

      auth = {
        ok: true,
        mode: "path_key",
        scope: "mcp:tools",
        accountId: matched.name,
      };
    } else {
      auth = verifyBearerToken(req, config, oauth);
      if (!auth.ok) {
        const base = getBaseUrl(req, config);
        sendJson(
          res,
          401,
          { error: "unauthorized", message: "Valid Bearer token required" },
          {
            "WWW-Authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"`,
          }
        );
        return;
      }
    }

    const account = auth.accountId || (auth.mode === "admin" ? "admin" : "default");
    const actor = auth.mode === "admin" ? "admin" : `gemini_app:${account}`;

    if (req.method === "GET") {
      sendJson(
        res,
        405,
        { error: "method_not_allowed", message: "GET SSE stream is not enabled; use POST /mcp" },
        { Allow: "POST, DELETE, OPTIONS" }
      );
      return;
    }

    if (req.method === "DELETE") {
      const sessionId = req.headers["mcp-session-id"];
      if (typeof sessionId === "string" && sessionId) {
        const existing = sessions.get(sessionId);
        if (existing && existing.actor === actor) {
          sessions.delete(sessionId);
        }
      }
      sendText(res, 204, "");
      return;
    }

    if (req.method !== "POST") {
      sendJson(
        res,
        405,
        { error: "method_not_allowed" },
        { Allow: "POST, DELETE, OPTIONS" }
      );
      return;
    }

    const rawBody = await readRawBody(req, MCP_MAX_BODY_BYTES);
    let parsed;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      sendJson(res, 400, rpcError(null, -32700, "Parse error: invalid JSON"));
      return;
    }

    pruneSessions();
    const headerSessionId =
      typeof req.headers["mcp-session-id"] === "string" ? req.headers["mcp-session-id"] : "";
    const candidateSession = headerSessionId ? sessions.get(headerSessionId) : null;
    const sessionRecord =
      candidateSession && candidateSession.actor === actor ? candidateSession : null;
    if (sessionRecord) {
      sessionRecord.lastSeenAt = Date.now();
      // Move to tail of Map to maintain true O(1) LRU order
      sessions.delete(headerSessionId);
      sessions.set(headerSessionId, sessionRecord);
    }

    const headerProtocol = req.headers["mcp-protocol-version"];
    const activeProtocolVersion = negotiateVersion(
      typeof headerProtocol === "string" ? headerProtocol : sessionRecord?.protocolVersion
    );

    const reqContext = {
      actor,
      account,
      authMode: auth.mode,
      sessionId: sessionRecord ? headerSessionId : null,
      sessionRecord,
      traceId: crypto.randomBytes(6).toString("hex"),
    };

    if (Array.isArray(parsed)) {
      if (parsed.length === 0) {
        sendJson(res, 400, rpcError(null, -32600, "Empty JSON-RPC batch is invalid"));
        return;
      }
      const responses = [];
      let newSessionId = null;
      let negotiatedProto = activeProtocolVersion;

      for (const item of parsed) {
        const outcome = await handleMessage(item, req, reqContext);
        if (outcome.sessionId) {
          newSessionId = outcome.sessionId;
        }
        if (outcome.protocolVersion) {
          negotiatedProto = outcome.protocolVersion;
        }
        if (outcome.response) {
          responses.push(outcome.response);
        }
      }

      const headers = {
        "MCP-Protocol-Version": negotiatedProto,
        ...(newSessionId
          ? { "Mcp-Session-Id": newSessionId }
          : sessionRecord && headerSessionId
            ? { "Mcp-Session-Id": headerSessionId }
            : {}),
      };

      if (responses.length === 0) {
        res.writeHead(202, headers);
        res.end();
        return;
      }
      sendJson(res, 200, responses, headers);
      return;
    }

    const outcome = await handleMessage(parsed, req, reqContext);
    const headers = {
      "MCP-Protocol-Version": outcome.protocolVersion || activeProtocolVersion,
      ...(outcome.sessionId
        ? { "Mcp-Session-Id": outcome.sessionId }
        : sessionRecord && headerSessionId
          ? { "Mcp-Session-Id": headerSessionId }
          : {}),
    };

    if (!outcome.response) {
      res.writeHead(202, headers);
      res.end();
      return;
    }

    if (
      outcome.response.error &&
      (outcome.response.id === null || outcome.response.id === undefined)
    ) {
      sendJson(res, 400, outcome.response, headers);
      return;
    }

    sendJson(res, 200, outcome.response, headers);
  }

  handleMcpRequest.registry = registry;
  handleMcpRequest.getSessionSummary = getSessionSummary;
  handleMcpRequest.pruneSessions = pruneSessions;
  handleMcpRequest.stop = () => clearInterval(sweepTimer);
  return handleMcpRequest;
}
