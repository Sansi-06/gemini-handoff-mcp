import fs from "node:fs/promises";
import path from "node:path";
import { APP_VERSION, resolveTenantFilesRoot } from "./config.mjs";
import {
  PolicyError,
  checkWriteAllowed,
  createUnifiedDiffPreview,
  inspectMounts,
  resolveBucketPath,
  resolveTaskAttachmentManifest,
  verifyDeliverable,
} from "./harness.mjs";
import { normalizeSlashes } from "./http-utils.mjs";
import {
  compileGlobMatcher,
  compileSafeRegex,
  isIgnoredDir,
  isLikelyBinary,
  isSensitivePath,
  resolveSandboxedPath,
  sha256Hex,
} from "./security.mjs";
import { AsyncKeyLock, atomicWriteFile } from "./store.mjs";

const MAX_READ_FILE_BYTES = 5 * 1024 * 1024;
const MAX_SEARCH_FILE_BYTES = 1 * 1024 * 1024;
const MAX_SNIPPET_LINE_CHARS = 400;
const HEX_RE = /^[a-f0-9]{8,64}$/i;

/**
 * Clamp integer tool parameter within [min, max] with default fallback.
 */
function clampInt(value, fallback, min, max) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.trunc(num)));
}

/**
 * Verify optimistic concurrency hash expectation (full SHA-256 or >=8 hex char prefix).
 * @param {string | null} actualSha256
 * @param {string | undefined} expectedSha256
 */
function assertExpectedSha256(actualSha256, expectedSha256) {
  if (expectedSha256 === undefined || expectedSha256 === null || expectedSha256 === "") {
    return;
  }
  const expected = String(expectedSha256).trim().toLowerCase();
  if (!HEX_RE.test(expected)) {
    throw new Error("expected_sha256 must be an 8-64 character hexadecimal SHA-256 prefix or digest");
  }
  if (!actualSha256) {
    throw new Error(
      `SHA-256 precondition failed: expected '${expected}', but target file does not exist yet`
    );
  }
  if (!actualSha256.toLowerCase().startsWith(expected)) {
    throw new Error(
      `SHA-256 mismatch (optimistic lock failed): expected '${expected}', actual '${actualSha256}'. Re-read the file before modifying.`
    );
  }
}

/**
 * Compact a very long matched line so minified files do not flood the context window.
 * @param {string} line
 * @param {string} [needle]
 */
function formatSnippetLine(line, needle = "") {
  if (line.length <= MAX_SNIPPET_LINE_CHARS) {
    return line;
  }
  let pivot = 0;
  if (needle) {
    const idx = line.toLowerCase().indexOf(needle.toLowerCase());
    if (idx !== -1) {
      pivot = Math.max(0, idx - 120);
    }
  }
  const slice = line.slice(pivot, pivot + MAX_SNIPPET_LINE_CHARS);
  const prefix = pivot > 0 ? "..." : "";
  const suffix = pivot + MAX_SNIPPET_LINE_CHARS < line.length ? "..." : "";
  return `${prefix}${slice}${suffix}`;
}

/**
 * Walk a sandboxed bucket (plus optional read-only virtual mounts), skipping symlinks,
 * ignored directories, and sensitive files.
 */
async function walkBucket({
  rootDir,
  mounts = {},
  subpath = ".",
  maxDepth = 4,
  maxEntries = 300,
  fileGlob = "",
}) {
  const globMatcher = compileGlobMatcher(fileGlob);
  const start = await resolveBucketPath(rootDir, mounts, subpath, {
    allowRoot: true,
    mustExist: true,
  });

  const stat = await fs.stat(start.fullPath);
  if (!stat.isDirectory()) {
    const matchesGlob = !globMatcher || globMatcher(start.relPath);
    return {
      baseRel: start.relPath,
      entries: matchesGlob
        ? [{ path: start.relPath, type: "file", size: stat.size, mtime: stat.mtime.toISOString() }]
        : [],
      total_returned: matchesGlob ? 1 : 0,
      skipped_sensitive_count: 0,
      skipped_ignored_dirs: 0,
      truncated: false,
    };
  }

  const entries = [];
  let truncated = false;
  let skippedSensitiveCount = 0;
  let skippedIgnoredDirs = 0;

  async function visit(dirFull, dirRel, depth, rootMountAlias) {
    if (entries.length >= maxEntries) {
      truncated = true;
      return;
    }

    let dirents;
    try {
      dirents = await fs.readdir(dirFull, { withFileTypes: true });
    } catch {
      return;
    }
    dirents.sort((a, b) => a.name.localeCompare(b.name));

    for (const dirent of dirents) {
      if (entries.length >= maxEntries) {
        truncated = true;
        return;
      }
      if (dirent.isSymbolicLink()) {
        continue;
      }

      const childRel = dirRel === "." ? dirent.name : `${dirRel}/${dirent.name}`;
      if (isSensitivePath(childRel)) {
        skippedSensitiveCount += 1;
        continue;
      }

      const childFull = path.join(dirFull, dirent.name);
      if (dirent.isDirectory()) {
        if (isIgnoredDir(dirent.name)) {
          skippedIgnoredDirs += 1;
          continue;
        }
        // When a fileGlob filter is active, only include matching files (still recurse into dirs).
        if (!globMatcher) {
          entries.push({
            path: `${childRel}/`,
            type: "dir",
            depth,
            ...(rootMountAlias ? { mount: true } : {}),
          });
        }
        if (depth < maxDepth) {
          await visit(childFull, childRel, depth + 1, rootMountAlias);
        }
      } else if (dirent.isFile()) {
        if (globMatcher && !globMatcher(childRel)) {
          continue;
        }
        let st;
        try {
          st = await fs.stat(childFull);
        } catch {
          continue;
        }
        entries.push({
          path: childRel,
          type: "file",
          size: st.size,
          mtime: st.mtime.toISOString(),
          depth,
          ...(rootMountAlias ? { mount: true } : {}),
        });
      }
    }
  }

  await visit(start.fullPath, start.relPath, 1, start.mountAlias);

  // When listing the bucket root, also enumerate admin-configured virtual read-only mounts.
  if (start.relPath === "." && !start.mountAlias && mounts && Object.keys(mounts).length > 0) {
    const existingTopNames = new Set(
      entries.map((e) => e.path.replace(/\/$/, "").split("/")[0])
    );
    const mountEntries = Object.entries(mounts).sort(([a], [b]) => a.localeCompare(b));
    for (const [alias, mountDir] of mountEntries) {
      if (entries.length >= maxEntries) {
        truncated = true;
        break;
      }
      if (existingTopNames.has(alias)) {
        continue;
      }
      let mountStat;
      try {
        mountStat = await fs.stat(mountDir);
      } catch {
        continue;
      }
      if (!mountStat.isDirectory()) {
        continue;
      }
      if (!globMatcher) {
        entries.push({ path: `${alias}/`, type: "dir", depth: 1, mount: true });
      }
      if (maxDepth > 1) {
        await visit(mountDir, alias, 2, alias);
      }
    }
  }

  return {
    baseRel: start.relPath,
    entries,
    total_returned: entries.length,
    skipped_sensitive_count: skippedSensitiveCount,
    skipped_ignored_dirs: skippedIgnoredDirs,
    truncated,
  };
}

/**
 * Shared text file reader for files, notes, and repo source files with exact
 * line-boundary truncation, EOF reporting, and SHA-256 content fingerprinting.
 */
async function readBucketText({
  rootDir,
  mounts = {},
  relPath,
  startLine = 1,
  endLine,
  maxChars = 30000,
  numbered = false,
}) {
  if (endLine !== undefined && endLine !== null && endLine < startLine) {
    throw new Error(`Invalid line range: end_line (${endLine}) cannot be less than start_line (${startLine})`);
  }

  const resolved = await resolveBucketPath(rootDir, mounts, relPath, {
    allowRoot: false,
    mustExist: true,
  });

  const stat = await fs.stat(resolved.fullPath);
  if (!stat.isFile()) {
    throw new Error(`Path is a directory, not a file: ${resolved.relPath}`);
  }
  if (stat.size > MAX_READ_FILE_BYTES) {
    throw new Error(
      `File ${resolved.relPath} (${stat.size} bytes) exceeds max readable size (${MAX_READ_FILE_BYTES} bytes)`
    );
  }

  const buffer = await fs.readFile(resolved.fullPath);
  if (isLikelyBinary(buffer)) {
    throw new Error(`File ${resolved.relPath} appears to be binary and cannot be read as text`);
  }

  const digest = sha256Hex(buffer);
  const mtimeIso = stat.mtime.toISOString();

  if (buffer.length === 0) {
    return `File: ${resolved.relPath} (empty file, 0 bytes, sha256=${digest}, mtime=${mtimeIso})`;
  }

  const allLines = buffer.toString("utf8").split(/\r?\n/);
  const totalLines = allLines.length;

  if (startLine > totalLines) {
    return (
      `File: ${resolved.relPath} (EOF: requested start_line=${startLine} exceeds total_lines=${totalLines}, ` +
      `${buffer.length} bytes, sha256=${digest})`
    );
  }

  const safeStart = Math.max(1, startLine);
  const requestedEnd =
    endLine !== undefined && endLine !== null ? Math.min(totalLines, endLine) : totalLines;

  const outLines = [];
  let usedChars = 0;
  let actualEnd = safeStart - 1;
  let charTruncated = false;
  let singleLineClipped = false;

  for (let lineNo = safeStart; lineNo <= requestedEnd; lineNo += 1) {
    const rawLine = allLines[lineNo - 1];
    const formatted = numbered ? `${lineNo} | ${rawLine}` : rawLine;
    const extraChars = outLines.length > 0 ? formatted.length + 1 : formatted.length;

    if (usedChars + extraChars > maxChars) {
      if (outLines.length === 0) {
        // First line itself exceeds maxChars: return a clipped prefix so progress is always visible.
        outLines.push(formatted.slice(0, maxChars));
        actualEnd = lineNo;
        singleLineClipped = true;
      }
      charTruncated = true;
      break;
    }

    outLines.push(formatted);
    usedChars += extraChars;
    actualEnd = lineNo;
  }

  const hasMoreLines = actualEnd < totalLines;
  const nextStartLine = actualEnd + 1;
  const body = outLines.join("\n");

  const headerParts = [
    `File: ${resolved.relPath}`,
    `lines ${safeStart}-${actualEnd} of ${totalLines}`,
    `${buffer.length} bytes`,
    `sha256=${digest}`,
  ];
  if (charTruncated) {
    headerParts.push(`truncated at ${maxChars} chars`);
  }

  const header = headerParts.join(" | ");
  let footer = "";
  if (charTruncated) {
    if (singleLineClipped) {
      footer =
        `\n\n...[line ${actualEnd} clipped at ${maxChars} chars; increase max_chars or pass start_line=${nextStartLine} for subsequent lines]`;
    } else if (hasMoreLines) {
      footer = `\n\n...[truncated at line boundary (max_chars=${maxChars}); pass start_line=${nextStartLine} to continue reading]`;
    }
  } else if (hasMoreLines && endLine !== undefined && endLine !== null) {
    footer = `\n\n...[end of requested range; ${totalLines - actualEnd} more lines remain starting at start_line=${nextStartLine}]`;
  }

  return `${header}\n\n${body}${footer}`;
}

/**
 * Shared sandboxed text search helper across a bucket (and optional virtual mounts)
 * with transparent scan telemetry (scanned, skipped_binary, skipped_too_large, tree_truncated).
 */
async function searchBucketFiles({
  rootDir,
  mounts = {},
  subpath = ".",
  matcher,
  literalNeedle = "",
  fileGlob = "",
  contextLines = 0,
  maxResults = 30,
}) {
  const start = await resolveBucketPath(rootDir, mounts, subpath, {
    allowRoot: true,
    mustExist: true,
  });

  const candidateFiles = [];
  let treeTruncated = false;
  let skippedSensitiveCount = 0;

  const startStat = await fs.stat(start.fullPath);
  if (startStat.isFile()) {
    const globMatcher = compileGlobMatcher(fileGlob);
    if (!globMatcher || globMatcher(start.relPath)) {
      candidateFiles.push({ fullPath: start.fullPath, relPath: start.relPath });
    }
  } else {
    const tree = await walkBucket({
      rootDir,
      mounts,
      subpath: start.relPath,
      maxDepth: 12,
      maxEntries: 5000,
      fileGlob,
    });
    treeTruncated = tree.truncated;
    skippedSensitiveCount = tree.skipped_sensitive_count;

    for (const item of tree.entries) {
      if (item.type !== "file") {
        continue;
      }
      const resolvedItem = await resolveBucketPath(rootDir, mounts, item.path, {
        allowRoot: false,
        mustExist: false,
      }).catch(() => null);
      if (resolvedItem) {
        candidateFiles.push({
          fullPath: resolvedItem.fullPath,
          relPath: normalizeSlashes(item.path),
        });
      }
    }
  }

  const matches = [];
  let truncated = false;
  let scannedFiles = 0;
  let skippedBinary = 0;
  let skippedTooLarge = 0;

  for (const file of candidateFiles) {
    if (matches.length >= maxResults) {
      truncated = true;
      break;
    }

    let stat;
    try {
      stat = await fs.stat(file.fullPath);
    } catch {
      continue;
    }
    if (!stat.isFile()) {
      continue;
    }
    if (stat.size > MAX_SEARCH_FILE_BYTES) {
      skippedTooLarge += 1;
      continue;
    }

    let buf;
    try {
      buf = await fs.readFile(file.fullPath);
    } catch {
      continue;
    }
    if (isLikelyBinary(buf)) {
      skippedBinary += 1;
      continue;
    }

    scannedFiles += 1;
    const lines = buf.toString("utf8").split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx += 1) {
      if (matcher(lines[idx])) {
        const lineNo = idx + 1;
        if (contextLines > 0) {
          const from = Math.max(0, idx - contextLines);
          const to = Math.min(lines.length - 1, idx + contextLines);
          const snippet = [];
          for (let c = from; c <= to; c += 1) {
            const marker = c === idx ? ">" : " ";
            const textLine = formatSnippetLine(lines[c], c === idx ? literalNeedle : "");
            snippet.push(`${marker} ${c + 1} | ${textLine}`);
          }
          matches.push({ path: file.relPath, line: lineNo, snippet: snippet.join("\n") });
        } else {
          matches.push({
            path: file.relPath,
            line: lineNo,
            snippet: formatSnippetLine(lines[idx], literalNeedle),
          });
        }

        if (matches.length >= maxResults) {
          truncated = true;
          break;
        }
      }
    }
  }

  return {
    matches,
    truncated,
    telemetry: {
      scanned_files: scannedFiles,
      skipped_binary: skippedBinary,
      skipped_too_large: skippedTooLarge,
      skipped_sensitive_count: skippedSensitiveCount,
      tree_truncated: treeTruncated,
    },
  };
}

/**
 * Format transparent search telemetry footer so LLMs never mistake skipped files for absence.
 */
function formatSearchFooter(telemetry, truncated, refineHint) {
  const notes = [];
  if (truncated) {
    notes.push(`results capped (${refineHint})`);
  }
  if (telemetry.tree_truncated) {
    notes.push("directory scan hit 5000-entry cap (narrow subpath)");
  }
  const parts = [`scanned=${telemetry.scanned_files}`];
  if (telemetry.skipped_too_large > 0) {
    parts.push(`skipped_large(>1MB)=${telemetry.skipped_too_large}`);
  }
  if (telemetry.skipped_binary > 0) {
    parts.push(`skipped_binary=${telemetry.skipped_binary}`);
  }
  const metaLine = `[search stats: ${parts.join(", ")}${notes.length ? `; ${notes.join("; ")}` : ""}]`;
  return metaLine;
}

/**
 * Perform deterministic exact-string replacement with Windows CRLF awareness and duplicate line reporting.
 */
function applySurgicalEdit(originalContent, oldText, newText, replaceAll = false) {
  if (typeof oldText !== "string" || oldText.length === 0) {
    throw new Error("'old_text' must be a non-empty string");
  }
  if (typeof newText !== "string") {
    throw new Error("'new_text' must be a string");
  }
  if (oldText === newText) {
    throw new Error("'new_text' is identical to 'old_text'; no changes requested");
  }

  const findOccurrences = (haystack, needle) => {
    const positions = [];
    let from = 0;
    while (from <= haystack.length - needle.length) {
      const idx = haystack.indexOf(needle, from);
      if (idx === -1) {
        break;
      }
      positions.push(idx);
      from = idx + needle.length;
    }
    return positions;
  };

  let targetContent = originalContent;
  let searchNeedle = oldText;
  let replacementText = newText;
  let normalizedCrlf = false;

  let positions = findOccurrences(targetContent, searchNeedle);
  if (positions.length === 0 && originalContent.includes("\r\n") && !oldText.includes("\r\n")) {
    const lfContent = originalContent.replace(/\r\n/g, "\n");
    const lfPositions = findOccurrences(lfContent, oldText);
    if (lfPositions.length > 0) {
      targetContent = lfContent;
      positions = lfPositions;
      normalizedCrlf = true;
      replacementText = newText.replace(/\r\n/g, "\n");
    }
  }

  if (positions.length === 0) {
    throw new Error(
      "old_text was not found in target file. Re-read the file to confirm exact text and indentation."
    );
  }

  if (positions.length > 1 && !replaceAll) {
    const matchedLines = positions.map((pos) => targetContent.slice(0, pos).split("\n").length);
    throw new Error(
      `old_text matched ${positions.length} times (at lines: ${matchedLines.join(", ")}). ` +
        `Provide more surrounding context to make it unique, or set replace_all=true.`
    );
  }

  let updated = targetContent.split(searchNeedle).join(replacementText);
  if (normalizedCrlf) {
    updated = updated.replace(/\n/g, "\r\n");
  }

  return {
    updatedContent: updated,
    replacements: positions.length,
  };
}

/**
 * Build a matcher function from query + regex/case flags.
 */
function buildSearchMatcher(query, { isRegex = false, caseSensitive = false } = {}) {
  const raw = String(query ?? "");
  if (!raw) {
    throw new Error("Search query cannot be empty");
  }
  if (isRegex) {
    const re = compileSafeRegex(raw, { caseSensitive });
    return { matcher: (line) => re.test(line), literalNeedle: "" };
  }
  if (caseSensitive) {
    return { matcher: (line) => line.includes(raw), literalNeedle: raw };
  }
  const needle = raw.toLowerCase();
  return { matcher: (line) => line.toLowerCase().includes(needle), literalNeedle: raw };
}

/**
 * Create the MCP tool definitions and executor bound to the store, harness components, and config.
 * Exposes all 12 original tools (upgraded) plus 8 harness engineering tools (20 total).
 *
 * @param {{
 *   store: import("./store.mjs").TaskStore,
 *   config: Record<string, any>,
 *   audit?: import("./harness.mjs").AuditLogger,
 *   snapshots?: import("./harness.mjs").SnapshotStore,
 *   getSessionSummary?: () => Record<string, any>
 * }} deps
 */
export function createToolRegistry({ store, config, audit, snapshots, getSessionSummary }) {
  const fileLock = new AsyncKeyLock();
  const maxWriteBytes = config.maxWriteBytes || 2 * 1024 * 1024;

  const readOnlyAnnotations = (title) => ({
    title,
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  });

  function isAdminCtx(ctx) {
    return ctx?.authMode === "admin";
  }

  function isTenantIsolated() {
    return config?.tenantIsolation !== false;
  }

  function getTenantFilesRoot(ctx) {
    if (isAdminCtx(ctx) || !isTenantIsolated()) {
      return config.filesRoot;
    }
    return resolveTenantFilesRoot(config, ctx?.account || "default");
  }

  function assertTaskAccess(task, ctx) {
    if (isAdminCtx(ctx) || !isTenantIsolated()) {
      return;
    }
    const callerAccount = String(ctx?.account || "default").trim().toLowerCase();
    const ownerAccount = String(task?.account || "default").trim().toLowerCase();
    if (ownerAccount !== callerAccount) {
      throw new PolicyError(
        `Access denied: task '${task?.id}' does not belong to account '${callerAccount}'`,
        "tenant_isolation_denied"
      );
    }
  }

  /**
   * Build unified workspace & harness status snapshot shared across MCP tool, MCP resource, and Admin API.
   */
  async function buildWorkspaceStatus({
    includeHostPaths = false,
    includeAdminMeta = false,
    account = "",
    actor = "",
  } = {}) {
    const scopedFilesRoot = account ? resolveTenantFilesRoot(config, account) : config.filesRoot;
    const [queue, filesTop, notesTop, reposTop, repoMountInfo, noteMountInfo, snapshotCount] =
      await Promise.all([
        store.getQueueStats({ account }),
        walkBucket({ rootDir: scopedFilesRoot, subpath: ".", maxDepth: 2, maxEntries: 100 }),
        walkBucket({
          rootDir: config.notesRoot,
          mounts: config.noteMounts,
          subpath: ".",
          maxDepth: 2,
          maxEntries: 100,
        }),
        walkBucket({
          rootDir: config.reposRoot,
          mounts: config.repoMounts,
          subpath: ".",
          maxDepth: 2,
          maxEntries: 100,
        }),
        inspectMounts(config.repoMounts, { includeHostPath: includeHostPaths }),
        inspectMounts(config.noteMounts, { includeHostPath: includeHostPaths }),
        snapshots ? snapshots.count({ account }) : Promise.resolve(0),
      ]);

    const status = {
      service: "gemini-handoff-mcp",
      harness_version: APP_VERSION,
      ...(includeAdminMeta
        ? {
            configured_accounts: [
              ...new Set([
                ...(config.accountKeys ? config.accountKeys.keys() : []),
                ...(config.accounts ? config.accounts.keys() : []),
              ]),
            ],
          }
        : {}),
      policy: {
        read_only_mode: Boolean(config.readOnlyMode),
        write_allowed_prefixes: config.writeAllowedPrefixes || [],
        max_write_bytes: maxWriteBytes,
        snapshot_retention_per_file: config.snapshotRetention ?? 20,
        max_tool_calls_per_minute: config.maxToolCallsPerMinute ?? 120,
        bucket_permissions: {
          files: config.readOnlyMode ? "read_only (READ_ONLY_MODE)" : "read_write",
          notes: "read_only",
          repos: "read_only",
        },
      },
      queue,
      workspace: {
        files: {
          preview_entries: filesTop.entries.slice(0, 30).map((e) => e.path),
          total_previewed: filesTop.total_returned,
          truncated: filesTop.truncated,
          ...(includeHostPaths ? { host_root: scopedFilesRoot } : {}),
        },
        notes: {
          preview_entries: notesTop.entries.slice(0, 30).map((e) => e.path),
          total_previewed: notesTop.total_returned,
          truncated: notesTop.truncated,
          mounts: noteMountInfo,
          ...(includeHostPaths ? { host_root: config.notesRoot } : {}),
        },
        repos: {
          preview_entries: reposTop.entries.slice(0, 30).map((e) => e.path),
          total_previewed: reposTop.total_returned,
          truncated: reposTop.truncated,
          mounts: repoMountInfo,
          ...(includeHostPaths ? { host_root: config.reposRoot } : {}),
        },
      },
      snapshots: {
        stored_count: snapshotCount,
      },
      ...(audit ? { telemetry: audit.getMetrics() } : {}),
      ...(getSessionSummary
        ? {
            sessions: getSessionSummary({
              includeDetails: includeAdminMeta,
              actorFilter: includeAdminMeta ? "" : actor,
            }),
          }
        : {}),
    };

    return status;
  }

  /**
   * Look up optional task contract when a write/edit supplies `task_id`.
   */
  async function loadTaskContract(taskId, ctx) {
    if (!taskId) {
      return null;
    }
    const task = await store.getTask(taskId, { includeResultMarkdown: false });
    assertTaskAccess(task, ctx);
    return task.contract || null;
  }

  const tools = [
    // =========================================================================
    // 1..12: Original 12 Tools (upgraded for determinism, pagination & safety)
    // =========================================================================
    {
      name: "list_tasks",
      description:
        "List delegated tasks from Antigravity in the Gemini Handoff queue. Default returns pending tasks; includes revision, progress, lease staleness, and contract flags.",
      annotations: readOnlyAnnotations("List Delegated Tasks"),
      inputSchema: {
        type: "object",
        properties: {
          status: {
            type: "string",
            enum: [
              "pending",
              "in_progress",
              "needs_input",
              "proposed",
              "completed",
              "failed",
              "archived",
              "all",
            ],
            description: "Filter tasks by status (default: pending).",
          },
          tag: {
            type: "string",
            description: "Optional case-insensitive tag filter.",
          },
          account: {
            type: "string",
            description: "Optional account filter (e.g. 'personal', 'work', 'all').",
          },
          limit: {
            type: "integer",
            minimum: 1,
            maximum: 100,
            description: "Maximum number of tasks to return (default: 20).",
          },
        },
        additionalProperties: false,
      },
      async execute(args, ctx) {
        let scopedAccount;
        if (isAdminCtx(ctx) || !isTenantIsolated()) {
          scopedAccount = args?.account || "";
        } else {
          const callerAccount = String(ctx?.account || "default").trim().toLowerCase();
          const requested = String(args?.account || "").trim().toLowerCase();
          if (requested && requested !== callerAccount) {
            throw new PolicyError(
              `Cross-account access denied: account '${callerAccount}' cannot list tasks for '${requested}'`,
              "tenant_isolation_denied"
            );
          }
          scopedAccount = callerAccount;
        }
        const tasks = await store.listTasks({
          status: args?.status || "pending",
          tag: args?.tag || "",
          account: scopedAccount,
          limit: clampInt(args?.limit, 20, 1, 100),
        });
        return { text: JSON.stringify({ count: tasks.length, tasks }, null, 2) };
      },
    },
    {
      name: "get_task",
      description:
        "Fetch full task specification, deliverable contract, resolved attachment manifest (bucket, existence, bytes, lines, sha256), checkpoints, and submitted result.",
      annotations: readOnlyAnnotations("Get Task Details"),
      inputSchema: {
        type: "object",
        properties: {
          task_id: {
            type: "string",
            description: "Task identifier (e.g. task_20261123_150000_ab12).",
          },
          include_result_markdown: {
            type: "boolean",
            description: "Whether to include full result_markdown payload (default: true).",
          },
        },
        required: ["task_id"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const includeResultMarkdown =
          args?.include_result_markdown === undefined ? true : Boolean(args.include_result_markdown);
        const task = await store.getTask(args?.task_id, { includeResultMarkdown });
        assertTaskAccess(task, ctx);
        const attachmentManifest = await resolveTaskAttachmentManifest(task.attached_files, config, {
          filesRoot: getTenantFilesRoot(ctx),
        });
        return {
          text: JSON.stringify(
            {
              ...task,
              attachment_manifest: attachmentManifest,
            },
            null,
            2
          ),
        };
      },
    },
    {
      name: "claim_task",
      description:
        "Claim a delegated task and mark it in_progress with an active lease so Antigravity knows work is underway. Rejects archived or already-completed tasks unless force=true.",
      annotations: {
        title: "Claim Task",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          task_id: { type: "string", description: "Task identifier to claim." },
          note: { type: "string", description: "Optional status note or initial plan." },
          lease_minutes: {
            type: "integer",
            minimum: 5,
            maximum: 1440,
            description: "Lease duration in minutes before considered stale (default: 60).",
          },
          force: {
            type: "boolean",
            description: "Set true to re-claim an already completed task (default: false).",
          },
        },
        required: ["task_id"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const existing = await store.getTask(args?.task_id, { includeResultMarkdown: false });
        assertTaskAccess(existing, ctx);
        const task = await store.claimTask(args?.task_id, args?.note, {
          actor: ctx.actor,
          force: Boolean(args?.force),
          leaseMinutes: args?.lease_minutes,
        });
        return {
          text: JSON.stringify(
            {
              id: task.id,
              revision: task.revision,
              status: task.status,
              claimed_at: task.claimed_at,
              lease_expires_at: task.lease_expires_at,
              note: task.claim_note,
            },
            null,
            2
          ),
        };
      },
    },
    {
      name: "submit_task_result",
      description:
        "Submit the completed deliverable for a delegated task. Automatically runs harness verification on declared artifacts, required Markdown sections, and summary budget.",
      annotations: {
        title: "Submit Task Result",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          task_id: { type: "string", description: "Task identifier being completed." },
          summary: {
            type: "string",
            description:
              "Concise high-signal executive summary (ideal for low-token Antigravity pickup).",
          },
          content: {
            type: "string",
            description: "Full Markdown report or deliverable content.",
          },
          artifacts: {
            type: "array",
            items: { type: "string" },
            description: "Optional relative file paths written in FILES_ROOT (verified on disk).",
          },
        },
        required: ["task_id", "summary", "content"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const task = await store.getTask(args?.task_id, { includeResultMarkdown: false });
        assertTaskAccess(task, ctx);
        if (task.status === "archived") {
          throw new Error(`Cannot submit result for archived task: ${task.id}`);
        }

        const verification = await verifyDeliverable({
          task,
          summary: args?.summary,
          content: args?.content,
          artifacts: args?.artifacts,
          filesRoot: getTenantFilesRoot(ctx),
          config,
        });

        if (verification.strict_failed) {
          const failedList = verification.checks
            .filter((c) => !c.passed)
            .map((c) => `- ${c.name}: ${c.detail}`)
            .join("\n");
          throw new PolicyError(
            `Task ${task.id} has strict_contract enabled and failed deliverable verification:\n${failedList}`,
            "strict_contract_failed"
          );
        }

        const res = await store.submitTaskResult(args?.task_id, {
          summary: args?.summary,
          content: args?.content,
          artifacts: args?.artifacts,
          artifact_manifest: verification.artifact_manifest,
          verification: {
            passed: verification.passed,
            verified_at: verification.verified_at,
            checks: verification.checks,
            warnings: verification.warnings,
          },
          actor: ctx.actor,
        });

        return {
          text: JSON.stringify(
            {
              id: res.id,
              revision: res.revision,
              status: res.status,
              completed_at: res.completed_at,
              result_file: res.result_file,
              result_bytes: res.result_bytes,
              result_sha256: res.result_sha256,
              result_artifacts: res.result_artifacts,
              result_artifact_manifest: res.result_artifact_manifest,
              verification: res.verification,
            },
            null,
            2
          ),
        };
      },
    },
    {
      name: "propose_task",
      description:
        "Submit an architectural proposal, design specification, or research roadmap initiated in Gemini APP back to the Bridge queue for Antigravity to review and implement.",
      annotations: {
        title: "Propose Task / Implementation Plan",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          title: {
            type: "string",
            description: "Concise descriptive title of the proposal or plan.",
          },
          summary: {
            type: "string",
            description: "High-signal executive summary (2-5 sentences) for Antigravity low-token pickup.",
          },
          plan_markdown: {
            type: "string",
            description: "Full Markdown proposal, architectural specification, or implementation plan.",
          },
          suggested_actions: {
            type: "string",
            description: "Concrete next steps recommended for Antigravity (e.g. files to create/edit, commands to run).",
          },
          attached_files: {
            type: "array",
            items: { type: "string" },
            description: "Optional list of relevant relative file paths in FILES_ROOT or NOTES_ROOT.",
          },
          tags: {
            type: "array",
            items: { type: "string" },
            description: "Optional categorization tags (e.g. ['architecture', 'auth', 'ui']).",
          },
          priority: {
            type: "string",
            enum: ["low", "normal", "high"],
            description: "Suggested priority (default: normal).",
          },
        },
        required: ["title", "summary", "plan_markdown"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const account = ctx?.account || "default";
        const res = await store.createProposal(
          {
            title: args?.title,
            summary: args?.summary,
            plan_markdown: args?.plan_markdown,
            suggested_actions: args?.suggested_actions,
            attached_files: args?.attached_files,
            tags: args?.tags,
            priority: args?.priority,
            account,
          },
          { actor: ctx?.actor || `gemini_app:${account}`, account }
        );

        return {
          text: JSON.stringify(
            {
              id: res.id,
              account: res.account,
              status: res.status,
              title: res.title,
              summary: res.result_summary,
              created_at: res.created_at,
              tags: res.tags,
              result_file: `${res.id}.result.md`,
              message:
                "Proposal registered successfully in the Bridge queue. When the user opens Antigravity, it can inspect this proposal and proceed with implementation.",
            },
            null,
            2
          ),
        };
      },
    },
    {
      name: "list_files",
      description:
        "List files and directories inside the sandboxed exchange workspace (FILES_ROOT) with sizes, timestamps, and optional glob filtering.",
      annotations: readOnlyAnnotations("List Exchange Files"),
      inputSchema: {
        type: "object",
        properties: {
          subpath: {
            type: "string",
            description: "Relative directory path inside FILES_ROOT (default: '.').",
          },
          recursive: {
            type: "boolean",
            description: "Whether to recurse into subdirectories (default: false).",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.md,.json' or 'reports/*.md'.",
          },
          max_entries: {
            type: "integer",
            minimum: 1,
            maximum: 500,
            description: "Maximum entries to list (default: 200).",
          },
        },
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const res = await walkBucket({
          rootDir: getTenantFilesRoot(ctx),
          subpath: args?.subpath || ".",
          maxDepth: args?.recursive ? 6 : 1,
          maxEntries: clampInt(args?.max_entries, 200, 1, 500),
          fileGlob: args?.file_glob || "",
        });
        return { text: JSON.stringify(res, null, 2) };
      },
    },
    {
      name: "read_file",
      description:
        "Read a UTF-8 text file from FILES_ROOT with line-boundary pagination, exact SHA-256 fingerprint (for optimistic locking), and optional line numbers.",
      annotations: readOnlyAnnotations("Read Exchange File"),
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path inside FILES_ROOT." },
          start_line: { type: "integer", minimum: 1, description: "1-based start line (default: 1)." },
          end_line: { type: "integer", minimum: 1, description: "Optional 1-based end line." },
          max_chars: {
            type: "integer",
            minimum: 100,
            maximum: 100000,
            description: "Maximum characters returned (default: 30000, max: 100000).",
          },
          line_numbers: {
            type: "boolean",
            description: "Prefix each line with its 1-based line number (default: false).",
          },
        },
        required: ["path"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const text = await readBucketText({
          rootDir: getTenantFilesRoot(ctx),
          relPath: args?.path,
          startLine: clampInt(args?.start_line, 1, 1, 10_000_000),
          endLine:
            args?.end_line !== undefined ? clampInt(args.end_line, 1, 1, 10_000_000) : undefined,
          maxChars: clampInt(args?.max_chars, 30000, 100, 100000),
          numbered: Boolean(args?.line_numbers),
        });
        return { text };
      },
    },
    {
      name: "write_file",
      description:
        "Atomically write or append a UTF-8 text file inside FILES_ROOT with automatic pre-write backup snapshot, optional expected_sha256 optimistic lock, dry_run preview, and policy enforcement.",
      annotations: {
        title: "Write Exchange File",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path inside FILES_ROOT." },
          content: { type: "string", description: "UTF-8 text content to write." },
          mode: {
            type: "string",
            enum: ["overwrite", "append", "create_only"],
            description: "Write mode (default: overwrite).",
          },
          expected_sha256: {
            type: "string",
            description:
              "Optional SHA-256 digest (or >=8 char prefix) from a prior read_file to guard against concurrent modifications.",
          },
          dry_run: {
            type: "boolean",
            description: "Validate policy, size, and SHA-256 without modifying disk (default: false).",
          },
          task_id: {
            type: "string",
            description: "Optional associated task_id for task-scoped write prefix checks and audit attribution.",
          },
        },
        required: ["path", "content"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        if (typeof args?.content !== "string") {
          throw new Error("'content' must be a UTF-8 string");
        }
        const content = args.content;
        const mode = args?.mode || "overwrite";
        const dryRun = Boolean(args?.dry_run);
        if (!["overwrite", "append", "create_only"].includes(mode)) {
          throw new Error(`Invalid write mode: ${mode}`);
        }
        const byteLen = Buffer.byteLength(content, "utf8");
        if (byteLen > maxWriteBytes) {
          throw new Error(
            `Content exceeds maximum ${maxWriteBytes} bytes write limit (${byteLen} bytes)`
          );
        }

        const tenantFilesRoot = getTenantFilesRoot(ctx);
        const taskContract = await loadTaskContract(args?.task_id, ctx);
        const preResolved = await resolveSandboxedPath(tenantFilesRoot, args?.path, {
          allowRoot: false,
          mustExist: false,
        });
        checkWriteAllowed(preResolved.relPath, config, { taskContract });

        return fileLock.withLock(`${ctx.account}:${preResolved.relPath}`, async () => {
          const resolved = await resolveSandboxedPath(tenantFilesRoot, preResolved.relPath, {
            allowRoot: false,
            mustExist: false,
          });

          let previousSha256 = null;
          let existingContent = "";

          if (resolved.exists) {
            const st = await fs.stat(resolved.fullPath);
            if (st.isDirectory()) {
              throw new Error(`Cannot overwrite directory: ${resolved.relPath}`);
            }
            if (mode === "create_only") {
              throw new Error(`File already exists (create_only mode): ${resolved.relPath}`);
            }
            if (mode === "append" && st.size + byteLen > maxWriteBytes) {
              throw new Error(`Appended file size would exceed ${maxWriteBytes} bytes limit`);
            }
            const existingBuf = await fs.readFile(resolved.fullPath);
            previousSha256 = sha256Hex(existingBuf);
            if (mode === "append") {
              existingContent = existingBuf.toString("utf8");
            }
          }

          assertExpectedSha256(previousSha256, args?.expected_sha256);

          const finalContent = mode === "append" ? existingContent + content : content;
          const finalBytes = Buffer.byteLength(finalContent, "utf8");
          const finalSha256 = sha256Hex(finalContent);
          const finalLines = finalContent.length === 0 ? 0 : finalContent.split(/\r?\n/).length;

          if (dryRun) {
            return {
              text: JSON.stringify(
                {
                  ok: true,
                  dry_run: true,
                  path: resolved.relPath,
                  mode,
                  existed: resolved.exists,
                  previous_sha256: previousSha256,
                  projected_sha256: finalSha256,
                  projected_bytes: finalBytes,
                  projected_lines: finalLines,
                },
                null,
                2
              ),
            };
          }

          let backupId = null;
          if (resolved.exists && snapshots) {
            const snap = await snapshots.capture({
              fullPath: resolved.fullPath,
              relPath: resolved.relPath,
              reason: `write_file:${mode}`,
              tool: "write_file",
              actor: ctx.actor,
              account: ctx.account,
              taskId: args?.task_id || null,
            });
            backupId = snap?.id || null;
          }

          if (mode === "create_only") {
            await fs.mkdir(path.dirname(resolved.fullPath), { recursive: true });
            await fs.writeFile(resolved.fullPath, finalContent, { encoding: "utf8", flag: "wx" });
          } else {
            await atomicWriteFile(resolved.fullPath, finalContent);
          }

          return {
            text: JSON.stringify(
              {
                ok: true,
                dry_run: false,
                path: resolved.relPath,
                mode,
                bytes: finalBytes,
                lines: finalLines,
                sha256: finalSha256,
                previous_sha256: previousSha256,
                backup_id: backupId,
              },
              null,
              2
            ),
          };
        });
      },
    },
    {
      name: "search_notes",
      description:
        "Search Markdown and text notes inside NOTES_ROOT (and configured NOTE_MOUNTS) by keyword or ReDoS-safe regex, with context lines, glob filter, and transparent scan stats.",
      annotations: readOnlyAnnotations("Search Notes"),
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search keyword or regex pattern." },
          is_regex: {
            type: "boolean",
            description: "Treat query as regular expression with ReDoS safety checks (default: false).",
          },
          case_sensitive: {
            type: "boolean",
            description: "Match case strictly (default: false).",
          },
          subpath: {
            type: "string",
            description: "Optional subdirectory or mount alias inside NOTES_ROOT (default: '.').",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.md,.txt'.",
          },
          context_lines: {
            type: "integer",
            minimum: 0,
            maximum: 5,
            description: "Context lines above and below each match (default: 2, range: 0-5).",
          },
          max_results: {
            type: "integer",
            minimum: 1,
            maximum: 50,
            description: "Maximum matches to return (default: 20, max: 50).",
          },
        },
        required: ["query"],
        additionalProperties: false,
      },
      async execute(args) {
        const { matcher, literalNeedle } = buildSearchMatcher(args?.query, {
          isRegex: Boolean(args?.is_regex),
          caseSensitive: Boolean(args?.case_sensitive),
        });

        const result = await searchBucketFiles({
          rootDir: config.notesRoot,
          mounts: config.noteMounts,
          subpath: args?.subpath || ".",
          matcher,
          literalNeedle,
          fileGlob: args?.file_glob || "",
          contextLines: clampInt(args?.context_lines, 2, 0, 5),
          maxResults: clampInt(args?.max_results, 20, 1, 50),
        });

        const footer = formatSearchFooter(
          result.telemetry,
          result.truncated,
          "refine query or subpath"
        );
        if (result.matches.length === 0) {
          return { text: `No matching notes found.\n\n${footer}` };
        }

        const formatted = result.matches
          .map((m) => `### ${m.path}:${m.line}\n${m.snippet}`)
          .join("\n\n");

        return { text: `${formatted}\n\n${footer}` };
      },
    },
    {
      name: "read_note",
      description:
        "Read a note file from NOTES_ROOT (or configured NOTE_MOUNTS) with line-boundary pagination, SHA-256 fingerprint, and optional line numbers.",
      annotations: readOnlyAnnotations("Read Note"),
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path inside NOTES_ROOT or mount alias." },
          start_line: { type: "integer", minimum: 1, description: "1-based start line (default: 1)." },
          end_line: { type: "integer", minimum: 1, description: "Optional 1-based end line." },
          max_chars: {
            type: "integer",
            minimum: 100,
            maximum: 100000,
            description: "Maximum characters returned (default: 30000, max: 100000).",
          },
          line_numbers: {
            type: "boolean",
            description: "Prefix each line with its 1-based line number (default: false).",
          },
        },
        required: ["path"],
        additionalProperties: false,
      },
      async execute(args) {
        const text = await readBucketText({
          rootDir: config.notesRoot,
          mounts: config.noteMounts,
          relPath: args?.path,
          startLine: clampInt(args?.start_line, 1, 1, 10_000_000),
          endLine:
            args?.end_line !== undefined ? clampInt(args.end_line, 1, 1, 10_000_000) : undefined,
          maxChars: clampInt(args?.max_chars, 30000, 100, 100000),
          numbered: Boolean(args?.line_numbers),
        });
        return { text };
      },
    },
    {
      name: "list_repo_tree",
      description:
        "Browse the read-only directory tree of synced repositories in REPOS_ROOT and live read-only host mounts (REPO_MOUNTS), with optional glob filtering.",
      annotations: readOnlyAnnotations("List Repository Tree"),
      inputSchema: {
        type: "object",
        properties: {
          repo_path: {
            type: "string",
            description: "Relative repository, mount alias, or subdirectory inside REPOS_ROOT (default: '.').",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.ts,.mjs' or 'src/**/*.js'.",
          },
          max_depth: {
            type: "integer",
            minimum: 1,
            maximum: 6,
            description: "Maximum traversal depth (default: 4, max: 6).",
          },
          max_entries: {
            type: "integer",
            minimum: 1,
            maximum: 500,
            description: "Maximum entries returned (default: 300, max: 500).",
          },
        },
        additionalProperties: false,
      },
      async execute(args) {
        const res = await walkBucket({
          rootDir: config.reposRoot,
          mounts: config.repoMounts,
          subpath: args?.repo_path || ".",
          maxDepth: clampInt(args?.max_depth, 4, 1, 6),
          maxEntries: clampInt(args?.max_entries, 300, 1, 500),
          fileGlob: args?.file_glob || "",
        });
        return { text: JSON.stringify(res, null, 2) };
      },
    },
    {
      name: "read_repo_file",
      description:
        "Read a read-only source file from REPOS_ROOT or live REPO_MOUNTS with line numbers, line-boundary pagination, and SHA-256 fingerprint.",
      annotations: readOnlyAnnotations("Read Repository File"),
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path inside REPOS_ROOT or mount alias." },
          start_line: { type: "integer", minimum: 1, description: "1-based start line (default: 1)." },
          end_line: { type: "integer", minimum: 1, description: "Optional 1-based end line." },
          max_chars: {
            type: "integer",
            minimum: 100,
            maximum: 100000,
            description: "Maximum characters returned (default: 30000, max: 100000).",
          },
          line_numbers: {
            type: "boolean",
            description: "Include 1-based line numbers (default: true).",
          },
        },
        required: ["path"],
        additionalProperties: false,
      },
      async execute(args) {
        const numbered = args?.line_numbers === undefined ? true : Boolean(args.line_numbers);
        const text = await readBucketText({
          rootDir: config.reposRoot,
          mounts: config.repoMounts,
          relPath: args?.path,
          startLine: clampInt(args?.start_line, 1, 1, 10_000_000),
          endLine:
            args?.end_line !== undefined ? clampInt(args.end_line, 1, 1, 10_000_000) : undefined,
          maxChars: clampInt(args?.max_chars, 30000, 100, 100000),
          numbered,
        });
        return { text };
      },
    },
    {
      name: "search_repo_code",
      description:
        "Search read-only repository source files inside REPOS_ROOT and live REPO_MOUNTS using literal text or ReDoS-safe regex, glob filters, optional context lines, and transparent scan stats.",
      annotations: readOnlyAnnotations("Search Repository Code"),
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Text or regex pattern to search for." },
          is_regex: {
            type: "boolean",
            description: "Treat query as regular expression with ReDoS safety checks (default: false).",
          },
          case_sensitive: {
            type: "boolean",
            description: "Match case strictly (default: false).",
          },
          repo_path: {
            type: "string",
            description: "Relative repository, mount alias, or directory path inside REPOS_ROOT (default: '.').",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.ts,.tsx', '*.py', or 'src/**/*.mjs'.",
          },
          context_lines: {
            type: "integer",
            minimum: 0,
            maximum: 5,
            description: "Optional context lines around each match (default: 0, range: 0-5).",
          },
          max_results: {
            type: "integer",
            minimum: 1,
            maximum: 80,
            description: "Maximum matches returned (default: 40, max: 80).",
          },
        },
        required: ["query"],
        additionalProperties: false,
      },
      async execute(args) {
        const { matcher, literalNeedle } = buildSearchMatcher(args?.query, {
          isRegex: Boolean(args?.is_regex),
          caseSensitive: Boolean(args?.case_sensitive),
        });
        const contextLines = clampInt(args?.context_lines, 0, 0, 5);

        const result = await searchBucketFiles({
          rootDir: config.reposRoot,
          mounts: config.repoMounts,
          subpath: args?.repo_path || ".",
          matcher,
          literalNeedle,
          fileGlob: args?.file_glob || "",
          contextLines,
          maxResults: clampInt(args?.max_results, 40, 1, 80),
        });

        const footer = formatSearchFooter(
          result.telemetry,
          result.truncated,
          "narrow repo_path or file_glob"
        );
        if (result.matches.length === 0) {
          return { text: `No code matches found.\n\n${footer}` };
        }

        const formatted =
          contextLines > 0
            ? result.matches.map((m) => `### ${m.path}:${m.line}\n${m.snippet}`).join("\n\n")
            : result.matches.map((m) => `${m.path}:${m.line}: ${m.snippet}`).join("\n");

        return { text: `${formatted}\n\n${footer}` };
      },
    },

    // =========================================================================
    // 13..20: Agent Harness Tools
    // =========================================================================
    {
      name: "get_workspace_status",
      description:
        "Inspect the live Gemini Handoff harness state in one call: active guardrails (read_only_mode, allowed write prefixes, limits), task queue counts, available repos/mounts/notes/files, and snapshot count.",
      annotations: readOnlyAnnotations("Get Workspace & Harness Status"),
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const isAdmin = isAdminCtx(ctx);
        const status = await buildWorkspaceStatus({
          includeHostPaths: false,
          includeAdminMeta: isAdmin,
          account: isAdmin || !isTenantIsolated() ? "" : ctx?.account || "default",
          actor: ctx?.actor || "",
        });
        status.current_account = ctx?.account || "admin";
        return { text: JSON.stringify(status, null, 2) };
      },
    },
    {
      name: "checkpoint_task",
      description:
        "Save incremental progress for a long-running task, refresh its lease, request operator/Antigravity input (status='needs_input' with structured questions), or record failure (status='failed').",
      annotations: {
        title: "Checkpoint Task Progress",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          task_id: { type: "string", description: "Task identifier to update." },
          progress_note: {
            type: "string",
            description: "Summary of progress achieved so far, blocker reason, or failure cause.",
          },
          status: {
            type: "string",
            enum: ["in_progress", "needs_input", "failed"],
            description: "Target state (default: in_progress).",
          },
          percent: {
            type: "integer",
            minimum: 0,
            maximum: 100,
            description: "Optional completion percentage estimate (0-100).",
          },
          questions: {
            type: "array",
            items: { type: "string" },
            description: "Structured clarifying questions when status='needs_input'.",
          },
          partial_artifacts: {
            type: "array",
            items: { type: "string" },
            description: "Optional relative file paths in FILES_ROOT written so far.",
          },
          lease_minutes: {
            type: "integer",
            minimum: 5,
            maximum: 1440,
            description: "Optional renewed lease duration when status='in_progress' (default: 60).",
          },
        },
        required: ["task_id", "progress_note"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const existing = await store.getTask(args?.task_id, { includeResultMarkdown: false });
        assertTaskAccess(existing, ctx);
        const { task, checkpoint } = await store.checkpointTask(args?.task_id, {
          note: args?.progress_note,
          status: args?.status || "in_progress",
          percent: args?.percent,
          questions: args?.questions,
          partial_artifacts: args?.partial_artifacts,
          leaseMinutes: args?.lease_minutes,
          actor: ctx.actor,
        });
        return {
          text: JSON.stringify(
            {
              id: task.id,
              revision: task.revision,
              status: task.status,
              progress_percent: task.progress_percent,
              lease_expires_at: task.lease_expires_at,
              checkpoint,
            },
            null,
            2
          ),
        };
      },
    },
    {
      name: "list_notes",
      description:
        "Browse Markdown and text notes inside NOTES_ROOT and configured live NOTE_MOUNTS with optional glob filtering.",
      annotations: readOnlyAnnotations("List Notes"),
      inputSchema: {
        type: "object",
        properties: {
          subpath: {
            type: "string",
            description: "Relative subdirectory or mount alias inside NOTES_ROOT (default: '.').",
          },
          recursive: {
            type: "boolean",
            description: "Whether to recurse into subdirectories (default: true).",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.md,.txt'.",
          },
          max_entries: {
            type: "integer",
            minimum: 1,
            maximum: 500,
            description: "Maximum entries to list (default: 200).",
          },
        },
        additionalProperties: false,
      },
      async execute(args) {
        const recursive = args?.recursive === undefined ? true : Boolean(args.recursive);
        const res = await walkBucket({
          rootDir: config.notesRoot,
          mounts: config.noteMounts,
          subpath: args?.subpath || ".",
          maxDepth: recursive ? 6 : 1,
          maxEntries: clampInt(args?.max_entries, 200, 1, 500),
          fileGlob: args?.file_glob || "",
        });
        return { text: JSON.stringify(res, null, 2) };
      },
    },
    {
      name: "search_files",
      description:
        "Search text files (uploaded specs, logs, reports) inside FILES_ROOT by keyword or ReDoS-safe regex with context lines and scan stats.",
      annotations: readOnlyAnnotations("Search Exchange Files"),
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search keyword or regex pattern." },
          is_regex: {
            type: "boolean",
            description: "Treat query as regular expression with ReDoS safety checks (default: false).",
          },
          case_sensitive: {
            type: "boolean",
            description: "Match case strictly (default: false).",
          },
          subpath: {
            type: "string",
            description: "Optional subdirectory or file path inside FILES_ROOT (default: '.').",
          },
          file_glob: {
            type: "string",
            description: "Optional comma-separated glob/extension filter, e.g. '.md,.log,.json'.",
          },
          context_lines: {
            type: "integer",
            minimum: 0,
            maximum: 5,
            description: "Context lines above and below each match (default: 2, range: 0-5).",
          },
          max_results: {
            type: "integer",
            minimum: 1,
            maximum: 50,
            description: "Maximum matches to return (default: 20, max: 50).",
          },
        },
        required: ["query"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const { matcher, literalNeedle } = buildSearchMatcher(args?.query, {
          isRegex: Boolean(args?.is_regex),
          caseSensitive: Boolean(args?.case_sensitive),
        });
        const contextLines = clampInt(args?.context_lines, 2, 0, 5);

        const result = await searchBucketFiles({
          rootDir: getTenantFilesRoot(ctx),
          subpath: args?.subpath || ".",
          matcher,
          literalNeedle,
          fileGlob: args?.file_glob || "",
          contextLines,
          maxResults: clampInt(args?.max_results, 20, 1, 50),
        });

        const footer = formatSearchFooter(
          result.telemetry,
          result.truncated,
          "refine query, subpath, or file_glob"
        );
        if (result.matches.length === 0) {
          return { text: `No matching files found.\n\n${footer}` };
        }

        const formatted =
          contextLines > 0
            ? result.matches.map((m) => `### ${m.path}:${m.line}\n${m.snippet}`).join("\n\n")
            : result.matches.map((m) => `${m.path}:${m.line}: ${m.snippet}`).join("\n");

        return { text: `${formatted}\n\n${footer}` };
      },
    },
    {
      name: "edit_file",
      description:
        "Surgically patch an existing UTF-8 text file in FILES_ROOT via exact string replacement with uniqueness checks, automatic snapshot backup, expected_sha256 optimistic lock, and dry_run diff preview.",
      annotations: {
        title: "Edit Exchange File",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative file path inside FILES_ROOT." },
          old_text: {
            type: "string",
            description: "Exact existing text block to replace (must be unique unless replace_all=true).",
          },
          new_text: {
            type: "string",
            description: "Replacement text block.",
          },
          replace_all: {
            type: "boolean",
            description: "Replace every occurrence of old_text instead of requiring uniqueness (default: false).",
          },
          expected_sha256: {
            type: "string",
            description: "Optional SHA-256 digest (or >=8 char prefix) from prior read_file.",
          },
          dry_run: {
            type: "boolean",
            description: "Preview the unified diff and projected SHA-256 without modifying disk (default: false).",
          },
          task_id: {
            type: "string",
            description: "Optional associated task_id for task-scoped write prefix checks and audit attribution.",
          },
        },
        required: ["path", "old_text", "new_text"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        const dryRun = Boolean(args?.dry_run);
        const replaceAll = Boolean(args?.replace_all);
        const tenantFilesRoot = getTenantFilesRoot(ctx);
        const taskContract = await loadTaskContract(args?.task_id, ctx);

        const preResolved = await resolveSandboxedPath(tenantFilesRoot, args?.path, {
          allowRoot: false,
          mustExist: true,
        });
        checkWriteAllowed(preResolved.relPath, config, { taskContract });

        return fileLock.withLock(`${ctx.account}:${preResolved.relPath}`, async () => {
          const resolved = await resolveSandboxedPath(tenantFilesRoot, preResolved.relPath, {
            allowRoot: false,
            mustExist: true,
          });
          const st = await fs.stat(resolved.fullPath);
          if (!st.isFile()) {
            throw new Error(`Path is a directory, not a file: ${resolved.relPath}`);
          }
          if (st.size > maxWriteBytes) {
            throw new Error(`File exceeds maximum editable size (${maxWriteBytes} bytes)`);
          }

          const origBuf = await fs.readFile(resolved.fullPath);
          if (isLikelyBinary(origBuf)) {
            throw new Error(`Cannot edit binary file: ${resolved.relPath}`);
          }

          const beforeSha256 = sha256Hex(origBuf);
          assertExpectedSha256(beforeSha256, args?.expected_sha256);

          const beforeText = origBuf.toString("utf8");
          const { updatedContent, replacements } = applySurgicalEdit(
            beforeText,
            args?.old_text,
            args?.new_text,
            replaceAll
          );

          const afterBytes = Buffer.byteLength(updatedContent, "utf8");
          if (afterBytes > maxWriteBytes) {
            throw new Error(
              `Edited file (${afterBytes} bytes) exceeds maximum ${maxWriteBytes} bytes limit`
            );
          }

          const afterSha256 = sha256Hex(updatedContent);
          const diffPreview = createUnifiedDiffPreview(beforeText, updatedContent, resolved.relPath);
          const afterLines = updatedContent.length === 0 ? 0 : updatedContent.split(/\r?\n/).length;

          if (dryRun) {
            return {
              text: JSON.stringify(
                {
                  ok: true,
                  dry_run: true,
                  path: resolved.relPath,
                  replacements,
                  before_sha256: beforeSha256,
                  projected_sha256: afterSha256,
                  projected_bytes: afterBytes,
                  projected_lines: afterLines,
                  diff_preview: diffPreview,
                },
                null,
                2
              ),
            };
          }

          let backupId = null;
          if (snapshots) {
            const snap = await snapshots.capture({
              fullPath: resolved.fullPath,
              relPath: resolved.relPath,
              reason: "edit_file",
              tool: "edit_file",
              actor: ctx.actor,
              account: ctx.account,
              taskId: args?.task_id || null,
            });
            backupId = snap?.id || null;
          }

          await atomicWriteFile(resolved.fullPath, updatedContent);

          return {
            text: JSON.stringify(
              {
                ok: true,
                dry_run: false,
                path: resolved.relPath,
                replacements,
                bytes: afterBytes,
                lines: afterLines,
                before_sha256: beforeSha256,
                after_sha256: afterSha256,
                backup_id: backupId,
                diff_preview: diffPreview,
              },
              null,
              2
            ),
          };
        });
      },
    },
    {
      name: "list_file_snapshots",
      description:
        "List automatic pre-write backup snapshots stored by the harness for FILES_ROOT files so previous versions can be audited or restored.",
      annotations: readOnlyAnnotations("List File Snapshots"),
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Optional relative file path in FILES_ROOT to filter snapshots.",
          },
          limit: {
            type: "integer",
            minimum: 1,
            maximum: 100,
            description: "Maximum snapshots to return (default: 20).",
          },
        },
        additionalProperties: false,
      },
      async execute(args, ctx) {
        if (!snapshots) {
          return { text: JSON.stringify({ count: 0, snapshots: [] }, null, 2) };
        }
        const items = await snapshots.list({
          path: args?.path || "",
          limit: clampInt(args?.limit, 20, 1, 100),
          account: isAdminCtx(ctx) || !isTenantIsolated() ? "" : ctx.account,
        });
        return { text: JSON.stringify({ count: items.length, snapshots: items }, null, 2) };
      },
    },
    {
      name: "restore_file_snapshot",
      description:
        "Restore a FILES_ROOT file from an automatic backup snapshot_id. Captures a pre_restore backup of the current file first so rollback is always reversible.",
      annotations: {
        title: "Restore File Snapshot",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
      inputSchema: {
        type: "object",
        properties: {
          snapshot_id: {
            type: "string",
            description: "Snapshot identifier returned by write_file, edit_file, or list_file_snapshots.",
          },
          task_id: {
            type: "string",
            description: "Optional associated task_id for audit attribution.",
          },
        },
        required: ["snapshot_id"],
        additionalProperties: false,
      },
      async execute(args, ctx) {
        if (!snapshots) {
          throw new Error("Snapshot store is not enabled");
        }
        const receipt = await snapshots.restore({
          snapshotId: args?.snapshot_id,
          filesRoot: getTenantFilesRoot(ctx),
          config,
          actor: ctx.actor,
          account: isAdminCtx(ctx) || !isTenantIsolated() ? "" : ctx.account,
          taskId: args?.task_id || null,
          fileLock,
        });
        return { text: JSON.stringify(receipt, null, 2) };
      },
    },
  ];

  const byName = new Map(tools.map((tool) => [tool.name, tool]));

  return {
    fileLock,
    buildWorkspaceStatus,
    listTools() {
      return tools.map(({ execute, ...descriptor }) => descriptor);
    },
    async callTool(name, args, context = {}) {
      const startMs = Date.now();
      const ctx = {
        actor: context.actor || "mcp",
        account: context.account || "default",
        authMode: context.authMode || "oauth",
        sessionId: context.sessionId || null,
        traceId: context.traceId || null,
      };
      const tool = byName.get(name);
      if (!tool) {
        audit?.log({
          category: "mcp_tool",
          action: name,
          status: "error",
          actor: ctx.actor,
          session_id: ctx.sessionId,
          trace_id: ctx.traceId,
          duration_ms: Date.now() - startMs,
          args,
          error: `Unknown tool: ${name}`,
        });
        return {
          isError: true,
          text: `Unknown tool: ${name}`,
        };
      }
      try {
        const result = await tool.execute(args ?? {}, ctx);
        audit?.log({
          category: "mcp_tool",
          action: name,
          status: "ok",
          actor: ctx.actor,
          session_id: ctx.sessionId,
          trace_id: ctx.traceId,
          duration_ms: Date.now() - startMs,
          args,
          result: { chars: result?.text?.length ?? 0 },
        });
        return result;
      } catch (err) {
        const isPolicy = err instanceof PolicyError;
        audit?.log({
          category: "mcp_tool",
          action: name,
          status: isPolicy ? "blocked" : "error",
          actor: ctx.actor,
          session_id: ctx.sessionId,
          trace_id: ctx.traceId,
          duration_ms: Date.now() - startMs,
          args,
          error: err?.message || String(err),
        });
        return {
          isError: true,
          text: `${isPolicy ? "Policy blocked" : "Tool error"} (${name}): ${err?.message || String(err)}`,
        };
      }
    },
  };
}
