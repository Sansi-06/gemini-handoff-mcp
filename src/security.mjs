import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { normalizeSlashes } from "./http-utils.mjs";

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "__pycache__",
  ".venv",
  "venv",
  "dist",
  "build",
  "target",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".turbo",
  ".parcel-cache",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".cache",
  "coverage",
]);

const SENSITIVE_EXACT = new Set([
  ".git",
  ".env",
  ".envrc",
  ".npmrc",
  ".pypirc",
  ".netrc",
  "oauth-state.json",
]);

const SENSITIVE_EXTENSIONS = [".pem", ".key", ".p12", ".pfx", ".jks", ".p8", ".keystore"];

const MOUNT_ALIAS_RE = /^[a-zA-Z0-9._-]{1,64}$/;

/**
 * Compute SHA-256 hex digest of a string or Buffer.
 * @param {string | Buffer} input
 * @returns {string}
 */
export function sha256Hex(input) {
  return crypto.createHash("sha256").update(input, Buffer.isBuffer(input) ? undefined : "utf8").digest("hex");
}

/**
 * Validate a logical virtual mount alias (e.g. `my-app`).
 * @param {string} alias
 * @returns {boolean}
 */
export function isValidMountAlias(alias) {
  if (typeof alias !== "string" || !MOUNT_ALIAS_RE.test(alias)) {
    return false;
  }
  if (alias === "." || alias === ".." || isSensitivePath(alias)) {
    return false;
  }
  return true;
}

/**
 * Constant-time string comparison using SHA-256 digests so length differences never throw or leak.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }
  const digestA = crypto.createHash("sha256").update(a, "utf8").digest();
  const digestB = crypto.createHash("sha256").update(b, "utf8").digest();
  return crypto.timingSafeEqual(digestA, digestB);
}

/**
 * Check if a single path segment matches sensitive credential or secret file patterns.
 * @param {string} segment
 * @returns {boolean}
 */
function isSensitiveSegment(segment) {
  const lower = segment.toLowerCase();
  if (!lower || lower === ".") {
    return false;
  }
  if (SENSITIVE_EXACT.has(lower) || lower.startsWith(".env.")) {
    return true;
  }
  if (SENSITIVE_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
    return true;
  }
  if (lower.startsWith("id_rsa") || lower.startsWith("id_ed25519")) {
    return true;
  }
  if (lower.includes("credentials") || lower.includes("secret")) {
    return true;
  }
  return false;
}

/**
 * Check whether any segment in a relative path points to a sensitive file or directory.
 * @param {string} relPath
 * @returns {boolean}
 */
export function isSensitivePath(relPath) {
  const normalized = normalizeSlashes(relPath);
  const segments = normalized.split("/").filter(Boolean);
  return segments.some(isSensitiveSegment);
}

/**
 * Check whether a directory name should be skipped during tree scans and code/note searches.
 * @param {string} name
 * @returns {boolean}
 */
export function isIgnoredDir(name) {
  return IGNORED_DIRS.has(String(name).toLowerCase());
}

/**
 * Check whether `target` stays inside `root` (both normalized absolute real paths).
 * Correctly allows legitimate filenames starting with `..` (e.g. `..notes.md`) inside `root`.
 * @param {string} root
 * @param {string} target
 * @returns {boolean}
 */
function isWithinRoot(root, target) {
  const rel = path.relative(root, target);
  if (rel === "") {
    return true;
  }
  if (path.isAbsolute(rel)) {
    return false;
  }
  return rel !== ".." && !rel.startsWith(`..${path.sep}`) && !rel.startsWith("../");
}

/**
 * Verify that `targetPath` and its nearest existing ancestor resolve via realpath inside `realRoot`,
 * and reject dangling symlinks along the path.
 * @param {string} resolvedRoot
 * @param {string} realRoot
 * @param {string} targetPath
 * @param {boolean} mustExist
 * @returns {Promise<boolean>} whether targetPath currently exists
 */
async function assertNoSymlinkEscape(resolvedRoot, realRoot, targetPath, mustExist) {
  try {
    await fs.lstat(targetPath);
    let realTarget;
    try {
      realTarget = await fs.realpath(targetPath);
    } catch {
      throw new Error("Dangling or unreadable symlink is not allowed inside sandbox");
    }
    if (!isWithinRoot(realRoot, realTarget)) {
      throw new Error("Symlink escapes sandbox root");
    }
    const realRel = normalizeSlashes(path.relative(realRoot, realTarget));
    if (realRel && realRel !== "." && isSensitivePath(realRel)) {
      throw new Error("Symlink targets a sensitive credential or environment file");
    }
    return true;
  } catch (err) {
    if (err?.code !== "ENOENT") {
      throw err;
    }
    if (mustExist) {
      throw new Error("Target path does not exist");
    }
  }

  let cursor = path.dirname(targetPath);
  while (isWithinRoot(resolvedRoot, cursor)) {
    try {
      await fs.lstat(cursor);
      let realCursor;
      try {
        realCursor = await fs.realpath(cursor);
      } catch {
        throw new Error("Dangling symlink in parent path is not allowed");
      }
      if (!isWithinRoot(realRoot, realCursor)) {
        throw new Error("Parent symlink escapes sandbox root");
      }
      const realCursorRel = normalizeSlashes(path.relative(realRoot, realCursor));
      if (realCursorRel && realCursorRel !== "." && isSensitivePath(realCursorRel)) {
        throw new Error("Parent symlink targets a sensitive credential or environment directory");
      }
      return false;
    } catch (err) {
      if (err?.code !== "ENOENT") {
        throw err;
      }
    }

    if (cursor === resolvedRoot) {
      break;
    }
    const parent = path.dirname(cursor);
    if (parent === cursor) {
      break;
    }
    cursor = parent;
  }

  return false;
}

/**
 * Resolve a caller-provided relative path safely inside `rootDir`.
 * Rejects traversal, absolute/drive/UNC paths, sensitive paths, and symlink escapes.
 *
 * @param {string} rootDir
 * @param {string} relPath
 * @param {{ allowRoot?: boolean, mustExist?: boolean }} [options]
 * @returns {Promise<{ fullPath: string, relPath: string, exists: boolean }>}
 */
export async function resolveSandboxedPath(
  rootDir,
  relPath,
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

  const isRootRequest = normalizedInput === "" || normalizedInput === ".";
  if (isRootRequest) {
    if (!allowRoot) {
      throw new Error("File path cannot be empty or '.'");
    }
  } else if (isSensitivePath(normalizedInput)) {
    throw new Error("Access to sensitive credential or environment files is blocked");
  }

  const resolvedRoot = path.resolve(rootDir);
  const resolvedTarget = isRootRequest
    ? resolvedRoot
    : path.resolve(resolvedRoot, normalizedInput);

  const relFromRoot = path.relative(resolvedRoot, resolvedTarget);
  if (!isWithinRoot(resolvedRoot, resolvedTarget)) {
    throw new Error("Path traversal outside sandbox root is forbidden");
  }

  const cleanRel = normalizeSlashes(relFromRoot) || ".";
  if (cleanRel === "." && !allowRoot) {
    throw new Error("File path cannot resolve to sandbox root");
  }
  if (cleanRel !== "." && isSensitivePath(cleanRel)) {
    throw new Error("Access to sensitive credential or environment files is blocked");
  }

  const realRoot = await fs.realpath(resolvedRoot);
  const exists = await assertNoSymlinkEscape(resolvedRoot, realRoot, resolvedTarget, mustExist);

  return {
    fullPath: resolvedTarget,
    relPath: cleanRel,
    exists,
  };
}

/**
 * Heuristic binary check scanning up to the first 8192 bytes for NUL bytes.
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export function isLikelyBinary(buffer) {
  const limit = Math.min(buffer.length, 8192);
  for (let i = 0; i < limit; i += 1) {
    if (buffer[i] === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Escape HTML special characters for safe server-rendered OAuth UI pages.
 * @param {unknown} str
 * @returns {string}
 */
export function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Inspect whether a regex pattern contains structural ReDoS hazards such as
 * nested repeating quantifiers, backreferences, or huge bounded quantifiers.
 * @param {string} pattern
 * @returns {string | null} reason if unsafe, null if safe
 */
function detectUnsafeRegex(pattern) {
  let inCharClass = false;
  let escaped = false;
  let wildcardCount = 0;
  // Stack of open groups: each tracks whether a repeating quantifier occurred inside it.
  const groupStack = [];

  const readQuantifierAt = (index) => {
    const ch = pattern[index];
    if (ch === "+" || ch === "*") {
      return { repeating: true, nextIndex: index + 1 };
    }
    if (ch === "?") {
      return { repeating: false, nextIndex: index + 1 };
    }
    if (ch === "{") {
      const m = pattern.slice(index).match(/^\{(\d+)(?:,(\d*))?\}/);
      if (m) {
        const min = Number(m[1]);
        const max = m[2] === undefined ? min : m[2] === "" ? Infinity : Number(m[2]);
        if (min > 500 || (Number.isFinite(max) && max > 500)) {
          return { tooLarge: true, repeating: true, nextIndex: index + m[0].length };
        }
        return { repeating: max > 1 || max === Infinity, nextIndex: index + m[0].length };
      }
    }
    return null;
  };

  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (escaped) {
      if (!inCharClass && (/[1-9]/.test(ch) || (ch === "k" && pattern[i + 1] === "<"))) {
        return "Backreferences are not allowed in regex search patterns";
      }
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (inCharClass) {
      if (ch === "]") {
        inCharClass = false;
      }
      continue;
    }
    if (ch === "[") {
      inCharClass = true;
      continue;
    }
    if (ch === "(") {
      groupStack.push({ hasRepeat: false, hasAlternation: false });
      continue;
    }
    if (ch === "|" && groupStack.length > 0) {
      groupStack[groupStack.length - 1].hasAlternation = true;
      continue;
    }
    if (ch === ")") {
      const closed = groupStack.pop();
      const q = readQuantifierAt(i + 1);
      if (q?.tooLarge) {
        return "Regex quantifier bound exceeds maximum allowed limit (500)";
      }
      if (closed && q?.repeating) {
        if (closed.hasRepeat) {
          return "Nested repeating quantifiers are blocked to prevent catastrophic backtracking (ReDoS)";
        }
        if (groupStack.length > 0) {
          groupStack[groupStack.length - 1].hasRepeat = true;
        }
      } else if (closed && closed.hasRepeat && groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasRepeat = true;
      }
      if (q) {
        i = q.nextIndex - 1;
      }
      continue;
    }
    if (ch === "." && (pattern[i + 1] === "*" || pattern[i + 1] === "+")) {
      wildcardCount += 1;
      if (wildcardCount >= 3) {
        return "Pattern contains too many chained '.*'/'.+' wildcards";
      }
    }

    const q = readQuantifierAt(i);
    if (q) {
      if (q.tooLarge) {
        return "Regex quantifier bound exceeds maximum allowed limit (500)";
      }
      if (q.repeating && groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasRepeat = true;
      }
      i = q.nextIndex - 1;
    }
  }

  return null;
}

/**
 * Compile a user-provided regex string with ReDoS safety checks.
 * @param {string} pattern
 * @param {{ caseSensitive?: boolean, maxLength?: number }} [options]
 * @returns {RegExp}
 */
export function compileSafeRegex(pattern, { caseSensitive = false, maxLength = 200 } = {}) {
  const src = String(pattern ?? "");
  if (!src) {
    throw new Error("Regex query cannot be empty");
  }
  if (src.length > maxLength) {
    throw new Error(`Regex query exceeds maximum length of ${maxLength} characters`);
  }
  const unsafeReason = detectUnsafeRegex(src);
  if (unsafeReason) {
    throw new Error(unsafeReason);
  }
  try {
    return new RegExp(src, caseSensitive ? "" : "i");
  } catch (err) {
    throw new Error(`Invalid regular expression: ${err.message}`);
  }
}

/**
 * Convert a single simple glob pattern into a case-insensitive matcher function.
 * @param {string} rawPattern
 * @returns {(relPath: string) => boolean}
 */
function compileSingleGlob(rawPattern) {
  const normalized = normalizeSlashes(rawPattern).trim().toLowerCase();
  if (
    normalized.startsWith(".") &&
    !normalized.includes("/") &&
    !normalized.includes("*") &&
    !normalized.includes("?")
  ) {
    return (relPath) => relPath.toLowerCase().endsWith(normalized);
  }

  const matchFullPath = normalized.includes("/");
  let reStr = "^";
  for (let i = 0; i < normalized.length; i += 1) {
    const ch = normalized[i];
    if (ch === "*") {
      if (normalized[i + 1] === "*") {
        if (normalized[i + 2] === "/") {
          reStr += "(?:.*/)?";
          i += 2;
        } else {
          reStr += ".*";
          i += 1;
        }
      } else {
        reStr += "[^/]*";
      }
    } else if (ch === "?") {
      reStr += "[^/]";
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      reStr += `\\${ch}`;
    } else {
      reStr += ch;
    }
  }
  reStr += "$";
  const regex = new RegExp(reStr, "i");

  return (relPath) => {
    const clean = normalizeSlashes(relPath);
    if (matchFullPath) {
      return regex.test(clean);
    }
    const base = clean.includes("/") ? clean.slice(clean.lastIndexOf("/") + 1) : clean;
    return regex.test(base);
  };
}

/**
 * Compile a comma-separated glob/extension filter (e.g. ".ts,.tsx", "*.py", "src/**\/*.mjs").
 * Returns null if no filter was provided.
 * @param {string | undefined} fileGlob
 * @returns {((relPath: string) => boolean) | null}
 */
export function compileGlobMatcher(fileGlob) {
  if (!fileGlob || typeof fileGlob !== "string" || !fileGlob.trim()) {
    return null;
  }
  const parts = fileGlob
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    return null;
  }
  const matchers = parts.map(compileSingleGlob);
  return (relPath) => matchers.some((fn) => fn(relPath));
}
