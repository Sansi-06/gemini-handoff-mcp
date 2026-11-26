import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeSlashes } from "./http-utils.mjs";
import { isValidMountAlias, timingSafeEqualStr } from "./security.mjs";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = path.resolve(MODULE_DIR, "..");

let pkgVersion = "1.0.0";
try {
  const pkg = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf8"));
  if (typeof pkg?.version === "string" && pkg.version.trim()) {
    pkgVersion = pkg.version.trim();
  }
} catch {
  // Fallback to 1.0.0 if package.json cannot be read
}
export const APP_VERSION = pkgVersion;

/**
 * Parse truthy/falsy boolean environment values.
 * @param {unknown} value
 * @param {boolean} [fallback]
 * @returns {boolean}
 */
export function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const lower = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(lower)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(lower)) {
    return false;
  }
  return fallback;
}

/**
 * Parse a bounded integer configuration value.
 * @param {unknown} value
 * @param {number} fallback
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function parseBoundedInt(value, fallback, min, max) {
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
 * Normalize comma-separated or array relative write prefixes (e.g. `reports/,drafts`).
 * @param {unknown} raw
 * @returns {string[]}
 */
export function normalizeWritePrefixes(raw) {
  const list = Array.isArray(raw)
    ? raw
    : String(raw ?? "")
        .split(",")
        .map((s) => s.trim());

  const cleaned = [];
  for (const item of list) {
    const norm = normalizeSlashes(String(item ?? "").trim())
      .replace(/^\/+/, "")
      .replace(/\/+$/, "");
    if (!norm || norm === "." || norm.includes("..")) {
      continue;
    }
    cleaned.push(norm);
  }
  return [...new Set(cleaned)];
}

/**
 * Parse read-only virtual mount definitions from `alias=/abs/path;alias2=/abs/path2`,
 * a JSON object string `{"alias":"/abs/path"}`, or a plain JS object.
 * @param {unknown} raw
 * @param {string} baseDir
 * @returns {Record<string, string>}
 */
export function parseMountSpec(raw, baseDir) {
  if (!raw) {
    return {};
  }

  let pairs = [];
  if (typeof raw === "object" && !Array.isArray(raw)) {
    pairs = Object.entries(raw);
  } else {
    const text = String(raw).trim();
    if (!text) {
      return {};
    }
    if (text.startsWith("{")) {
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          pairs = Object.entries(parsed);
        }
      } catch {
        throw new Error(`Invalid JSON mount specification: ${text}`);
      }
    } else {
      for (const entry of text.split(/[;\r\n]+/)) {
        const trimmed = entry.trim();
        if (!trimmed) {
          continue;
        }
        const eq = trimmed.indexOf("=");
        if (eq <= 0) {
          throw new Error(
            `Invalid mount entry '${trimmed}'. Expected 'alias=/path/to/dir' separated by ';'.`
          );
        }
        pairs.push([trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim()]);
      }
    }
  }

  const mounts = {};
  for (const [aliasRaw, targetRaw] of pairs) {
    const alias = String(aliasRaw).trim();
    const target = String(targetRaw ?? "").trim();
    if (!isValidMountAlias(alias)) {
      throw new Error(
        `Invalid mount alias '${alias}'. Use 1-64 characters [a-zA-Z0-9._-] (non-sensitive).`
      );
    }
    if (!target) {
      throw new Error(`Mount '${alias}' is missing a directory path`);
    }
    mounts[alias] = path.resolve(baseDir, target);
  }
  return mounts;
}

/**
 * Parse a .env file into a key-value map.
 * Optionally assigns parsed values into `process.env`.
 *
 * @param {string} envPath
 * @param {{ override?: boolean, assignToProcessEnv?: boolean }} [options]
 * @returns {Record<string, string>}
 */
export function loadEnvFile(envPath, { override = false, assignToProcessEnv = true } = {}) {
  if (!envPath || !fs.existsSync(envPath)) {
    return {};
  }

  const content = fs.readFileSync(envPath, "utf8");
  const parsed = {};

  for (const rawLine of content.split(/\r?\n/)) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const line = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
    const eqIndex = line.indexOf("=");
    if (eqIndex <= 0) {
      continue;
    }

    const key = line.slice(0, eqIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }

    let value = line.slice(eqIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') {
        value = value
          .replace(/\\n/g, "\n")
          .replace(/\\r/g, "\r")
          .replace(/\\t/g, "\t")
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, "\\");
      }
    } else {
      const commentIndex = value.indexOf(" #");
      if (commentIndex !== -1) {
        value = value.slice(0, commentIndex).trim();
      }
    }

    parsed[key] = value;
    if (assignToProcessEnv && (override || process.env[key] === undefined)) {
      process.env[key] = value;
    }
  }

  return parsed;
}

/**
 * Ensure all required storage directories exist on disk.
 * @param {ReturnType<typeof loadConfig>} config
 */
export function ensureStorageDirs(config) {
  for (const dir of [
    config.dataDir,
    config.tasksDir,
    config.filesRoot,
    config.notesRoot,
    config.reposRoot,
    config.snapshotsDir,
  ].filter(Boolean)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Parse comma-separated or array origin allowlist (e.g. "https://gemini.google.com,http://localhost:3000").
 * @param {unknown} raw
 * @returns {string[]}
 */
export function parseAllowedOrigins(raw) {
  const list = Array.isArray(raw)
    ? raw
    : String(raw ?? "")
        .split(",")
        .map((s) => s.trim());
  const origins = [];
  for (const item of list) {
    if (!item) {
      continue;
    }
    try {
      const u = new URL(item);
      if (u.protocol === "http:" || u.protocol === "https:") {
        origins.push(u.origin);
      }
    } catch {
      // Ignore malformed origins
    }
  }
  return [...new Set(origins)];
}

/**
 * Resolve per-account isolated FILES_ROOT directory when tenant isolation is active.
 * Default account keeps legacy `config.filesRoot` for seamless single-account compatibility.
 * Named accounts (e.g. acc1, acc2, personal, work) are isolated under DATA_DIR/accounts/<account>/files.
 * @param {Record<string, any>} config
 * @param {string} [account]
 * @returns {string}
 */
export function resolveTenantFilesRoot(config, account = "default") {
  const clean = String(account || "default").trim().toLowerCase() || "default";
  if (config?.tenantIsolation === false || clean === "default" || clean === "admin") {
    return config.filesRoot;
  }
  if (!/^[a-z0-9_.@-]{1,64}$/.test(clean) || clean === "." || clean === "..") {
    throw new Error(`Invalid account namespace: ${clean}`);
  }
  const baseDataDir = config.dataDir || path.dirname(config.filesRoot);
  const tenantDir = path.join(baseDataDir, "accounts", clean, "files");
  fs.mkdirSync(tenantDir, { recursive: true });
  return tenantDir;
}

/**
 * Parse multi-account passphrases from delimited string or object.
 * Format: "personal:pass1,work:pass2" or "personal:pass1;work:pass2" or JSON.
 * @param {unknown} rawPassphrases
 * @param {string} [defaultPassphrase]
 * @returns {Map<string, { name: string, passphrase: string }>}
 */
export function parseAccounts(rawPassphrases, defaultPassphrase = "") {
  const accounts = new Map();

  const addAccount = (name, passphrase) => {
    const cleanName = String(name ?? "").trim().toLowerCase();
    const cleanPass = String(passphrase ?? "").trim();
    if (cleanName && cleanPass && /^[a-z0-9_-]{1,32}$/.test(cleanName)) {
      accounts.set(cleanName, { name: cleanName, passphrase: cleanPass });
    }
  };

  if (rawPassphrases) {
    if (typeof rawPassphrases === "object" && !Array.isArray(rawPassphrases)) {
      for (const [k, v] of Object.entries(rawPassphrases)) {
        addAccount(k, v);
      }
    } else {
      const str = String(rawPassphrases).trim();
      if (str.startsWith("{")) {
        try {
          const parsed = JSON.parse(str);
          for (const [k, v] of Object.entries(parsed)) {
            addAccount(k, v);
          }
        } catch {
          // fall through
        }
      }
      if (accounts.size === 0) {
        const tokens = str.split(/[;,]/);
        for (const token of tokens) {
          const trimmed = token.trim();
          if (!trimmed) continue;
          const idx = trimmed.indexOf(":");
          if (idx !== -1) {
            addAccount(trimmed.slice(0, idx), trimmed.slice(idx + 1));
          }
        }
      }
    }
  }

  if (defaultPassphrase) {
    const cleanPass = String(defaultPassphrase).trim();
    if (cleanPass && !accounts.has("default")) {
      accounts.set("default", { name: "default", passphrase: cleanPass });
    }
  }

  return accounts;
}

/**
 * Parse per-account secret path keys for zero-prompt `/mcp/u/<key>` connections.
 * Format: "acc1:gbk_xxx,acc2:gbk_yyy" or ";" delimited or JSON object.
 * @param {unknown} raw
 * @returns {Map<string, { name: string, key: string }>}
 */
export function parseAccountKeys(raw) {
  const accountKeys = new Map();

  const addEntry = (name, key) => {
    const cleanName = String(name ?? "").trim().toLowerCase();
    const cleanKey = String(key ?? "").trim();
    if (
      cleanName &&
      /^[a-z0-9_.@-]{1,64}$/.test(cleanName) &&
      cleanKey.length >= 8 &&
      /^[A-Za-z0-9._~-]+$/.test(cleanKey)
    ) {
      accountKeys.set(cleanName, { name: cleanName, key: cleanKey });
    }
  };

  if (raw) {
    if (typeof raw === "object" && !Array.isArray(raw)) {
      for (const [k, v] of Object.entries(raw)) {
        addEntry(k, v);
      }
    } else {
      const str = String(raw).trim();
      if (str.startsWith("{")) {
        try {
          const parsed = JSON.parse(str);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            for (const [k, v] of Object.entries(parsed)) {
              addEntry(k, v);
            }
          }
        } catch {
          // fall through to delimited parsing
        }
      }
      if (accountKeys.size === 0) {
        for (const token of str.split(/[;,]/)) {
          const trimmed = token.trim();
          if (!trimmed) continue;
          const idx = trimmed.indexOf(":");
          if (idx !== -1) {
            addEntry(trimmed.slice(0, idx), trimmed.slice(idx + 1));
          }
        }
      }
    }
  }

  return accountKeys;
}

/**
 * Match a submitted path key against configured per-account keys in constant time.
 * Iterates all configured entries without early return to avoid timing position leaks.
 * @param {string} providedKey
 * @param {Record<string, any>} config
 * @returns {{ name: string } | null}
 */
export function resolveAccountByPathKey(providedKey, config) {
  if (typeof providedKey !== "string" || !providedKey) {
    return null;
  }
  const accountKeys = config.accountKeys || new Map();
  let matched = null;
  for (const entry of accountKeys.values()) {
    if (timingSafeEqualStr(providedKey, entry.key)) {
      matched = { name: entry.name };
    }
  }
  return matched;
}

/**
 * Match a submitted passphrase against configured multi-accounts in constant time.
 * @param {string} passphrase
 * @param {Record<string, any>} config
 * @returns {{ name: string, passphrase: string } | null}
 */
export function resolveAccountByPassphrase(passphrase, config) {
  if (typeof passphrase !== "string" || !passphrase) {
    return null;
  }
  const accounts = config.accounts || new Map();
  for (const account of accounts.values()) {
    if (timingSafeEqualStr(passphrase, account.passphrase)) {
      return account;
    }
  }
  if (config.ownerPassphrase && timingSafeEqualStr(passphrase, config.ownerPassphrase)) {
    return { name: "default", passphrase: config.ownerPassphrase };
  }
  return null;
}

/**
 * Load and validate server configuration from .env, process.env, and explicit overrides.
 * @param {Record<string, any>} [overrides]
 */
export function loadConfig(overrides = {}) {
  const {
    envPath = path.join(PROJECT_ROOT, ".env"),
    skipDotEnv = false,
    ...restOverrides
  } = overrides;

  const fileEnv = skipDotEnv
    ? {}
    : loadEnvFile(envPath, { override: false, assignToProcessEnv: false });

  const pick = (envKey, overrideKey, fallback = "") => {
    if (restOverrides[overrideKey] !== undefined && restOverrides[overrideKey] !== null) {
      return restOverrides[overrideKey];
    }
    if (process.env[envKey] !== undefined) {
      return process.env[envKey];
    }
    if (fileEnv[envKey] !== undefined) {
      return fileEnv[envKey];
    }
    return fallback;
  };

  const baseDir = restOverrides.baseDir
    ? path.resolve(restOverrides.baseDir)
    : PROJECT_ROOT;

  const rawDataDir = String(pick("DATA_DIR", "dataDir", "./data")).trim() || "./data";
  const dataDir = path.resolve(baseDir, rawDataDir);

  const resolveBucketDir = (envKey, overrideKey, defaultSubdir) => {
    const raw = String(pick(envKey, overrideKey, "")).trim();
    return raw ? path.resolve(baseDir, raw) : path.join(dataDir, defaultSubdir);
  };

  const rawPort = Number(pick("PORT", "port", 8787));
  const port = Number.isInteger(rawPort) && rawPort >= 0 && rawPort <= 65535 ? rawPort : 8787;
  const host = String(pick("HOST", "host", "127.0.0.1")).trim() || "127.0.0.1";
  const rawAdminPort = pick("ADMIN_PORT", "adminPort", "");
  const parsedAdminPort = rawAdminPort === "" ? null : Number(rawAdminPort);
  const adminPort =
    parsedAdminPort !== null &&
    Number.isInteger(parsedAdminPort) &&
    parsedAdminPort >= 0 &&
    parsedAdminPort <= 65535
      ? parsedAdminPort
      : null;
  const adminHost = String(pick("ADMIN_HOST", "adminHost", "127.0.0.1")).trim() || "127.0.0.1";
  const publicBaseUrl = String(pick("PUBLIC_BASE_URL", "publicBaseUrl", ""))
    .trim()
    .replace(/\/+$/, "");

  const ownerPassphrase = String(pick("OWNER_PASSPHRASE", "ownerPassphrase", "")).trim();
  const rawAccounts = pick("OWNER_PASSPHRASES", "ownerPassphrases", "");
  const accounts = parseAccounts(rawAccounts, ownerPassphrase);
  const rawAccountKeys = pick("MCP_ACCOUNT_KEYS", "mcpAccountKeys", "");
  const accountKeys = parseAccountKeys(rawAccountKeys);
  const primaryPassphrase = ownerPassphrase || accounts.values().next().value?.passphrase || "";
  const adminToken = String(pick("ADMIN_TOKEN", "adminToken", "")).trim();

  if ((!primaryPassphrase && accountKeys.size === 0) || !adminToken) {
    throw new Error(
      "Missing OWNER_PASSPHRASE (or MCP_ACCOUNT_KEYS) or ADMIN_TOKEN. Run `node cli/handoff-cli.mjs init-env` first or configure them in .env / environment variables."
    );
  }

  const rawAllowedUris = pick("ALLOWED_REDIRECT_URIS", "allowedRedirectUris", "");
  const allowedRedirectUris = Array.isArray(rawAllowedUris)
    ? rawAllowedUris.map((u) => String(u).trim()).filter(Boolean)
    : String(rawAllowedUris)
        .split(",")
        .map((u) => u.trim())
        .filter(Boolean);

  const readOnlyMode = parseBoolean(pick("READ_ONLY_MODE", "readOnlyMode", false), false);
  const writeAllowedPrefixes = normalizeWritePrefixes(
    pick("WRITE_ALLOWED_PREFIXES", "writeAllowedPrefixes", "")
  );
  const tenantIsolation = parseBoolean(pick("TENANT_ISOLATION", "tenantIsolation", true), true);
  const allowedOrigins = parseAllowedOrigins(pick("ALLOWED_ORIGINS", "allowedOrigins", ""));
  const sessionTtlMs = parseBoundedInt(
    pick("MCP_SESSION_TTL_MS", "sessionTtlMs", 20 * 60 * 1000),
    20 * 60 * 1000,
    60 * 1000,
    24 * 60 * 60 * 1000
  );
  const zeroCallSessionTtlMs = parseBoundedInt(
    pick("MCP_ZERO_CALL_SESSION_TTL_MS", "zeroCallSessionTtlMs", 5 * 60 * 1000),
    5 * 60 * 1000,
    30 * 1000,
    60 * 60 * 1000
  );
  const maxSessions = parseBoundedInt(
    pick("MCP_MAX_SESSIONS", "maxSessions", 256),
    256,
    16,
    2000
  );
  const maxWriteBytes = parseBoundedInt(
    pick("MAX_WRITE_BYTES", "maxWriteBytes", 2 * 1024 * 1024),
    2 * 1024 * 1024,
    1024,
    10 * 1024 * 1024
  );
  const snapshotRetention = parseBoundedInt(
    pick("SNAPSHOT_RETENTION", "snapshotRetention", 20),
    20,
    0,
    200
  );
  const maxToolCallsPerMinute = parseBoundedInt(
    pick("MAX_TOOL_CALLS_PER_MINUTE", "maxToolCallsPerMinute", 120),
    120,
    0,
    10_000
  );
  const oauthMaxFailedAuth = parseBoundedInt(
    pick("OAUTH_MAX_FAILED_AUTH", "oauthMaxFailedAuth", 15),
    15,
    1,
    1000
  );
  const repoMounts = parseMountSpec(pick("REPO_MOUNTS", "repoMounts", ""), baseDir);
  const noteMounts = parseMountSpec(pick("NOTE_MOUNTS", "noteMounts", ""), baseDir);

  const config = {
    port,
    host,
    adminPort,
    adminHost,
    publicBaseUrl,
    dataDir,
    tasksDir: path.join(dataDir, "tasks"),
    filesRoot: resolveBucketDir("FILES_ROOT", "filesRoot", "files"),
    notesRoot: resolveBucketDir("NOTES_ROOT", "notesRoot", "notes"),
    reposRoot: resolveBucketDir("REPOS_ROOT", "reposRoot", "repos"),
    snapshotsDir: path.join(dataDir, "snapshots"),
    auditLogFile: path.join(dataDir, "audit.jsonl"),
    oauthStateFile: path.join(dataDir, "oauth-state.json"),
    ownerPassphrase,
    accounts,
    accountKeys,
    adminToken,
    staticOAuthClientId: String(pick("STATIC_OAUTH_CLIENT_ID", "staticOAuthClientId", "")).trim(),
    staticOAuthClientSecret: String(
      pick("STATIC_OAUTH_CLIENT_SECRET", "staticOAuthClientSecret", "")
    ).trim(),
    allowedRedirectUris,
    readOnlyMode,
    writeAllowedPrefixes,
    tenantIsolation,
    allowedOrigins,
    sessionTtlMs,
    zeroCallSessionTtlMs,
    maxSessions,
    maxWriteBytes,
    snapshotRetention,
    maxToolCallsPerMinute,
    oauthMaxFailedAuth,
    repoMounts,
    noteMounts,
    bridgeUrl: String(pick("BRIDGE_URL", "bridgeUrl", "http://127.0.0.1:8787"))
      .trim()
      .replace(/\/+$/, ""),
  };

  ensureStorageDirs(config);
  return config;
}
