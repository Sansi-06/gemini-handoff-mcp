import crypto from "node:crypto";
import fs from "node:fs";
import { resolveAccountByPassphrase, resolveAccountByPathKey } from "./config.mjs";
import { SlidingWindowRateLimiter } from "./harness.mjs";
import {
  HttpError,
  extractBearerToken,
  readJsonBody,
  readRawBody,
  sendHtml,
  sendJson,
} from "./http-utils.mjs";
import { escapeHtml, timingSafeEqualStr } from "./security.mjs";
import { atomicWriteFile } from "./store.mjs";

const OAUTH_MAX_BODY_BYTES = 64 * 1024;
const MAX_STATE_LENGTH = 16384;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CSRF_TTL_MS = 15 * 60 * 1000;

/**
 * SHA-256 hex digest helper used for storing sensitive tokens at rest.
 * @param {string} value
 * @returns {string}
 */
function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Compute PKCE S256 challenge from code_verifier.
 * @param {string} verifier
 * @returns {string}
 */
function computeS256Challenge(verifier) {
  return crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
}

/**
 * Validate redirect URI safety: HTTPS everywhere, or HTTP strictly on localhost / 127.0.0.1.
 * Also allows explicitly configured ALLOWED_REDIRECT_URIS.
 * @param {string} rawUri
 * @param {string[]} [allowedRedirectUris]
 * @returns {boolean}
 */
function isValidRedirectUri(rawUri, allowedRedirectUris = []) {
  if (typeof rawUri !== "string" || rawUri.length === 0 || rawUri.length > 2048) {
    return false;
  }
  if (allowedRedirectUris.includes(rawUri)) {
    return true;
  }
  try {
    const parsed = new URL(rawUri);
    if (parsed.hash) {
      return false;
    }
    if (parsed.protocol === "https:") {
      return Boolean(parsed.hostname);
    }
    if (parsed.protocol === "http:") {
      return parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
    }
    return false;
  } catch {
    return false;
  }
}

const SAFE_HOST_RE = /^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$/;

/**
 * Determine canonical external base URL honoring reverse proxy headers or PUBLIC_BASE_URL.
 * @param {import("node:http").IncomingMessage} req
 * @param {Record<string, any>} config
 * @returns {string}
 */
export function getBaseUrl(req, config) {
  if (config.publicBaseUrl) {
    return config.publicBaseUrl.replace(/\/+$/, "");
  }
  const rawProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const proto =
    rawProto === "https" || rawProto === "http"
      ? rawProto
      : req.socket?.encrypted
        ? "https"
        : "http";
  const rawHost = String(req.headers["x-forwarded-host"] || req.headers.host || "")
    .split(",")[0]
    .trim();
  const host = SAFE_HOST_RE.test(rawHost) ? rawHost : `127.0.0.1:${config.port}`;
  return `${proto}://${host}`;
}

/**
 * Persistent OAuth 2.1 + PKCE + RFC 7591 Dynamic Client Registration manager.
 */
export class OAuthManager {
  /**
   * @param {string} stateFile
   * @param {Record<string, any>} config
   */
  constructor(stateFile, config) {
    this.stateFile = stateFile;
    this.config = config;
    this.clients = new Map();
    this.codes = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
    this.csrfTokens = new Map();
    this._saveQueue = Promise.resolve();
    this.authFailureLimiter = new SlidingWindowRateLimiter({
      maxRequests: config?.oauthMaxFailedAuth ?? 15,
      windowMs: 15 * 60 * 1000,
    });
    this.registerLimiter = new SlidingWindowRateLimiter({
      maxRequests: 30,
      windowMs: 60 * 60 * 1000,
    });

    this.#loadFromDisk();
  }

  #loadFromDisk() {
    if (!this.stateFile || !fs.existsSync(this.stateFile)) {
      return;
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(this.stateFile, "utf8"));
      for (const [k, v] of Object.entries(parsed.clients ?? {})) {
        this.clients.set(k, v);
      }
      for (const [k, v] of Object.entries(parsed.accessTokens ?? {})) {
        this.accessTokens.set(k, v);
      }
      for (const [k, v] of Object.entries(parsed.refreshTokens ?? {})) {
        this.refreshTokens.set(k, v);
      }
      this.pruneExpired();
    } catch {
      // Corrupt state file resets cleanly rather than blocking boot.
    }
  }

  /**
   * Remove expired codes, CSRF tokens, access tokens, and refresh tokens.
   */
  pruneExpired() {
    const now = Date.now();
    for (const [k, v] of this.codes) {
      if (v.expiresAt <= now) {
        this.codes.delete(k);
      }
    }
    for (const [k, v] of this.csrfTokens) {
      if (v.expiresAt <= now) {
        this.csrfTokens.delete(k);
      }
    }
    for (const [k, v] of this.accessTokens) {
      if (v.expiresAt <= now) {
        this.accessTokens.delete(k);
      }
    }
    for (const [k, v] of this.refreshTokens) {
      if (v.expiresAt <= now) {
        this.refreshTokens.delete(k);
      }
    }
  }

  /**
   * Persist registered clients and active tokens atomically.
   * @returns {Promise<void>}
   */
  save() {
    this.pruneExpired();
    const snapshot = JSON.stringify(
      {
        clients: Object.fromEntries(this.clients),
        accessTokens: Object.fromEntries(this.accessTokens),
        refreshTokens: Object.fromEntries(this.refreshTokens),
      },
      null,
      2
    );

    const nextSave = this._saveQueue
      .catch(() => {})
      .then(() => atomicWriteFile(this.stateFile, `${snapshot}\n`));
    this._saveQueue = nextSave;
    return nextSave;
  }

  /**
   * Register a new OAuth client via RFC 7591 Dynamic Client Registration.
   * @param {Record<string, any>} payload
   */
  async registerClient(payload) {
    const redirectUris = payload?.redirect_uris;
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new HttpError(400, "redirect_uris must be a non-empty array");
    }

    const cleanedUris = redirectUris.map((u) => String(u));
    for (const uri of cleanedUris) {
      if (!isValidRedirectUri(uri, this.config.allowedRedirectUris)) {
        throw new HttpError(400, `Invalid or disallowed redirect_uri: ${uri}`);
      }
    }

    const authMethod = ["none", "client_secret_post", "client_secret_basic"].includes(
      payload?.token_endpoint_auth_method
    )
      ? payload.token_endpoint_auth_method
      : "client_secret_post";

    const clientId = `gb_c_${crypto.randomBytes(12).toString("hex")}`;
    const issuedAt = Math.floor(Date.now() / 1000);
    const isPublic = authMethod === "none";
    const clientSecret = isPublic ? null : `gb_s_${crypto.randomBytes(16).toString("hex")}`;

    const record = {
      client_id: clientId,
      client_secret_hash: clientSecret ? sha256Hex(clientSecret) : null,
      client_id_issued_at: issuedAt,
      redirect_uris: cleanedUris,
      token_endpoint_auth_method: authMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: String(payload?.client_name || "Gemini MCP Client").slice(0, 120),
      scope: String(payload?.scope || "mcp:tools"),
    };

    this.clients.set(clientId, record);
    await this.save();

    const response = {
      client_id: record.client_id,
      client_id_issued_at: record.client_id_issued_at,
      redirect_uris: record.redirect_uris,
      token_endpoint_auth_method: record.token_endpoint_auth_method,
      grant_types: record.grant_types,
      response_types: record.response_types,
      client_name: record.client_name,
      scope: record.scope,
    };

    if (clientSecret) {
      response.client_secret = clientSecret;
      response.client_secret_expires_at = 0;
    }

    return response;
  }

  /**
   * Look up either a dynamically registered client or the configured static OAuth client.
   * @param {string} clientId
   */
  resolveClient(clientId) {
    if (!clientId) {
      return null;
    }
    const dcrClient = this.clients.get(clientId);
    if (dcrClient) {
      return { ...dcrClient, isStatic: false };
    }
    if (
      this.config.staticOAuthClientId &&
      timingSafeEqualStr(clientId, this.config.staticOAuthClientId)
    ) {
      const hasSecret = Boolean(this.config.staticOAuthClientSecret);
      return {
        client_id: this.config.staticOAuthClientId,
        client_secret_plain: this.config.staticOAuthClientSecret || null,
        redirect_uris: this.config.allowedRedirectUris,
        token_endpoint_auth_method: hasSecret ? "client_secret_post" : "none",
        client_name: "Static Configured OAuth Client",
        scope: "mcp:tools",
        isStatic: true,
      };
    }
    return null;
  }

  /**
   * Check whether `redirectUri` is permitted for `client`.
   * @param {ReturnType<OAuthManager["resolveClient"]>} client
   * @param {string} redirectUri
   * @returns {boolean}
   */
  isRedirectAllowed(client, redirectUri) {
    if (!client || !redirectUri) {
      return false;
    }
    if (!client.isStatic) {
      return client.redirect_uris.includes(redirectUri);
    }
    if (client.redirect_uris.length > 0) {
      return client.redirect_uris.includes(redirectUri);
    }
    return isValidRedirectUri(redirectUri, this.config.allowedRedirectUris);
  }

  /**
   * Verify client credentials if the client is confidential.
   * @param {NonNullable<ReturnType<OAuthManager["resolveClient"]>>} client
   * @param {string | null} providedSecret
   * @returns {boolean}
   */
  verifyClientSecret(client, providedSecret) {
    if (client.token_endpoint_auth_method === "none") {
      return true;
    }
    if (!providedSecret) {
      return false;
    }
    if (client.isStatic) {
      return timingSafeEqualStr(providedSecret, client.client_secret_plain || "");
    }
    return timingSafeEqualStr(sha256Hex(providedSecret), client.client_secret_hash || "");
  }

  /**
   * Issue a single-use CSRF token bound to the consent form.
   * @returns {string}
   */
  issueCsrfToken() {
    this.pruneExpired();
    const token = crypto.randomBytes(24).toString("base64url");
    this.csrfTokens.set(token, { expiresAt: Date.now() + CSRF_TTL_MS });
    return token;
  }

  /**
   * Consume a CSRF token if valid and unexpired.
   * @param {string} token
   * @returns {boolean}
   */
  consumeCsrfToken(token) {
    if (!token) {
      return false;
    }
    const entry = this.csrfTokens.get(token);
    if (!entry) {
      return false;
    }
    this.csrfTokens.delete(token);
    return entry.expiresAt > Date.now();
  }

  /**
   * Issue a single-use authorization code after passphrase approval.
   */
  issueAuthorizationCode({ clientId, redirectUri, codeChallenge, codeChallengeMethod, scope, resource, accountId = "default" }) {
    this.pruneExpired();
    const code = crypto.randomBytes(32).toString("base64url");
    this.codes.set(code, {
      clientId,
      redirectUri,
      codeChallenge: codeChallenge || null,
      codeChallengeMethod: codeChallengeMethod || null,
      scope: scope || "mcp:tools",
      resource: resource || null,
      accountId: accountId || "default",
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });
    return code;
  }

  /**
   * Issue an access_token + refresh_token pair and persist hashes.
   */
  async issueTokenPair({ clientId, scope, resource, accountId = "default" }) {
    const accessToken = `gb_at_${crypto.randomBytes(32).toString("base64url")}`;
    const refreshToken = `gb_rt_${crypto.randomBytes(32).toString("base64url")}`;
    const now = Date.now();

    this.accessTokens.set(sha256Hex(accessToken), {
      clientId,
      scope,
      resource: resource || null,
      accountId,
      expiresAt: now + ACCESS_TOKEN_TTL_MS,
    });

    this.refreshTokens.set(sha256Hex(refreshToken), {
      clientId,
      scope,
      resource: resource || null,
      accountId,
      expiresAt: now + REFRESH_TOKEN_TTL_MS,
    });

    await this.save();

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
      refresh_token: refreshToken,
      scope,
      account_id: accountId,
    };
  }

  /**
   * Exchange an authorization code for tokens, verifying client, redirect_uri, and PKCE S256.
   */
  async exchangeAuthorizationCode({ code, client, redirectUri, codeVerifier }) {
    if (!code) {
      throw new HttpError(400, "Missing authorization code");
    }
    const record = this.codes.get(code);
    // Delete immediately to guarantee single-use and prevent replay attacks.
    this.codes.delete(code);

    if (!record || record.expiresAt <= Date.now()) {
      throw new HttpError(400, "Invalid or expired authorization code");
    }
    if (record.clientId !== client.client_id) {
      throw new HttpError(400, "Authorization code was not issued to this client");
    }
    if (record.redirectUri !== redirectUri) {
      throw new HttpError(400, "redirect_uri mismatch");
    }
    if (record.codeChallenge) {
      if (!codeVerifier) {
        throw new HttpError(400, "Missing PKCE code_verifier");
      }
      const computed = computeS256Challenge(codeVerifier);
      if (!timingSafeEqualStr(computed, record.codeChallenge)) {
        throw new HttpError(400, "Invalid PKCE code_verifier");
      }
    }

    return this.issueTokenPair({
      clientId: client.client_id,
      scope: record.scope,
      resource: record.resource,
      accountId: record.accountId || "default",
    });
  }

  /**
   * Rotate a refresh token and issue a fresh access/refresh token pair.
   */
  async exchangeRefreshToken({ refreshToken, client }) {
    if (!refreshToken) {
      throw new HttpError(400, "Missing refresh_token");
    }
    const hash = sha256Hex(refreshToken);
    const record = this.refreshTokens.get(hash);
    if (!record || record.expiresAt <= Date.now()) {
      this.refreshTokens.delete(hash);
      throw new HttpError(400, "Invalid or expired refresh_token");
    }
    if (record.clientId !== client.client_id) {
      throw new HttpError(400, "refresh_token was not issued to this client");
    }

    this.refreshTokens.delete(hash);
    return this.issueTokenPair({
      clientId: client.client_id,
      scope: record.scope,
      resource: record.resource,
      accountId: record.accountId || "default",
    });
  }

  /**
   * Validate an OAuth access token.
   * @param {string} token
   */
  validateAccessToken(token) {
    if (!token) {
      return null;
    }
    const entry = this.accessTokens.get(sha256Hex(token));
    if (!entry || entry.expiresAt <= Date.now()) {
      return null;
    }
    return entry;
  }
}

/**
 * Verify incoming Bearer auth against OAuth access tokens or ADMIN_TOKEN.
 * @param {import("node:http").IncomingMessage} req
 * @param {Record<string, any>} config
 * @param {OAuthManager} oauth
 * @returns {{ ok: boolean, mode?: "oauth" | "admin", scope?: string }}
 */
export function verifyBearerToken(req, config, oauth) {
  const token = extractBearerToken(req);
  if (!token) {
    return { ok: false };
  }
  if (timingSafeEqualStr(token, config.adminToken)) {
    return { ok: true, mode: "admin", scope: "mcp:tools", accountId: "admin" };
  }
  const tokenRecord = oauth.validateAccessToken(token);
  if (tokenRecord) {
    return {
      ok: true,
      mode: "oauth",
      scope: tokenRecord.scope,
      clientId: tokenRecord.clientId,
      accountId: tokenRecord.accountId || "default",
    };
  }
  return { ok: false };
}

/**
 * Validate OAuth /authorize parameters from either query string or form body.
 */
function validateAuthorizeParams(params, oauth) {
  const responseType = params.get("response_type") || "";
  const clientId = params.get("client_id") || "";
  const redirectUri = params.get("redirect_uri") || "";
  const state = params.get("state") || "";
  const codeChallenge = params.get("code_challenge") || "";
  const codeChallengeMethod = params.get("code_challenge_method") || "";
  const scope = params.get("scope") || "mcp:tools";
  const resource = params.get("resource") || "";

  if (responseType !== "code") {
    throw new HttpError(400, "Unsupported response_type; only 'code' is supported");
  }
  if (state.length > MAX_STATE_LENGTH) {
    throw new HttpError(400, `state exceeds maximum length (${MAX_STATE_LENGTH})`);
  }

  const client = oauth.resolveClient(clientId);
  if (!client) {
    throw new HttpError(400, "Unknown client_id");
  }
  if (!oauth.isRedirectAllowed(client, redirectUri)) {
    throw new HttpError(400, "Invalid or unregistered redirect_uri");
  }

  if (client.token_endpoint_auth_method === "none" && !codeChallenge) {
    throw new HttpError(400, "PKCE code_challenge is required for public clients");
  }
  if (codeChallenge && codeChallengeMethod !== "S256") {
    throw new HttpError(400, "Only code_challenge_method=S256 is supported");
  }

  return {
    client,
    clientId,
    redirectUri,
    state,
    codeChallenge,
    codeChallengeMethod,
    scope,
    resource,
  };
}

/**
 * Render HTML owner passphrase approval form in Chinese.
 */
function renderConsentHtml({
  clientName,
  scope,
  csrfToken,
  clientId,
  redirectUri,
  state,
  codeChallenge,
  codeChallengeMethod,
  resource,
  errorMessage = "",
}) {
  const hiddenField = (name, value) =>
    `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>授权 Gemini APP 接入 Gemini Handoff MCP</title>
  <link rel="icon" type="image/svg+xml" href="/assets/logo.svg">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; background: #0b1120; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 16px; max-width: 440px; width: 100%; padding: 28px 24px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
    .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
    .brand img { width: 40px; height: 40px; flex-shrink: 0; }
    .badge { display: inline-flex; align-items: center; background: #1e3a8a; color: #93c5fd; font-size: 0.78rem; font-weight: 600; padding: 4px 10px; border-radius: 9999px; }
    h1 { font-size: 1.35rem; margin: 0 0 8px; color: #f8fafc; font-weight: 700; }
    p { font-size: 0.92rem; line-height: 1.5; color: #94a3b8; margin: 0 0 18px; }
    .meta { background: #0f172a; border-radius: 10px; padding: 12px 14px; font-size: 0.85rem; margin-bottom: 20px; border: 1px solid #334155; overflow-wrap: anywhere; }
    .meta div { margin-bottom: 4px; }
    .meta div:last-child { margin-bottom: 0; }
    .err { background: #7f1d1d; color: #fecaca; border: 1px solid #b91c1c; border-radius: 10px; padding: 12px 14px; font-size: 0.88rem; margin-bottom: 18px; }
    label { display: block; font-size: 0.88rem; font-weight: 600; margin-bottom: 8px; color: #f1f5f9; }
    input[type="password"] { width: 100%; box-sizing: border-box; padding: 11px 14px; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 0.95rem; margin-bottom: 18px; }
    input:focus { outline: none; border-color: #3b82f6; }
    button { width: 100%; padding: 13px 18px; border: 0; border-radius: 10px; background: #2563eb; color: #fff; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.15s ease; }
    button:hover { background: #1d4ed8; }
    .footer { text-align: center; font-size: 0.8rem; color: #64748b; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <img src="/assets/logo.svg" alt="Gemini Handoff MCP Logo">
      <div class="badge">Gemini Handoff MCP</div>
    </div>
    <h1>授权接入您的工作区</h1>
    <p>应用客户端正在请求关联您的 Gemini Handoff 工具与安全沙箱工作区。</p>
    <div class="meta">
      <div><span style="color:#64748b">请求客户端：</span><strong>${escapeHtml(clientName)}</strong></div>
      <div><span style="color:#64748b">重定向地址 / </span><strong>Redirect URI:</strong> ${escapeHtml(redirectUri)}</div>
      <div><span style="color:#64748b">授权范围：</span>${escapeHtml(scope)}</div>
    </div>
    ${errorMessage ? `<div class="err">${escapeHtml(errorMessage)}</div>` : ""}
    <form method="POST" action="/oauth/authorize">
      ${hiddenField("csrf_token", csrfToken)}
      ${hiddenField("response_type", "code")}
      ${hiddenField("client_id", clientId)}
      ${hiddenField("redirect_uri", redirectUri)}
      ${hiddenField("state", state)}
      ${hiddenField("code_challenge", codeChallenge)}
      ${hiddenField("code_challenge_method", codeChallengeMethod)}
      ${hiddenField("scope", scope)}
      ${hiddenField("resource", resource)}
      <label for="passphrase">授权口令（来自服务器 .env OWNER_PASSPHRASE / OWNER_PASSPHRASES）</label>
      <input id="passphrase" name="passphrase" type="password" required autocomplete="current-password" autofocus placeholder="请输入授权口令">
      <button type="submit">确认授权并连接</button>
    </form>
    <div class="footer">若使用免密码专属直连链接（/mcp/u/密钥），请选用无身份验证模式</div>
  </div>
</body>
</html>`;
}

/**
 * Extract client_id and client_secret from Authorization: Basic or token payload.
 */
function extractClientCredentials(req, params) {
  const auth = req.headers.authorization;
  let basicId = null;
  let basicSecret = null;

  if (typeof auth === "string" && auth.toLowerCase().startsWith("basic ")) {
    try {
      const decoded = Buffer.from(auth.slice(6).trim(), "base64").toString("utf8");
      const idx = decoded.indexOf(":");
      if (idx !== -1) {
        basicId = decodeURIComponent(decoded.slice(0, idx));
        basicSecret = decodeURIComponent(decoded.slice(idx + 1));
      }
    } catch {
      return { clientId: "", clientSecret: null };
    }
  }

  const clientId = basicId || params.client_id || "";
  const clientSecret = basicSecret !== null ? basicSecret : params.client_secret || null;
  return { clientId, clientSecret };
}

/**
 * Parse /oauth/token body supporting both form-urlencoded and JSON.
 */
async function parseTokenBody(req) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  const raw = await readRawBody(req, OAUTH_MAX_BODY_BYTES);

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(raw || "{}");
    } catch {
      throw new HttpError(400, "Invalid JSON token request");
    }
  }

  const form = new URLSearchParams(raw);
  return Object.fromEntries(form.entries());
}

/**
 * Derive rate-limit client key safely (only honor forwarded IP headers when peer is loopback proxy).
 * @param {import("node:http").IncomingMessage} req
 * @returns {string}
 */
function getClientKey(req) {
  const peer = String(req.socket?.remoteAddress || "unknown");
  const isLoopbackPeer = peer === "127.0.0.1" || peer === "::1" || peer === "::ffff:127.0.0.1";
  if (isLoopbackPeer) {
    const cfIp = req.headers["cf-connecting-ip"];
    if (typeof cfIp === "string" && cfIp.trim()) {
      return cfIp.trim().slice(0, 64);
    }
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.trim()) {
      return xff.split(",")[0].trim().slice(0, 64);
    }
  }
  return peer.slice(0, 64);
}

/**
 * Decode a URL path segment and validate it against configured per-account path keys.
 * @param {string} rawSegment
 * @param {Record<string, any>} config
 * @returns {{ key: string, account: string } | null}
 */
function extractValidPathKeyAccount(rawSegment, config) {
  if (typeof rawSegment !== "string" || !rawSegment) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(rawSegment);
  } catch {
    return null;
  }
  const matched = resolveAccountByPathKey(decoded, config);
  if (!matched) {
    return null;
  }
  return { key: decoded, account: matched.name };
}

/**
 * Inspect an RFC 8707 `resource` parameter to see if it points to `/mcp/u/<valid_key>`.
 * @param {string} resource
 * @param {Record<string, any>} config
 * @returns {{ key: string, account: string } | null}
 */
function extractAccountFromResourceUrl(resource, config) {
  if (typeof resource !== "string" || !resource) {
    return null;
  }
  try {
    const parsed = new URL(resource);
    const match = parsed.pathname.match(/^\/mcp\/u\/([^/]+)\/?$/);
    if (!match) {
      return null;
    }
    return extractValidPathKeyAccount(match[1], config);
  } catch {
    return null;
  }
}

/**
 * Handle OAuth discovery, DCR, authorization consent, and token endpoints.
 * Returns true if the request path was handled, false otherwise.
 *
 * @param {import("node:http").IncomingMessage} req
 * @param {import("node:http").ServerResponse} res
 * @param {URL} url
 * @param {Record<string, any>} config
 * @param {OAuthManager} oauth
 * @param {import("./harness.mjs").AuditLogger} [audit]
 * @returns {Promise<boolean>}
 */
export async function handleOAuthRequest(req, res, url, config, oauth, audit) {
  const pathname = url.pathname;
  const base = getBaseUrl(req, config);
  const clientKey = getClientKey(req);

  if (req.method === "GET") {
    const prmMatch =
      pathname.match(/^\/\.well-known\/oauth-protected-resource\/mcp\/u\/([^/]+)\/?$/) ||
      pathname.match(/^\/mcp\/u\/([^/]+)\/\.well-known\/oauth-protected-resource\/?$/);
    if (prmMatch) {
      const found = extractValidPathKeyAccount(prmMatch[1], config);
      if (!found) {
        sendJson(res, 404, { error: "not_found" });
        return true;
      }
      sendJson(res, 200, {
        resource: `${base}/mcp/u/${found.key}`,
        authorization_servers: [`${base}/u/${found.key}`],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp:tools"],
      });
      return true;
    }

    const asMatchA = pathname.match(
      /^\/\.well-known\/(?:oauth-authorization-server|openid-configuration)\/(u|mcp\/u)\/([^/]+)\/?$/
    );
    const asMatchB = pathname.match(
      /^\/(u|mcp\/u)\/([^/]+)\/\.well-known\/(?:oauth-authorization-server|openid-configuration)\/?$/
    );
    const asMatch = asMatchA || asMatchB;
    if (asMatch) {
      const prefix = asMatch[1];
      const found = extractValidPathKeyAccount(asMatch[2], config);
      if (!found) {
        sendJson(res, 404, { error: "not_found" });
        return true;
      }
      sendJson(res, 200, {
        issuer: `${base}/${prefix}/${found.key}`,
        authorization_endpoint: `${base}/u/${found.key}/oauth/authorize`,
        token_endpoint: `${base}/u/${found.key}/oauth/token`,
        registration_endpoint: `${base}/u/${found.key}/oauth/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported: [
          "none",
          "client_secret_post",
          "client_secret_basic",
        ],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["mcp:tools"],
      });
      return true;
    }
  }

  if (
    req.method === "GET" &&
    (pathname === "/.well-known/oauth-protected-resource" ||
      pathname === "/.well-known/oauth-protected-resource/mcp")
  ) {
    sendJson(res, 200, {
      resource: `${base}/mcp`,
      authorization_servers: [base],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp:tools"],
    });
    return true;
  }

  if (
    req.method === "GET" &&
    (pathname === "/.well-known/oauth-authorization-server" ||
      pathname === "/.well-known/openid-configuration")
  ) {
    sendJson(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: [
        "none",
        "client_secret_post",
        "client_secret_basic",
      ],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["mcp:tools"],
    });
    return true;
  }

  let effectivePath = pathname;
  let pathKeyAccount = null;
  const scopedOAuthMatch = pathname.match(
    /^\/(?:mcp\/)?u\/([^/]+)(\/oauth\/(?:register|authorize|token))$/
  );
  if (scopedOAuthMatch) {
    const found = extractValidPathKeyAccount(scopedOAuthMatch[1], config);
    if (!found) {
      oauth.authFailureLimiter.consume(clientKey);
      audit?.log({
        category: "oauth",
        action: "scoped_oauth",
        status: "blocked",
        actor: clientKey,
        error: "Invalid or revoked MCP account key",
      });
      sendJson(res, 403, {
        error: "forbidden",
        message: "Invalid or revoked MCP account key",
      });
      return true;
    }
    pathKeyAccount = found.account;
    effectivePath = scopedOAuthMatch[2];
  }

  if (effectivePath === "/oauth/register") {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "POST" });
      return true;
    }
    const regQuota = oauth.registerLimiter.consume(clientKey);
    if (!regQuota.allowed) {
      audit?.log({
        category: "oauth",
        action: "dcr_register",
        status: "blocked",
        actor: clientKey,
        error: "DCR registration rate limit exceeded",
      });
      sendJson(
        res,
        429,
        { error: "too_many_requests", error_description: "Registration rate limit exceeded" },
        { "Retry-After": String(Math.ceil(regQuota.retryAfterMs / 1000)) }
      );
      return true;
    }
    const payload = await readJsonBody(req, OAUTH_MAX_BODY_BYTES);
    const client = await oauth.registerClient(payload);
    audit?.log({
      category: "oauth",
      action: "dcr_register",
      status: "ok",
      actor: clientKey,
      result: { client_id: client.client_id, client_name: client.client_name },
    });
    sendJson(res, 201, client, { "Cache-Control": "no-store" });
    return true;
  }

  if (effectivePath === "/oauth/authorize") {
    if (req.method === "GET") {
      const authReq = validateAuthorizeParams(url.searchParams, oauth);
      const autoAccount =
        pathKeyAccount || extractAccountFromResourceUrl(authReq.resource, config)?.account || null;
      if (autoAccount) {
        const code = oauth.issueAuthorizationCode({
          clientId: authReq.clientId,
          redirectUri: authReq.redirectUri,
          codeChallenge: authReq.codeChallenge,
          codeChallengeMethod: authReq.codeChallengeMethod,
          scope: authReq.scope,
          resource: authReq.resource,
          accountId: autoAccount,
        });

        audit?.log({
          category: "oauth",
          action: "authorize_auto_key",
          status: "ok",
          actor: clientKey,
          result: {
            client_id: authReq.clientId,
            scope: authReq.scope,
            account: autoAccount,
          },
        });

        const target = new URL(authReq.redirectUri);
        target.searchParams.set("code", code);
        if (authReq.state) {
          target.searchParams.set("state", authReq.state);
        }

        res.writeHead(302, {
          Location: target.toString(),
          "Cache-Control": "no-store",
        });
        res.end();
        return true;
      }

      const csrfToken = oauth.issueCsrfToken();
      sendHtml(
        res,
        200,
        renderConsentHtml({
          clientName: authReq.client.client_name,
          scope: authReq.scope,
          csrfToken,
          clientId: authReq.clientId,
          redirectUri: authReq.redirectUri,
          state: authReq.state,
          codeChallenge: authReq.codeChallenge,
          codeChallengeMethod: authReq.codeChallengeMethod,
          resource: authReq.resource,
        })
      );
      return true;
    }

    if (req.method === "POST") {
      const failStatus = oauth.authFailureLimiter.peek(clientKey);
      if (failStatus.limit > 0 && failStatus.remaining <= 0) {
        audit?.log({
          category: "oauth",
          action: "authorize_consent",
          status: "blocked",
          actor: clientKey,
          error: "Too many failed passphrase attempts",
        });
        sendJson(
          res,
          429,
          { error: "too_many_requests", message: "尝试次数过多，请稍后再试。" },
          { "Retry-After": "900" }
        );
        return true;
      }

      const raw = await readRawBody(req, OAUTH_MAX_BODY_BYTES);
      const form = new URLSearchParams(raw);
      const authReq = validateAuthorizeParams(form, oauth);
      const csrfToken = form.get("csrf_token") || "";
      const passphrase = form.get("passphrase") || "";

      if (!oauth.consumeCsrfToken(csrfToken)) {
        const freshCsrf = oauth.issueCsrfToken();
        sendHtml(
          res,
          403,
          renderConsentHtml({
            clientName: authReq.client.client_name,
            scope: authReq.scope,
            csrfToken: freshCsrf,
            clientId: authReq.clientId,
            redirectUri: authReq.redirectUri,
            state: authReq.state,
            codeChallenge: authReq.codeChallenge,
            codeChallengeMethod: authReq.codeChallengeMethod,
            resource: authReq.resource,
            errorMessage: "页面授权已过期，请重新输入口令确认。",
          })
        );
        return true;
      }

      const matchedAccount = resolveAccountByPassphrase(passphrase, config);
      if (!matchedAccount) {
        oauth.authFailureLimiter.consume(clientKey);
        audit?.log({
          category: "oauth",
          action: "authorize_consent",
          status: "blocked",
          actor: clientKey,
          args: { client_id: authReq.clientId },
          error: "Invalid account passphrase",
        });
        const freshCsrf = oauth.issueCsrfToken();
        sendHtml(
          res,
          403,
          renderConsentHtml({
            clientName: authReq.client.client_name,
            scope: authReq.scope,
            csrfToken: freshCsrf,
            clientId: authReq.clientId,
            redirectUri: authReq.redirectUri,
            state: authReq.state,
            codeChallenge: authReq.codeChallenge,
            codeChallengeMethod: authReq.codeChallengeMethod,
            resource: authReq.resource,
            errorMessage: "授权口令不正确，请核对后重试。",
          })
        );
        return true;
      }

      const code = oauth.issueAuthorizationCode({
        clientId: authReq.clientId,
        redirectUri: authReq.redirectUri,
        codeChallenge: authReq.codeChallenge,
        codeChallengeMethod: authReq.codeChallengeMethod,
        scope: authReq.scope,
        resource: authReq.resource,
        accountId: matchedAccount.name,
      });

      audit?.log({
        category: "oauth",
        action: "authorize_consent",
        status: "ok",
        actor: clientKey,
        result: {
          client_id: authReq.clientId,
          scope: authReq.scope,
          account: matchedAccount.name,
        },
      });

      const target = new URL(authReq.redirectUri);
      target.searchParams.set("code", code);
      if (authReq.state) {
        target.searchParams.set("state", authReq.state);
      }

      res.writeHead(302, {
        Location: target.toString(),
        "Cache-Control": "no-store",
      });
      res.end();
      return true;
    }

    sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "GET, POST" });
    return true;
  }

  if (effectivePath === "/oauth/token") {
    if (req.method !== "POST") {
      sendJson(res, 405, { error: "method_not_allowed" }, { Allow: "POST" });
      return true;
    }

    const body = await parseTokenBody(req);
    const { clientId, clientSecret } = extractClientCredentials(req, body);
    const client = oauth.resolveClient(clientId);

    if (!client || !oauth.verifyClientSecret(client, clientSecret)) {
      sendJson(
        res,
        401,
        { error: "invalid_client", error_description: "Client authentication failed" },
        { "Cache-Control": "no-store", Pragma: "no-cache" }
      );
      return true;
    }

    const grantType = body.grant_type;
    let tokenResponse;

    try {
      if (grantType === "authorization_code") {
        tokenResponse = await oauth.exchangeAuthorizationCode({
          code: body.code,
          client,
          redirectUri: body.redirect_uri,
          codeVerifier: body.code_verifier,
        });
      } else if (grantType === "refresh_token") {
        tokenResponse = await oauth.exchangeRefreshToken({
          refreshToken: body.refresh_token,
          client,
        });
      } else {
        sendJson(
          res,
          400,
          { error: "unsupported_grant_type", error_description: `Unsupported grant_type: ${grantType}` },
          { "Cache-Control": "no-store", Pragma: "no-cache" }
        );
        return true;
      }
    } catch (err) {
      if (err instanceof HttpError && err.status === 400) {
        sendJson(
          res,
          400,
          { error: "invalid_grant", error_description: err.message },
          { "Cache-Control": "no-store", Pragma: "no-cache" }
        );
        return true;
      }
      throw err;
    }

    sendJson(res, 200, tokenResponse, {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    });
    return true;
  }

  return false;
}
