/**
 * Shared HTTP parsing and response helpers.
 */

export class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} message
   * @param {Record<string, string>} [headers]
   */
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

/**
 * Normalize path separators to forward slashes.
 * @param {string} value
 * @returns {string}
 */
export function normalizeSlashes(value) {
  return String(value).replace(/\\/g, "/");
}

/**
 * Read full HTTP request body as a UTF-8 string with strict byte limit.
 * @param {import("node:http").IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<string>}
 */
export async function readRawBody(req, maxBytes = 3 * 1024 * 1024) {
  const chunks = [];
  let total = 0;

  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      throw new HttpError(413, `Request body exceeds ${maxBytes} bytes limit`);
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Read and parse JSON HTTP request body.
 * @param {import("node:http").IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<any>}
 */
export async function readJsonBody(req, maxBytes = 3 * 1024 * 1024) {
  const raw = await readRawBody(req, maxBytes);
  if (!raw.trim()) {
    return {};
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, "Invalid JSON body");
  }
}

/**
 * Send JSON HTTP response.
 * @param {import("node:http").ServerResponse} res
 * @param {number} status
 * @param {unknown} payload
 * @param {Record<string, string>} [headers]
 */
export function sendJson(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body, "utf8"),
    ...headers,
  });
  res.end(body);
}

/**
 * Send HTML HTTP response.
 * @param {import("node:http").ServerResponse} res
 * @param {number} status
 * @param {string} html
 * @param {Record<string, string>} [headers]
 */
export function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(html, "utf8"),
    ...headers,
  });
  res.end(html);
}

/**
 * Send plain text or empty response.
 * @param {import("node:http").ServerResponse} res
 * @param {number} status
 * @param {string} [text]
 * @param {Record<string, string>} [headers]
 */
export function sendText(res, status, text = "", headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(text, "utf8"),
    ...headers,
  });
  res.end(text);
}

/**
 * Extract Bearer token from Authorization header.
 * @param {import("node:http").IncomingMessage} req
 * @returns {string | null}
 */
export function extractBearerToken(req) {
  const header = req.headers.authorization;
  if (typeof header !== "string") {
    return null;
  }
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return null;
  }
  const token = match[1].trim();
  return token.length > 0 ? token : null;
}
