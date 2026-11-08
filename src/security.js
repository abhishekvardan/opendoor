import crypto from "node:crypto";

/**
 * An error whose code and message are safe to show to agents. Errors thrown by your action
 * handlers are surfaced the same way if they carry a string `code` and a `status` below 500.
 */
export class OpenDoorError extends Error {
  constructor(code, message, status = 400, details) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

/** Normalises anything thrown by an action into an exposable error, hiding internals. */
export function toPublicError(err) {
  if (err instanceof OpenDoorError) return err;
  if (err && typeof err.code === "string" && Number(err.status) >= 400 && Number(err.status) < 500) {
    return new OpenDoorError(err.code, err.message, Number(err.status), err.details);
  }
  return new OpenDoorError("INTERNAL_ERROR", "The site could not complete this action.", 500);
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");
export const sha256 = (v) => crypto.createHash("sha256").update(v).digest("hex");
/** Opaque 256-bit secret with a readable prefix. Only its SHA-256 hash is stored. */
export const randomToken = (prefix) => `${prefix}_${b64url(crypto.randomBytes(32))}`;
export const randomId = (bytes = 9) => b64url(crypto.randomBytes(bytes));

export function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** RFC 7636 S256. */
export function verifyPkce(verifier, challenge) {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(String(verifier))) return false;
  return safeEqual(b64url(crypto.createHash("sha256").update(verifier).digest()), challenge);
}

export const escapeHtml = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Sliding one-minute window per key. */
export function rateLimiter(perMinute) {
  const windows = new Map();
  return (key) => {
    const now = Date.now();
    const hits = (windows.get(key) ?? []).filter((t) => now - t < 60_000);
    hits.push(now);
    windows.set(key, hits);
    if (windows.size > 10_000) windows.delete(windows.keys().next().value);
    return hits.length > perMinute;
  };
}

const SENSITIVE = /(token|secret|password|card|cvc|cvv|authorization|ssn)/i;
/** Copies input for the audit log with sensitive-looking fields removed and long values trimmed. */
export function redact(value, depth = 0) {
  if (value == null || depth > 4) return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redact(v, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SENSITIVE.test(k) ? "[redacted]" : redact(v, depth + 1)]));
  }
  return typeof value === "string" && value.length > 300 ? value.slice(0, 300) + "…" : value;
}
