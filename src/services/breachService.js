/**
 * Breach lookup service — provider chain with a stable result contract.
 *
 *   1. XposedOrNot v1      (source: "xposedornot")   — free, NO API key needed
 *   2. Local mock DB       (source: "mock-fallback") — offline demo data
 *
 * Every provider maps its raw response into the same internal breach shape:
 *   { id, site, domain, breachDate, addedDate, dataClasses, accounts,
 *     severity, verified, description, passwordRisk? }
 *
 * Successful lookups are cached for CACHE_TTL_MS. Fallback results are not
 * cached so the live provider is retried on the next request.
 */
const crypto = require('crypto');
const config = require('../config');
const { BREACHES, SAMPLE_KNOWN_EMAILS } = require('../data/breaches');

const BREACH_BY_ID = new Map(BREACHES.map((b) => [b.id, b]));
const XON_BASE = 'https://api.xposedornot.com/v1';

/** @type {Map<string, { at: number, result: object }>} */
const cache = new Map();

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
function stableHash(str) {
  return crypto.createHash('sha256').update(str.toLowerCase().trim()).digest();
}

function normalizeEmail(raw) {
  return String(raw || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

function deriveSeverity(item, dataClassesText) {
  const records = Number(item.xposed_records) || 0;
  const hasPw = /password/i.test(dataClassesText);
  let sev = 1 + Math.log10(records + 1) * 1.4;
  if (hasPw) sev += 1.5;
  return clamp(Math.round(sev), 1, 10);
}

function slugify(name) {
  return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'unknown-breach';
}

async function fetchJson(url, { headers = {}, timeoutMs = config.fetchTimeoutMs } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { Accept: 'application/json', ...headers } });
    return { res, json: res.ok ? await res.json() : null };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Provider 1: XposedOrNot (free, no API key required)
// ---------------------------------------------------------------------------

/** Map an XposedOrNot breaches_details item to our internal shape. Exported for tests. */
function mapXonBreach(item) {
  const dataClasses = String(item.xposed_data || '').split(';').map((s) => s.trim()).filter(Boolean);
  return {
    id: slugify(item.breach),
    site: item.breach || 'Unknown site',
    domain: item.domain || '---',
    breachDate: String(item.xposed_date || '').slice(0, 10) || item.added?.slice(0, 10) || 'unknown',
    addedDate: item.added ? String(item.added).slice(0, 10) : undefined,
    dataClasses,
    accounts: Number(item.xposed_records) || 0,
    severity: deriveSeverity(item, String(item.xposed_data || '')),
    verified: String(item.verified).toLowerCase() === 'yes',
    description: item.details || 'No description available.',
    passwordRisk: item.password_risk || 'unknown',
  };
}

async function lookupViaXon(email) {
  const url = `${XON_BASE}/breach-analytics?email=${encodeURIComponent(email)}`;
  const { res, json } = await fetchJson(url);
  if (!res.ok) throw new Error(`XposedOrNot responded ${res.status}`);

  // Clean address shapes: {"Error":"Not found","email":null} or
  // {"ExposedBreaches":null,...}
  if (json && json.Error) {
    return { email, valid: true, breached: false, breachCount: 0, breaches: [], source: 'xposedornot' };
  }
  const details = json?.ExposedBreaches?.breaches_details;
  if (!Array.isArray(details) || details.length === 0) {
    return { email, valid: true, breached: false, breachCount: 0, breaches: [], source: 'xposedornot' };
  }

  const seen = new Set();
  const breaches = [];
  for (const item of details) {
    const mapped = mapXonBreach(item);
    if (!seen.has(mapped.id)) { seen.add(mapped.id); breaches.push(mapped); }
  }
  breaches.sort((a, b) => (a.breachDate < b.breachDate ? 1 : -1));
  return { email, valid: true, breached: breaches.length > 0, breachCount: breaches.length, breaches, source: 'xposedornot' };
}

// ---------------------------------------------------------------------------
// Provider 2: local mock DB (sync)
// ---------------------------------------------------------------------------
function pseudoBreachesFor(email) {
  const digest = stableHash(email);
  const roll = digest[0];
  let count;
  if (roll < 0x40) count = 0;
  else if (roll < 0x9E) count = 1;
  else if (roll < 0xC8) count = 2;
  else if (roll < 0xE2) count = 3;
  else count = 4;
  const chosen = [];
  for (let i = 0; i < count; i += 1) {
    const idx = digest[i + 1] % BREACHES.length;
    const breach = BREACHES[idx];
    if (!chosen.includes(breach)) chosen.push(breach);
  }
  return chosen;
}

function lookupBreachesMock(rawEmail) {
  const email = normalizeEmail(rawEmail);
  if (!isValidEmail(email)) {
    return { email: rawEmail, valid: false, breached: false, breachCount: 0, breaches: [], source: 'mock' };
  }
  const curated = SAMPLE_KNOWN_EMAILS[email];
  const matches = curated
    ? curated.map((id) => BREACH_BY_ID.get(id)).filter(Boolean)
    : pseudoBreachesFor(email);
  return { email, valid: true, breached: matches.length > 0, breachCount: matches.length, breaches: matches, source: 'mock' };
}

// ---------------------------------------------------------------------------
// Public API — provider chain: XposedOrNot → mock
// ---------------------------------------------------------------------------
async function lookupBreaches(rawEmail) {
  const email = normalizeEmail(rawEmail);
  if (!isValidEmail(email)) {
    return { email: rawEmail, valid: false, breached: false, breachCount: 0, breaches: [], source: 'none' };
  }

  const hit = cache.get(email);
  if (hit && Date.now() - hit.at < config.cacheTtlMs) {
    return { ...hit.result, cached: true };
  }

  try {
    const result = await lookupViaXon(email);
    cache.set(email, { at: Date.now(), result });
    return result;
  } catch (err) {
    const fallback = lookupBreachesMock(email);
    fallback.source = 'mock-fallback';
    fallback.warning = `Live breach provider unreachable (${err.message}); showing simulated demo data instead.`;
    return fallback;
  }
}

/** Reference feed of major historical breaches (local dataset). */
function listBreaches() {
  return [...BREACHES].sort((a, b) => (a.breachDate < b.breachDate ? 1 : -1));
}

module.exports = {
  lookupBreaches,       // async, live + fallback
  lookupBreachesMock,   // sync, mock only (tests / offline)
  listBreaches,
  isValidEmail,
  normalizeEmail,
  mapXonBreach,         // exported for unit tests
};
