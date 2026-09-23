/**
 * Routes: /api/analyze, /api/breaches, /api/stats, /api/health
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { lookupBreaches, listBreaches } = require('../services/breachService');
const { predictRisk } = require('../services/riskEngine');

const router = express.Router();

// ---- Simple persistent store (swap for Postgres/Mongo later) ---------------
const ANALYSES_FILE = path.join(__dirname, '..', 'data', 'analyses.json');
const analyses = loadAnalyses();

function saveAnalyses() {
  try {
    fs.mkdirSync(path.dirname(ANALYSES_FILE), { recursive: true });
    fs.writeFileSync(ANALYSES_FILE, JSON.stringify(analyses, null, 2));
  } catch (err) {
    console.error('Failed to persist analyses:', err.message);
  }
}

function loadAnalyses() {
  try {
    if (fs.existsSync(ANALYSES_FILE)) {
      const raw = JSON.parse(fs.readFileSync(ANALYSES_FILE, 'utf8'));
      if (Array.isArray(raw)) return raw;
    }
  } catch (err) {
    console.error('Failed to load analyses:', err.message);
  }
  return [];
}

function recordAnalysis(email, prediction, lookup) {
  const record = {
    id: crypto.randomUUID(),
    email,
    checkedAt: new Date().toISOString(),
    breached: lookup.breached,
    breachCount: lookup.breachCount,
    riskScore: prediction.riskScore,
    riskLevel: prediction.riskLevel,
  };
  analyses.push(record);
  if (analyses.length > 500) analyses.shift(); // cap memory
  saveAnalyses();
  return record;
}

// ---- Validation middleware -------------------------------------------------
function validateEmail(req, res, next) {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
  if (!email) {
    return res.status(400).json({ error: 'Email is required', code: 'EMAIL_REQUIRED' });
  }
  if (email.length > 254) {
    return res.status(400).json({ error: 'Email too long', code: 'EMAIL_TOO_LONG' });
  }
  req.email = email;
  next();
}

// ---- Routes ----------------------------------------------------------------

/**
 * POST /api/analyze
 * Body: { "email": "user@example.com" }
 * Full breach check + AI risk prediction in one call.
 */
router.post('/analyze', validateEmail, async (req, res) => {
  const started = Date.now();
  try {
    const lookup = await lookupBreaches(req.email);
    const prediction = predictRisk(lookup);
    const record = recordAnalysis(lookup.email, prediction, lookup);

    res.json({
      success: true,
      query: { email: lookup.email, checkedAt: record.checkedAt },
      breach: {
        breached: lookup.breached,
        breachCount: lookup.breachCount,
        breaches: lookup.breaches,
      },
      prediction: {
        riskScore: prediction.riskScore,
        riskLevel: prediction.riskLevel,
        summary: prediction.summary,
        factors: prediction.factors,
        advice: prediction.advice,
        breachExposure: prediction.breachExposure,
      },
      meta: {
        processingMs: Date.now() - started,
        modelVersion: 'risk-engine-v1.1',
        source: lookup.source,
        cached: Boolean(lookup.cached),
        ...(lookup.warning ? { warning: lookup.warning } : {}),
      },
    });
  } catch (err) {
    console.error('Analyze failed:', err.message);
    res.status(500).json({ error: 'Analysis failed', detail: err.message });
  }
});

/** GET /api/breaches — latest known breaches feed. */
router.get('/breaches', (req, res) => {
  const breaches = listBreaches();
  res.json({ success: true, count: breaches.length, breaches });
});

/** GET /api/stats — aggregate stats over past analyses. */
router.get('/stats', (req, res) => {
  const total = analyses.length;
  const byLevel = { low: 0, moderate: 0, high: 0, critical: 0, invalid: 0 };
  let scoreSum = 0;
  let scored = 0;
  for (const a of analyses) {
    if (a.riskLevel in byLevel) byLevel[a.riskLevel] += 1;
    if (typeof a.riskScore === 'number') { scoreSum += a.riskScore; scored += 1; }
  }
  const breachedCount = analyses.filter((a) => a.breached).length;
  res.json({
    success: true,
    totalAnalyses: total,
    breachedCount,
    avgRiskScore: scored ? Math.round(scoreSum / scored) : null,
    byLevel,
    lastUpdated: new Date().toISOString(),
  });
});

/** GET /api/health */
router.get('/health', (req, res) => {
  res.json({ status: 'ok', uptimeSec: Math.round(process.uptime()), timestamp: new Date().toISOString() });
});

module.exports = router;
