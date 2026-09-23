/**
 * Risk prediction engine — the "AI" layer.
 *
 * A transparent, feature-weighted points model. Every factor that moves the
 * score is returned with its point contribution, so predictions are fully
 * explainable (no black box). Inputs:
 *
 *   f1  breachCount        — how many known breaches contain the address
 *   f2  credentialExposure — password/credential data classes exposed
 *   f3  recency            — how recent the newest breach is
 *   f4  severity           — max severity of the breaches
 *   f5  localPartRisk      — heuristic on the local part of the address
 *   f6  domainReputation   — provider risk (disposable / custom / major)
 *   f7  dataRichness       — volume of PII classes exposed
 *
 * Total points map linearly onto 0-100. Replace `predictRisk` internals with
 * an ML service call later if needed; the output contract
 * ({ riskScore, riskLevel, factors, summary, advice }) stays the same.
 */
const DAY_MS = 24 * 60 * 60 * 1000;

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
  'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com',
]);

const MAJOR_DOMAINS = new Set([
  'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com',
  'proton.me', 'protonmail.com', 'aol.com', 'live.com',
]);

const HIGH_VALUE_LOCAL = /^(admin|root|support|info|billing|security|noreply|no-reply|help|contact|ceo|cfo|hr|it|office|finance|legal|dev|test|sales)/i;

const WEAK_LOCAL_PATTERNS = [
  { re: /^\d{1,4}/, weight: 0.35, reason: 'Short numeric prefix in the address' },
  { re: /(123|1234|12345)\d*$/, weight: 0.30, reason: 'Sequential digits at the end of the address' },
  { re: /^(test|demo|sample|temp|fake)/i, weight: 0.30, reason: 'Address looks like a throwaway/test account' },
  { re: /(pass|pwd|secret|admin)/i, weight: 0.25, reason: 'Address hints at privileged credentials' },
];

const RISK_MULTIPLIER = 6.0; // points -> score

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

function localPartRisk(email) {
  const local = email.split('@')[0] || '';
  let risk = 0;
  const notes = [];
  if (HIGH_VALUE_LOCAL.test(local)) {
    risk += 0.5;
    notes.push('Address looks like a high-value role account (admin/support/finance…)');
  }
  if (local.length <= 4) {
    risk += 0.2;
    notes.push('Very short local part — common in easy-to-guess accounts');
  }
  for (const p of WEAK_LOCAL_PATTERNS) {
    if (p.re.test(local)) {
      risk += p.weight;
      notes.push(p.reason);
    }
  }
  return { risk: clamp(risk, 0, 1), notes };
}

function domainRisk(domain) {
  if (DISPOSABLE_DOMAINS.has(domain)) return { risk: 0.85, note: 'Disposable email domain' };
  if (MAJOR_DOMAINS.has(domain)) return { risk: 0.25, note: 'Major provider — high attacker targeting' };
  return { risk: 0.45, note: 'Custom domain — security quality varies' };
}

/**
 * Core prediction.
 * @param {object} lookup result of breachService.lookupBreaches()
 * @returns {{ riskScore, riskLevel, factors, summary, advice, breachExposure }}
 */
function predictRisk(lookup) {
  const { email, valid, breached, breaches = [] } = lookup;

  if (!valid) {
    return {
      riskScore: null,
      riskLevel: 'invalid',
      factors: [],
      summary: 'The provided address is not a valid email, so no risk can be predicted.',
      advice: ['Correct the email format (name@domain.tld) and retry.'],
      breachExposure: { count: 0, credential: false, newestBreachDays: null, maxSeverity: 0, piiClasses: [] },
    };
  }

  // ---- Feature extraction -------------------------------------------------
  const breachCount = breaches.length;
  const credentialBreaches = breaches.filter((b) =>
    b.dataClasses.some((c) => /password/i.test(c)));
  const credentialExposure = credentialBreaches.length > 0;
  const piiClasses = [...new Set(breaches.flatMap((b) => b.dataClasses))];
  const maxSeverity = breaches.reduce((m, b) => Math.max(m, b.severity), 0);

  let newestDays = null;
  let newestCredentialDays = null;
  if (breaches.length) {
    const newest = Math.max(...breaches.map((b) => new Date(b.breachDate).getTime()));
    newestDays = Math.max(0, Math.round((Date.now() - newest) / DAY_MS));
    if (credentialBreaches.length) {
      const newestCred = Math.max(...credentialBreaches.map((b) => new Date(b.breachDate).getTime()));
      newestCredentialDays = Math.max(0, Math.round((Date.now() - newestCred) / DAY_MS));
    }
  }

  const domain = email.split('@')[1] || '';
  const { risk: localRisk, notes: localNotes } = localPartRisk(email);
  const { risk: domRisk, note: domNote } = domainRisk(domain);

  // ---- Weighted points model ----------------------------------------------
  const recencyPts = newestDays === null ? 0
    : newestDays < 90 ? 2.0
    : newestDays < 365 ? 1.2
    : newestDays < 730 ? 0.7
    : newestDays < 1825 ? 0.3
    : 0.1;

  const factors = [
    {
      id: 'breachCount', label: 'Breach count',
      value: breachCount,
      impact: clamp(Math.min(breachCount, 5) * 1.1, 0, 5.5),
      detail: breachCount ? `Found in ${breachCount} known breach${breachCount > 1 ? 'es' : ''}` : 'No known breaches',
    },
    {
      id: 'credentialExposure', label: 'Credential exposure',
      value: credentialExposure ? 1 : 0,
      impact: !credentialExposure ? 0
        : newestCredentialDays !== null && newestCredentialDays < 730 ? 3.0
        : 1.5,
      detail: !credentialExposure ? 'No password exposure detected'
        : newestCredentialDays !== null && newestCredentialDays < 730
          ? 'Passwords leaked recently (last 2 years) — extremely dangerous'
          : `Passwords leaked, but oldest leak is ${Math.round((newestCredentialDays || 0) / 365)} years old — likely rotated by now`,
    },
    {
      id: 'recency', label: 'Recency of newest breach',
      value: newestDays,
      impact: recencyPts,
      detail: newestDays === null ? 'No breach history'
        : newestDays < 90 ? `Breached within the last ${newestDays} days — urgent`
        : `Most recent breach was ${newestDays} days ago`,
    },
    {
      id: 'severity', label: 'Max breach severity',
      value: maxSeverity,
      impact: (maxSeverity / 10) * 1.5,
      detail: maxSeverity ? `Worst breach rated ${maxSeverity}/10` : 'No rated breaches',
    },
    {
      id: 'localPartRisk', label: 'Address structure',
      value: Number(localRisk.toFixed(2)),
      impact: localRisk * 1.2,
      detail: localNotes.length ? localNotes.join('; ') : 'Address structure looks ordinary',
    },
    {
      id: 'domainReputation', label: 'Domain reputation',
      value: Number(domRisk.toFixed(2)),
      impact: domRisk * 0.8,
      detail: domNote,
    },
    {
      id: 'dataRichness', label: 'PII richness',
      value: piiClasses.length,
      impact: Math.min(piiClasses.length, 10) * 0.12,
      detail: piiClasses.length ? `${piiClasses.length} types of personal data exposed` : 'No personal data exposure',
    },
  ];

  const totalPoints = factors.reduce((s, x) => s + x.impact, 0);
  const riskScore = clamp(Math.round(totalPoints * RISK_MULTIPLIER), 1, 99);

  // ---- Level + narrative --------------------------------------------------
  let riskLevel;
  if (riskScore >= 75) riskLevel = 'critical';
  else if (riskScore >= 50) riskLevel = 'high';
  else if (riskScore >= 25) riskLevel = 'moderate';
  else riskLevel = 'low';

  const topFactors = [...factors].filter((x) => x.impact > 0).sort((a, b) => b.impact - a.impact).slice(0, 3);
  const summary = !breached
    ? `No breach records found for ${email}. Predicted risk is low, but absence of data is not proof of safety — new breaches surface continuously.`
    : `${email} appears in ${breachCount} known breach${breachCount > 1 ? 'es' : ''}${credentialExposure ? ' including leaked passwords' : ''}. The model estimates a ${riskScore}/100 (${riskLevel}) compromise risk, driven mainly by ${topFactors.map((x) => x.label.toLowerCase()).join(', ')}.`;

  // ---- Actionable advice --------------------------------------------------
  const advice = [];
  if (credentialExposure) {
    advice.push('Change the password immediately everywhere it was reused — leaked passwords are actively used in credential-stuffing attacks.');
    advice.push('Enable two-factor authentication (app-based or hardware key, not SMS if possible).');
  }
  if (riskLevel === 'critical' || riskLevel === 'high') {
    advice.push('Review account recovery options and revoke unknown active sessions on critical services.');
    advice.push('Use a password manager to give every site a unique password going forward.');
  }
  if (piiClasses.some((c) => /phone/i.test(c))) advice.push('Expect smishing/phishing attempts via SMS or calls — verify requests through official channels.');
  if (piiClasses.some((c) => /address|orders/i.test(c))) advice.push('Watch for targeted delivery/support scams using your leaked order or address data.');
  if (domNote === 'Disposable email domain') advice.push('Consider migrating off the disposable domain to a permanent, secured mailbox.');
  if (!advice.length) advice.push('No immediate action required — keep 2FA on and monitor for new breach alerts.');

  return {
    riskScore,
    riskLevel,
    factors: factors.map(({ id, label, value, impact, detail }) => ({
      id, label, value,
      impact: Number(impact.toFixed(3)),
      impactPct: totalPoints > 0 ? Math.round((impact / totalPoints) * 100) : 0,
      detail,
    })),
    summary,
    advice,
    breachExposure: {
      count: breachCount,
      credential: credentialExposure,
      newestBreachDays: newestDays,
      maxSeverity,
      piiClasses,
    },
  };
}

module.exports = { predictRisk };
