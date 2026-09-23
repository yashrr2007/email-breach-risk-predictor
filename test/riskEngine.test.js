/**
 * Smoke tests for the risk prediction backend.
 * Run with: node --test
 *
 * Tests use the deterministic mock lookup (lookupBreachesMock) so they never
 * depend on the network. The live XposedOrNot path shares the same contract.
 */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { lookupBreachesMock, isValidEmail, mapXonBreach } = require('../src/services/breachService');
const { predictRisk } = require('../src/services/riskEngine');

test('validates email formats', () => {
  assert.equal(isValidEmail('user@example.com'), true);
  assert.equal(isValidEmail('not-an-email'), false);
  assert.equal(isValidEmail('user@nodot'), false);
});

test('mock lookup returns curated results for sample emails', () => {
  const r = lookupBreachesMock('victim@example.com');
  assert.equal(r.valid, true);
  assert.equal(r.breached, true);
  assert.ok(r.breachCount >= 3);
});

test('mock lookup is deterministic for unknown emails', () => {
  const a = lookupBreachesMock('random.person@unknown-domain.io');
  const b = lookupBreachesMock('RANDOM.PERSON@Unknown-Domain.io');
  assert.deepEqual(a.breaches.map((x) => x.id), b.breaches.map((x) => x.id));
});

test('invalid email yields invalid prediction', () => {
  const r = predictRisk(lookupBreachesMock('nope'));
  assert.equal(r.riskLevel, 'invalid');
  assert.equal(r.riskScore, null);
});

test('credential-exposed victim scores higher than clean address', () => {
  const victim = predictRisk(lookupBreachesMock('victim@example.com'));
  assert.ok(victim.riskScore >= 50, `expected high risk, got ${victim.riskScore}`);
  assert.equal(victim.breachExposure.credential, true);

  const clean = predictRisk(lookupBreachesMock('freshuser@proton.me'));
  assert.ok(clean.riskScore < victim.riskScore, `clean ${clean.riskScore} should be < victim ${victim.riskScore}`);
  assert.ok(['low', 'moderate'].includes(clean.riskLevel), `clean level was ${clean.riskLevel}`);
});

test('every prediction includes factors, summary and advice', () => {
  const r = predictRisk(lookupBreachesMock('admin@company.com'));
  assert.ok(Array.isArray(r.factors) && r.factors.length === 7);
  assert.ok(r.summary.length > 20);
  assert.ok(Array.isArray(r.advice) && r.advice.length > 0);
});

test('risk score stays within 0-100 bounds for edge inputs', () => {
  for (const email of ['a@b.co', 'admin@test.com', '12345@gmail.com', 'zzzzzzzz@mailinator.com']) {
    const r = predictRisk(lookupBreachesMock(email));
    assert.ok(r.riskScore >= 0 && r.riskScore <= 100, `${email} -> ${r.riskScore}`);
  }
});

test('mapXonBreach splits semicolon data classes and maps fields', () => {
  const mapped = mapXonBreach({
    breach: 'Adobe',
    domain: 'adobe.com',
    xposed_date: '2013-10-04',
    xposed_data: 'Email addresses;Passwords;Password hints;',
    xposed_records: 152445165,
    verified: 'Yes',
    details: 'Adobe breach.'
  });
  assert.equal(mapped.id, 'adobe');
  assert.deepEqual(mapped.dataClasses, ['Email addresses', 'Passwords', 'Password hints']);
  assert.equal(mapped.accounts, 152445165);
  assert.equal(mapped.verified, true);
  assert.ok(mapped.severity >= 8, `severity ${mapped.severity} should be high for 152M + passwords`);
});
