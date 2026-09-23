/**
 * Tiny config loader with dependency-free .env support.
 * Variables already present in the real environment take precedence over .env.
 */
const fs = require('fs');
const path = require('path');

(function loadDotEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  try {
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2];
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!(key in process.env)) process.env[key] = val;
    }
  } catch (err) {
    console.error('Config: failed to read .env:', err.message);
  }
})();

const config = {
  port: Number(process.env.PORT) > 0 ? Number(process.env.PORT) : 3000,

  // Breach data comes from XposedOrNot's public API — free, no key required.
  // https://xposedornot.com/api_doc

  fetchTimeoutMs: Number(process.env.FETCH_TIMEOUT_MS) || 8000,
  cacheTtlMs: Number(process.env.CACHE_TTL_MS) || 30 * 60 * 1000,
};

module.exports = config;
