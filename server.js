/**
 * Email Breach & AI Risk Prediction API
 * -------------------------------------
 * POST /api/analyze  -> breach lookup + AI risk prediction
 * GET  /api/breaches -> known breach feed
 * GET  /api/stats    -> aggregate stats of past analyses
 * GET  /api/health   -> health check
 *
 * Serves a dashboard UI at http://localhost:3000
 */
const express = require('express');
const path = require('path');
const config = require('./src/config');
const apiRoutes = require('./src/routes/api');

const app = express();
const PORT = config.port;

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false }));

// Static dashboard
app.use(express.static(path.join(__dirname, 'public')));

// API
app.use('/api', apiRoutes);

// 404 for unknown API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found', path: req.originalUrl });
});

// Central error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🛡  Email Breach Risk API running at http://localhost:${PORT}`);
  console.log('   POST /api/analyze   - check an email\n   GET  /api/breaches  - breach feed\n   GET  /api/stats     - usage stats\n');
  console.log('   breach provider: XposedOrNot (free, no API key required)');
});
