# Email Breach Risk Predictor

Backend API + dashboard that checks whether an email address appears in known real-world data breaches and predicts the **risk of account compromise** with an explainable AI scoring model.

Built with Node.js + Express. No API keys, no accounts — works out of the box.

## What it does

1. **Live breach lookup** — queries the free [XposedOrNot](https://xposedornot.com) API (no key required) for real breach records tied to the email.
2. **AI risk prediction** — a weighted 7-factor scoring model converts raw breach data into a 0–100 risk score, from `1/LOW` to `100/CRITICAL`.
3. **Explainability** — every score ships with per-factor contribution breakdowns (breach count, credential exposure, recency, severity, address structure, domain reputation, PII richness), so you can see *why* an address scored what it did.
4. **Actionable advice** — recommendations adapt to what actually leaked (passwords → rotate + 2FA; addresses → scam warnings).
5. **Graceful degradation** — if the live API is unreachable, it falls back to a local demo dataset and the UI clearly labels the mode.

## API

| Endpoint | Method | Description |
|---|---|---|
| `/api/analyze` | POST | Full analysis: `{ "email": "you@example.com" }` → breaches + risk score + factors + advice |
| `/api/breaches` | GET | Recent breach feed from the database |
| `/api/stats` | GET | Aggregate stats over past analyses |
| `/api/health` | GET | Health check + active breach provider |

### Example

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"email":"test@gmail.com"}'
```

## Run it

```bash
npm install
npm start        # → http://localhost:3000 (API + dashboard)
npm test         # 8 unit tests for the risk engine & breach mapper
```

Open `http://localhost:3000` in a browser for the dashboard UI.

## Deploy it (free)

**One-click:** fork/clone this repo, then on [dashboard.render.com](https://dashboard.render.com) → **New + → Web Service** → connect the repo. Render reads `render.yaml` and does the rest.

Or click:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/yashrr2007/email-breach-risk-predictor)

The service goes live at `https://breachguard-ai.onrender.com` (name set in `render.yaml`). Free tier notes: sleeps after ~15 min idle (first request takes ~50 s to wake), and analysis history is ephemeral. For local tunneling instead, run `npm start` + `npm run tunnel` (Cloudflare quick tunnel — random URL each run).

## Configuration (optional)

Copy `.env.example` → `.env` to tune the port, fetch timeout, or cache TTL. Defaults work fine with no config at all.

## Project structure

```
server.js                   Express app: API routes + static dashboard
src/
  config.js                 Dependency-free .env loader
  routes/api.js             Endpoints, validation, persistent history
  services/
    breachService.js        Live breach lookup (XposedOrNot → mock fallback), cache
    riskEngine.js           AI risk model: 7 weighted factors → 0–100 score + explanation
  data/
    breaches.js             Offline demo breach dataset
    analyses.json           Analysis history (gitignored — user data)
public/                     Dashboard UI (vanilla JS, dark mode)
test/riskEngine.test.js     Unit tests
```

## Disclaimer

The risk score is a model estimate for demonstration/educational purposes — not a guarantee that an account is or isn't compromised. Breach data via the free XposedOrNot API.
