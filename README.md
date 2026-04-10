# 🛡 OWASP Shield — Web App

A persistent, real-time OWASP Top 10 vulnerability scanner with a live terminal UI.
Runs as a proper **Flask web server** — no serverless timeouts, no cold start delays.

> ⚠️ **AUTHORIZED USE ONLY.** Only scan systems you own or have explicit written permission to test.

---

## 🌐 Free Hosting Options

| Platform | Free Tier | Sleep? | Best For |
|---|---|---|---|
| **Render** ⭐ | 750 hrs/mo | Yes (15 min) | Easiest setup |
| **Railway** | $5 credit/mo | No | Best performance |
| **Fly.io** | 3 shared VMs | No | Most control |

**Recommendation: Start with Render** — it has the easiest GitHub integration and is completely free.

---

## 🚀 Deploy on Render (Recommended — 5 minutes)

### Step 1 — Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit — OWASP Shield"
git remote add origin https://github.com/YOUR_USERNAME/owasp-shield.git
git push -u origin main
```

### Step 2 — Create Render service
1. Go to [render.com](https://render.com) → Sign up (free, no credit card)
2. Click **New** → **Web Service**
3. Connect your GitHub account → select your repo
4. Render auto-detects `render.yaml` — settings are pre-filled:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --workers 2 --threads 8 --timeout 300 --bind 0.0.0.0:$PORT`
5. Click **Create Web Service**

### Step 3 — Done! 🎉
Your app is live at `https://owasp-shield-xxxx.onrender.com`

> **Note**: Render free tier spins down after 15 minutes of inactivity. First request after sleep takes ~30s to wake up. Upgrade to Render Starter ($7/mo) to keep it always-on.

---

## 🚀 Deploy on Railway (Alternative)

1. Go to [railway.app](https://railway.app) → Login with GitHub
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your repo → Railway auto-detects Python
4. Set the **Start Command** (Settings → Deploy):
   ```
   gunicorn app:app --workers 2 --threads 8 --timeout 300 --bind 0.0.0.0:$PORT
   ```
5. Deploy → get your URL from Settings → Domains

Railway gives $5 free credit/month which runs a small app ~500 hours/month.

---

## 🚀 Deploy on Fly.io

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login and launch
fly auth login
fly launch      # auto-detects, creates fly.toml
fly deploy
```

---

## 📁 Project Structure

```
owasp-shield/
├── app.py              ← Flask server (SSE streaming, scan orchestration)
├── templates/
│   └── index.html      ← Full UI (dark terminal dashboard)
├── lib/                ← Scanner engine (your original modules)
│   ├── analyzer.py
│   ├── payloads.py
│   ├── scanner.py
│   ├── thread_engine.py
│   ├── reporter.py
│   └── utils.py
├── requirements.txt    ← Flask, gunicorn, requests, beautifulsoup4
├── render.yaml         ← Render deploy config (auto-detected)
└── README.md
```

---

## ⚙️ How It Works

```
Browser  ──POST /api/scan──▶  Flask
                                │
                          starts thread
                                │
Browser ◀──SSE stream────  scan events (log lines, findings, phases)
                                │
                          scan complete
                                │
Browser ◀──{ findings }──  final JSON
```

1. User submits URL → POST to `/api/scan` → gets `scan_id`
2. Browser opens SSE stream to `/api/stream/<scan_id>`
3. Flask background thread runs the full scanner, pushes events to a queue
4. SSE endpoint streams events live — terminal updates in real-time
5. On completion, full results rendered in the dashboard

---

## 🖥 Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Run dev server
python app.py

# Or with gunicorn (production-like)
gunicorn app:app --workers 2 --threads 8 --timeout 300 --bind 0.0.0.0:5000
```

Open `http://localhost:5000`

---

## 🔌 API Reference

### POST /api/scan
Start a new scan.

**Request body:**
```json
{
  "url":     "https://target.example.com",
  "quick":   false,
  "checks":  ["sqli", "xss", "headers"],
  "workers": 4,
  "timeout": 10,
  "cookie":  "session=abc; auth=xyz"
}
```
Omit `checks` to run all. Set `quick: true` for Critical/High payloads only.

**Response:**
```json
{ "scan_id": "a1b2c3d4-..." }
```

### GET /api/stream/{scan_id}
Server-Sent Events stream. Each event is a JSON object:

| type | fields |
|---|---|
| `log` | `level` (info/success/warn/error), `msg`, `ts` |
| `phase` | `phase`, `msg`, `ts` |
| `finding` | `severity`, `description`, `category`, `url`, `parameter` |
| `done` | `result` (full scan result JSON) |
| `error` | `msg` |
| `ping` | heartbeat (ignore) |

### GET /api/result/{scan_id}
Fetch the final result JSON after scan completes.

---

## 🛡 Security

- Internal/private IP addresses are blocked
- Only `http://` and `https://` URLs accepted
- Scanner runs in isolated background threads per scan
- No scan data persisted to disk (in-memory only)

---

*MIT License — Educational / Authorized Use Only*
