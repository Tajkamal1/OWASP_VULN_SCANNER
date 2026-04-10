# 🛡 OWASP Shield — Web UI

A full-featured OWASP Top 10 vulnerability scanner with a dark, terminal-style web interface.
Built for deployment on **Vercel** via **GitHub**.

> ⚠️ **AUTHORIZED USE ONLY.** Only scan systems you own or have explicit written permission to test.

---

## 🚀 Deploy to Vercel (5 minutes)

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/owasp-shield.git
git push -u origin main
```

### 2. Connect Vercel
1. Go to [vercel.com](https://vercel.com) → **Add New Project**
2. Import your GitHub repository
3. Vercel auto-detects the config — just click **Deploy**

### 3. Done! 🎉
Your scanner is live at `https://your-project.vercel.app`

---

## 📁 Project Structure

```
owasp-web/
├── index.html          ← Frontend UI (served as static)
├── vercel.json         ← Vercel routing + Python runtime config
├── requirements.txt    ← Python dependencies for Vercel
├── api/
│   ├── scan.py         ← Serverless API endpoint (POST /api/scan)
│   └── lib/            ← Scanner engine modules
│       ├── analyzer.py
│       ├── payloads.py
│       ├── scanner.py
│       ├── thread_engine.py
│       ├── reporter.py
│       └── utils.py
└── README.md
```

---

## ⚙️ How It Works

| Component | Description |
|---|---|
| `index.html` | Dark terminal-style UI — URL input, check selector, results dashboard |
| `api/scan.py` | Vercel Python serverless function — wraps the scanner engine into a JSON API |
| `api/lib/` | Original scanner modules (analyzer, payloads, scanner, etc.) |

**Request flow:**
1. User enters target URL → clicks "Launch Scan"
2. Browser POSTs to `/api/scan` with scan options
3. Vercel runs `api/scan.py` (Python 3.9 serverless)
4. Scanner crawls target, runs injection payloads, checks headers/paths
5. Results returned as JSON → rendered in the dashboard

---

## 🔧 API Usage

```bash
curl -X POST https://your-project.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url":     "https://example.com",
    "quick":   true,
    "checks":  ["sqli", "xss", "headers"],
    "workers": 3,
    "timeout": 8,
    "cookie":  "session=abc"
  }'
```

**Response:**
```json
{
  "url":         "https://example.com",
  "duration":    12.4,
  "findings":    [...],
  "stats":       {"critical":0, "high":1, "medium":2, "low":3, "info":5},
  "tech_stack":  ["nginx", "php"],
  "forms_found": 2,
  "params_found": 4
}
```

**Supported checks:** `sqli`, `xss`, `ssti`, `cmdi`, `lfi`, `xxe`, `ssrf`, `redirect`, `headers`, `paths`, `auth`

---

## ⚡ Vercel Limits

| Tier | Max Function Duration |
|---|---|
| Hobby (free) | 10 seconds |
| Pro | 60 seconds |

The API defaults to **Quick mode** (critical/high payloads only) which fits within free tier limits for most targets. Use **Full mode** with a Pro plan for comprehensive scans.

---

## 🛠 Local Development

```bash
pip install -r requirements.txt vercel
vercel dev
```

Then open `http://localhost:3000`

---

*MIT License — Educational / Authorized Use Only*
"# OWASP_VULN_SCANNER" 
