# DarkWatch — Dark Web Asset Monitoring Tool

A prototype threat intelligence dashboard that monitors company assets across
breach databases, paste sites, dark web forums, and public threat intel feeds.

---

## Folder Structure

```
darkweb-monitor/
├── app.py                  # Flask backend (scan engine + API routes)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── index.html          # Main dashboard HTML
└── static/
    ├── css/
    │   └── style.css       # All styles (dark cyber aesthetic)
    └── js/
        └── main.js         # Frontend logic (scan, render, filter, modal)
```

---

## Setup Instructions

### Prerequisites
- Python 3.8+
- pip

### Steps

```bash
# 1. Clone or extract the project
cd darkweb-monitor

# 2. Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate       # macOS/Linux
venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py

# 5. Open your browser
# Navigate to: http://localhost:5000
```

---

## How to Use

1. Fill in one or more asset fields:
   - **Domain Name** – e.g. `acmecorp.com`
   - **Company Name** – e.g. `Acme Corporation`
   - **Email Domain** – e.g. `acmecorp.com`
   - **Brand Keywords** – comma-separated, e.g. `acme, acmecorp`
   - **IP Address** – optional, e.g. `203.0.113.42`

2. Click **INITIATE SCAN** (or **LOAD DEMO** to auto-fill sample data).

3. Watch the animated radar scanning progress.

4. Review the dashboard:
   - Overall Risk Score (0–100)
   - Severity breakdown (High / Medium / Low)
   - Category breakdown with bar chart
   - Filterable findings table
   - Click **DETAIL ▶** on any row to view full finding data in a modal.

---

## Architecture

```
Browser (HTML/CSS/JS)
    │
    │  POST /scan (JSON payload)
    ▼
Flask Backend (app.py)
    ├── scan_credential_leaks()     → Simulates HaveIBeenPwned
    ├── scan_paste_sites()          → Simulates Pastebin scraper
    ├── scan_dark_web_forums()      → Simulates forum crawl
    ├── scan_brand_impersonation()  → Typosquatting detection
    ├── scan_exposed_emails()       → Email exposure scan
    ├── scan_ip_reputation()        → AbuseIPDB/GreyNoise check
    └── calculate_risk_score()      → Weighted severity scoring
    │
    │  JSON response (findings array + risk + summary)
    ▼
Frontend renders dashboard with filter + modal
```

---

## Scanning Logic

Each scan module simulates a different threat intelligence source:

| Module | What it simulates | Real API (production) |
|---|---|---|
| `scan_credential_leaks` | Email found in breach dumps | HaveIBeenPwned v3 API |
| `scan_paste_sites` | Keyword mentions in pastes | Pastebin scraper / Google Dorks |
| `scan_dark_web_forums` | Forum thread mentions | DarkOwl, Flare.io, Recorded Future |
| `scan_brand_impersonation` | Typosquat / phishing domains | DomainTools, URLscan.io |
| `scan_exposed_emails` | Emails in public sources | Hunter.io, Emailrep.io |
| `scan_ip_reputation` | IP in threat feeds | AbuseIPDB, GreyNoise, Shodan |

### Risk Scoring

```
score = Σ (High × 10) + (Medium × 5) + (Low × 2)
score = min(score, 100)

0–19  → Low
20–39 → Medium
40–69 → High
70+   → Critical
```

---

## Sample Test Input

```
Domain:        acmecorp.com
Company:       Acme Corporation
Email Domain:  acmecorp.com
Keywords:      acme, acmecorp, acme-login
IP Address:    203.0.113.42
```

### Sample Output Structure

```json
{
  "status": "completed",
  "scan_time": "2024-04-16 14:32:01",
  "risk": { "score": 72, "label": "Critical", "color": "#ff2d55" },
  "summary": {
    "total": 18,
    "high": 7,
    "medium": 8,
    "low": 3,
    "categories": {
      "Credential Leak": 4,
      "Paste Site Mention": 3,
      "Dark Web Mention": 2,
      "Brand Impersonation": 3,
      "Exposed Email": 5,
      "IP Threat Intel": 1
    }
  },
  "findings": [
    {
      "category": "Credential Leak",
      "severity": "High",
      "source": "Collection #1 (2019)",
      "detail": "Email 'admin@acmecorp.com' found in breach database",
      "data": {
        "email": "admin@acmecorp.com",
        "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99...",
        "breach_date": "2019-01-17 00:00:00",
        "data_types": ["Email", "Password", "Username"]
      },
      "timestamp": "2024-03-12 09:44:22"
    }
    // ... more findings
  ]
}
```

---

## Assumptions

- All scan data is **simulated** using realistic mock data; no real external API calls are made.
- The tool assumes the user has legitimate authorization to scan the assets they provide.
- Email generation is random-realistic (not scraped from real sources).
- Risk scores are illustrative and not calibrated to real-world threat models.

---

## Limitations

- **No real data**: All findings are mocked. Real threat detection requires paid APIs.
- **No persistence**: Scan results are not stored; each scan is stateless.
- **No authentication**: The tool has no user login; anyone with access can scan.
- **Rate limiting**: No rate limiting on the `/scan` endpoint.
- **Single-threaded**: Scans run sequentially; no async parallelism.

---


## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 + Flask |
| Frontend | Vanilla HTML5 / CSS3 / JavaScript |
| Fonts | Google Fonts (Orbitron, Rajdhani, Share Tech Mono) |
| Data | Simulated (mock engine in app.py) |

---

