"""
Dark Web Asset Monitoring Tool - Backend
Author: Senior Security Engineer
Description: Flask backend that simulates dark web monitoring by querying
             mock datasets and public threat intelligence sources.
"""

from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
import random
import hashlib
import time
import json
import re

app = Flask(__name__)

# ─────────────────────────────────────────────
# MOCK DATA ENGINE
# Simulates results from: breach datasets, paste sites,
# dark web forums, and public threat intel sources.
# In production, replace with real API calls (see comments).
# ─────────────────────────────────────────────

BREACH_SOURCES = [
    "Collection #1 (2019)", "LinkedIn Breach (2021)", "RockYou2021",
    "Adobe Breach (2013)", "Canva Breach (2019)", "Zynga Breach (2019)",
    "Gravatar Leak (2020)", "Facebook Scrape (2021)", "Twitch Leak (2021)",
    "Twitter Scrape (2023)", "Dark Web Marketplace Dump", "Combolist Forum Post"
]

PASTE_SITES = [
    "Pastebin.com", "Ghostbin", "Rentry.co", "Hastebin",
    "PrivateBin", "0bin.net", "Dpaste", "Termbin"
]

DARK_WEB_FORUMS = [
    "BreachForums", "RaidForums Archive", "XSS.is", "Nulled.to",
    "Cracked.io Archive", "Exploit.in", "Telegram Data Channel"
]

THREAT_INTEL_SOURCES = [
    "AlienVault OTX", "Shodan (simulated)", "GreyNoise", "URLhaus",
    "PhishTank", "AbuseIPDB (simulated)"
]


def generate_random_email(domain):
    """Generate realistic-looking leaked email addresses for a domain."""
    prefixes = [
        "admin", "info", "hr", "support", "ceo", "cto", "finance",
        "sales", "john.doe", "jane.smith", "m.johnson", "a.patel",
        "r.kumar", "dev", "noreply", "contact", "hello", "it"
    ]
    return f"{random.choice(prefixes)}@{domain}"


def generate_password_hash():
    """Generate a realistic-looking partial password hash."""
    chars = "abcdef0123456789"
    return "".join(random.choices(chars, k=32)) + "..."


def random_past_date(days_back=730):
    """Return a random datetime within the past N days."""
    delta = random.randint(0, days_back)
    dt = datetime.now() - timedelta(days=delta)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def calculate_risk_score(findings):
    """
    Risk scoring logic based on severity weights.
    High=10pts, Medium=5pts, Low=2pts per finding.
    Score is normalized to 0-100.
    """
    score = 0
    weights = {"High": 10, "Medium": 5, "Low": 2}
    for f in findings:
        score += weights.get(f.get("severity", "Low"), 2)
    # Normalize: cap at 100
    normalized = min(score, 100)
    if normalized >= 70:
        risk_label = "Critical"
        risk_color = "#ff2d55"
    elif normalized >= 40:
        risk_label = "High"
        risk_color = "#ff6b35"
    elif normalized >= 20:
        risk_label = "Medium"
        risk_color = "#ffd60a"
    else:
        risk_label = "Low"
        risk_color = "#30d158"
    return {"score": normalized, "label": risk_label, "color": risk_color}


# ─────────────────────────────────────────────
# SCAN MODULES
# Each function simulates one type of threat scan.
# Replace mock logic with real API calls in production.
# ─────────────────────────────────────────────

def scan_credential_leaks(domain, email_domain, company):
    """
    Simulates HaveIBeenPwned-style breach scanning.
    Production: Use https://haveibeenpwned.com/API/v3
    """
    findings = []
    # Simulate 2–5 credential leak hits
    count = random.randint(2, 5)
    for _ in range(count):
        email = generate_email_variant(email_domain or domain)
        source = random.choice(BREACH_SOURCES)
        severity = random.choice(["High", "High", "Medium", "Medium", "Low"])
        findings.append({
            "category": "Credential Leak",
            "severity": severity,
            "source": source,
            "detail": f"Email '{email}' found in breach database '{source}'",
            "data": {
                "email": email,
                "password_hash": generate_password_hash(),
                "breach_date": random_past_date(1000),
                "data_types": random.sample(
                    ["Email", "Password", "Username", "IP Address", "Phone", "Name"], k=3
                )
            },
            "timestamp": random_past_date(30)
        })
    return findings


def generate_email_variant(domain):
    prefixes = ["admin", "info", "hr", "john.doe", "jane.smith",
                "support", "ceo", "sales", "it", "noreply"]
    return f"{random.choice(prefixes)}@{domain}"


def scan_paste_sites(domain, company, keywords):
    """
    Simulates paste site scanning (Pastebin, Ghostbin, etc.)
    Production: Use Google Dorks API or Pastebin scraper.
    """
    findings = []
    count = random.randint(1, 4)
    for _ in range(count):
        site = random.choice(PASTE_SITES)
        kw = random.choice(keywords.split(",") if keywords else [domain])
        kw = kw.strip()
        severity = random.choice(["Medium", "Medium", "High", "Low"])
        paste_id = hashlib.md5(f"{kw}{random.random()}".encode()).hexdigest()[:8]
        findings.append({
            "category": "Paste Site Mention",
            "severity": severity,
            "source": site,
            "detail": f"Keyword '{kw}' found in paste: {site}/paste/{paste_id}",
            "data": {
                "url": f"https://{site.lower().replace('.', '')}.com/paste/{paste_id}",
                "keyword_matched": kw,
                "paste_type": random.choice(["Raw dump", "Config file", "Email list", "API keys", "SQL dump"]),
                "lines_matched": random.randint(1, 50)
            },
            "timestamp": random_past_date(90)
        })
    return findings


def scan_dark_web_forums(domain, company, keywords):
    """
    Simulates dark web forum mention scanning.
    Production: Use Recorded Future, DarkOwl, or Flare.io APIs.
    """
    findings = []
    count = random.randint(1, 3)
    for _ in range(count):
        forum = random.choice(DARK_WEB_FORUMS)
        severity = random.choice(["High", "High", "Medium"])
        thread_id = random.randint(100000, 999999)
        target = random.choice([domain, company] + (keywords.split(",") if keywords else []))
        target = target.strip()
        findings.append({
            "category": "Dark Web Mention",
            "severity": severity,
            "source": forum,
            "detail": f"'{target}' mentioned in thread #{thread_id} on {forum}",
            "data": {
                "forum": forum,
                "thread_id": str(thread_id),
                "context": random.choice([
                    "Database for sale", "Credential dump shared", "Access credentials posted",
                    "Internal data advertised", "VPN credentials listed", "Admin panel access offered"
                ]),
                "actor": f"threat_actor_{random.randint(100, 999)}",
                "price_mentioned": random.choice([None, "$50", "$200", "$500", "0.05 BTC"])
            },
            "timestamp": random_past_date(60)
        })
    return findings


def scan_brand_impersonation(domain, company):
    """
    Detects typosquatting domains and phishing attempts.
    Production: Use DomainTools, WhoisXML API, or URLscan.io.
    """
    findings = []
    typosquat_patterns = [
        f"{company.lower().replace(' ', '')}-login.com",
        f"{company.lower().replace(' ', '')}support.net",
        f"secure-{domain}",
        f"{domain.split('.')[0]}-verify.com",
        f"{company.lower().replace(' ', '')}helpdesk.org",
        f"login-{domain.split('.')[0]}.com"
    ]
    count = random.randint(1, 3)
    for i in range(count):
        fake_domain = typosquat_patterns[i % len(typosquat_patterns)]
        severity = random.choice(["High", "Medium"])
        findings.append({
            "category": "Brand Impersonation",
            "severity": severity,
            "source": random.choice(["PhishTank", "URLscan.io", "WHOIS Database", "Google SafeBrowsing"]),
            "detail": f"Suspicious domain '{fake_domain}' may be impersonating '{company}'",
            "data": {
                "fake_domain": fake_domain,
                "registrar": random.choice(["Namecheap", "GoDaddy", "NameSilo", "Porkbun"]),
                "registered_date": random_past_date(180),
                "ip_address": f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "hosting_country": random.choice(["RU", "CN", "NL", "UA", "BR"])
            },
            "timestamp": random_past_date(45)
        })
    return findings


def scan_exposed_emails(domain, email_domain):
    """
    Scans for exposed email addresses in public sources.
    Production: Use Hunter.io, Emailrep.io, or custom scraper.
    """
    findings = []
    target_domain = email_domain or domain
    count = random.randint(2, 6)
    for _ in range(count):
        email = generate_email_variant(target_domain)
        severity = "Medium" if "admin" in email or "ceo" in email or "cto" in email else "Low"
        findings.append({
            "category": "Exposed Email",
            "severity": severity,
            "source": random.choice(["Hunter.io", "LinkedIn Scrape", "Public GitHub", "Job Board", "WHOIS Records"]),
            "detail": f"Email '{email}' exposed in public source",
            "data": {
                "email": email,
                "exposure_type": random.choice(["Job listing", "Conference speaker", "GitHub commit", "WHOIS record", "Forum post"]),
                "times_seen": random.randint(1, 15),
                "associated_breaches": random.randint(0, 3)
            },
            "timestamp": random_past_date(120)
        })
    return findings


def scan_ip_reputation(ip_address):
    """
    Checks IP against threat intel feeds.
    Production: Use AbuseIPDB, GreyNoise, or Shodan APIs.
    """
    if not ip_address:
        return []
    findings = []
    severity = random.choice(["High", "Medium", "Low"])
    findings.append({
        "category": "IP Threat Intel",
        "severity": severity,
        "source": random.choice(THREAT_INTEL_SOURCES),
        "detail": f"IP {ip_address} flagged in threat intelligence feed",
        "data": {
            "ip": ip_address,
            "abuse_confidence": f"{random.randint(10, 95)}%",
            "reports": random.randint(1, 50),
            "last_reported": random_past_date(30),
            "categories": random.sample(
                ["SSH Brute Force", "Port Scan", "Web Scraping", "DDoS", "Phishing", "Malware"], k=2
            ),
            "country": random.choice(["RU", "CN", "US", "DE", "NL", "UA"])
        },
        "timestamp": random_past_date(15)
    })
    return findings


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Main scan endpoint. Receives asset inputs, runs all scan modules,
    aggregates findings, calculates risk score, and returns JSON.
    """
    data = request.get_json()

    domain = data.get("domain", "").strip()
    company = data.get("company", "").strip()
    email_domain = data.get("email_domain", "").strip()
    keywords = data.get("keywords", "").strip()
    ip_address = data.get("ip_address", "").strip()

    # Basic validation
    if not domain and not company:
        return jsonify({"error": "Please provide at least a domain or company name."}), 400

    # Simulate scan delay (realistic feel)
    time.sleep(1.5)

    # Run all scan modules
    all_findings = []
    all_findings += scan_credential_leaks(domain, email_domain, company)
    all_findings += scan_paste_sites(domain, company, keywords)
    all_findings += scan_dark_web_forums(domain, company, keywords)
    all_findings += scan_brand_impersonation(domain, company)
    all_findings += scan_exposed_emails(domain, email_domain)
    all_findings += scan_ip_reputation(ip_address)

    # Sort findings by severity (High first)
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    # Calculate overall risk score
    risk = calculate_risk_score(all_findings)

    # Build summary
    summary = {
        "total": len(all_findings),
        "high": sum(1 for f in all_findings if f["severity"] == "High"),
        "medium": sum(1 for f in all_findings if f["severity"] == "Medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "Low"),
        "categories": {}
    }
    for f in all_findings:
        cat = f["category"]
        summary["categories"][cat] = summary["categories"].get(cat, 0) + 1

    return jsonify({
        "status": "completed",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "assets_scanned": {
            "domain": domain,
            "company": company,
            "email_domain": email_domain,
            "keywords": keywords,
            "ip_address": ip_address
        },
        "risk": risk,
        "summary": summary,
        "findings": all_findings
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
