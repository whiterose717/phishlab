#!/usr/bin/env python3
"""
Generate campaign export (CSV) + user awareness report from real GoPhish data.
Mirrors section 6 (Export CSV) and section 9 (Measuring User Awareness) of task.txt.
"""
import csv
import sys
from datetime import datetime, timezone

import requests

KEY = open("/root/.gophish_api_key").read().strip()
BASE = "https://127.0.0.1:3333"
HDR = {"Authorization": f"Bearer {KEY}"}
OUT = "/home/whiterose/Desktop/phi"

camp = requests.get(f"{BASE}/api/campaigns/", headers=HDR, verify=False).json()
camp = [c for c in camp if c["name"] == "Password Reset Simulation"][-1]
print(f"campaign: {camp['name']} id={camp['id']} status={camp['status']}")

results = camp["results"]
rows = []
for r in results:
    rows.append({
        "rid": r["id"],
        "email": r["email"],
        "first_name": r["first_name"],
        "last_name": r["last_name"],
        "status": r["status"],
        "ip": r["ip"],
        "latitude": r["latitude"],
        "longitude": r["longitude"],
        "send_date": r["send_date"],
        "reported": r["reported"],
        "modified_date": r["modified_date"],
    })

# ---- CSV export (section 6) -------------------------------------------------
csv_path = f"{OUT}/campaign_export.csv"
with open(csv_path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print(f"exported -> {csv_path}")

# ---- metrics (section 9) ----------------------------------------------------
sent = len(rows)
opened = sum(1 for r in rows if r["status"] in ("Email Opened", "Opened", "Clicked Link", "Submitted Data"))
clicked = sum(1 for r in rows if r["status"] in ("Clicked Link", "Submitted Data"))
submitted = sum(1 for r in rows if r["status"] == "Submitted Data")
reported = sum(1 for r in rows if r["reported"])

open_rate = opened / sent * 100
click_rate = clicked / sent * 100
submit_rate = submitted / sent * 100
# guide's formula: (Clicked Link + Submitted Data) / Total Emails Sent
phish_prone_guide = (clicked + submitted) / sent * 100
# deduped: a submitter already clicked
unique_compromised = len({r["email"] for r in rows if r["status"] in ("Clicked Link", "Submitted Data")})
phish_prone_unique = unique_compromised / sent * 100

print(f"\nmetrics: sent={sent} opened={opened} clicked={clicked} submitted={submitted}")
print(f"  open rate        : {open_rate:.0f}%")
print(f"  click rate       : {click_rate:.0f}%")
print(f"  submit rate      : {submit_rate:.0f}%")
print(f"  phishing-prone (guide formula): {phish_prone_guide:.0f}%")
print(f"  phishing-prone (unique users) : {phish_prone_unique:.0f}%")

# ---- awareness report (section 9) -------------------------------------------
ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
md = f"""# User Security Awareness Report — Phishing Simulation

**Campaign:** Password Reset Simulation
**Platform:** GoPhish v0.12.1 (lab, Kali Linux) · **Mail server:** Mailhog (local catch-all)
**Generated:** {ts}

## Summary

A realistic "password expiration" phishing email was sent to {sent} test users.
The email carried a tracking pixel and a link to a credential-capture page that
cloned the look of a Microsoft 365 sign-in, then redirected victims to the real
office.com after submission.

| Metric | Value |
|---|---|
| Emails sent | {sent} |
| Emails opened | {opened} ({open_rate:.0f}%) |
| Clicked link | {clicked} ({click_rate:.0f}%) |
| Credentials submitted | {submitted} ({submit_rate:.0f}%) |
| Reported as phishing | {reported} |
| Phishing-prone % (guide formula: (clicked + submitted) / sent) | {phish_prone_guide:.0f}% |
| Phishing-prone % (unique users) | {phish_prone_unique:.0f}% |

## Per-user results

| User | Status | IP |
|---|---|---|
""" + "\n".join(
    f"| {r['first_name']} {r['last_name']} ({r['email']}) | {r['status']} | {r['ip'] or '-'} |"
    for r in rows
) + """

## Observations

- **Open rate of {open_rate:.0f}%** — most users looked at the email, which is
  typical even for skeptical users.
- **{click_rate:.0f}% clicked and {submit_rate:.0f}% submitted credentials.** The
  captured example shows the exact data GoPhish logs on submission — username,
  password, victim IP and browser user-agent (see `simulate_victims.py` /
  campaign events in `gophish.db`).
- **Report rate is 0** because no report channel was configured for this lab.
  In production, enable GoPhish's built-in reporting (or a dedicated mailbox /
  "Report Phish" button) so users have a way to flag suspicious mail.

## Recommendations

1. Train users to check the sender address and hover links before clicking —
   the simulated sender (`it-support@example.com`) differs from the real IT address.
2. Deploy **SPF/DKIM/DMARC** on the organization domain (see
   `dns_authentication.md`) and set DMARC policy to quarantine/reject so
   look-alike and spoofed mail fails authentication.
3. Require **MFA** so that captured passwords alone are not enough to log in.
4. Run simulations quarterly and track the phishing-prone trend per team;
   target below 5% for mature awareness programs.

*Lab artifacts: this report, `campaign_export.csv`, `gophish_lab.py`
(setup), `simulate_victims.py` (telemetry), `dns_authentication.md` (SPF/DKIM/DMARC checks).*
"""
md = md.replace("{open_rate:.0f}%", f"{open_rate:.0f}%").replace("{click_rate:.0f}%", f"{click_rate:.0f}%").replace("{submit_rate:.0f}%", f"{submit_rate:.0f}%")

report_path = f"{OUT}/awareness_report.md"
with open(report_path, "w") as f:
    f.write(md)
print(f"report -> {report_path}")
