#!/usr/bin/python3
"""
phishlab — advanced CLI for the GoPhish phishing-simulation lab.

One tool for the whole workflow from task.txt:
  setup     create sending profile, template, landing page, group (idempotent)
  launch    create + launch the campaign
  simulate  emulate victim opens/clicks/submissions (via Mailhog)
  status    live campaign stats and per-user results
  events    event log from gophish.db (with captured-credential details)
  report    export campaign CSV + user-awareness report
  dns       SPF / DKIM / DMARC checks for a domain (dig)
  health    verify gophish, phish server and mailhog are up
  reset     delete every lab object
  creds     print access details

Config via flags or env: PHISHLAB_ADMIN, PHISHLAB_PHISH, PHISHLAB_MAILHOG,
PHISHLAB_DB, PHISHLAB_KEYFILE, PHISHLAB_TARGETS.
"""
import argparse
import csv
import json
import os
import quopri
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------- config ----
ADMIN = os.environ.get("PHISHLAB_ADMIN", "https://127.0.0.1:3333")
PHISH = os.environ.get("PHISHLAB_PHISH", "http://10.0.2.15:8888")
MAILHOG = os.environ.get("PHISHLAB_MAILHOG", "http://localhost:8025")
DB = os.environ.get("PHISHLAB_DB", "/opt/gophish/gophish.db")
KEYFILE = os.environ.get("PHISHLAB_KEYFILE", "/root/.gophish_api_key")

CAMPAIGN = "Password Reset Simulation"
NAMES = {
    "smtp": {"Lab Sender"},
    "templates": {"Password Reset"},
    "pages": {"Office365 Login"},
    "groups": {"Test Users"},
    "campaigns": {CAMPAIGN},
}

USERS = [
    ("John", "Doe", "john.doe@example.com"),
    ("Jane", "Smith", "jane.smith@example.com"),
    ("Bob", "Johnson", "bob.johnson@example.com"),
    ("Alice", "Williams", "alice.williams@example.com"),
    ("Charlie", "Brown", "charlie.brown@example.com"),
]

# default victim behavior per user (overridable with --open/--click/--submit)
DEFAULT_BEHAVIOR = {
    "jane.smith@example.com": ("open", "click", "submit"),
    "john.doe@example.com": ("open", "click"),
    "bob.johnson@example.com": ("open",),
}
CAPTURED_CREDS = {
    "jane.smith@example.com": ("jane.smith@contoso.com", "Summer2026!"),
}

TEMPLATE_HTML = """<html><head><meta charset="utf-8"></head><body style="font-family:Arial,sans-serif">
<p>Dear {{.FirstName}},</p>
<p>Our records show that your account password is scheduled to <b>expire within 24 hours</b>.</p>
<p>To avoid interruption of your access to email, calendar and files, please
<a href="{{.URL}}">verify your account and reset your password here</a>.</p>
<p>If you did not request this change, contact the IT Service Desk.</p>
<p>Regards,<br/>IT Support Team</p>
{{.Tracker}}
</body></html>"""
TEMPLATE_TEXT = ("Dear {{.FirstName}},\n\n"
                 "Your account password is scheduled to expire within 24 hours. "
                 "Please visit {{.URL}} to reset it.\n\n"
                 "Regards, IT Support Team")

PAGE_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Sign in to your account</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;background:#f2f2f2;margin:0}
 .card{max-width:440px;margin:60px auto;background:#fff;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
 .logo{color:#0078d4;font-size:22px;font-weight:600;margin-bottom:24px}
 h1{font-size:24px;font-weight:600;margin:0 0 8px}
 p{color:#555;font-size:14px;margin:0 0 24px}
 input{width:100%;box-sizing:border-box;padding:6px 10px;margin:0 0 16px;border:1px solid #666;font-size:14px}
 button{background:#0067b8;color:#fff;border:0;padding:10px 24px;font-size:14px;cursor:pointer;float:right}
 .foot{margin-top:30px;color:#999;font-size:12px}
</style></head><body>
<div class="card">
  <div class="logo">Contoso</div>
  <h1>Sign in</h1>
  <p>Your password has expired. Sign in to set a new one.</p>
  <form method="post">
    <input type="text" name="username" placeholder="someone@example.com" autofocus>
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign in</button>
  </form>
  <div class="foot">&copy; Contoso IT</div>
</div></body></html>"""


# ---------------------------------------------------------------- helpers ----
def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def api(session, method, path, payload=None, expect=(200, 201)):
    r = session.request(method, f"{ADMIN}/api{path}", json=payload, timeout=15)
    if r.status_code not in expect:
        die(f"{method} /api{path} -> HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def connect():
    if not os.path.exists(KEYFILE):
        die(f"API key file {KEYFILE} not found — run `phishlab creds` or re-inject a key")
    s = requests.Session()
    s.verify = False
    s.headers["Authorization"] = f"Bearer {open(KEYFILE).read().strip()}"
    api(s, "GET", "/campaigns/")
    return s


def fmt(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts or "-"


def table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)] if rows \
        else [len(h) for h in headers]
    line = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    sep = "  ".join("-" * w for w in widths)
    print(line)
    print(sep)
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


# ------------------------------------------------------------- subcommands ----
def cmd_creds(_a):
    print("admin panel :", ADMIN)
    print("login       : admin /", end=" ")
    if os.path.exists(KEYFILE):
        print("<see below>")
    else:
        print("(see /var/log/gophish.log first-run password)")
    print("phish server:", PHISH)
    print("mailhog UI  :", MAILHOG)
    print("database    :", DB)
    if os.path.exists(KEYFILE):
        print("api key     :", open(KEYFILE).read().strip())


def cmd_setup(_a):
    s = connect()
    for path, names in NAMES.items():
        for item in api(s, "GET", f"/{path}/"):
            if item["name"] in names:
                api(s, "DELETE", f"/{path}/{item['id']}", expect=(200,))
                print(f"[reset] deleted {path}/{item['id']}")
    smtp = api(s, "POST", "/smtp/", {
        "name": "Lab Sender", "from_address": "IT Support <it-support@example.com>",
        "host": "localhost:1025", "ignore_cert_errors": True})
    tpl = api(s, "POST", "/templates/", {
        "name": "Password Reset", "subject": "Action Required: Password Expiration",
        "html": TEMPLATE_HTML, "text": TEMPLATE_TEXT})
    page = api(s, "POST", "/pages/", {
        "name": "Office365 Login", "html": PAGE_HTML,
        "capture_credentials": True, "capture_passwords": True,
        "redirect_url": "https://www.office.com"})
    grp = api(s, "POST", "/groups/", {
        "name": "Test Users",
        "targets": [{"first_name": fn, "last_name": ln, "email": em} for fn, ln, em in USERS]})
    print(f"[setup] smtp={smtp['id']} template={tpl['id']} page={page['id']} group={grp['id']} ({len(grp['targets'])} targets)")
    print(f"[setup] done — run `phishlab launch`")


def cmd_launch(a):
    s = connect()
    find = lambda path, name: next((x for x in api(s, "GET", f"/{path}/") if x["name"] == name), None)
    smtp, tpl, page, grp = (find(p, n) for p, n in
                            (("smtp", "Lab Sender"), ("templates", "Password Reset"),
                             ("pages", "Office365 Login"), ("groups", "Test Users")))
    missing = [n for n, x in (("smtp", smtp), ("template", tpl), ("page", page), ("group", grp)) if x is None]
    if missing:
        die(f"missing objects: {missing} — run `phishlab setup` first")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    camp = api(s, "POST", "/campaigns/", {
        "name": CAMPAIGN,
        "template": {"id": tpl["id"], "name": tpl["name"]},
        "page": {"id": page["id"], "name": page["name"]},
        "smtp": {"id": smtp["id"], "name": smtp["name"]},
        "groups": [{"id": grp["id"], "name": grp["name"]}],
        "url": PHISH, "launch_date": now})
    print(f"[launch] campaign id={camp['id']} url={camp['url']}")
    n = len(grp["targets"])
    for _ in range(45):
        c = api(s, "GET", f"/campaigns/{camp['id']}")
        sent = sum(1 for r in c["results"] if r["status"] != "Event Not Sent")
        if sent >= n:
            print(f"[launch] all {sent} emails sent")
            return camp["id"]
        time.sleep(2)
    die("campaign did not finish sending in time")


def cmd_simulate(a):
    s = connect()
    camp = api(s, "GET", "/campaigns/")[-1] if False else None
    camp = next((c for c in api(s, "GET", "/campaigns/") if c["name"] == CAMPAIGN), None)
    if not camp:
        die("campaign not found — run `phishlab launch` first")
    msgs = requests.get(f"{MAILHOG}/api/v2/messages", timeout=10).json()["items"]
    rid_by_user = {}
    for m in msgs[: len(camp["results"])]:
        to = re.search(r"<([^>]+)>", m["Content"]["Headers"].get("To", [""])[0])
        raw = quopri.decodestring(m["Raw"]["Data"].encode()).decode(errors="replace")
        rid = re.findall(r"rid=([A-Za-z0-9]+)", raw)
        if to and rid:
            rid_by_user[to.group(1)] = rid[0]
    behavior = dict(DEFAULT_BEHAVIOR)
    if a.open or a.click or a.submit:
        behavior = {u: () for u in rid_by_user}
        for u in list(behavior):
            acts = []
            if a.open: acts.append("open")
            if a.click: acts.append("click")
            if a.submit: acts.append("submit")
            behavior[u] = tuple(acts)
    print(f"[simulate] {len(rid_by_user)} emails found in mailhog")
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for user, acts in behavior.items():
        rid = rid_by_user.get(user)
        if not rid:
            print(f"[simulate] ! no rid for {user}")
            continue
        for act in acts:
            if act == "open":
                r = requests.get(f"{PHISH}/track?rid={rid}", headers=ua, timeout=10)
            elif act == "click":
                r = requests.get(f"{PHISH}/?rid={rid}", headers=ua, timeout=10)
            elif act == "submit":
                creds = CAPTURED_CREDS.get(user, (user, "LabPass2026!"))
                r = requests.post(f"{PHISH}/?rid={rid}", data={"username": creds[0], "password": creds[1]},
                                  headers=ua, timeout=10, allow_redirects=False)
            print(f"[simulate] {act:6s} {user:32s} HTTP {r.status_code}")
            time.sleep(0.3)
    print("[simulate] done — check `phishlab events`")


def cmd_status(a):
    s = connect()
    camp = next((c for c in api(s, "GET", "/campaigns/") if c["name"] == CAMPAIGN), None)
    if not camp:
        die("campaign not found — run `phishlab launch`")
    rows = camp["results"]
    sent = len(rows)
    opened = sum(1 for r in rows if r["status"] in ("Email Opened", "Opened", "Clicked Link", "Submitted Data"))
    clicked = sum(1 for r in rows if r["status"] in ("Clicked Link", "Submitted Data"))
    submitted = sum(1 for r in rows if r["status"] == "Submitted Data")
    reported = sum(1 for r in rows if r["reported"])
    if a.json:
        print(json.dumps({
            "campaign": camp["name"], "id": camp["id"], "status": camp["status"],
            "sent": sent, "opened": opened, "clicked": clicked, "submitted": submitted,
            "reported": reported,
            "open_rate_pct": round(opened / sent * 100, 1) if sent else 0,
            "click_rate_pct": round(clicked / sent * 100, 1) if sent else 0,
            "submit_rate_pct": round(submitted / sent * 100, 1) if sent else 0,
            "phish_prone_pct": round((clicked + submitted) / sent * 100, 1) if sent else 0,
        }, indent=2))
        return
    print(f"campaign: {camp['name']} (id {camp['id']}, {camp['status']})")
    table(["user", "status", "ip", "reported", "modified"],
          [[r["email"], r["status"], r["ip"] or "-", "yes" if r["reported"] else "no", fmt(r["modified_date"])]
           for r in rows])
    print(f"\nsent {sent} | opened {opened} ({opened/sent*100:.0f}%) | clicked {clicked} "
          f"({clicked/sent*100:.0f}%) | submitted {submitted} ({submitted/sent*100:.0f}%) | "
          f"reported {reported}")
    print(f"phishing-prone: {(clicked+submitted)/sent*100:.0f}% (guide) | "
          f"{len({r['email'] for r in rows if r['status'] in ('Clicked Link','Submitted Data')})/sent*100:.0f}% (unique)")


def cmd_events(a):
    if not os.path.exists(DB):
        die(f"database {DB} not found")
    con = sqlite3.connect(DB)
    q = ("SELECT id, email, message, details, time FROM events "
         "WHERE campaign_id = (SELECT MAX(campaign_id) FROM events) ORDER BY id")
    rows = con.execute(q).fetchall()
    for rid, email, msg, details, ts in rows:
        line = f"{fmt(ts)}  {msg:15s} {email or '-':35s}"
        if a.details and details:
            blob = details.encode() if isinstance(details, str) else details
            try:
                d = json.loads(blob.decode())
                payload = d.get("payload", {})
                creds = {k: v for k, v in payload.items() if k not in ("rid",)}
                line += f" -> {json.dumps(creds)}"
            except Exception:
                line += f" -> {blob.decode(errors='replace')[:120]}"
        print(line)


def cmd_report(a):
    s = connect()
    camp = next((c for c in api(s, "GET", "/campaigns/") if c["name"] == CAMPAIGN), None)
    if not camp:
        die("campaign not found — run `phishlab launch`")
    outdir = a.outdir
    os.makedirs(outdir, exist_ok=True)
    rows = camp["results"]
    csv_path = os.path.join(outdir, "campaign_export.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rid", "email", "first_name", "last_name", "status",
                                          "ip", "latitude", "longitude", "send_date",
                                          "reported", "modified_date"])
        w.writeheader()
        for r in rows:
            w.writerow({"rid": r["id"], "email": r["email"], "first_name": r["first_name"],
                        "last_name": r["last_name"], "status": r["status"], "ip": r["ip"] or "",
                        "latitude": r["latitude"], "longitude": r["longitude"],
                        "send_date": r["send_date"], "reported": r["reported"],
                        "modified_date": r["modified_date"]})
    sent = len(rows)
    opened = sum(1 for r in rows if r["status"] in ("Email Opened", "Opened", "Clicked Link", "Submitted Data"))
    clicked = sum(1 for r in rows if r["status"] in ("Clicked Link", "Submitted Data"))
    submitted = sum(1 for r in rows if r["status"] == "Submitted Data")
    reported = sum(1 for r in rows if r["reported"])
    if a.csv_only:
        print(f"csv -> {csv_path}")
        return
    md = f"""# User Security Awareness Report — Phishing Simulation

**Campaign:** {camp['name']} · **Platform:** GoPhish (lab) · **Phish URL:** {PHISH}
**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

## Summary

| Metric | Value |
|---|---|
| Emails sent | {sent} |
| Emails opened | {opened} ({opened/sent*100:.0f}%) |
| Clicked link | {clicked} ({clicked/sent*100:.0f}%) |
| Credentials submitted | {submitted} ({submitted/sent*100:.0f}%) |
| Reported as phishing | {reported} |
| Phishing-prone (guide formula) | {(clicked+submitted)/sent*100:.0f}% |
| Phishing-prone (unique users) | {len({r['email'] for r in rows if r['status'] in ('Clicked Link','Submitted Data')})/sent*100:.0f}% |

## Per-user results

| User | Status | IP |
|---|---|---|
""" + "\n".join(f"| {r['first_name']} {r['last_name']} ({r['email']}) | {r['status']} | {r['ip'] or '-'} |"
                 for r in rows) + """

## Observations & recommendations

- Users should be trained to check the sender address and hover links before clicking.
- Deploy SPF/DKIM/DMARC (`phishlab dns <domain>`) and set DMARC to quarantine/reject.
- Require MFA so captured passwords alone do not grant access.
- Run simulations quarterly and track the phishing-prone trend per team.

*Artifacts: this report, campaign_export.csv, `phishlab` CLI.*
"""
    md_path = os.path.join(outdir, "awareness_report.md")
    with open(md_path, "w") as f:
        f.write(md)
    print(f"csv    -> {csv_path}")
    print(f"report -> {md_path}")


def cmd_dns(a):
    domain = a.domain
    if not domain:
        die("usage: phishlab dns <domain>")
    dig = shutil.which("dig") or die("dig not found")
    def q(txt, query):
        out = subprocess.run([dig, "+short", "TXT", query], capture_output=True, text=True).stdout
        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            return None
        return txt + " | " + " ; ".join(l.strip('"') for l in lines)
    print(f"== SPF   {domain}")
    print("  ", q("spf", domain) or "(no SPF record)")
    print(f"== DMARC {domain}")
    print("  ", q("dmarc", f"_dmarc.{domain}") or "(no DMARC record)")
    for sel in a.selector:
        print(f"== DKIM {sel}._domainkey.{domain}")
        print("  ", q("dkim", f"{sel}._domainkey.{domain}") or "(no DKIM record)")
    print("\ninterpretation:",
          "DMARC reject/quarantine + valid SPF/DKIM => spoofing fails at the server."
          if any("p=reject" in l or "p=quarantine" in l
                 for l in subprocess.run([dig, "+short", "TXT", f"_dmarc.{domain}"],
                                         capture_output=True, text=True).stdout.splitlines())
          else "no strict DMARC policy found — display-name spoofing is likely to land in the inbox.")


def cmd_health(_a):
    ok = True
    checks = [
        ("gophish admin (https 3333)", lambda: requests.get(f"{ADMIN}/login", verify=False, timeout=5).status_code == 200),
        ("phish server (http 8888)", lambda: requests.get(f"{PHISH}/robots.txt", timeout=5).status_code == 200),
        ("mailhog smtp (1025)", lambda: requests.get(f"{MAILHOG}/api/v2/messages", timeout=5).status_code == 200),
        ("mailhog ui (8025)", lambda: requests.get(MAILHOG, timeout=5).status_code == 200),
        ("api key file", lambda: os.path.exists(KEYFILE)),
    ]
    for name, fn in checks:
        try:
            good = fn()
        except Exception:
            good = False
        print(f"[{'ok' if good else 'FAIL'}] {name}")
        ok = ok and good
    sys.exit(0 if ok else 1)


def cmd_reset(_a):
    s = connect()
    for path, names in NAMES.items():
        for item in api(s, "GET", f"/{path}/"):
            if item["name"] in names:
                api(s, "DELETE", f"/{path}/{item['id']}", expect=(200,))
                print(f"[reset] deleted {path}/{item['id']}")
    print("[reset] lab objects removed — `phishlab setup` rebuilds them")


# ------------------------------------------------------------------ main ----
def main():
    p = argparse.ArgumentParser(prog="phishlab", description="GoPhish phishing-simulation lab CLI")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("creds", help="print access details")
    sub.add_parser("setup", help="create sending profile, template, landing page, group")
    sub.add_parser("launch", help="create and launch the campaign")
    pa = sub.add_parser("simulate", help="emulate victim opens/clicks/submissions")
    pa.add_argument("--open", action="store_true", help="apply open to all users")
    pa.add_argument("--click", action="store_true", help="apply click to all users")
    pa.add_argument("--submit", action="store_true", help="apply submit to all users")
    ps = sub.add_parser("status", help="campaign stats and per-user results")
    ps.add_argument("--json", action="store_true", help="machine-readable output")
    pe = sub.add_parser("events", help="event log from the database")
    pe.add_argument("--details", action="store_true", help="include captured data")
    pr = sub.add_parser("report", help="export CSV + awareness report")
    pr.add_argument("--outdir", default="/home/whiterose/Desktop/phi", help="output directory")
    pr.add_argument("--csv-only", action="store_true", help="only write the CSV export")
    pd = sub.add_parser("dns", help="SPF/DKIM/DMARC checks for a domain")
    pd.add_argument("domain", nargs="?", help="domain to check, e.g. example.com")
    pd.add_argument("--selector", action="append", default=["default", "google"],
                    help="DKIM selector(s) to query (repeatable)")
    sub.add_parser("health", help="verify all lab services")
    sub.add_parser("reset", help="delete all lab objects")

    a = p.parse_args()
    if not a.cmd:
        p.print_help()
        return
    {"creds": cmd_creds, "setup": cmd_setup, "launch": cmd_launch, "simulate": cmd_simulate,
     "status": cmd_status, "events": cmd_events, "report": cmd_report, "dns": cmd_dns,
     "health": cmd_health, "reset": cmd_reset}[a.cmd](a)


if __name__ == "__main__":
    main()
