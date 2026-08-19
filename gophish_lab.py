#!/usr/bin/env python3
"""
GoPhish lab automation - drives the full phishing-simulation workflow from task.txt
via the GoPhish REST API:
  sending profile (Mailhog) -> template (tracking pixel + {{.URL}}) -> landing page
  (credential capture + redirect) -> user group -> campaign launch.

Authorized lab use only. All recipients are fictional example.com addresses and
all mail is caught by local Mailhog.
"""
import json
import sys
import time
import urllib3
from datetime import datetime, timezone

import requests

urllib3.disable_warnings()

BASE = "https://127.0.0.1:3333"
ADMIN_USER = "admin"
ADMIN_PASS = sys.argv[1] if len(sys.argv) > 1 else ""   # pass the admin password as argv[1]
PHISH_URL = "http://10.0.2.15:8888"   # campaign URL served by the GoPhish phish server

s = requests.Session()
s.verify = False


def get_api_key():
    key = open("/root/.gophish_api_key").read().strip()
    s.headers.update({"Authorization": f"Bearer {key}"})
    r = s.get(f"{BASE}/api/campaigns/")
    print(f"[apikey] bearer auth -> HTTP {r.status_code}")
    if r.status_code != 200:
        sys.exit("API key rejected")
    return key


def api(method, path, payload=None):
    r = s.request(method, f"{BASE}/api{path}", json=payload)
    if r.status_code not in (200, 201):
        print(f"[!] {method} {path} -> HTTP {r.status_code}: {r.text[:400]}")
        sys.exit(1)
    return r.json()


def cleanup():
    """Remove artifacts from previous runs so the script is idempotent."""
    for path, names in (("/smtp/", {"Lab Sender"}),
                        ("/templates/", {"Password Reset"}),
                        ("/pages/", {"Office365 Login"}),
                        ("/groups/", {"Test Users"}),
                        ("/campaigns/", {"Password Reset Simulation"})):
        for item in api("GET", path):
            if item["name"] in names:
                api("DELETE", f"{path}{item['id']}")
                print(f"[cleanup] deleted {path}{item['id']}")


# --------------------------------------------------------------------------
# 4.1 Sending Profile -> Mailhog
# --------------------------------------------------------------------------
def create_sending_profile():
    profile = api("POST", "/smtp/", {
        "name": "Lab Sender",
        "from_address": "IT Support <it-support@example.com>",
        "host": "localhost:1025",
        "ignore_cert_errors": True,
    })
    print(f"[smtp] '{profile['name']}' id={profile['id']}")
    return profile["id"]


# --------------------------------------------------------------------------
# 4.2 Email Template (tracking image + phishing link + personalization)
# --------------------------------------------------------------------------
def create_template():
    html = """<html><head><meta charset="utf-8"></head><body style="font-family:Arial,sans-serif">
<p>Dear {{.FirstName}},</p>
<p>Our records show that your account password is scheduled to <b>expire within 24 hours</b>.</p>
<p>To avoid interruption of your access to email, calendar and files, please
<a href="{{.URL}}">verify your account and reset your password here</a>.</p>
<p>If you did not request this change, contact the IT Service Desk.</p>
<p>Regards,<br/>IT Support Team</p>
{{.Tracker}}
</body></html>"""
    text = ("Dear {{.FirstName}},\n\n"
            "Your account password is scheduled to expire within 24 hours. "
            "Please visit {{.URL}} to reset it.\n\n"
            "Regards, IT Support Team")
    tpl = api("POST", "/templates/", {
        "name": "Password Reset",
        "subject": "Action Required: Password Expiration",
        "html": html,
        "text": text,
    })
    print(f"[template] '{tpl['name']}' id={tpl['id']}")
    return tpl["id"]


# --------------------------------------------------------------------------
# 4.3 Landing Page (Office 365-style credential capture + redirect)
# --------------------------------------------------------------------------
def create_landing_page():
    page_html = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
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
    page = api("POST", "/pages/", {
        "name": "Office365 Login",
        "html": page_html,
        "capture_credentials": True,
        "capture_passwords": True,
        "redirect_url": "https://www.office.com",
    })
    print(f"[page] '{page['name']}' id={page['id']} capture={page['capture_credentials']} "
          f"redirect={page['redirect_url']}")
    return page["id"]


# --------------------------------------------------------------------------
# 4.4 User Group (fictional users)
# --------------------------------------------------------------------------
def create_group():
    users = [
        ("John", "Doe", "john.doe@example.com"),
        ("Jane", "Smith", "jane.smith@example.com"),
        ("Bob", "Johnson", "bob.johnson@example.com"),
        ("Alice", "Williams", "alice.williams@example.com"),
        ("Charlie", "Brown", "charlie.brown@example.com"),
    ]
    targets = [{"first_name": fn, "last_name": ln, "email": em} for fn, ln, em in users]
    grp = api("POST", "/groups/", {"name": "Test Users", "targets": targets})
    print(f"[group] '{grp['name']}' id={grp['id']} targets={len(grp['targets'])}")
    return grp["id"]


# --------------------------------------------------------------------------
# 5. Launch campaign
# --------------------------------------------------------------------------
def launch_campaign(smtp_id, tpl_id, page_id, grp_id):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    camp = api("POST", "/campaigns/", {
        "name": "Password Reset Simulation",
        "template": {"id": tpl_id, "name": "Password Reset"},
        "page": {"id": page_id, "name": "Office365 Login"},
        "smtp": {"id": smtp_id, "name": "Lab Sender"},
        "groups": [{"id": grp_id, "name": "Test Users"}],
        "url": PHISH_URL,
        "launch_date": now,
    })
    print(f"[campaign] '{camp['name']}' id={camp['id']} url={camp['url']}")
    return camp["id"]


def wait_for_completion(camp_id, timeout=90):
    for _ in range(timeout):
        c = api("GET", f"/campaigns/{camp_id}")
        sent = len([r for r in c.get("results", []) if r["status"] != "Event Not Sent"])
        print(f"[campaign] status={c['status']} results={len(c.get('results', []))} sent={sent}")
        if c["status"] in ("Completed", "In Progress") and sent >= 5:
            return c
        time.sleep(2)
    return c


if __name__ == "__main__":
    get_api_key()
    cleanup()
    smtp = create_sending_profile()
    tpl = create_template()
    page = create_landing_page()
    grp = create_group()
    cid = launch_campaign(smtp, tpl, page, grp)
    camp = wait_for_completion(cid)
    with open("/home/whiterose/Desktop/phi/campaign_id.txt", "w") as f:
        f.write(str(cid))
    print("\nDONE. campaign id:", cid)