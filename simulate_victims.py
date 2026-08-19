#!/usr/bin/env python3
"""
Simulate victim behavior against the GoPhish campaign (lab only):
- fetch the 5 emails from Mailhog (campaign 2)
- exercise tracking pixel (open), landing page (click), credential form (submit)
- verify captured data via the GoPhish DB
"""
import json
import quopri
import re
import subprocess
import sys
import time

import requests

MAILHOG = "http://localhost:8025"
PHISH = "http://10.0.2.15:8888"
DB = "/opt/gophish/gophish.db"

BEHAVIOR = {
    "jane.smith@example.com": ("open", "click", "submit"),
    "john.doe@example.com": ("open", "click"),
    "bob.johnson@example.com": ("open",),
    "alice.williams@example.com": (),
    "charlie.brown@example.com": (),
}
CREDS = {
    "jane.smith@example.com": ("jane.smith@contoso.com", "Summer2026!"),
}


def get_campaign2_messages():
    msgs = requests.get(f"{MAILHOG}/api/v2/messages").json()["items"]
    out = {}
    for m in msgs[:5]:  # newest 5 = current campaign
        h = m["Content"]["Headers"]
        to = re.search(r"<([^>]+)>", h.get("To", [""])[0]).group(1)
        raw = quopri.decodestring(m["Raw"]["Data"].encode()).decode(errors="replace")
        rid = re.findall(r"rid=([A-Za-z0-9]+)", raw)[0].strip()
        out[to] = rid
    return out


def main():
    inbox = get_campaign2_messages()
    print("campaign emails -> rid mapping:")
    for to, rid in inbox.items():
        print(f"  {to}  rid={rid}")

    for to, actions in BEHAVIOR.items():
        rid = inbox[to]
        for act in actions:
            if act == "open":
                r = requests.get(f"{PHISH}/track?rid={rid}",
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                print(f"[open]    {to}: GET /track HTTP {r.status_code}")
            elif act == "click":
                r = requests.get(f"{PHISH}/?rid={rid}",
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                print(f"[click]   {to}: GET / HTTP {r.status_code}")
            elif act == "submit":
                user, pwd = CREDS[to]
                r = requests.post(f"{PHISH}/?rid={rid}",
                                  data={"username": user, "password": pwd},
                                  headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                                  allow_redirects=False)
                print(f"[submit]  {to}: POST / HTTP {r.status_code} "
                      f"(redirect: {r.headers.get('Location', '-')})")
            time.sleep(0.3)

    print("\nwaiting 3s for GoPhish to record events...")
    time.sleep(3)

    # Pull the event log straight from the DB to show what GoPhish captured
    q = """SELECT email, message, CAST(details AS TEXT) FROM events
           WHERE campaign_id = (SELECT MAX(campaign_id) FROM events)
           ORDER BY id;"""
    rows = subprocess.run(["sqlite3", "-separator", " | ", DB, q],
                          capture_output=True, text=True).stdout.strip()
    print("\nGoPhish event log (from gophish.db):")
    print(rows)


if __name__ == "__main__":
    main()