# phishlab — Phishing Simulation Lab CLI

**Name:** `phishlab`
**Version:** 1.0
**Location:** `/usr/local/bin/phishlab` (canonical source: `/home/whiterose/Desktop/phi/phishlab.py`)
**Dependencies:** GoPhish v0.12.1 (admin API + phishing server), Mailhog (local mail catcher), Python 3 + `requests`, `sqlite3`, `dig`, `curl`.

## Description

`phishlab` is a command-line tool that automates an entire phishing-simulation
lab. It drives **GoPhish** (the open-source phishing framework) through its REST
API to:

1. build a realistic phishing email (tracking pixel + phishing link),
2. create a credential-capture landing page that redirects victims to the real
   site after submission,
3. send the emails through a local **Mailhog** SMTP server (no real inboxes
   needed),
4. simulate victims opening emails, clicking links and submitting credentials,
5. report exactly what GoPhish recorded — opens, clicks, captured passwords,
   victim IPs and user-agents,
6. generate a user-awareness report (CSV + Markdown),
7. check a domain's SPF/DKIM/DMARC protection.

Everything runs locally on one machine: senders and recipients are fictional
(`*@example.com`), and all mail is swallowed by Mailhog.

## Architecture

```
                ┌────────────────────────────────────────────────┐
   you  ──────► │ phishlab CLI  (/usr/local/bin/phishlab)        │
                │   │  REST API (Bearer key)                     │
                │   ▼                                            │
                │  GoPhish admin server  https://127.0.0.1:3333  │
                │   │  SMTP (localhost:1025)                     │
                │   ▼                                            │
                │  Mailhog (docker)   SMTP :1025  UI :8025       │
                └────────────────────────────────────────────────┘
                                    │ emails contain:
                                    │   link    http://10.0.2.15:8888/?rid=XXXX
                                    │   pixel   http://10.0.2.15:8888/track?rid=XXXX
                                    ▼
                GoPhish phishing server  http://0.0.0.0:8888
                   GET  /track?rid=…   → records "Email Opened"
                   GET  /?rid=…        → serves fake login page, records "Clicked Link"
                   POST /?rid=…        → captures credentials, records "Submitted Data",
                                          redirects to https://www.office.com
                                    ▼
                Data stored in /opt/gophish/gophish.db (SQLite)
                                    ▼
                phishlab status / events / report  ← reads the data back
```

Key facts: the admin UI (browser) lives on `https://127.0.0.1:3333`, the
phishing server on `:8888` (moved off :80 because nginx owns it), Mailhog on
`:1025` (SMTP) and `:8025` (web UI). GoPhish stores its API key in **plaintext**
in the `users` table; `phishlab` uses a Bearer key injected there and mirrored
to `/root/.gophish_api_key`.

## Install (fresh machine)

```bash
# 1. dependencies
apt update && apt install -y curl wget unzip sqlite3 openssl dnsutils python3 python3-pip docker.io
pip install --break-system-packages requests

# 2. GoPhish
mkdir -p /opt/gophish && cd /opt/gophish
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip && chmod +x gophish
# IMPORTANT: if port 80 is busy, edit config.json -> phish_server.listen_url = "0.0.0.0:8888"
./gophish &

# 3. Mailhog
docker run -d --name mailhog --restart unless-stopped -p 1025:1025 -p 8025:8025 mailhog/mailhog

# 4. API key (skip the web-login CSRF dance; key is stored plaintext in the DB)
pkill -x gophish
KEY=$(openssl rand -hex 32)
echo "$KEY" > /root/.gophish_api_key
sqlite3 /opt/gophish/gophish.db "UPDATE users SET api_key='$KEY' WHERE username='admin';"
cd /opt/gophish && nohup ./gophish >> /var/log/gophish.log 2>&1 &

# 5. the tool
cp /path/to/phishlab.py /usr/local/bin/phishlab && chmod +x /usr/local/bin/phishlab
phishlab health
```

## Usage

### Daily loop

```bash
phishlab setup      # (re)build objects: SMTP profile, template, landing page, group
phishlab launch     # create + launch campaign; waits until all emails are sent
phishlab simulate   # emulate victims: opens, clicks, one credential submission
phishlab status     # stats table + rates (also --json for machines)
phishlab events --details   # event timeline incl. captured credentials
phishlab report     # writes campaign_export.csv + awareness_report.md
```

### Support commands

```bash
phishlab health     # verify gophish admin, phish server, mailhog, api key
phishlab dns <domain> [--selector s1 --selector s2]
                    # SPF / DMARC / DKIM checks + interpretation
phishlab reset      # delete all lab objects (setup rebuilds them)
phishlab creds      # print URLs, login, api key
```

### Configuration

Environment variables override the defaults:

| Variable | Default |
|---|---|
| `PHISHLAB_ADMIN` | `https://127.0.0.1:3333` |
| `PHISHLAB_PHISH` | `http://10.0.2.15:8888` |
| `PHISHLAB_MAILHOG` | `http://localhost:8025` |
| `PHISHLAB_DB` | `/opt/gophish/gophish.db` |
| `PHISHLAB_KEYFILE` | `/root/.gophish_api_key` |

Edit `USERS` in the script (or export `PHISHLAB_TARGETS`) to change recipients;
edit `DEFAULT_BEHAVIOR` to change who opens/clicks/submits; change the SMTP
profile host in `cmd_setup` to a real relay (AWS SES / Mailgun / Gmail SMTP)
for live delivery tests.

## What the campaign does

**Email template** ("Password Reset"): a realistic "password expires in 24
hours" email, personalized with `{{.FirstName}}`, linking to `{{.URL}}`, and
carrying the tracking pixel `{{.Tracker}}` (renders a hidden 1-pixel `<img>`
pointing at `/track?rid=…`).

**Landing page** ("Office365 Login"): a Microsoft-365-styled sign-in form.
`capture_credentials: true` makes GoPhish intercept the form POST and log
username + password (plus the visitor's IP and user-agent); `redirect_url`
sends the victim to the real site afterwards.

**Campaign** ("Password Reset Simulation"): launches immediately, one email per
user, each with a unique `rid`. Every interaction is an event in `gophish.db`:

```
Campaign Created → Email Sent → Email Opened → Clicked Link → Submitted Data
```

## Metrics (what the numbers mean)

- **Open rate** = opened / sent
- **Click rate** = clicked / sent
- **Submit rate** = submitted / sent
- **Phishing-prone** = (clicked + submitted) / sent  *(guide formula — counts a
  submitter as both clicked and submitted)*
- **Phishing-prone (unique)** = distinct users who clicked or submitted / sent
- **Report rate** = reported / sent (needs a report channel; 0 in this lab)

## SPF / DKIM / DMARC checks

`phishlab dns <domain>` runs `dig TXT` for the domain's SPF record, `_dmarc.<domain>`
for DMARC, and `[selector]._domainkey.<domain>` for DKIM (default selectors:
`default`, `google`). It then interprets the policy: a DMARC `p=reject` or
`p=quarantine` means spoofing that domain fails at the receiving server; no
DMARC record means display-name spoofing will land in the inbox.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `bind: address already in use` on :3333 | another GoPhish is running — `pkill -x gophish` |
| `bind: address already in use` on :80 | nginx owns :80; re-extract resets config.json → re-apply `"0.0.0.0:8888"` in `phish_server` |
| `phishlab launch` → connection refused | GoPhish is down — restart it, then `phishlab health` |
| `cp: cannot stat ...` | wrong path — the script lives at `/home/whiterose/Desktop/phi/phishlab.py` (root's `~` is `/root`) |
| `/usr/local/bin/python3` hangs | broken build on this box — shebang must stay `#!/usr/bin/python3` |
| `simulate` maps wrong emails | Mailhog API returns newest first; run `simulate` right after `launch` |
| `docker run mailhog` → name conflict | container already exists — it is the running one, no action needed |
| API key rejected | keyfile and DB `users.api_key` must match (plaintext column) |