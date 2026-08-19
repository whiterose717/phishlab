# SPF / DKIM / DMARC — Live DNS Checks

Commands from task.txt section 7.1, run against real domains to show what
"well-authenticated" vs "spoofable" looks like.

## 1. SPF — which IPs may send mail for the domain

```bash
dig TXT yourdomain.com | grep "v=spf1"
```

| Domain | SPF record | Meaning |
|---|---|---|
| gmail.com | `v=spf1 redirect=_spf.google.com` | delegate to `_spf.google.com`, which lists `ip4:74.125.0.0/16`, `ip4:209.85.128.0/17`, ... |
| microsoft.com | `v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com ... -all` | complex chain of includes, hard-fail `-all` |
| example.com | `v=spf1 -all` | no sender allowed — hard fail for everyone |

## 2. DMARC — policy when SPF/DKIM fail

```bash
dig TXT _dmarc.yourdomain.com
```

| Domain | DMARC | Policy |
|---|---|---|
| gmail.com | `v=DMARC1; p=none; sp=quarantine; ...` | none (monitor) for the apex, quarantine for subdomains |
| microsoft.com | `v=DMARC1; p=reject; pct=100; rua=...; ruf=...; fo=1` | **reject** 100% of failing mail, aggregate + forensic reports |
| example.com | `v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s` | strict alignment on both DKIM and SPF |

## 3. DKIM — cryptographic signature verification

```bash
dig TXT default._domainkey.yourdomain.com
dig TXT google._domainkey.yourdomain.com
```

| Record | Result |
|---|---|
| `google._domainkey.github.com` | `v=DKIM1; k=rsa; p=<RSA public key>` — a real published DKIM key |
| `default._domainkey.github.com`, `s1._domainkey.amazon.com`, `selector1._domainkey.office.com` | empty — selectors are per-domain, so guessing the selector is part of DKIM testing |

## What this means for the simulation (task.txt section 7.2)

- **Display-name spoofing** ("IT Support <it-support@example.com>") works against
  users who only read the name — that is exactly what this lab's campaign does.
- **Spoofing a DMARC-protected domain fails**: with `p=reject`, receiving servers
  drop mail that fails SPF + DKIM alignment. A simulator must instead use a
  **look-alike domain it owns** (typosquat, e.g. `contoso-secure.com`) and set up
  valid SPF/DKIM/DMARC on *that* domain — the technique used by real attackers
  and, with permission, by authorized red teams.
- **Lab implication**: mail from `it-support@example.com` is only deliverable in
  the lab because Mailhog accepts everything. In a real simulation use your own
  domain + SMTP relay (AWS SES / Mailgun / Gmail SMTP) so delivery passes
  authentication.
