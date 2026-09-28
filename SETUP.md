# LinkSniffer — Setup Guide (v1.1.0)

**What's new in 1.1.0:** redirect-chain unmasking, typosquat detection, correct handling of domains like `.com.ph` / `.co.uk`, confidence levels, safer rendering (no HTML injection), auto-updating service worker, rate-limited and origin-locked worker.


## The app works right now, with zero setup

Everything in the main app folder is already a complete, functional PWA. Open
`index.html` (or deploy it to GitHub Pages) and it will scan links using
**local heuristics only** — punycode/homograph tricks, IP-as-domain, link
shorteners, brand-impersonation patterns, suspicious TLDs, urgency language,
and more. No API keys, no backend, no internet dependency for this part.

The `worker/` folder is a separate, optional add-on you deploy later to blend
in real threat-intelligence data (Google Safe Browsing, URLhaus, VirusTotal,
domain age). Until you connect it, the app clearly labels results as
"LOCAL ONLY" — nothing is silently missing.

---

## What to prepare (all free)

| # | What | Where to get it |
|---|------|------------------|
| 1 | Google Safe Browsing API key | [Google Cloud Console](https://console.cloud.google.com) → new project → APIs & Services → Library → enable "Safe Browsing API" → Credentials → Create API Key |
| 2 | abuse.ch Auth-Key (covers URLhaus) | [auth.abuse.ch](https://auth.abuse.ch) → register → your profile page shows the Auth-Key |
| 3 | *(optional)* VirusTotal API key | [virustotal.com](https://www.virustotal.com) → sign up → click your profile icon → API Key |
| 4 | Free Cloudflare account | [dash.cloudflare.com](https://dash.cloudflare.com) → sign up (this hosts the proxy that keeps your keys private) |
| 5 | Node.js installed on your machine | only needed once, to run the deploy tool ("Wrangler") |

Note: Safe Browsing's free tier is for non-commercial use — fine for a
personal or portfolio project.

---

## Why there's a separate "worker" folder

Anything in the PWA's own code (`app.js`, etc.) is fully visible to anyone
who opens their browser's dev tools — so API keys can **never** live there.
The `worker/` folder is a small proxy that runs on Cloudflare's free tier,
stores your keys as encrypted secrets, and is the only thing that ever talks
to Google/abuse.ch/VirusTotal directly. Your PWA only ever talks to *your*
worker.

```
   Your phone/browser  →  your Cloudflare Worker  →  Google / URLhaus / VirusTotal
   (no keys here)          (keys live here, hidden)
```

---

## Deploying the worker (do this once you have your keys)

```bash
cd worker
npm install -g wrangler        # one-time install of Cloudflare's CLI
wrangler login                  # opens a browser tab to connect your Cloudflare account

wrangler secret put SAFE_BROWSING_KEY
wrangler secret put URLHAUS_AUTH_KEY
wrangler secret put VIRUSTOTAL_KEY     # optional — skip if you don't have one yet

wrangler deploy
```

Wrangler will print a URL that looks like:
`https://linksniffer-api.<your-subdomain>.workers.dev`

**You can add keys one at a time, whenever you get them** — `worker.js`
already skips any check whose key isn't set, so partial setup works fine.
Re-run `wrangler secret put NAME` any time to add a new one, then
`wrangler deploy` again.

---

## Connecting the app to your worker

Open `app.js` and change this line near the top:

```js
const WORKER_API_URL = null;
```

to:

```js
const WORKER_API_URL = "https://linksniffer-api.<your-subdomain>.workers.dev/scan";
```

That's it — the app will automatically start blending real threat-intel data
into every scan, and the footer/dossier will switch from "LOCAL ONLY" to
"FULL (LOCAL + EXTERNAL)".

---

## Deploying the app itself

Same as your other projects: push the contents of the main folder (not
`worker/`) to a GitHub repo, then Settings → Pages → deploy from branch.
The `worker/` folder deploys separately to Cloudflare and doesn't belong in
the Pages site.

---

## Locking the worker to your site (recommended)

In `worker/wrangler.toml`, uncomment the `[vars]` block and set your GitHub Pages
origin (no path, no trailing slash):

```toml
[vars]
ALLOWED_ORIGIN = "https://yourname.github.io"
```

Then run `wrangler deploy` again. Browsers on other sites will be refused.
The worker also rate-limits each client to 20 scans per minute and refuses
private/internal addresses.

## Updating the app later

The service worker is network-first and auto-reloads when a new version is
detected. When you ship a change, bump `VERSION` in `sw.js` and `APP_VERSION`
in `app.js`, push to GitHub, and installed copies pick it up on next open.
