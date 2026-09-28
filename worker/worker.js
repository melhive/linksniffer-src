/*
  LinkSniffer API proxy (v1.1.0) — deploy to Cloudflare Workers.
  The ONLY thing that holds your API keys. The PWA just calls this URL.

  Secrets (set with `wrangler secret put <NAME>`):
    SAFE_BROWSING_KEY   - Google Safe Browsing API key
    URLHAUS_AUTH_KEY    - abuse.ch Auth-Key
    VIRUSTOTAL_KEY      - VirusTotal API key (optional)
  Optional plain variable:
    ALLOWED_ORIGIN      - e.g. https://yourname.github.io  (set in wrangler.toml [vars])

  Any key not set is skipped, so partial setup works.
*/

const MAX_HOPS = 8;
const RATE_LIMIT = 20;          // requests
const RATE_WINDOW_MS = 60_000;  // per minute, per client IP (per isolate)
const hits = new Map();

function corsHeaders(env, request) {
  const allowed = env.ALLOWED_ORIGIN || "*";
  const origin = request.headers.get("Origin") || "";
  const allow = allowed === "*" ? "*" : (origin === allowed ? allowed : allowed);
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

function json(env, request, obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env, request) },
  });
}

function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear(); // keep memory bounded
  return arr.length > RATE_LIMIT;
}

/* Block internal/private targets (SSRF guard) */
function isBlockedHost(host) {
  host = host.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    const [a, b] = host.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  if (host.includes(":")) return true; // block raw IPv6 literals
  return false;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders(env, request) });
    if (request.method !== "POST") return json(env, request, { error: "Method not allowed" }, 405);

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    if (rateLimited(ip)) return json(env, request, { error: "Rate limit exceeded. Try again in a minute." }, 429);

    let body;
    try { body = await request.json(); } catch { return json(env, request, { error: "Invalid JSON body" }, 400); }

    const targetUrl = body && body.url;
    if (!targetUrl || typeof targetUrl !== "string" || targetUrl.length > 2048) {
      return json(env, request, { error: "Missing or invalid 'url'" }, 400);
    }

    let parsed;
    try { parsed = new URL(targetUrl); } catch { return json(env, request, { error: "Invalid URL" }, 400); }
    if (!/^https?:$/.test(parsed.protocol)) return json(env, request, { error: "Only http/https URLs are supported" }, 400);
    if (isBlockedHost(parsed.hostname)) {
      return json(env, request, {
        riskScore: 0, chain: [targetUrl], finalUrl: targetUrl,
        findings: [{ severity: "low", label: "Private/internal address", detail: "Not scanned externally — points at a local or private network." }],
        sources: ["Private address guard"],
      });
    }

    /* 1) Unmask redirects */
    const { chain, finalUrl, error: chainError } = await followRedirects(targetUrl);
    const urlsToCheck = [...new Set([targetUrl, finalUrl])];
    const finalHost = safeHost(finalUrl);

    /* 2) Threat-intel checks on original + final URL */
    const checks = await Promise.allSettled([
      checkSafeBrowsing(urlsToCheck, env.SAFE_BROWSING_KEY),
      checkUrlhaus(urlsToCheck, env.URLHAUS_AUTH_KEY),
      checkVirusTotal(urlsToCheck, env.VIRUSTOTAL_KEY),
      checkDomainAge(finalHost || parsed.hostname),
    ]);

    const findings = [];
    const sources = [];
    let weightedRisk = 0, weightTotal = 0;

    if (chain.length > 1) {
      findings.push({
        severity: chain.length > 3 ? "medium" : "low",
        label: `Redirect chain unmasked (${chain.length - 1} hop${chain.length > 2 ? "s" : ""})`,
        detail: `Final destination: ${finalUrl}`,
      });
      sources.push("Redirect unmasking");
    }
    if (chainError) {
      findings.push({ severity: "low", label: "Redirect trace incomplete", detail: chainError });
    }

    for (const r of checks) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { source, weight, risk, finding } = r.value;
      sources.push(source);
      if (finding) findings.push(finding);
      weightedRisk += risk * weight;
      weightTotal += weight;
    }

    // Redirect-chain length adds a small nudge even without blacklist hits
    const chainNudge = chain.length > 4 ? 15 : chain.length > 2 ? 8 : 0;
    const base = weightTotal > 0 ? Math.round(weightedRisk / weightTotal) : 0;
    const riskScore = Math.min(100, base + chainNudge);

    return json(env, request, {
      riskScore, findings, chain, finalUrl,
      sources: sources.length ? sources : ["No external sources configured yet"],
    });
  },
};

function safeHost(u) { try { return new URL(u).hostname; } catch { return null; } }

/* ---------------- Redirect unmasking ---------------- */
async function followRedirects(startUrl) {
  const chain = [startUrl];
  let current = startUrl;
  try {
    for (let i = 0; i < MAX_HOPS; i++) {
      const host = safeHost(current);
      if (!host || isBlockedHost(host)) return { chain, finalUrl: current, error: "Stopped: redirect led to a private/internal address." };
      let res = await fetch(current, { method: "HEAD", redirect: "manual", headers: { "User-Agent": "LinkSniffer/1.1 (+redirect-trace)" } });
      if (res.status === 405 || res.status === 501) {
        res = await fetch(current, { method: "GET", redirect: "manual", headers: { "User-Agent": "LinkSniffer/1.1 (+redirect-trace)" } });
      }
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("Location");
        if (!loc) break;
        const next = new URL(loc, current).toString();
        if (chain.includes(next)) return { chain, finalUrl: current, error: "Redirect loop detected." };
        chain.push(next);
        current = next;
      } else {
        break;
      }
      if (i === MAX_HOPS - 1) return { chain, finalUrl: current, error: `Stopped after ${MAX_HOPS} hops.` };
    }
  } catch (e) {
    return { chain, finalUrl: current, error: "Could not reach the target to trace redirects (it may be offline or blocking scanners)." };
  }
  return { chain, finalUrl: current };
}

/* ---------------- Google Safe Browsing ---------------- */
async function checkSafeBrowsing(urls, apiKey) {
  if (!apiKey) return null;
  const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: { clientId: "linksniffer", clientVersion: "1.1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map(url => ({ url })),
      },
    }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  const hit = data.matches && data.matches.length > 0;
  return {
    source: "Google Safe Browsing", weight: 3, risk: hit ? 100 : 0,
    finding: hit ? { severity: "high", label: "Flagged by Google Safe Browsing", detail: [...new Set(data.matches.map(m => m.threatType))].join(", ") } : null,
  };
}

/* ---------------- abuse.ch URLhaus ---------------- */
async function checkUrlhaus(urls, authKey) {
  if (!authKey) return null;
  let hit = null;
  for (const url of urls) {
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: { "Auth-Key": authKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: "url=" + encodeURIComponent(url),
    });
    if (!res.ok) continue;
    const data = await res.json();
    if (data.query_status === "ok") { hit = data; break; }
  }
  return {
    source: "URLhaus", weight: 3, risk: hit ? 100 : 0,
    finding: hit ? { severity: "high", label: "Listed in URLhaus malware database", detail: `Threat type: ${hit.threat || "unknown"}.` } : null,
  };
}

/* ---------------- VirusTotal (cached lookup only) ---------------- */
async function checkVirusTotal(urls, apiKey) {
  if (!apiKey) return null;
  let worst = null, seen = false;
  for (const url of urls) {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${base64UrlEncode(url)}`, { headers: { "x-apikey": apiKey } });
    if (res.status === 404) continue;
    if (!res.ok) continue;
    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats;
    if (!stats) continue;
    seen = true;
    const malicious = stats.malicious || 0, suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
    const risk = Math.round(((malicious * 2 + suspicious) / (total * 2)) * 100);
    if (!worst || risk > worst.risk) worst = { risk, malicious };
  }
  if (!seen) return { source: "VirusTotal (no prior report)", weight: 0, risk: 0, finding: null };
  return {
    source: "VirusTotal", weight: 3, risk: worst.risk,
    finding: worst.malicious > 0 ? { severity: "high", label: `${worst.malicious} security vendors flagged this URL`, detail: "Based on VirusTotal's aggregated engine results." } : null,
  };
}

function base64UrlEncode(str) {
  return btoa(str).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/* ---------------- Domain age via RDAP (free, no key) ---------------- */
const MULTI = new Set(["co.uk","org.uk","com.au","co.nz","co.jp","co.in","com.br","com.ph","net.ph","org.ph","com.sg","com.my","com.hk","co.za","com.mx","com.tr","co.id","com.vn"]);
function registrable(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  return MULTI.has(p.slice(-2).join(".")) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}

async function checkDomainAge(hostname) {
  if (!hostname || /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
  try {
    const res = await fetch(`https://rdap.org/domain/${registrable(hostname)}`);
    if (!res.ok) return null;
    const data = await res.json();
    const reg = (data.events || []).find(e => e.eventAction === "registration");
    if (!reg) return null;
    const ageDays = (Date.now() - new Date(reg.eventDate).getTime()) / 86400000;
    let risk = 0, finding = null;
    if (ageDays < 30) {
      risk = 60;
      finding = { severity: "high", label: "Newly registered domain", detail: `Registered ${Math.max(0, Math.round(ageDays))} day(s) ago. Fresh domains are disproportionately used for scams.` };
    } else if (ageDays < 180) {
      risk = 25;
      finding = { severity: "medium", label: "Recently registered domain", detail: `Registered ~${Math.round(ageDays / 30)} month(s) ago.` };
    }
    return { source: "Domain age (RDAP)", weight: 2, risk, finding };
  } catch { return null; }
}
