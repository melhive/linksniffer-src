/*
  LinkSniffer API proxy — deploy this to Cloudflare Workers.
  It is the ONLY thing that ever holds your API keys. The frontend PWA
  never sees them; it just calls this worker's URL.

  Secrets expected (set with `wrangler secret put <NAME>`):
    SAFE_BROWSING_KEY   - Google Safe Browsing API key (required for that check)
    URLHAUS_AUTH_KEY    - abuse.ch Auth-Key (required for that check)
    VIRUSTOTAL_KEY      - VirusTotal API key (optional — skipped if absent)

  Any key you haven't set yet is simply skipped, so you can deploy this
  now and add sources one at a time as you get keys.
*/

const ALLOWED_ORIGIN = "*"; // tighten to your GitHub Pages origin once deployed, e.g. "https://yourname.github.io"

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: corsHeaders() });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const targetUrl = body.url;
    if (!targetUrl || typeof targetUrl !== "string") {
      return json({ error: "Missing 'url'" }, 400);
    }

    let hostname;
    try {
      hostname = new URL(targetUrl).hostname;
    } catch {
      return json({ error: "Invalid URL" }, 400);
    }

    const checks = await Promise.allSettled([
      checkSafeBrowsing(targetUrl, env.SAFE_BROWSING_KEY),
      checkUrlhaus(targetUrl, env.URLHAUS_AUTH_KEY),
      checkVirusTotal(targetUrl, env.VIRUSTOTAL_KEY),
      checkDomainAge(hostname),
    ]);

    const findings = [];
    const sources = [];
    let weightedRisk = 0;
    let weightTotal = 0;

    for (const result of checks) {
      if (result.status !== "fulfilled" || !result.value) continue;
      const { source, weight, risk, finding } = result.value;
      sources.push(source);
      if (finding) findings.push(finding);
      weightedRisk += risk * weight;
      weightTotal += weight;
    }

    const riskScore = weightTotal > 0 ? Math.round(weightedRisk / weightTotal) : 0;

    return json({ riskScore, findings, sources: sources.length ? sources : ["No external sources configured yet"] });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

/* ---------------- Google Safe Browsing ---------------- */
async function checkSafeBrowsing(url, apiKey) {
  if (!apiKey) return null;
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: { clientId: "linksniffer", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  const hit = data.matches && data.matches.length > 0;
  return {
    source: "Google Safe Browsing",
    weight: 3,
    risk: hit ? 100 : 0,
    finding: hit
      ? { severity: "high", label: "Flagged by Google Safe Browsing", detail: data.matches.map(m => m.threatType).join(", ") }
      : null,
  };
}

/* ---------------- abuse.ch URLhaus ---------------- */
async function checkUrlhaus(url, authKey) {
  if (!authKey) return null;
  const res = await fetch("https://urlhaus-api.abuse.ch/v1/url/", {
    method: "POST",
    headers: { "Auth-Key": authKey, "Content-Type": "application/x-www-form-urlencoded" },
    body: "url=" + encodeURIComponent(url),
  });
  if (!res.ok) return null;
  const data = await res.json();
  const hit = data.query_status === "ok";
  return {
    source: "URLhaus",
    weight: 3,
    risk: hit ? 100 : 0,
    finding: hit
      ? { severity: "high", label: "Listed in URLhaus malware database", detail: `Threat type: ${data.threat || "unknown"}.` }
      : null,
  };
}

/* ---------------- VirusTotal (cached lookup only, no submission) ---------------- */
async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return null;
  const id = base64UrlEncode(url);
  const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { "x-apikey": apiKey },
  });
  if (res.status === 404) {
    return { source: "VirusTotal (not yet analyzed)", weight: 0, risk: 0, finding: null };
  }
  if (!res.ok) return null;
  const data = await res.json();
  const stats = data.data?.attributes?.last_analysis_stats;
  if (!stats) return null;
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
  const risk = Math.round(((malicious * 2 + suspicious) / (total * 2)) * 100);
  return {
    source: "VirusTotal",
    weight: 3,
    risk,
    finding: malicious > 0
      ? { severity: "high", label: `${malicious} security vendors flagged this URL`, detail: "Based on VirusTotal's aggregated engine results." }
      : null,
  };
}

function base64UrlEncode(str) {
  return btoa(str).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

/* ---------------- Domain age via RDAP (free, no key required) ---------------- */
async function checkDomainAge(hostname) {
  const root = hostname.split(".").slice(-2).join(".");
  try {
    const res = await fetch(`https://rdap.org/domain/${root}`);
    if (!res.ok) return null;
    const data = await res.json();
    const regEvent = (data.events || []).find(e => e.eventAction === "registration");
    if (!regEvent) return null;
    const ageDays = (Date.now() - new Date(regEvent.eventDate).getTime()) / 86400000;
    let risk = 0;
    let finding = null;
    if (ageDays < 30) {
      risk = 60;
      finding = { severity: "high", label: "Newly registered domain", detail: `Registered ${Math.round(ageDays)} day(s) ago. Freshly created domains are disproportionately used for scams.` };
    } else if (ageDays < 180) {
      risk = 25;
      finding = { severity: "medium", label: "Recently registered domain", detail: `Registered ~${Math.round(ageDays / 30)} month(s) ago.` };
    }
    return { source: "Domain age (RDAP)", weight: 2, risk, finding };
  } catch {
    return null;
  }
}
