/*
  heuristics.js (v1.1.0)
  Runs entirely client-side — no API key, no network call, works fully offline.
  Returns a risk contribution (0-100, higher = more suspicious) plus a list
  of human-readable findings that get merged with any external API results.
*/

const SHORTENERS = [
  "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
  "cutt.ly","rb.gy","rebrand.ly","shorturl.at","tiny.cc","s.id"
];

const SUSPICIOUS_TLDS = [
  "zip","mov","top","xyz","click","country","work","support","gq","tk",
  "ml","cf","ga","link","fit","loan","men","review","download","stream"
];

/* Brand keyword -> official registrable domains */
const BRANDS = {
  paypal: ["paypal.com"],
  apple: ["apple.com","icloud.com"],
  microsoft: ["microsoft.com","live.com","office.com","outlook.com","microsoftonline.com"],
  google: ["google.com","gmail.com","youtube.com","goo.gl"],
  amazon: ["amazon.com","amazon.co.uk","amazon.ph","amazonaws.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com","fb.com","meta.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  telegram: ["telegram.org","t.me"],
  linkedin: ["linkedin.com"],
  twitter: ["twitter.com","x.com"],
  coinbase: ["coinbase.com"],
  binance: ["binance.com"],
  metamask: ["metamask.io"],
  dropbox: ["dropbox.com"],
  github: ["github.com"],
  steam: ["steampowered.com","steamcommunity.com"],
  shopee: ["shopee.ph","shopee.com"],
  lazada: ["lazada.com.ph","lazada.com"],
  gcash: ["gcash.com"],
  paymaya: ["maya.ph","paymaya.com"],
  bdo: ["bdo.com.ph"],
  bpi: ["bpi.com.ph"],
  landbank: ["landbank.com"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  usps: ["usps.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  irs: ["irs.gov"],
};

const SENSITIVE_KEYWORDS = [
  "verify","secure","update","confirm","login","signin","account",
  "billing","suspend","unlock","reset","password","wallet","claim","prize"
];

/* Small public-suffix list: multi-label suffixes we must treat as one unit.
   Not exhaustive — covers common ones so example.com.ph / bbc.co.uk parse right. */
const MULTI_SUFFIXES = new Set([
  "co.uk","org.uk","ac.uk","gov.uk","com.au","net.au","org.au","co.nz","co.jp",
  "co.in","com.br","com.mx","com.ar","com.tr","co.za","com.sg","com.my","com.hk",
  "com.ph","net.ph","org.ph","gov.ph","edu.ph","com.cn","com.tw","co.kr","co.id",
  "com.vn","com.pk","com.bd","com.ng","com.eg","co.il","com.sa","com.ua"
]);

function getRegistrable(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last2 = parts.slice(-2).join(".");
  if (MULTI_SUFFIXES.has(last2)) return parts.slice(-3).join(".");
  return last2;
}

function isIpAddress(host) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return true;
  return host.includes(":") && /^[0-9a-f:]+$/i.test(host);
}

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(
        prev[j] + 1, cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = cur;
  }
  return prev[n];
}

/* Undo common look-alike swaps: paypa1 -> paypal, rnicrosoft -> microsoft, g00gle -> google */
function deLeet(s) {
  return s.replace(/rn/g, "m").replace(/vv/g, "w")
          .replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e")
          .replace(/5/g, "s").replace(/\$/g, "s");
}

function detectTyposquat(registrable) {
  const label = registrable.split(".")[0];
  const normalized = deLeet(label);
  const officialSet = new Set(Object.values(BRANDS).flat());
  if (officialSet.has(registrable)) return null;

  for (const brand of Object.keys(BRANDS)) {
    if (brand.length < 4) continue;
    const dist = Math.min(levenshtein(label, brand), levenshtein(normalized, brand));
    const threshold = brand.length >= 7 ? 2 : 1;
    if (dist > 0 && dist <= threshold) return { brand, dist, label };
    // look-alike swap that collapses exactly to the brand (paypa1, g00gle)
    if (label !== brand && normalized === brand) return { brand, dist: 1, label };
  }
  return null;
}

function analyzeUrlLocally(rawUrl) {
  const findings = [];
  let risk = 0;
  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    return {
      risk: 100,
      findings: [{ severity: "high", label: "Malformed URL", detail: "Could not be parsed as a valid URL at all." }],
      host: null, rootDomain: null,
    };
  }

  const host = parsed.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();
  const rootDomain = getRegistrable(host);

  if (parsed.protocol !== "https:") {
    risk += 15;
    findings.push({ severity: "medium", label: "No HTTPS", detail: "Connection isn't encrypted — credentials or data could be intercepted." });
  }

  if (isIpAddress(host)) {
    risk += 30;
    findings.push({ severity: "high", label: "IP address as domain", detail: "Legitimate sites almost never link directly to a bare IP address." });
  }

  if (host.includes("xn--")) {
    risk += 30;
    findings.push({ severity: "high", label: "Punycode domain", detail: "Uses internationalized characters that can visually impersonate a real brand." });
  }

  if (parsed.username || parsed.password) {
    risk += 25;
    findings.push({ severity: "high", label: "Credentials embedded in URL", detail: "Text before '@' is ignored by browsers — often used to disguise the real destination." });
  }

  if (SHORTENERS.some(s => host === s || host.endsWith("." + s))) {
    risk += 15;
    findings.push({ severity: "medium", label: "Shortened link", detail: "Real destination is hidden behind a link shortener." });
  }

  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    risk += 15;
    findings.push({ severity: "medium", label: `Higher-risk TLD (.${tld})`, detail: "This top-level domain sees disproportionately high abuse rates." });
  }

  const extraLabels = host.split(".").length - rootDomain.split(".").length;
  if (!isIpAddress(host) && extraLabels >= 3) {
    risk += 12;
    findings.push({ severity: "medium", label: "Excessive subdomains", detail: `${extraLabels} subdomain levels — often used to bury the real base domain.` });
  }

  // Brand keyword present but domain isn't an official one for that brand
  const officialSet = new Set(Object.values(BRANDS).flat());
  const isOfficial = officialSet.has(rootDomain);
  if (!isOfficial && !isIpAddress(host)) {
    const brandHit = Object.keys(BRANDS).find(b => host.includes(b));
    if (brandHit) {
      risk += 30;
      findings.push({ severity: "high", label: "Possible brand impersonation", detail: `Contains "${brandHit}" but the registered domain (${rootDomain}) doesn't belong to that brand.` });
    } else {
      const typo = detectTyposquat(rootDomain);
      if (typo) {
        risk += 35;
        findings.push({ severity: "high", label: "Typosquatting suspected", detail: `"${typo.label}" closely resembles "${typo.brand}" (edit distance ${typo.dist}).` });
      }
    }
  }

  const sensHit = SENSITIVE_KEYWORDS.filter(k => full.includes(k));
  if (sensHit.length >= 2) {
    risk += 12;
    findings.push({ severity: "medium", label: "Urgency / credential-harvest language", detail: `URL contains: ${sensHit.slice(0, 3).join(", ")}.` });
  }

  if (host.split("-").length - 1 >= 4) {
    risk += 10;
    findings.push({ severity: "low", label: "Heavily hyphenated domain", detail: "Common in auto-generated phishing domains." });
  }
  if (rawUrl.length > 120) {
    risk += 8;
    findings.push({ severity: "low", label: "Unusually long URL", detail: `${rawUrl.length} characters — can be used to hide the true destination.` });
  }

  if (findings.length === 0) {
    findings.push({ severity: "low", label: "No local red flags", detail: "Structure of the URL itself looks unremarkable." });
  }

  return { risk: Math.min(risk, 100), findings, host, rootDomain };
}
