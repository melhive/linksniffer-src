/*
  heuristics.js
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

const BRAND_KEYWORDS = [
  "paypal","apple","microsoft","google","amazon","netflix","facebook",
  "instagram","bank","chase","wellsfargo","dhl","fedex","usps","irs",
  "coinbase","binance","icloud","outlook","office365"
];

const SENSITIVE_KEYWORDS = [
  "verify","secure","update","confirm","login","signin","account",
  "billing","suspend","unlock","reset","password"
];

function isIpAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[0-9a-f:]+$/i.test(host) && host.includes(":");
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
      host: null,
    };
  }

  const host = parsed.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();

  // Protocol
  if (parsed.protocol !== "https:") {
    risk += 15;
    findings.push({ severity: "medium", label: "No HTTPS", detail: "Connection isn't encrypted — credentials or data could be intercepted." });
  }

  // IP address as host
  if (isIpAddress(host)) {
    risk += 30;
    findings.push({ severity: "high", label: "IP address as domain", detail: "Legitimate sites almost never link directly to a bare IP address." });
  }

  // Punycode / homograph
  if (host.includes("xn--")) {
    risk += 30;
    findings.push({ severity: "high", label: "Punycode domain", detail: "Uses internationalized characters that can visually impersonate a real brand (e.g. а vs a)." });
  }

  // @ symbol trick
  if (rawUrl.includes("@") && rawUrl.indexOf("@") < rawUrl.indexOf(host)) {
    risk += 25;
    findings.push({ severity: "high", label: "'@' in URL", detail: "Everything before '@' is ignored by browsers — often used to disguise the real destination." });
  }

  // URL shortener
  if (SHORTENERS.some(s => host === s || host.endsWith("." + s))) {
    risk += 15;
    findings.push({ severity: "medium", label: "Shortened link", detail: "Real destination is hidden behind a link shortener." });
  }

  // Suspicious TLD
  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    risk += 15;
    findings.push({ severity: "medium", label: `Higher-risk TLD (.${tld})`, detail: "This top-level domain sees disproportionately high abuse rates." });
  }

  // Excessive subdomains
  const labelCount = host.split(".").length;
  if (labelCount >= 5) {
    risk += 12;
    findings.push({ severity: "medium", label: "Excessive subdomains", detail: `${labelCount} domain labels — often used to bury the real base domain.` });
  }

  // Brand keyword not on the real brand domain
  const rootDomain = host.split(".").slice(-2).join(".");
  const brandHit = BRAND_KEYWORDS.find(b => host.includes(b));
  if (brandHit && !rootDomain.startsWith(brandHit)) {
    risk += 30;
    findings.push({ severity: "high", label: "Possible brand impersonation", detail: `Contains "${brandHit}" but the domain doesn't belong to that brand.` });
  }

  // Sensitive action keywords
  const sensHit = SENSITIVE_KEYWORDS.filter(k => full.includes(k));
  if (sensHit.length >= 2) {
    risk += 12;
    findings.push({ severity: "medium", label: "Urgency / credential-harvest language", detail: `Path or query contains: ${sensHit.slice(0,3).join(", ")}.` });
  }

  // Excessive length / hyphens
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
