/* ============================================================
   CONFIG — the only line you need to touch after deploying
   the Cloudflare Worker proxy from the /worker folder.
   See SETUP.md. Leave as null to run on local heuristics only.
   ============================================================ */
const APP_VERSION = "1.1.0";
const WORKER_API_URL = null; // e.g. "https://linksniffer-api.YOURNAME.workers.dev/scan"

/* ---------------- IndexedDB (scan history) ---------------- */
const DB_NAME = "linksniffer";
const STORE = "scans";
let dbPromise = new Promise((resolve, reject) => {
  const req = indexedDB.open(DB_NAME, 1);
  req.onupgradeneeded = () => {
    const db = req.result;
    if (!db.objectStoreNames.contains(STORE)) {
      db.createObjectStore(STORE, { keyPath: "id" });
    }
  };
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

async function saveScan(record) {
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getAllScans() {
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => resolve(req.result.sort((a, b) => b.timestamp - a.timestamp));
    req.onerror = () => reject(req.error);
  });
}

async function clearAllScans() {
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}


/* ---------------- Safe DOM helper (no innerHTML with untrusted data) ---------------- */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return node;
}

/* ---------------- DOM refs ---------------- */
const $ = (id) => document.getElementById(id);
const scanForm = $("scanForm");
const urlInput = $("urlInput");
const scanBtn = $("scanBtn");
const idleState = $("idleState");
const scanningState = $("scanningState");
const resultsState = $("resultsState");
const terminalLog = $("terminalLog");
const reticlePct = $("reticlePct");
const connStatus = $("connStatus");
const footerNote = $("footerNote");

/* ---------------- Tabs ---------------- */
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => { t.classList.remove("active"); t.setAttribute("aria-selected","false"); });
    tab.classList.add("active"); tab.setAttribute("aria-selected","true");
    const name = tab.dataset.tab;
    $("panel-scan").dataset.active = String(name === "scan");
    $("panel-history").dataset.active = String(name === "history");
    if (name === "history") renderHistory();
  });
});

/* ---------------- Connection status ---------------- */
function updateConnStatus() {
  const online = navigator.onLine;
  connStatus.dataset.state = online ? "online" : "offline";
  footerNote.textContent = WORKER_API_URL
    ? (online ? "Local heuristics + external threat intel active." : "Offline — local heuristics only until reconnected.")
    : "Local heuristics active. External threat intel not yet connected (see SETUP.md).";
}
window.addEventListener("online", updateConnStatus);
window.addEventListener("offline", updateConnStatus);
updateConnStatus();

/* ---------------- Terminal scan animation ---------------- */
const SCAN_STEPS = [
  "INITIALIZING TARGET LOCK",
  "NORMALIZING URL",
  "UNMASKING REDIRECT CHAIN",
  "CHECKING DOMAIN STRUCTURE",
  "SCANNING FOR HOMOGRAPH / TYPOSQUAT",
  "CROSS-REFERENCING BLACKLISTS",
  "QUERYING THREAT INTEL SOURCES",
  "SCORING RISK PROFILE",
  "COMPILING DOSSIER",
];

function runTerminalAnimation() {
  terminalLog.replaceChildren();
  reticlePct.textContent = "0%";
  return new Promise((resolve) => {
    let i = 0;
    const total = SCAN_STEPS.length;
    const interval = setInterval(() => {
      if (i >= total) { clearInterval(interval); resolve(); return; }
      const line = document.createElement("div");
      line.className = "line";
      line.style.animationDelay = "0s";
      line.appendChild(el("span", { class: "t", text: `[${String(i+1).padStart(2,"0")}]` }));
      line.appendChild(document.createTextNode(SCAN_STEPS[i] + "..."));
      terminalLog.appendChild(line);
      terminalLog.scrollTop = terminalLog.scrollHeight;
      reticlePct.textContent = Math.round(((i + 1) / total) * 100) + "%";
      i++;
    }, 260);
  });
}

/* ---------------- External worker call ---------------- */
async function fetchExternal(url) {
  if (!WORKER_API_URL) return null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 9000);
  try {
    const res = await fetch(WORKER_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error("worker returned " + res.status);
    return await res.json();
  } catch (e) {
    clearTimeout(timeout);
    console.warn("External scan unavailable:", e.message);
    return null;
  }
}

/* ---------------- Verdict combining ---------------- */
function combineResults(localResult, externalResult) {
  let localRisk = localResult.risk;
  let findings = [...localResult.findings];
  let sources = ["Local heuristics"];
  let chain = [localResult.url];
  let finalUrl = null;

  const hasExternal = !!(externalResult && typeof externalResult.riskScore === "number");

  if (hasExternal) {
    chain = Array.isArray(externalResult.chain) && externalResult.chain.length ? externalResult.chain : chain;
    finalUrl = externalResult.finalUrl || null;

    // Re-run local analysis on the unmasked destination and keep the worse result
    if (finalUrl && finalUrl !== localResult.url) {
      const finalLocal = analyzeUrlLocally(finalUrl);
      if (finalLocal.risk > localRisk) localRisk = finalLocal.risk;
      finalLocal.findings
        .filter(f => f.label !== "No local red flags")
        .forEach(f => findings.push({ ...f, label: "Destination: " + f.label }));
    }
    if (Array.isArray(externalResult.findings)) findings = findings.concat(externalResult.findings);
    if (Array.isArray(externalResult.sources)) sources = sources.concat(externalResult.sources);
  }

  const risk = hasExternal
    ? Math.round(localRisk * 0.35 + externalResult.riskScore * 0.65)
    : localRisk;

  const clamped = Math.max(0, Math.min(100, risk));
  const safety = 100 - clamped;
  let level;
  if (clamped <= 25) level = "safe";
  else if (clamped <= 60) level = "suspicious";
  else level = "malicious";
  // Pattern analysis alone can't prove a link is malicious — require a stronger score without external evidence
  if (!hasExternal && level === "malicious" && clamped < 75) level = "suspicious";

  // Confidence: how much real evidence backs the verdict
  const realSources = sources.filter(s => !/^(Local heuristics|No external|Redirect unmasking)/.test(s) && !/no prior report/i.test(s));
  let confidence = "LOW";
  if (hasExternal && realSources.length >= 2) confidence = "HIGH";
  else if (hasExternal && realSources.length === 1) confidence = "MEDIUM";

  return { risk: clamped, safety, level, findings, sources, external: hasExternal, confidence, chain, finalUrl };
}

/* ---------------- Results rendering ---------------- */
const LEVEL_LABEL = { safe: "NO THREATS DETECTED", suspicious: "SUSPICIOUS", malicious: "MALICIOUS" };

function renderResults(url, combined, localResult) {
  const badge = $("verdictBadge");
  badge.textContent = LEVEL_LABEL[combined.level];
  badge.dataset.level = combined.level;

  $("scoreNum").textContent = combined.safety;
  $("verdictTarget").textContent = url;

  const fill = $("verdictMeterFill");
  fill.style.width = combined.safety + "%";
  fill.dataset.level = combined.level;

  const grid = $("dossierGrid");
  grid.replaceChildren();
  const rows = [
    ["HOST", localResult.host || "—"],
    ["REGISTERED DOMAIN", localResult.rootDomain || "—"],
    ["PROTOCOL", url.startsWith("https") ? "HTTPS" : "HTTP"],
    ["CONFIDENCE", combined.confidence || "LOW"],
    ["SCAN MODE", combined.external ? "FULL (LOCAL + EXTERNAL)" : "LOCAL ONLY"],
    ["SCANNED AT", new Date(combined.timestamp || Date.now()).toLocaleString()],
  ];
  if (combined.finalUrl && combined.finalUrl !== url) rows.push(["FINAL DESTINATION", combined.finalUrl]);
  rows.forEach(([k, v]) => {
    grid.appendChild(el("div", { class: "dossier-item" }, el("span", { class: "k", text: k }), el("span", { class: "v", text: v })));
  });

  // Redirect chain (only when there is more than one hop)
  const chainBox = $("chainBox");
  const chainList = $("chainList");
  chainList.replaceChildren();
  if (combined.chain && combined.chain.length > 1) {
    combined.chain.forEach((u, i) => {
      chainList.appendChild(el("li", {}, el("span", { class: "hop", text: i === 0 ? "START" : (i === combined.chain.length - 1 ? "END" : "HOP " + i) }), el("span", { class: "hopurl", text: u })));
    });
    chainBox.classList.remove("hidden");
  } else {
    chainBox.classList.add("hidden");
  }

  const list = $("findingsList");
  list.replaceChildren();
  combined.findings.forEach(f => {
    list.appendChild(el("li", {}, el("span", { class: "sev " + f.severity }), el("span", { class: "txt" }, el("b", { text: f.label }), el("span", { text: f.detail }))));
  });

  const note = combined.external
    ? `Sources consulted: ${combined.sources.join(", ")}.`
    : `Sources consulted: ${combined.sources.join(", ")}. Confidence is low: only URL-pattern analysis ran. Connect the worker API (see SETUP.md) for real threat-intel cross-checks.`;
  $("sourceNote").textContent = note + " No detection does not guarantee a link is safe.";

  idleState.classList.add("hidden");
  scanningState.classList.add("hidden");
  resultsState.classList.remove("hidden");
}

/* ---------------- History rendering ---------------- */
async function renderHistory(filter = "") {
  const list = $("historyList");
  const empty = $("historyEmpty");
  const scans = await getAllScans();
  $("historyCount").textContent = scans.length;

  const filtered = filter
    ? scans.filter(s => s.url.toLowerCase().includes(filter.toLowerCase()) || s.level.includes(filter.toLowerCase()))
    : scans;

  list.replaceChildren();
  empty.classList.toggle("hidden", filtered.length > 0);

  filtered.forEach(s => {
    const li = el("li", {},
      el("span", { class: "tag " + s.level, text: (LEVEL_LABEL[s.level] || s.level).split(" ")[0] }),
      el("span", { class: "info" },
        el("span", { class: "url", text: s.url }),
        el("span", { class: "meta", text: `${new Date(s.timestamp).toLocaleString()} · safety ${s.safety}%` })
      ));
    li.addEventListener("click", () => {
      document.querySelector('.tab[data-tab="scan"]').click();
      renderResults(s.url, s, s.localResult);
    });
    list.appendChild(li);
  });
}

$("historySearch").addEventListener("input", (e) => renderHistory(e.target.value));
$("clearHistoryBtn").addEventListener("click", async () => {
  if (confirm("Clear all scan history? This cannot be undone.")) {
    await clearAllScans();
    renderHistory();
  }
});

/* ---------------- Scan flow ---------------- */
function normalizeUrl(raw) {
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) raw = "http://" + raw;
  return raw;
}

scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = normalizeUrl(urlInput.value);

  scanBtn.disabled = true;
  idleState.classList.add("hidden");
  resultsState.classList.add("hidden");
  scanningState.classList.remove("hidden");

  const localResult = analyzeUrlLocally(url);
  localResult.url = url;

  const [_, externalResult] = await Promise.all([
    runTerminalAnimation(),
    fetchExternal(url),
  ]);

  const combined = combineResults(localResult, externalResult);

  const record = {
    id: url + "::" + Date.now(),
    url,
    timestamp: Date.now(),
    risk: combined.risk,
    safety: combined.safety,
    level: combined.level,
    findings: combined.findings,
    sources: combined.sources,
    external: combined.external,
    confidence: combined.confidence,
    chain: combined.chain,
    finalUrl: combined.finalUrl,
    localResult,
  };
  await saveScan(record);

  renderResults(url, combined, localResult);
  scanBtn.disabled = false;
});

$("rescanBtn").addEventListener("click", () => {
  resultsState.classList.add("hidden");
  idleState.classList.remove("hidden");
  urlInput.value = "";
  urlInput.focus();
});

renderHistory();

/* ---------------- Service worker (auto-update) ---------------- */
if ("serviceWorker" in navigator) {
  let reloaded = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (reloaded || !navigator.serviceWorker.controller) return;
    reloaded = true;
    if (scanningState.classList.contains("hidden")) location.reload();
  });
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").then(reg => reg.update()).catch(err => console.warn("SW registration failed:", err));
  });
}

document.getElementById("footerVersion").textContent = "v" + APP_VERSION;
