/* ============================================================
   CONFIG — the only line you need to touch after deploying
   the Cloudflare Worker proxy from the /worker folder.
   See SETUP.md. Leave as null to run on local heuristics only.
   ============================================================ */
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
  "RESOLVING HOSTNAME",
  "CHECKING DOMAIN STRUCTURE",
  "SCANNING FOR HOMOGRAPH / PUNYCODE",
  "CROSS-REFERENCING BLACKLISTS",
  "QUERYING THREAT INTEL SOURCES",
  "SCORING RISK PROFILE",
  "COMPILING DOSSIER",
];

function runTerminalAnimation() {
  terminalLog.innerHTML = "";
  reticlePct.textContent = "0%";
  return new Promise((resolve) => {
    let i = 0;
    const total = SCAN_STEPS.length;
    const interval = setInterval(() => {
      if (i >= total) { clearInterval(interval); resolve(); return; }
      const line = document.createElement("div");
      line.className = "line";
      line.style.animationDelay = "0s";
      line.innerHTML = `<span class="t">[${String(i+1).padStart(2,"0")}]</span>${SCAN_STEPS[i]}...`;
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
  let risk, findings = [...localResult.findings], sources = ["Local heuristics"];

  if (externalResult && typeof externalResult.riskScore === "number") {
    // 35% local pattern analysis, 65% real threat-intel signal
    risk = Math.round(localResult.risk * 0.35 + externalResult.riskScore * 0.65);
    if (Array.isArray(externalResult.findings)) findings = findings.concat(externalResult.findings);
    if (Array.isArray(externalResult.sources)) sources = sources.concat(externalResult.sources);
  } else {
    risk = localResult.risk;
  }

  risk = Math.max(0, Math.min(100, risk));
  const safety = 100 - risk;
  let level;
  if (risk <= 25) level = "safe";
  else if (risk <= 60) level = "suspicious";
  else level = "malicious";

  return { risk, safety, level, findings, sources, external: !!externalResult };
}

/* ---------------- Results rendering ---------------- */
function renderResults(url, combined, localResult) {
  const badge = $("verdictBadge");
  badge.textContent = combined.level.toUpperCase();
  badge.dataset.level = combined.level;

  $("scoreNum").textContent = combined.safety;
  $("verdictTarget").textContent = url;

  const fill = $("verdictMeterFill");
  fill.style.width = combined.safety + "%";
  fill.dataset.level = combined.level;

  const grid = $("dossierGrid");
  grid.innerHTML = "";
  const rows = [
    ["HOST", localResult.host || "—"],
    ["PROTOCOL", url.startsWith("https") ? "HTTPS" : "HTTP"],
    ["SCAN MODE", combined.external ? "FULL (LOCAL + EXTERNAL)" : "LOCAL ONLY"],
    ["SCANNED AT", new Date().toLocaleString()],
  ];
  rows.forEach(([k, v]) => {
    const div = document.createElement("div");
    div.className = "dossier-item";
    div.innerHTML = `<span class="k">${k}</span><span class="v">${v}</span>`;
    grid.appendChild(div);
  });

  const list = $("findingsList");
  list.innerHTML = "";
  combined.findings.forEach(f => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="sev ${f.severity}"></span><span class="txt"><b>${f.label}</b><span>${f.detail}</span></span>`;
    list.appendChild(li);
  });

  $("sourceNote").textContent = combined.external
    ? `Sources consulted: ${combined.sources.join(", ")}.`
    : `Sources consulted: ${combined.sources.join(", ")}. Connect the worker API (see SETUP.md) for real-time threat-intel cross-checks.`;

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

  list.innerHTML = "";
  empty.classList.toggle("hidden", filtered.length > 0);

  filtered.forEach(s => {
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="tag ${s.level}">${s.level.toUpperCase()}</span>
      <span class="info">
        <span class="url">${s.url}</span>
        <span class="meta">${new Date(s.timestamp).toLocaleString()} · safety ${s.safety}%</span>
      </span>`;
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

/* ---------------- Service worker ---------------- */
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(err => console.warn("SW registration failed:", err));
  });
}
