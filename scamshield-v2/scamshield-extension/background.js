// background.js  (v2.0) - service worker
//
// Automatic behaviour:
//  * scans every page you open (URL check instantly, page check when it loads)
//  * re-scans on single-page-app navigation
//  * shows warnings on risky pages
//  * keeps its threat rules up to date by itself (alarm every few hours)
//
// "Self-upgrade" = DATA updates (rules.json fetched from your server).
// Chrome forbids downloading new CODE into extensions, so code updates come
// through the Chrome Web Store (see README).

const BUNDLED_RULES_PATH = "rules.json";
const DEFAULTS = {
  backendUrl: "http://127.0.0.1:8000/predict", // set "" to disable
  rulesUrl: "https://raw.githubusercontent.com/Raj-H-Patel/Scamshield-rules/main/rules.json",
  domainAgeCheck: true,   // asks rdap.org how old the domain is (sends only the domain name)
  showWarnings: true,
  updateHours: 6
};
const THRESH = { suspicious: 30, dangerous: 60 };
const AGE_TTL = 7 * 24 * 3600 * 1000;
const AGE_FAIL_TTL = 3600 * 1000;

const MULTI_PART_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
  "com.au", "net.au", "org.au",
  "co.jp", "co.za", "com.br", "com.cn", "com.sg", "co.nz"
]);
const TRUSTED_SUFFIXES = [".gov", ".edu", ".mil", ".gov.in", ".nic.in", ".ac.in", ".edu.in"];
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly"]);

// ---------- helpers ----------
function registrableDomain(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function isLocalHost(host) {
  return (
    host === "localhost" || host.endsWith(".local") ||
    /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  );
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

function deLeet(s) {
  return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s")
          .replace(/rn/g, "m").replace(/vv/g, "w");
}

const sigmoid = x => 1 / (1 + Math.exp(-x));
const clamp01 = x => Math.max(0, Math.min(1, x));

// ---------- settings + rules ----------
async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULTS, ...(settings || {}) };
}

function sanitizeRules(r) {
  if (!r || typeof r !== "object") return null;
  const version = Number(r.version);
  if (!Number.isFinite(version)) return null;
  const list = (x, max = 200000) =>
    Array.isArray(x)
      ? x.filter(s => typeof s === "string" && s.length > 0 && s.length < 256)
         .slice(0, max).map(s => s.toLowerCase().trim())
      : [];
  let model = null;
  if (r.model && typeof r.model === "object" && r.model.weights && Number.isFinite(Number(r.model.bias))) {
    const w = {};
    for (const [k, v] of Object.entries(r.model.weights)) {
      if (Number.isFinite(Number(v))) w[k] = Number(v);
    }
    model = { bias: Number(r.model.bias), weights: w };
  }
  return {
    version,
    trustedDomains: list(r.trustedDomains),
    blockedDomains: list(r.blockedDomains),
    brandTokens: list(r.brandTokens, 500),
    suspiciousTlds: list(r.suspiciousTlds, 500),
    model
  };
}

let rules = null;
let trustedSet = new Set();
let blockedSet = new Set();
let userTrusted = new Set();   // registrable domains the user trusts
let userBlocked = new Set();   // hostnames the user reported

function applyRules(r) {
  rules = r;
  trustedSet = new Set(r.trustedDomains);
  blockedSet = new Set(r.blockedDomains);
}

async function loadRules() {
  const stored = (await chrome.storage.local.get("rules")).rules;
  let bundled = null;
  try {
    const res = await fetch(chrome.runtime.getURL(BUNDLED_RULES_PATH));
    bundled = sanitizeRules(await res.json());
  } catch (e) { /* ignore */ }
  const candidates = [sanitizeRules(stored), bundled].filter(Boolean).sort((a, b) => b.version - a.version);
  applyRules(candidates[0] || {
    version: 0, trustedDomains: [], blockedDomains: [], brandTokens: [], suspiciousTlds: [], model: null
  });
  const u = await chrome.storage.local.get(["userTrusted", "userBlocked"]);
  userTrusted = new Set(u.userTrusted || []);
  userBlocked = new Set(u.userBlocked || []);
}
const ready = loadRules();

async function updateRules() {
  await ready;
  const s = await getSettings();
  if (!s.rulesUrl || s.rulesUrl.includes("YOUR_USERNAME") || !s.rulesUrl.startsWith("https://")) {
    return { ok: false, reason: "Rules URL not configured yet" };
  }
  try {
    const res = await fetch(s.rulesUrl, { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const incoming = sanitizeRules(await res.json());
    if (!incoming) throw new Error("Invalid rules file");
    await chrome.storage.local.set({ rulesCheckedAt: Date.now() });
    if (incoming.version <= rules.version) {
      return { ok: true, changed: false, version: rules.version };
    }
    await chrome.storage.local.set({ rules: incoming, rulesUpdatedAt: Date.now() });
    applyRules(incoming);
    return { ok: true, changed: true, version: incoming.version };
  } catch (e) {
    return { ok: false, reason: String(e.message || e) };
  }
}

async function ensureAlarm() {
  const s = await getSettings();
  const existing = await chrome.alarms.get("rules-update");
  if (!existing) chrome.alarms.create("rules-update", { delayInMinutes: 1, periodInMinutes: Math.max(60, s.updateHours * 60) });
}

// ---------- trust ----------
function isTrusted(host) {
  const reg = registrableDomain(host);
  return trustedSet.has(reg) || TRUSTED_SUFFIXES.some(s => host.endsWith(s));
}

// ---------- URL heuristics ----------
function urlAnalysis(urlString) {
  let score = 0;
  const reasons = [];
  const flags = { isIp: 0, noHttps: 0, badTld: 0, brand: 0, typo: 0, hyphens: 0, depth: 0, len: 0, digitRatio: 0 };
  let url;
  try { url = new URL(urlString); } catch (e) { return { score: 0, reasons, flags }; }

  const host = url.hostname.toLowerCase();
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  flags.len = (host + url.pathname).length;

  if (isIp) { score += 25; flags.isIp = 1; reasons.push("URL uses a raw IP address instead of a domain name"); }
  if (url.protocol !== "https:") { score += 5; flags.noHttps = 1; reasons.push("Site is not served over HTTPS"); }
  if (url.username || url.password) { score += 20; reasons.push("URL contains a username/@ section, often used to hide the real destination"); }

  if (!isIp) {
    const reg = registrableDomain(host);
    const sld = reg.split(".")[0];
    const tokens = host.split(/[.\-]/);
    const brands = rules.brandTokens;
    flags.digitRatio = (host.match(/\d/g) || []).length / host.length;

    const brand = tokens.find(t => brands.includes(t));
    if (brand) {
      score += 30; flags.brand = 1;
      reasons.push(`Domain name imitates a well-known brand ("${brand}") but is not its official site`);
    } else {
      // look-alike spelling: paypa1.com, arnazon.com, gooogle.com
      const parts = sld.split("-");
      const typo = brands.find(b => parts.some(t =>
        t !== b && ((b.length >= 3 && deLeet(t) === b) || (b.length >= 6 && levenshtein(t, b) <= 1))
      ));
      if (typo) {
        score += 25; flags.typo = 1;
        reasons.push(`Domain looks like a misspelling of "${typo}" (typosquatting)`);
      }
    }

    if (host.includes("xn--")) { score += 15; reasons.push("Domain uses lookalike (punycode) characters"); }

    const tld = host.split(".").pop();
    if (rules.suspiciousTlds.includes(tld)) {
      score += 10; flags.badTld = 1;
      reasons.push(`Domain uses a TLD (.${tld}) that is common on throwaway scam sites`);
    }

    const hy = (host.match(/-/g) || []).length;
    flags.hyphens = hy;
    if (hy >= 4) { score += 10; reasons.push("Domain has an unusually high number of hyphens"); }

    const extra = host.split(".").length - reg.split(".").length;
    flags.depth = extra;
    if (extra >= 3) { score += 10; reasons.push("Domain has an unusually deep subdomain structure"); }

    if (SHORTENERS.has(reg)) { score += 10; reasons.push("URL uses a link-shortening service"); }
  }

  if (flags.len > 100) { score += 5; reasons.push("URL path is unusually long"); }
  return { score, reasons, flags };
}

// ---------- page heuristics ----------
function pageAnalysis(f, uflags) {
  let score = 0;
  const reasons = [];
  const flags = { hasPassword: f.passwordFieldCount > 0 ? 1 : 0, titleBrandMismatch: 0 };

  if (flags.hasPassword && f.protocol !== "https:") {
    score += 25; reasons.push("Page asks for a password over an insecure (non-HTTPS) connection");
  }
  if (f.passwordFormExternalAction) {
    score += 30; reasons.push("Login form sends your password to a different website");
  }
  if (f.keywordHits >= 2) {
    score += 15; reasons.push("Page uses urgent account-verification wording typical of phishing");
  }
  if (flags.hasPassword && f.totalLinks > 10 && f.externalLinkRatio > 0.9) {
    score += 10; reasons.push("Login page where almost every link leads to other websites");
  }
  // "PayPal - Log in" on a domain that is not PayPal
  if (flags.hasPassword && f.title) {
    const t = f.title.toLowerCase();
    const brand = rules.brandTokens.find(b => new RegExp("\\b" + b + "\\b").test(t));
    if (brand && !f.hostname.toLowerCase().includes(brand)) {
      score += 20; flags.titleBrandMismatch = 1;
      reasons.push(`Login page is titled with "${brand}" but the site is not ${brand}`);
    }
  }
  return { score, reasons, flags };
}

// ---------- domain age (RDAP) ----------
async function domainAgeDays(reg) {
  const { ageCache = {} } = await chrome.storage.local.get("ageCache");
  const hit = ageCache[reg];
  if (hit && Date.now() - hit.t < (hit.days === null ? AGE_FAIL_TTL : AGE_TTL)) return hit.days;

  let days = null;
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 3000);
  try {
    const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(reg), { signal: ctrl.signal });
    if (res.ok) {
      const j = await res.json();
      const ev = (j.events || []).find(e => e.eventAction === "registration");
      if (ev && ev.eventDate) {
        const d = Math.floor((Date.now() - Date.parse(ev.eventDate)) / 86400000);
        if (Number.isFinite(d) && d >= 0) days = d;
      }
    }
  } catch (e) { /* offline / unsupported TLD */ }
  clearTimeout(timeout);

  ageCache[reg] = { t: Date.now(), days };
  const keys = Object.keys(ageCache);
  if (keys.length > 400) {
    keys.sort((a, b) => ageCache[a].t - ageCache[b].t).slice(0, 100).forEach(k => delete ageCache[k]);
  }
  await chrome.storage.local.set({ ageCache });
  return days;
}

// ---------- on-device model ----------
function modelProbability(m, uf, pf, f, ageDays) {
  if (!m) return null;
  const x = {
    urlLen: clamp01(uf.len / 200),
    digitRatio: clamp01(uf.digitRatio * 2),
    hyphens: clamp01(uf.hyphens / 6),
    subdepth: clamp01(uf.depth / 4),
    isIp: uf.isIp, noHttps: uf.noHttps, badTld: uf.badTld,
    brandInDomain: uf.brand, typosquat: uf.typo,
    hasPassword: pf.hasPassword,
    passwordExternal: f.passwordFormExternalAction ? 1 : 0,
    keywordHits: clamp01((f.keywordHits || 0) / 4),
    extLinkLogin: pf.hasPassword ? clamp01(f.externalLinkRatio || 0) : 0,
    newDomain: ageDays !== null && ageDays < 30 ? 1 : 0,
    titleBrandMismatch: pf.titleBrandMismatch
  };
  let z = m.bias;
  for (const [k, w] of Object.entries(m.weights)) z += w * (x[k] || 0);
  return sigmoid(z);
}

// ---------- backend (optional) ----------
async function getBackendPrediction(url, payload) {
  if (!url) return null;
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 2500);
  try {
    const res = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload), signal: ctrl.signal
    });
    clearTimeout(timeout);
    if (!res.ok) throw new Error("status " + res.status);
    return await res.json();
  } catch (e) {
    clearTimeout(timeout);
    return null;
  }
}

function verdictFor(score) {
  return score >= THRESH.dangerous ? "Dangerous" : score >= THRESH.suspicious ? "Suspicious" : "Safe";
}

// ---------- core: features -> result (no tab side effects) ----------
async function computeResult(features, preliminary = false) {
  await ready;
  const settings = await getSettings();
  const host = (features.hostname || "").toLowerCase();
  const reg = registrableDomain(host);
  let r;

  if (!/^https?:$/.test(features.protocol) || isLocalHost(host)) {
    r = { verdict: "Safe", score: 0, reasons: ["Local or browser-internal page"], source: "local" };
  } else if (userBlocked.has(host)) {
    r = { verdict: "Dangerous", score: 100, reasons: ["You reported this site as a scam"], source: "user-report" };
  } else if (userTrusted.has(reg)) {
    r = { verdict: "Safe", score: 0, reasons: ["You marked this site as trusted"], source: "user-trusted" };
  } else if (blockedSet.has(host)) {
    r = { verdict: "Dangerous", score: 100, reasons: [`Listed as a known phishing site (threat rules v${rules.version})`], source: "threat-list" };
  } else if (isTrusted(host)) {
    r = { verdict: "Safe", score: 0, reasons: ["Recognized, well-known website"], source: "trusted-list" };
  } else {
    const u = urlAnalysis(features.url);
    const p = preliminary ? { score: 0, reasons: [], flags: { hasPassword: 0, titleBrandMismatch: 0 } } : pageAnalysis(features, u.flags);
    const isIp = u.flags.isIp === 1;

    const [ageDays, backend] = preliminary ? [null, null] : await Promise.all([
      settings.domainAgeCheck && !isIp ? domainAgeDays(reg) : Promise.resolve(null),
      getBackendPrediction(settings.backendUrl, features)
    ]);

    let heuristic = u.score + p.score;
    const reasons = [...u.reasons, ...p.reasons];
    if (ageDays !== null) {
      if (ageDays < 30) { heuristic += 25; reasons.push(`Domain was registered only ${ageDays} day(s) ago`); }
      else if (ageDays < 90) { heuristic += 10; reasons.push(`Domain is quite new (${ageDays} days old)`); }
    }

    let score = Math.min(100, heuristic);
    let source = preliminary ? "url-check (page scan pending)" : "heuristics";

    const prob = preliminary ? null : modelProbability(rules.model, u.flags, p.flags, features, ageDays);
    if (prob !== null) {
      const m = Math.round(prob * 100);
      score = Math.max(score, Math.round(0.5 * score + 0.5 * m)); // model can only raise the score
      if (m >= 60) reasons.push(`On-device model rates this page ${m}% likely to be phishing`);
      source = "heuristics+model";
    }

    if (backend && typeof backend.score === "number") {
      score = Math.max(score, Math.min(100, Math.round(backend.score)));
      (backend.reasons || []).forEach(x => typeof x === "string" && reasons.unshift(x));
      source += "+backend";
    }
    r = { verdict: verdictFor(score), score, reasons, source };
  }

  r.url = features.url;
  r.hostname = features.hostname;
  r.preliminary = preliminary;
  r.rulesVersion = rules.version;
  return r;
}

// ---------- tab side effects ----------
function updateBadge(tabId, verdict) {
  const colors = { Safe: "#2ecc71", Suspicious: "#f39c12", Dangerous: "#e74c3c" };
  const text = { Safe: "OK", Suspicious: "!", Dangerous: "!!" };
  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[verdict] || "#999999" }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text: text[verdict] || "" }).catch(() => {});
}

async function analyzeAndStore(features, tabId, preliminary = false) {
  const key = "r" + tabId;
  if (preliminary) {
    const cur = (await chrome.storage.session.get(key))[key];
    if (cur && cur.url === features.url && !cur.preliminary) return;
  }
  const result = await computeResult(features, preliminary);
  await chrome.storage.session.set({ [key]: result });
  updateBadge(tabId, result.verdict);

  if (!preliminary && result.verdict !== "Safe") {
    const s = await getSettings();
    if (s.showWarnings) {
      chrome.tabs.sendMessage(tabId, {
        type: "SHOW_WARNING",
        result: { verdict: result.verdict, score: result.score, reasons: result.reasons.slice(0, 4), hostname: result.hostname }
      }).catch(() => {});
    }
  }
}

function urlOnlyFeatures(urlString) {
  const u = new URL(urlString);
  return {
    url: urlString, hostname: u.hostname, protocol: u.protocol,
    formCount: 0, passwordFieldCount: 0, passwordFormExternalAction: false,
    keywordHits: 0, totalLinks: 0, externalLinkRatio: 0, hasFavicon: true, title: ""
  };
}

// ---------- events ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fromPopup = !sender.tab;

  if (msg.type === "PAGE_FEATURES" && sender.tab && sender.frameId === 0) {
    analyzeAndStore(msg.payload, sender.tab.id).catch(() => {});
    return false;
  }
  if (!fromPopup) return false;

  if (msg.type === "GET_RESULT") {
    chrome.storage.session.get("r" + msg.tabId).then(o => sendResponse(o["r" + msg.tabId] || null));
    return true;
  }
  if (msg.type === "GET_STATUS") {
    (async () => {
      await ready;
      const st = await chrome.storage.local.get(["rulesCheckedAt", "rulesUpdatedAt"]);
      sendResponse({
        version: rules.version, blocked: blockedSet.size,
        checkedAt: st.rulesCheckedAt || null, extVersion: chrome.runtime.getManifest().version
      });
    })();
    return true;
  }
  if (msg.type === "UPDATE_RULES") {
    updateRules().then(sendResponse);
    return true;
  }
  if (msg.type === "TRUST_SITE") {
    (async () => {
      await ready;
      userTrusted.add(registrableDomain(String(msg.hostname).toLowerCase()));
      userBlocked.delete(String(msg.hostname).toLowerCase());
      await chrome.storage.local.set({ userTrusted: [...userTrusted], userBlocked: [...userBlocked] });
      sendResponse({ ok: true });
    })();
    return true;
  }
  if (msg.type === "REPORT_SITE") {
    (async () => {
      await ready;
      const h = String(msg.hostname).toLowerCase();
      userBlocked.add(h);
      userTrusted.delete(registrableDomain(h));
      const { reports = [] } = await chrome.storage.local.get("reports");
      reports.push({ url: String(msg.url).slice(0, 500), hostname: h, label: "scam", time: Date.now() });
      await chrome.storage.local.set({
        userBlocked: [...userBlocked], userTrusted: [...userTrusted], reports: reports.slice(-500)
      });
      sendResponse({ ok: true });
    })();
    return true;
  }
  return false;
});

// Instant URL-only verdict as soon as navigation commits (before the page loads)
chrome.webNavigation.onCommitted.addListener(d => {
  if (d.frameId !== 0) return;
  try { analyzeAndStore(urlOnlyFeatures(d.url), d.tabId, true).catch(() => {}); } catch (e) { /* non-http */ }
});

// Single-page apps change URL without a reload: ask the page to re-scan
chrome.webNavigation.onHistoryStateUpdated.addListener(d => {
  if (d.frameId !== 0) return;
  try { analyzeAndStore(urlOnlyFeatures(d.url), d.tabId, true).catch(() => {}); } catch (e) {}
  chrome.tabs.sendMessage(d.tabId, { type: "RESCAN" }).catch(() => {});
});

chrome.tabs.onRemoved.addListener(tabId => chrome.storage.session.remove("r" + tabId));

// ---------- auto-update ----------
chrome.runtime.onInstalled.addListener(() => { ensureAlarm(); updateRules(); });
chrome.runtime.onStartup.addListener(() => { ensureAlarm(); updateRules(); });
chrome.alarms.onAlarm.addListener(a => { if (a.name === "rules-update") updateRules(); });
// New extension version downloaded by Chrome -> apply it right away
chrome.runtime.onUpdateAvailable.addListener(() => chrome.runtime.reload());
