// content.js  (v2.0)
// 1. Extracts lightweight page signals and sends them to background.js.
// 2. Re-scans automatically when the page changes (SPA navigation, login
//    form injected late) so nothing is missed.
// 3. Shows a warning banner/overlay when background.js says the page is risky.

const URGENCY_PHRASES = [
  "verify your account", "verify your identity", "confirm your identity",
  "confirm your account", "account has been suspended", "account will be suspended",
  "account has been locked", "unusual activity", "suspicious activity",
  "update your payment", "update your billing", "re-enter your password",
  "your account will be closed", "act now", "within 24 hours"
];

const MULTI_PART_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk",
  "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
  "com.au", "net.au", "org.au",
  "co.jp", "co.za", "com.br", "com.cn", "com.sg", "co.nz"
]);

function registrableDomain(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

function extractPageFeatures() {
  const here = registrableDomain(window.location.hostname);
  const forms = Array.from(document.forms);
  const passwordFields = document.querySelectorAll('input[type="password"]').length;

  const passwordFormExternalAction = forms.some(f => {
    if (!f.querySelector('input[type="password"]')) return false;
    const action = f.getAttribute("action");
    if (!action) return false;
    try {
      const u = new URL(action, window.location.href);
      return /^https?:$/.test(u.protocol) && registrableDomain(u.hostname) !== here;
    } catch (e) { return false; }
  });

  const bodyText = document.body ? document.body.innerText.slice(0, 20000).toLowerCase() : "";
  const keywordHits = URGENCY_PHRASES.filter(k => bodyText.includes(k)).length;

  const links = Array.from(document.links || []).filter(l => /^https?:$/.test(l.protocol));
  const externalLinks = links.filter(l => registrableDomain(l.hostname) !== here);
  const externalLinkRatio = links.length > 0 ? externalLinks.length / links.length : 0;

  return {
    url: window.location.href,
    hostname: window.location.hostname,
    protocol: window.location.protocol,
    formCount: forms.length,
    passwordFieldCount: passwordFields,
    passwordFormExternalAction,
    keywordHits,
    totalLinks: links.length,
    externalLinkRatio: Number(externalLinkRatio.toFixed(2)),
    hasFavicon: !!document.querySelector('link[rel~="icon"]'),
    title: document.title || ""
  };
}

// ---------- sending (only when something meaningful changed) ----------
let lastKey = "";
let sendCount = 0;

function sendFeatures() {
  try {
    const f = extractPageFeatures();
    const key = JSON.stringify([f.url, f.passwordFieldCount, f.formCount, f.keywordHits, f.passwordFormExternalAction, f.title]);
    if (key === lastKey) return;
    lastKey = key;
    sendCount++;
    chrome.runtime.sendMessage({ type: "PAGE_FEATURES", payload: f }).catch(() => {});
  } catch (e) { /* extension reloaded or page restricted - ignore */ }
}

sendFeatures();

// Re-scan when the DOM changes (debounced, and stops after a while so it never
// burns CPU on busy pages).
let timer = null;
const observer = new MutationObserver(() => {
  clearTimeout(timer);
  timer = setTimeout(() => {
    if (sendCount >= 15) { observer.disconnect(); return; }
    sendFeatures();
  }, 800);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
setTimeout(() => observer.disconnect(), 60000);

// ---------- warning UI ----------
let dismissed = new Set();

function removeWarning() {
  const old = document.getElementById("scamshield-warning-host");
  if (old) old.remove();
}

function showWarning(info) {
  if (dismissed.has(info.verdict + location.href)) return;
  removeWarning();

  const host = document.createElement("div");
  host.id = "scamshield-warning-host";
  host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;pointer-events:none;";
  const root = host.attachShadow({ mode: "closed" });

  const danger = info.verdict === "Dangerous";
  const style = document.createElement("style");
  style.textContent = `
    *{box-sizing:border-box;font-family:"Segoe UI",Roboto,Arial,sans-serif}
    .overlay{pointer-events:auto;position:fixed;inset:0;background:rgba(18,20,28,.97);color:#f0f0f5;
      display:flex;align-items:center;justify-content:center;padding:24px}
    .card{max-width:520px;width:100%;background:#1b1e2b;border:2px solid #e74c3c;border-radius:14px;padding:28px}
    h1{margin:0 0 8px;font-size:24px;color:#e74c3c}
    p{margin:0 0 12px;font-size:14px;color:#c3c3d1;line-height:1.5}
    ul{margin:0 0 18px;padding-left:20px;font-size:13px;color:#b3b3c6;line-height:1.6}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    button{cursor:pointer;border:0;border-radius:8px;padding:10px 16px;font-size:14px;font-weight:600}
    .safe{background:#2ecc71;color:#08210f}
    .ghost{background:transparent;color:#9a9ab0;border:1px solid #3a3d52}
    .banner{pointer-events:auto;position:fixed;top:0;left:0;right:0;background:#f39c12;color:#2b1a00;
      padding:10px 16px;display:flex;align-items:center;gap:12px;font-size:14px}
    .banner span{flex:1}
    .banner button{background:#2b1a00;color:#fff;padding:6px 12px}
  `;
  root.appendChild(style);

  const reasons = (info.reasons || []).slice(0, 4);

  if (danger) {
    const overlay = document.createElement("div");
    overlay.className = "overlay";
    const card = document.createElement("div");
    card.className = "card";
    const h1 = document.createElement("h1");
    h1.textContent = "⚠️ Dangerous website";
    const p = document.createElement("p");
    p.textContent = `ScamShield thinks ${info.hostname} may be a scam or phishing site (risk score ${info.score}/100). Don't enter passwords, OTPs or payment details here.`;
    const ul = document.createElement("ul");
    reasons.forEach(r => { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); });
    const row = document.createElement("div");
    row.className = "row";
    const back = document.createElement("button");
    back.className = "safe";
    back.textContent = "Take me to safety";
    back.onclick = () => { if (history.length > 1) history.back(); else location.href = "about:blank"; };
    const go = document.createElement("button");
    go.className = "ghost";
    go.textContent = "Continue anyway";
    go.onclick = () => { dismissed.add(info.verdict + location.href); removeWarning(); };
    row.append(back, go);
    card.append(h1, p, ul, row);
    overlay.appendChild(card);
    root.appendChild(overlay);
  } else {
    const banner = document.createElement("div");
    banner.className = "banner";
    const span = document.createElement("span");
    span.textContent = `⚠️ ScamShield: this site looks suspicious${reasons[0] ? " — " + reasons[0] : ""}. Be careful with personal info.`;
    const x = document.createElement("button");
    x.textContent = "Dismiss";
    x.onclick = () => { dismissed.add(info.verdict + location.href); removeWarning(); };
    banner.append(span, x);
    root.appendChild(banner);
  }

  document.documentElement.appendChild(host);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SHOW_WARNING") showWarning(msg.result);
  if (msg.type === "RESCAN") { lastKey = ""; sendCount = 0; setTimeout(sendFeatures, 600); }
});
