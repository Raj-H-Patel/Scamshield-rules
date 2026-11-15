// popup.js (v2.0)
const $ = id => document.getElementById(id);
const send = msg => new Promise(res => chrome.runtime.sendMessage(msg, res));

function fmtVersion(v) {
  const s = String(v);
  return s.length >= 8 ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}${s.length > 8 ? " #" + s.slice(8) : ""}` : s;
}

async function renderStatus() {
  const st = await send({ type: "GET_STATUS" });
  if (!st) return;
  const checked = st.checkedAt ? new Date(st.checkedAt).toLocaleString() : "never";
  $("status-text").textContent =
    `v${st.extVersion} · rules ${fmtVersion(st.version)} · ${st.blocked} blocked · checked ${checked}`;
}

document.addEventListener("DOMContentLoaded", async () => {
  // settings
  const { settings = {} } = await chrome.storage.local.get("settings");
  $("opt-warn").checked = settings.showWarnings !== false;
  $("opt-age").checked = settings.domainAgeCheck !== false;
  const save = async () => {
    const cur = (await chrome.storage.local.get("settings")).settings || {};
    await chrome.storage.local.set({
      settings: { ...cur, showWarnings: $("opt-warn").checked, domainAgeCheck: $("opt-age").checked }
    });
  };
  $("opt-warn").addEventListener("change", save);
  $("opt-age").addEventListener("change", save);

  $("btn-update").addEventListener("click", async () => {
    const b = $("btn-update");
    b.disabled = true; b.textContent = "Checking…";
    const r = await send({ type: "UPDATE_RULES" });
    b.textContent = !r ? "Failed" : !r.ok ? r.reason : r.changed ? "Updated ✓" : "Already latest ✓";
    await renderStatus();
    setTimeout(() => { b.disabled = false; b.textContent = "Update now"; }, 2500);
  });
  renderStatus();

  // current tab result
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const result = tab ? await send({ type: "GET_RESULT", tabId: tab.id }) : null;

  $("loading").classList.add("hidden");
  if (!result) { $("empty").classList.remove("hidden"); return; }
  $("result").classList.remove("hidden");

  $("verdict-badge").classList.add(result.verdict);
  $("verdict-text").textContent = result.verdict;
  $("score-text").textContent = result.score;
  $("score-bar-fill").style.width = result.score + "%";
  $("hostname-text").textContent = result.hostname || result.url;

  const list = $("reasons-list");
  list.innerHTML = "";
  const reasons = result.reasons && result.reasons.length ? result.reasons : ["No red flags detected."];
  reasons.forEach(r => { const li = document.createElement("li"); li.textContent = r; list.appendChild(li); });
  $("source-text").textContent = "Source: " + (result.source || "heuristics");

  const act = async type => {
    await send({ type, hostname: result.hostname, url: result.url });
    chrome.tabs.reload(tab.id);
    window.close();
  };
  $("btn-trust").addEventListener("click", () => act("TRUST_SITE"));
  $("btn-report").addEventListener("click", () => act("REPORT_SITE"));
});
