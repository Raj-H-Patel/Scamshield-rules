# ScamShield v2.0 — Scam Website Detector (Chrome, Manifest V3)

## What changed from v1.1
| Area | v1.1 | v2.0 |
|---|---|---|
| Scanning | page load only | instant URL check on navigation + page scan + auto re-scan for single-page apps and late-loaded login forms |
| Warnings | badge/popup only | full-screen warning (Dangerous) / banner (Suspicious) on the page |
| Rules | hard-coded in JS | `rules.json`, **auto-updated every 6 h** from your server |
| Detection | URL + page heuristics | + typosquatting (`paypa1.com`), brand-in-title mismatch, domain age (RDAP), threat-list blocklist, on-device logistic model |
| Reliability | results lost when service worker slept | results kept in `chrome.storage.session` |
| User control | none | "Trust this site", "Report as scam", settings toggles, "Update now" |
| Permissions | activeTab, scripting, tabs, storage | storage, alarms, webNavigation (less access) |

## Load it
1. `chrome://extensions` → Developer mode → **Load unpacked** → select this folder.
2. Browse normally. It scans automatically; click the icon for details.

## How "upgrade itself" works (be accurate in your viva)
Chrome Manifest V3 **does not allow downloading new code** into an extension. So there are two update channels:
1. **Data updates (automatic, every 6 h):** `background.js` fetches `rules.json` from a URL you control (trusted list, phishing blocklist, brand names, model weights). It validates the file, and only applies it if the version number is higher. No code is executed from it.
2. **Code updates:** publish to the Chrome Web Store (unlisted is fine). Chrome auto-updates installed copies; the extension reloads itself on `onUpdateAvailable`.

### Set up the data channel (10 minutes)
1. Create a public GitHub repo `scamshield-rules`; upload the contents of the `rules-repo/` folder.
2. In GitHub → Actions, run **Update ScamShield rules** once (it then runs every 6 h and rebuilds `rules.json` with a fresh phishing-host list).
3. In `background.js`, replace `YOUR_USERNAME` in `DEFAULTS.rulesUrl` with your GitHub username (URL form: `https://raw.githubusercontent.com/<you>/scamshield-rules/main/rules.json`).
4. Reload the extension, open the popup, click **Update now**: it should say "Updated ✓".

Check the phishing feed's terms of use (OpenPhish's free feed is for non-commercial use) and cite it in your report.

## Detection pipeline
`navigation → URL heuristics (instant) → page features (content.js) → domain age (RDAP) → on-device model → optional backend → verdict`
- Score ≥ 60 Dangerous, ≥ 30 Suspicious, else Safe.
- The on-device model and backend can only **raise** a score (reduces the chance an ML mistake hides a clear red flag).
- **Honest status:** the model weights in `rules.json` are hand-set starter values. To make the ML claim real, train on a labeled dataset using these 15 feature names and publish the weights in `rules.json` → `model`.

## Backend (optional)
If `backendUrl` (default `http://127.0.0.1:8000/predict`) responds, its `score` is blended in. The POST body is the features object (see `content.js`) and the response must be `{ "verdict", "score", "reasons": [] }`. Set `backendUrl` to `""` in settings storage to disable it.

## Privacy
- Page text never leaves your browser.
- Domain age check sends only the domain name to `rdap.org` (toggle in popup).
- The optional backend receives URL + page features.

## Limitations (mention in the report)
- Trusted-list matching is by registrable domain, so abuse of user-content subdomains on trusted sites is not caught.
- Heuristics cause some false positives (e.g. a real site containing a brand word) — hence "Trust this site".
- Blocklist coverage depends on the feed; brand-new phishing sites rely on heuristics.
