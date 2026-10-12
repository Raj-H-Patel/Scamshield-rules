"""Builds rules.json = rules_base.json + a fresh phishing-host blocklist.
Run daily by GitHub Actions. Check the feed's terms of use before publishing."""
import json, time, urllib.request
from urllib.parse import urlparse

FEED = "https://openphish.com/feed.txt"      # one phishing URL per line
MAX_HOSTS = 50000

base = json.load(open("rules_base.json"))
trusted = set(base["trustedDomains"])

req = urllib.request.Request(FEED, headers={"User-Agent": "scamshield-rules-builder"})
lines = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "ignore").splitlines()

hosts = set()
for line in lines:
    h = (urlparse(line.strip()).hostname or "").lower()
    if not h or "." not in h:
        continue
    reg = ".".join(h.split(".")[-2:])
    if reg in trusted:           # never block trusted domains
        continue
    hosts.add(h)

base["blockedDomains"] = sorted(hosts)[:MAX_HOSTS]
base["version"] = int(time.strftime("%Y%m%d%H"))   # e.g. 2026101218 (always increases)
json.dump(base, open("rules.json", "w"), separators=(",", ":"))
print(f"rules.json written: {len(base['blockedDomains'])} blocked hosts, version {base['version']}")
