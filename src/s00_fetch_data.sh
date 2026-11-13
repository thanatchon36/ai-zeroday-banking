#!/usr/bin/env bash
# Step 0: download the two public inputs into data/raw/.
#   1. CVE List V5 bulk snapshot (official CVE Program release on GitHub)
#   2. CISA Known Exploited Vulnerabilities catalogue (official CISA GitHub mirror)
# The paper uses the snapshot of 2026-11-12 (CVE) and catalogue version 2026.11.10 (KEV).
# Later downloads give later snapshots; results will differ accordingly.
set -euo pipefail
mkdir -p "$(dirname "$0")/../data/raw"
cd "$(dirname "$0")/../data/raw"
curl -sSL -o kev.json https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json
TAG=$(curl -sSL -o /dev/null -w "%{url_effective}" https://github.com/CVEProject/cvelistV5/releases/latest | sed 's#.*/tag/##')
DAY=$(echo "$TAG" | sed -E 's/cve_([0-9-]+)_.*/\1/')
curl -sSL -o cves_all.zip.zip "https://github.com/CVEProject/cvelistV5/releases/download/${TAG}/${DAY}_all_CVEs_at_midnight.zip.zip"
unzip -o -q cves_all.zip.zip && rm cves_all.zip.zip
echo "downloaded KEV and CVE List V5 (${TAG})"
