"""Step 1: Flatten the CVE List V5 bulk snapshot into one analysis table.

Input : data/raw/cves.zip  (official CVE Program bulk release, CVEProject/cvelistV5)
Output: data/processed/cve_records.csv.gz

One row per CVE record. Only metadata needed for the paper is kept: dates,
assigner, first affected vendor/product, first CWE, maximum CVSS base score,
the free-text credits (used to detect AI-credited discoveries) and the CISA
ADP SSVC "Exploitation" decision point where present.
"""
import csv
import gzip
import sys
import zipfile
from pathlib import Path

import orjson

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "raw" / "cves.zip"
OUT = ROOT / "data" / "processed" / "cve_records.csv.gz"

FIELDS = [
    "cve_id", "state", "assigner", "date_reserved", "date_published",
    "date_public", "vendor", "product", "cwe", "cvss_max", "ssvc_exploitation",
    "credit_types", "credits", "description",
]


def _cvss_scores(metrics):
    out = []
    for m in metrics or []:
        for key, val in m.items():
            if key.startswith("cvssV") and isinstance(val, dict):
                s = val.get("baseScore")
                if isinstance(s, (int, float)):
                    out.append(float(s))
    return out


def _ssvc(adp_list):
    for adp in adp_list or []:
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        for m in adp.get("metrics") or []:
            other = m.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            for opt in (other.get("content") or {}).get("options") or []:
                if "Exploitation" in opt:
                    return opt["Exploitation"]
    return ""


def _clean(s, n):
    return " ".join(str(s).split())[:n]


def parse(rec):
    meta = rec.get("cveMetadata") or {}
    cont = rec.get("containers") or {}
    cna = cont.get("cna") or {}
    adp = cont.get("adp") or []
    aff = (cna.get("affected") or [{}])
    vendor = aff[0].get("vendor", "") if aff else ""
    product = aff[0].get("product", "") if aff else ""
    cwe = ""
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            if d.get("cweId"):
                cwe = d["cweId"]
                break
        if cwe:
            break
    scores = _cvss_scores(cna.get("metrics"))
    for a in adp:
        scores += _cvss_scores(a.get("metrics"))
    credits = [c.get("value", "") for c in cna.get("credits") or []]
    ctypes = [c.get("type", "") for c in cna.get("credits") or []]
    desc = ""
    for d in cna.get("descriptions") or []:
        if str(d.get("lang", "")).lower().startswith("en"):
            desc = d.get("value", "")
            break
    return {
        "cve_id": meta.get("cveId", ""),
        "state": meta.get("state", ""),
        "assigner": meta.get("assignerShortName", ""),
        "date_reserved": (meta.get("dateReserved") or "")[:10],
        "date_published": (meta.get("datePublished") or "")[:10],
        "date_public": (cna.get("datePublic") or "")[:10],
        "vendor": _clean(vendor, 80),
        "product": _clean(product, 80),
        "cwe": cwe,
        "cvss_max": max(scores) if scores else "",
        "ssvc_exploitation": _ssvc(adp),
        "credit_types": "|".join(t for t in ctypes if t),
        "credits": _clean(" || ".join(credits), 600),
        "description": _clean(desc, 300),
    }


def main():
    if not SRC.exists():
        sys.exit(f"missing {SRC}; run src/s00_fetch_data.sh first")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with zipfile.ZipFile(SRC) as z, gzip.open(OUT, "wt", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for name in z.namelist():
            if not name.endswith(".json") or "/CVE-" not in name:
                continue
            try:
                rec = orjson.loads(z.read(name))
            except Exception:
                continue
            w.writerow(parse(rec))
            n += 1
            if n % 50000 == 0:
                print(f"  {n:,} records", flush=True)
    print(f"wrote {n:,} records -> {OUT}")


if __name__ == "__main__":
    main()
