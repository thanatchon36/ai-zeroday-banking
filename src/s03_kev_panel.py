"""Step 3: Build the exploitation panel from CISA's Known Exploited Vulnerabilities catalogue.

Input : data/raw/kev.json, data/processed/cve_ai_flags.csv.gz,
        data/curated/kev_category_rules.csv, data/curated/banking_relevance.csv
Output: data/processed/kev_panel.csv

Adds: product category, banking-relevance weight, CVE publication date, the lag
from CVE publication to KEV listing, and a zero-day proxy.

Zero-day proxy. The KEV catalogue opened on 2021-11-03 with a back-filled list,
so lags are only meaningful for CVEs published on or after that date. For those,
a vulnerability listed within 7 days of CVE publication ("early-listed") was in
almost all cases exploited at or before disclosure, i.e. as a zero-day. Section 4
of the paper benchmarks this proxy against published annual zero-day counts.
"""
import json
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
P = ROOT / "data" / "processed"
C = ROOT / "data" / "curated"
KEV_START = pd.Timestamp("2021-11-03")
ZD_WINDOW = 7  # days


def load_rules():
    r = pd.read_csv(C / "kev_category_rules.csv").sort_values("priority")
    return [(row.category, re.compile(row.pattern, re.I)) for row in r.itertuples()]


def categorise(text, rules):
    for cat, rx in rules:
        if rx.search(text):
            return cat
    return None


def main():
    kev = pd.DataFrame(json.load(open(RAW / "kev.json"))["vulnerabilities"])
    rules = load_rules()
    primary = (kev["vendorProject"] + " | " + kev["product"]).tolist()
    backup = kev["vulnerabilityName"].tolist()
    cats = []
    for a, b in zip(primary, backup):
        c = categorise(a, rules) or categorise(b, rules) or "Unclassified"
        cats.append(c)
    kev["category"] = cats
    rel = pd.read_csv(C / "banking_relevance.csv")
    kev = kev.merge(rel[["category", "weight", "internet_facing"]], on="category", how="left")

    cve = pd.read_csv(P / "cve_ai_flags.csv.gz", dtype=str, keep_default_na=False,
                      usecols=["cve_id", "date_reserved", "date_published", "cvss_max",
                               "ai_tier", "ai_label", "has_credit"])
    kev = kev.merge(cve, left_on="cveID", right_on="cve_id", how="left")
    kev["date_added"] = pd.to_datetime(kev["dateAdded"])
    kev["date_pub"] = pd.to_datetime(kev["date_published"], errors="coerce")
    kev["lag_days"] = (kev["date_added"] - kev["date_pub"]).dt.days
    kev["post_launch"] = kev["date_pub"] >= KEV_START
    kev["early_listed"] = kev["post_launch"] & (kev["lag_days"] <= ZD_WINDOW)
    kev["year_added"] = kev["date_added"].dt.year
    kev["year_pub"] = kev["date_pub"].dt.year
    kev["ransomware"] = (kev["knownRansomwareCampaignUse"] == "Known").astype(int)
    kev["cwe_first"] = kev["cwes"].apply(lambda x: x[0] if isinstance(x, list) and x else "")
    kev["ai_tier"] = pd.to_numeric(kev["ai_tier"], errors="coerce").fillna(0).astype(int)
    keep = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "date_published",
            "date_reserved", "lag_days", "post_launch", "early_listed", "year_added", "year_pub",
            "category", "weight", "internet_facing", "ransomware", "cwe_first", "cvss_max",
            "ai_tier", "ai_label"]
    kev[keep].to_csv(P / "kev_panel.csv", index=False)
    print(f"KEV entries: {len(kev):,}; unclassified: {(kev.category == 'Unclassified').sum()}")
    print(kev["category"].value_counts().to_string())
    pl = kev[kev.post_launch]
    print(f"post-launch CVEs: {len(pl):,}; early-listed (<= {ZD_WINDOW} d): {int(pl.early_listed.sum()):,}")
    print("AI-credited CVEs that are in KEV:", int((kev.ai_tier > 0).sum()))


if __name__ == "__main__":
    main()
