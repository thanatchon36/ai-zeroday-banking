"""Step 4: Empirical analysis of disclosure volume, AI-credited discovery and exploitation.

Inputs : data/processed/cve_ai_flags.csv.gz, data/processed/ai_credited_cves.csv,
         data/processed/kev_panel.csv, data/curated/banking_relevance.csv
Outputs: outputs/tables/*.csv and outputs/key_numbers.json

Every number quoted in the paper is written to key_numbers.json by this script
(or by s06/s07), so the text can be checked against the code.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "data" / "processed"
C = ROOT / "data" / "curated"
T = ROOT / "outputs" / "tables"
T.mkdir(parents=True, exist_ok=True)
SNAPSHOT = pd.Timestamp("2026-11-12")
LAST_FULL_MONTH = "2026-10"
KN = {}


def hhi(counts):
    s = np.asarray(counts, dtype=float)
    s = s / s.sum()
    return float((s ** 2).sum())


def disclosure_volume(f):
    f = f.copy()
    f["y"] = f.date_published.str[:4]
    f["m"] = f.date_published.str[5:7]
    f["ym"] = f.date_published.str[:7]
    annual = f[(f.y >= "2015")].groupby("y").size().rename("cves").to_frame()
    jan_oct = f[(f.m <= "10")].groupby("y").size().rename("cves_jan_oct")
    annual = annual.join(jan_oct)
    annual.to_csv(T / "cve_annual.csv")
    KN["cve_2025_full"] = int(annual.loc["2025", "cves"])
    KN["cve_2026_ytd"] = int(annual.loc["2026", "cves"])
    KN["cve_2025_jan_oct"] = int(annual.loc["2025", "cves_jan_oct"])
    KN["cve_2026_jan_oct"] = int(annual.loc["2026", "cves_jan_oct"])
    KN["cve_growth_jan_oct"] = round(KN["cve_2026_jan_oct"] / KN["cve_2025_jan_oct"], 2)
    KN["cve_2024_full"] = int(annual.loc["2024", "cves"])

    monthly = f[(f.ym >= "2024-01") & (f.ym <= LAST_FULL_MONTH)].groupby("ym").agg(
        cves=("cve_id", "size"),
        ai_tier1=("ai_tier", lambda s: int((s == 1).sum())),
        ai_tier2=("ai_tier", lambda s: int((s == 2).sum())),
        credited=("has_credit", "sum"),
    )
    monthly["ai_any"] = monthly.ai_tier1 + monthly.ai_tier2
    monthly["ai_share_all_pct"] = 100 * monthly.ai_any / monthly.cves
    monthly["ai_share_credited_pct"] = 100 * monthly.ai_any / monthly.credited.replace(0, np.nan)
    monthly.to_csv(T / "cve_monthly_ai.csv")
    KN["cves_oct_2025"] = int(monthly.loc["2025-10", "cves"])
    KN["cves_oct_2026"] = int(monthly.loc["2026-10", "cves"])
    KN["ai_share_credited_oct_2026_pct"] = round(float(monthly.loc["2026-10", "ai_share_credited_pct"]), 1)
    KN["ai_share_all_oct_2026_pct"] = round(float(monthly.loc["2026-10", "ai_share_all_pct"]), 1)
    KN["credit_coverage_2026_pct"] = round(100 * f[f.y == "2026"].has_credit.mean(), 1)

    # Log-linear growth of monthly AI-credited CVEs, 2025-07 .. last full month
    g = monthly.loc["2025-07":LAST_FULL_MONTH, "ai_any"]
    x = np.arange(len(g))
    yv = np.log(g.values + 1)
    sl = stats.linregress(x, yv)
    KN["ai_monthly_growth_pct"] = round(100 * (np.exp(sl.slope) - 1), 1)
    KN["ai_monthly_growth_se"] = round(100 * np.exp(sl.slope) * sl.stderr, 1)
    KN["ai_doubling_months"] = round(np.log(2) / sl.slope, 1)

    vend = {"microsoft": "Microsoft", "Chrome": "Google Chrome", "oracle": "Oracle",
            "apple": "Apple", "mozilla": "Mozilla", "ibm": "IBM", "cisco": "Cisco",
            "redhat": "Red Hat", "apache": "Apache SF", "Linux": "Linux kernel",
            "fortinet": "Fortinet", "palo_alto": "Palo Alto Networks", "sap": "SAP",
            "vmware": "VMware (Broadcom)", "openssl": "OpenSSL"}
    sub = f[f.assigner.isin(vend) & (f.m <= "10") & f.y.isin(["2025", "2026"])]
    tab = sub.groupby(["assigner", "y"]).size().unstack(fill_value=0)
    cred = sub[sub.y == "2026"].groupby("assigner").has_credit.mean() * 100
    ai26 = sub[sub.y == "2026"].groupby("assigner").ai_tier.apply(lambda s: int((s > 0).sum()))
    tab = tab.assign(ratio=(tab["2026"] / tab["2025"]).round(1), credit_pct_2026=cred.round(0),
                     ai_credited_2026=ai26)
    tab.index = [vend[i] for i in tab.index]
    tab = tab.sort_values("2026", ascending=False)
    tab.to_csv(T / "vendor_surge.csv")
    for k in ["Microsoft", "Google Chrome", "Oracle"]:
        KN[f"surge_{k.split()[0].lower()}"] = float(tab.loc[k, "ratio"])
    return monthly


def ai_profile(f, ai):
    ai = ai.copy()
    KN["ai_total"] = len(ai)
    KN["ai_tier1"] = int((ai.ai_tier == 1).sum())
    KN["ai_tier2"] = int((ai.ai_tier == 2).sum())
    KN["ai_2026"] = int((ai.date_published >= "2026-01-01").sum())
    KN["ai_2025"] = int(((ai.date_published >= "2025-01-01") & (ai.date_published < "2026-01-01")).sum())
    KN["ai_first_tier1_date"] = ai[ai.ai_tier == 1].date_published.min()

    dev = ai.assign(developer=ai.ai_developer.str.split("; ")).explode("developer")
    dev_tab = dev.groupby(["developer", "ai_tier"]).size().unstack(fill_value=0)
    dev_tab.columns = [f"tier{c}" for c in dev_tab.columns]
    dev_tab["total"] = dev_tab.sum(axis=1)
    dev_tab = dev_tab.sort_values("total", ascending=False)
    dev_tab.to_csv(T / "ai_by_developer.csv")

    dom = ai.groupby("domain").agg(n=("cve_id", "size"),
                                   tier1=("ai_tier", lambda s: int((s == 1).sum())))
    dom["share_pct"] = (100 * dom.n / dom.n.sum()).round(1)
    dom.sort_values("n", ascending=False).to_csv(T / "ai_by_domain.csv")

    crypto = ai[ai.domain == "Cryptography, TLS & PKI"]
    ct = crypto.groupby("vendor").size().sort_values(ascending=False)
    ct.to_csv(T / "ai_crypto_libraries.csv")
    KN["ai_crypto_total"] = int(len(crypto))
    KN["ai_bouncycastle"] = int(ct.filter(like="Bouncy").sum())
    KN["ai_openssl"] = int(ct.get("OpenSSL", 0))
    KN["ai_wolfssl"] = int(ct.filter(like="wolfSS").sum())

    # Severity comparison (2026 publications, CVSS where present)
    s = f[f.date_published >= "2026-01-01"].copy()
    s["cv"] = pd.to_numeric(s.cvss_max, errors="coerce")
    rows = []
    groups = {"AI-credited (tier 1)": s.ai_tier == 1, "AI-credited (tier 2)": s.ai_tier == 2,
              "Human-credited": (s.has_credit == 1) & (s.ai_tier == 0),
              "All other 2026 CVEs": s.ai_tier == 0}
    for name, mask in groups.items():
        x = s.loc[mask, "cv"].dropna()
        rows.append({"group": name, "n_scored": len(x), "mean_cvss": round(x.mean(), 2),
                     "share_high_pct": round(100 * (x >= 7).mean(), 1),
                     "share_critical_pct": round(100 * (x >= 9).mean(), 1)})
    sev = pd.DataFrame(rows)
    sev.to_csv(T / "ai_severity.csv", index=False)
    a = s.loc[s.ai_tier > 0, "cv"].dropna()
    h = s.loc[(s.has_credit == 1) & (s.ai_tier == 0), "cv"].dropna()
    mw = stats.mannwhitneyu(a, h, alternative="two-sided")
    KN["sev_ai_mean"] = round(a.mean(), 2)
    KN["sev_human_mean"] = round(h.mean(), 2)
    KN["sev_mw_p"] = float(f"{mw.pvalue:.3g}")


def exploitation(kev):
    kev = kev.copy()
    KN["kev_total"] = len(kev)
    KN["kev_unclassified_pct"] = round(100 * (kev.category == "Unclassified").mean(), 1)
    ya = kev.groupby("year_added").size()
    KN["kev_added_2025"] = int(ya.get(2025, 0))
    KN["kev_added_2026_ytd"] = int(ya.get(2026, 0))
    KN["kev_added_2024"] = int(ya.get(2024, 0))

    # Category x year (additions), excluding the back-filled 2021 launch year
    cy = kev[kev.year_added >= 2022].groupby(["category", "year_added"]).size().unstack(fill_value=0)
    cy.to_csv(T / "kev_category_by_year.csv")

    # Vendor concentration of exploitation
    vy = kev.groupby(["year_added", "vendorProject"]).size()
    h = {int(y): round(hhi(vy.loc[y].values), 3) for y in sorted(kev.year_added.unique())}
    pd.Series(h, name="hhi").to_csv(T / "kev_vendor_hhi.csv")
    top = kev[kev.year_added >= 2022].vendorProject.value_counts()
    top10_share = round(100 * top.head(10).sum() / top.sum(), 1)
    KN["kev_top10_vendor_share_pct"] = top10_share
    KN["kev_n_vendors_2022on"] = int(top.size)
    top.head(15).to_csv(T / "kev_top_vendors.csv")

    # Lags (post-launch CVEs only)
    pl = kev[kev.post_launch].copy()
    KN["kev_post_launch_n"] = len(pl)
    KN["kev_post_launch_early_pct"] = round(100 * pl.early_listed.mean(), 1)
    KN["kev_post_launch_median_lag"] = float(pl.lag_days.median())
    # Censoring-robust cohort: publications up to 180 days before snapshot,
    # listings within 180 days of publication.
    cutoff = SNAPSHOT - pd.Timedelta(days=180)
    co = pl[(pd.to_datetime(pl.date_published) <= cutoff) & (pl.lag_days <= 180)].copy()
    lag = co.groupby("year_pub").agg(n=("cveID", "size"),
                                     median_lag=("lag_days", "median"),
                                     p25=("lag_days", lambda x: x.quantile(.25)),
                                     p75=("lag_days", lambda x: x.quantile(.75)),
                                     share_le0_pct=("lag_days", lambda x: round(100 * (x <= 0).mean(), 1)),
                                     share_le7_pct=("lag_days", lambda x: round(100 * (x <= 7).mean(), 1)))
    lag.to_csv(T / "kev_lag_by_year.csv")
    for y in lag.index:
        KN[f"lag_median_{int(y)}"] = float(lag.loc[y, "median_lag"])
        KN[f"lag_le7_{int(y)}"] = float(lag.loc[y, "share_le7_pct"])
    # Trend test on lag (Kendall tau between publication date and lag, within cohort)
    tau = stats.kendalltau(pd.to_datetime(co.date_published).map(pd.Timestamp.toordinal), co.lag_days)
    KN["lag_trend_tau"] = round(tau.statistic, 3)
    KN["lag_trend_p"] = float(f"{tau.pvalue:.3g}")

    # Zero-day proxy counts vs published benchmarks
    zd = pl.groupby("year_pub").early_listed.sum().astype(int)
    bench = pd.DataFrame({"early_listed": zd})
    ext = pd.read_csv(C / "zero_day_benchmarks.csv").set_index("year")
    bench = bench.join(ext, how="left")
    bench.to_csv(T / "zero_day_proxy_benchmark.csv")
    both = bench.dropna(subset=["reported"])
    KN["proxy_years_compared"] = ", ".join(str(int(y)) for y in both.index)
    KN["proxy_mean_abs_pct_error"] = round(float((abs(both.early_listed - both.reported) / both.reported).mean() * 100), 1)
    for y in zd.index:
        KN[f"early_listed_{int(y)}"] = int(zd.loc[y])

    # Category profile and bank-weighted exploitation pressure
    rel = pd.read_csv(C / "banking_relevance.csv").set_index("category")
    prof = pl.groupby("category").agg(n=("cveID", "size"),
                                      early_pct=("early_listed", lambda x: round(100 * x.mean(), 1)),
                                      median_lag=("lag_days", "median"),
                                      ransomware_pct=("ransomware", lambda x: round(100 * x.mean(), 1)))
    prof = prof.join(rel[["weight", "internet_facing"]])
    prof["zero_day_like"] = (prof.n * prof.early_pct / 100).round(0).astype(int)
    prof["pressure"] = prof.n * prof.weight
    prof["pressure_zd"] = prof.zero_day_like * prof.weight
    prof = prof.sort_values("pressure", ascending=False)
    prof.to_csv(T / "kev_category_profile.csv")

    # Sensitivity of the bank-weighted ranking to the weights
    base_rank = prof.pressure.rank(ascending=False)
    rng = np.random.default_rng(20261112)
    taus = []
    for _ in range(2000):
        w = np.clip(prof.weight + rng.uniform(-0.3, 0.3, len(prof)), 0.05, 1.0)
        r = (prof.n * w).rank(ascending=False)
        taus.append(stats.kendalltau(base_rank, r).statistic)
    uni = prof.n.rank(ascending=False)
    KN["weight_sens_tau_median"] = round(float(np.median(taus)), 3)
    KN["weight_sens_tau_p05"] = round(float(np.quantile(taus, 0.05)), 3)
    KN["weight_uniform_tau"] = round(float(stats.kendalltau(base_rank, uni).statistic), 3)
    top3 = list(prof.index[:3])
    KN["pressure_top3"] = "; ".join(top3)

    edge = kev[kev.category == "Enterprise edge & network infrastructure"]
    KN["edge_share_2022_pct"] = round(100 * (edge.year_added == 2022).sum() / (kev.year_added == 2022).sum(), 1)
    KN["edge_share_2026_pct"] = round(100 * (edge.year_added == 2026).sum() / (kev.year_added == 2026).sum(), 1)
    itm = kev[kev.category == "IT management & remote access tools"]
    KN["itmgmt_share_2026_pct"] = round(100 * (itm.year_added == 2026).sum() / (kev.year_added == 2026).sum(), 1)
    aip = kev[kev.category == "AI & automation platforms"]
    KN["ai_platform_kev_n"] = int(len(aip))
    KN["ai_platform_kev_2026"] = int((aip.year_added == 2026).sum())

    # Exploitation intensity: KEV additions per 1,000 new CVEs (by publication year)
    return pl


def ai_to_exploitation(kev, f):
    x = kev[kev.ai_tier > 0][["cveID", "vendorProject", "product", "ai_label", "date_published",
                              "dateAdded", "lag_days", "category"]].sort_values("dateAdded")
    x.to_csv(T / "ai_credited_in_kev.csv", index=False)
    KN["ai_in_kev_n"] = int(len(x))
    KN["ai_in_kev_median_lag"] = float(x.lag_days.median())
    KN["ai_in_kev_tier1"] = int((kev.ai_tier == 1).sum())
    # Exploitation rate of AI-credited vs human-credited CVEs (2023-2026 publications)
    f2 = f[(f.date_published >= "2023-01-01")].copy()
    inkev = set(kev.cveID)
    f2["kev"] = f2.cve_id.isin(inkev)
    ai_rate = f2[f2.ai_tier > 0].kev.mean() * 1000
    hum_rate = f2[(f2.has_credit == 1) & (f2.ai_tier == 0)].kev.mean() * 1000
    all_rate = f2.kev.mean() * 1000
    KN["kev_per_1000_ai"] = round(ai_rate, 1)
    KN["kev_per_1000_human"] = round(hum_rate, 1)
    KN["kev_per_1000_all"] = round(all_rate, 1)
    # Ratio of exploitation to disclosure by publication year
    f["y"] = f.date_published.str[:4]
    ratio = (f[f.y >= "2022"].assign(kev=lambda d: d.cve_id.isin(inkev))
             .groupby("y").kev.agg(["sum", "size"]))
    ratio["kev_per_1000"] = (1000 * ratio["sum"] / ratio["size"]).round(2)
    ratio.to_csv(T / "kev_per_1000_by_year.csv")
    KN["kev_per_1000_2022"] = float(ratio.loc["2022", "kev_per_1000"])
    KN["kev_per_1000_2026"] = float(ratio.loc["2026", "kev_per_1000"])
    # Censoring-robust version: KEV listing within 180 days of publication,
    # cohorts published from 2022 up to 180 days before the snapshot.
    lagmap = dict(zip(kev.loc[kev.post_launch, "cveID"], kev.loc[kev.post_launch, "lag_days"]))
    g = f.copy()
    g["dp"] = pd.to_datetime(g.date_published, errors="coerce")
    g = g[(g.dp >= "2022-01-01") & (g.dp <= SNAPSHOT - pd.Timedelta(days=180))]
    g["k180"] = g.cve_id.map(lagmap) <= 180
    g["half"] = g.dp.dt.year.astype(str) + "H" + ((g.dp.dt.month - 1) // 6 + 1).astype(str)
    hh = g.groupby("half").agg(cves=("cve_id", "size"), kev_within_180d=("k180", "sum"))
    hh["per_1000"] = (1000 * hh.kev_within_180d / hh.cves).round(2)
    hh.to_csv(T / "kev180_per_1000_by_half.csv")
    KN["k180_per1000_2022H1"] = float(hh.loc["2022H1", "per_1000"])
    KN["k180_per1000_2025H2"] = float(hh.loc["2025H2", "per_1000"])
    KN["k180_per1000_2026H1"] = float(hh.loc["2026H1", "per_1000"])
    KN["k180_per1000_mean_2022_2025"] = round(float(hh.loc["2022H1":"2025H2", "per_1000"].mean()), 2)
    for t in (1, 2):
        sub = g[g.ai_tier == t]
        KN[f"k180_ai_tier{t}_n"] = int(len(sub))
        KN[f"k180_ai_tier{t}_kev"] = int(sub.k180.sum())
    lab = kev[kev.ai_tier > 0].ai_label.value_counts()
    KN["ai_in_kev_horizon3"] = int(lab.get("Horizon3.ai", 0))


def main():
    f = pd.read_csv(P / "cve_ai_flags.csv.gz", dtype=str, keep_default_na=False)
    f["ai_tier"] = f.ai_tier.astype(int)
    f["has_credit"] = f.has_credit.astype(int)
    ai = pd.read_csv(P / "ai_credited_cves.csv", dtype=str, keep_default_na=False)
    ai["ai_tier"] = ai.ai_tier.astype(int)
    kev = pd.read_csv(P / "kev_panel.csv")
    KN["snapshot_date"] = str(SNAPSHOT.date())
    KN["cve_published_total"] = len(f)
    disclosure_volume(f)
    ai_profile(f, ai)
    exploitation(kev)
    ai_to_exploitation(kev, f)
    out = ROOT / "outputs" / "key_numbers.json"
    prev = json.loads(out.read_text()) if out.exists() else {}
    prev.update(KN)
    out.write_text(json.dumps(prev, indent=1, default=str))
    print(json.dumps(KN, indent=1, default=str))


if __name__ == "__main__":
    main()
