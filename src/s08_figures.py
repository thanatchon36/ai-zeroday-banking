"""Step 8: Publication figures (PDF for LaTeX, PNG for preview).

All figures read only from outputs/tables and data/processed, so they can be
regenerated without re-running the analysis.
"""
import textwrap
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "outputs" / "tables"
P = ROOT / "data" / "processed"
C = ROOT / "data" / "curated"
F = ROOT / "outputs" / "figures"
F.mkdir(parents=True, exist_ok=True)

NAVY, TEAL, ORANGE, RED, GREY, LIGHT = "#1f3b5c", "#2a9d8f", "#e9a03b", "#c4453c", "#8a8f98", "#d9dee5"
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8.5, "axes.titlesize": 9, "axes.labelsize": 8.5,
    "xtick.labelsize": 7.5, "ytick.labelsize": 7.5, "legend.fontsize": 7.5, "axes.spines.top": False,
    "axes.spines.right": False, "axes.grid": True, "grid.color": "#e6e6e6", "grid.linewidth": 0.6,
    "axes.axisbelow": True, "figure.dpi": 150, "savefig.bbox": "tight", "savefig.pad_inches": 0.05,
    "pdf.fonttype": 42,
})
W = 6.3  # text width in inches


def save(fig, name):
    fig.savefig(F / f"{name}.pdf")
    fig.savefig(F / f"{name}.png", dpi=170)
    plt.close(fig)


def wrap(s, n):
    return "\n".join(textwrap.wrap(s, n))


def fig_lifecycle():
    fig, ax = plt.subplots(figsize=(W, 2.9))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 60)
    ax.axis("off")
    stages = [(2, "Bug\nintroduced"), (20, "Discovered"), (38, "Exploited\n(zero-day)"),
              (56, "Disclosed\nand patched"), (74, "Copycat\nexploitation"), (90, "Patch\ndeployed")]
    ax.annotate("", xy=(99, 30), xytext=(1, 30), arrowprops=dict(arrowstyle="-|>", color=NAVY, lw=1.4))
    for x, lab in stages:
        ax.plot([x + 4], [30], "o", color=NAVY, ms=6, zorder=3)
        ax.text(x + 4, 34, lab, ha="center", va="bottom", fontsize=7.5, color=NAVY)
    ax.add_patch(FancyBboxPatch((42, 23.5), 18, 3.5, boxstyle="round,pad=0.2", fc=RED, ec="none", alpha=0.25))
    ax.text(51, 21.5, "zero-day window", ha="center", va="top", fontsize=7, color=RED)
    ax.add_patch(FancyBboxPatch((60, 23.5), 34, 3.5, boxstyle="round,pad=0.2", fc=ORANGE, ec="none", alpha=0.25))
    ax.text(77, 21.5, "n-day window (patch latency)", ha="center", va="top", fontsize=7, color="#9a6614")
    off = [(18, "AI attacker: faster\nbug-finding in\nclosed products"),
           (46, "AI attacker: scaled\ntargeting and\npost-exploitation"),
           (78, "AI attacker: patch\ndiffing, exploit in\nhours not weeks")]
    dfn = [(24, "AI defender: find and\nfix before release\n(pre-emption)"),
           (60, "AI defender: faster\ntriage and patch\nengineering"),
           (94, "AI defender: faster\ndeployment and\ndetection")]
    for x, t in off:
        ax.text(x, 56, t, ha="center", va="top", fontsize=6.8, color=RED,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec=RED, lw=0.6))
    for x, t in dfn:
        ax.text(x, 13, t, ha="center", va="top", fontsize=6.8, color=TEAL,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec=TEAL, lw=0.6))
    save(fig, "fig01_lifecycle")


def fig_cve_volume():
    a = pd.read_csv(T / "cve_annual.csv", dtype={"y": str}).set_index("y")
    m = pd.read_csv(T / "cve_monthly_ai.csv").set_index("ym")
    fig, axes = plt.subplots(1, 2, figsize=(W, 2.5), gridspec_kw={"width_ratios": [1, 1.25]})
    ax = axes[0]
    yrs = a.index.tolist()
    cols = [NAVY] * (len(yrs) - 1) + [ORANGE]
    ax.bar(range(len(yrs)), a.cves / 1000, color=cols, width=0.75)
    ax.set_xticks(range(len(yrs)))
    ax.set_xticklabels([y[2:] for y in yrs])
    ax.set_xlabel("Publication year (20xx)")
    ax.set_ylabel("Published CVEs (thousands)")
    ax.set_title("(a) Annual CVE publications", loc="left")
    ax.text(len(yrs) - 1, a.cves.iloc[-1] / 1000 + 2, "2026\nto 12 Nov", ha="center", va="bottom", fontsize=6.8, color="#9a6614")
    ax.set_ylim(0, a.cves.max() / 1000 * 1.25)
    ax = axes[1]
    x = pd.to_datetime(m.index)
    ax.plot(x, m.cves / 1000, color=NAVY, lw=1.6, marker="o", ms=2.5)
    ax.set_ylabel("CVEs per month (thousands)")
    ax.set_title("(b) Monthly CVE publications, 2024-2026", loc="left")
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%b\n%Y"))
    ax.xaxis.set_major_locator(matplotlib.dates.MonthLocator(bymonth=[1, 7]))
    ax.set_ylim(0, m.cves.max() / 1000 * 1.15)
    fig.tight_layout(w_pad=2)
    save(fig, "fig02_cve_volume")


def fig_vendor_surge():
    v = pd.read_csv(T / "vendor_surge.csv", index_col=0)
    v = v.sort_values("2026")
    fig, ax = plt.subplots(figsize=(W, 3.3))
    y = np.arange(len(v))
    ax.hlines(y, v["2025"], v["2026"], color=LIGHT, lw=3, zorder=1)
    ax.scatter(v["2025"], y, color=GREY, s=22, zorder=2, label="Jan-Oct 2025")
    ax.scatter(v["2026"], y, color=NAVY, s=26, zorder=3, label="Jan-Oct 2026")
    ax.set_xscale("log")
    ax.set_yticks(y)
    ax.set_yticklabels(v.index)
    for yi, (_, r) in zip(y, v.iterrows()):
        ax.text(max(r["2026"], r["2025"]) * 1.25, yi, f"x{r.ratio:.1f}", va="center", fontsize=7, color=NAVY)
    ax.set_xlim(v[["2025", "2026"]].min().min() * 0.6, v[["2025", "2026"]].max().max() * 3.2)
    ax.set_xlabel("CVEs assigned by the vendor's CNA (log scale)")
    ax.legend(loc="lower right", frameon=False)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig03_vendor_surge")


def fig_ai_monthly():
    m = pd.read_csv(T / "cve_monthly_ai.csv").set_index("ym").loc["2025-01":]
    x = np.arange(len(m))
    fig, axes = plt.subplots(2, 1, figsize=(W, 3.6), sharex=True, gridspec_kw={"height_ratios": [1.5, 1]})
    ax = axes[0]
    ax.bar(x, m.ai_tier1, color=NAVY, label="Tier 1: AI model or agent named")
    ax.bar(x, m.ai_tier2, bottom=m.ai_tier1, color=TEAL, label="Tier 2: AI-native organisation credited")
    ax.set_ylabel("AI-credited CVEs")
    ax.set_title("(a) CVEs whose credits name AI systems or AI-native organisations", loc="left")
    ax.legend(frameon=False, loc="upper left")
    ax = axes[1]
    ax.plot(x, m.ai_share_credited_pct, color=ORANGE, marker="o", ms=3, lw=1.5, label="% of CVEs with any credit")
    ax.plot(x, m.ai_share_all_pct, color=GREY, marker="s", ms=2.5, lw=1.2, label="% of all CVEs")
    ax.set_ylabel("Share (%)")
    ax.set_title("(b) AI-credited share (lower bound)", loc="left")
    ax.legend(frameon=False, loc="upper left")
    labs = [pd.Timestamp(i).strftime("%b\n%y") if pd.Timestamp(i).month in (1, 4, 7, 10) else "" for i in m.index]
    ax.set_xticks(x)
    ax.set_xticklabels(labs)
    fig.tight_layout(h_pad=1.0)
    save(fig, "fig04_ai_monthly")


def fig_ai_breakdown():
    d = pd.read_csv(T / "ai_by_developer.csv", index_col=0).head(10).iloc[::-1]
    dm = pd.read_csv(T / "ai_by_domain.csv", index_col=0).iloc[::-1]
    d.index = [("Other AI tools / orgs" if i == "Various" else i) for i in d.index]
    dm.index = [("Other / unclassified" if i == "Other software" else i) for i in dm.index]
    fig, axes = plt.subplots(1, 2, figsize=(W, 3.6), gridspec_kw={"width_ratios": [0.85, 1.15]})
    ax = axes[0]
    y = np.arange(len(d))
    t1 = d.get("tier1", pd.Series(0, index=d.index)).fillna(0)
    t2 = d.get("tier2", pd.Series(0, index=d.index)).fillna(0)
    ax.barh(y, t1, color=NAVY, label="Tier 1")
    ax.barh(y, t2, left=t1, color=TEAL, label="Tier 2")
    ax.set_yticks(y)
    ax.set_yticklabels([wrap(s, 18) for s in d.index])
    ax.set_xlabel("CVEs credited")
    ax.set_title("(a) By developer (top 10)", loc="left")
    ax.legend(frameon=False, loc="lower right")
    ax.grid(axis="y", visible=False)
    ax = axes[1]
    y = np.arange(len(dm))
    colors = [ORANGE if "Cryptography" in s else NAVY for s in dm.index]
    ax.barh(y, dm.n, color=colors)
    ax.set_yticks(y)
    ax.set_yticklabels(dm.index, fontsize=7)
    ax.set_xlabel("CVEs credited")
    ax.set_title("(b) By affected software domain", loc="left")
    ax.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.5)
    save(fig, "fig05_ai_breakdown")


def fig_kev_heatmap():
    cy = pd.read_csv(T / "kev_category_by_year.csv", index_col=0)
    cy = cy.loc[cy.sum(axis=1).sort_values(ascending=False).index]
    fig, ax = plt.subplots(figsize=(W, 3.9))
    shares = cy.div(cy.sum(axis=0), axis=1) * 100
    im = ax.imshow(shares.values, cmap="Blues", aspect="auto", vmin=0, vmax=shares.values.max())
    ax.set_xticks(range(cy.shape[1]))
    ax.set_xticklabels([f"{c}\n(n={int(cy[c].sum())})" if str(c) != "2026" else f"2026 YTD\n(n={int(cy[c].sum())})" for c in cy.columns])
    ax.set_yticks(range(cy.shape[0]))
    ax.set_yticklabels(cy.index)
    for i in range(cy.shape[0]):
        for j in range(cy.shape[1]):
            v = shares.values[i, j]
            ax.text(j, i, f"{v:.0f}%", ha="center", va="center", fontsize=6.8,
                    color="white" if v > shares.values.max() * 0.55 else "#222222")
    ax.grid(False)
    ax.set_xlabel("Year added to the KEV catalogue")
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("Share of the year's additions (%)")
    fig.tight_layout()
    save(fig, "fig06_kev_categories")


def fig_lags():
    kev = pd.read_csv(P / "kev_panel.csv")
    pl = kev[kev.post_launch & kev.year_pub.between(2022, 2026)]
    b = pd.read_csv(T / "zero_day_proxy_benchmark.csv").set_index("year_pub").loc[2022:]
    fig, axes = plt.subplots(1, 2, figsize=(W, 2.6), gridspec_kw={"width_ratios": [1.2, 1]})
    ax = axes[0]
    pal = {2022: GREY, 2023: "#6c8ebf", 2024: TEAL, 2025: NAVY, 2026: ORANGE}
    for yv, g in pl.groupby("year_pub"):
        x = np.sort(np.clip(g.lag_days.values, -30, 365))
        ax.step(x, np.arange(1, len(x) + 1) / len(x), where="post", color=pal[int(yv)], lw=1.4, label=str(int(yv)))
    ax.axvline(7, color=RED, lw=0.8, ls="--")
    ax.text(10, 0.06, "7-day\nzero-day proxy", fontsize=6.8, color=RED, va="bottom")
    ax.set_xlim(-30, 365)
    ax.set_xlabel("Days from CVE publication to KEV listing")
    ax.set_ylabel("Cumulative share")
    ax.set_title("(a) Listing-lag distribution by publication year", loc="left")
    ax.legend(frameon=False, title="CVE year", loc="lower right", title_fontsize=7)
    ax = axes[1]
    x = np.arange(len(b))
    ax.bar(x - 0.2, b.early_listed, width=0.4, color=NAVY, label="KEV early-listed (this paper)")
    ax.bar(x + 0.2, b.reported.fillna(0), width=0.4, color=ORANGE, label="Reported zero-days (industry)")
    for xi, r in zip(x, b.itertuples()):
        if pd.isna(r.reported):
            ax.text(xi + 0.2, 3, "n/a", ha="center", fontsize=6.5, color=GREY, rotation=90)
    ax.set_xticks(x)
    ax.set_xticklabels([str(i) if i != 2026 else "2026\nYTD" for i in b.index])
    ax.set_ylabel("Vulnerabilities")
    ax.set_title("(b) Zero-day proxy vs published counts", loc="left")
    ax.legend(frameon=False, loc="upper left")
    ax.set_ylim(0, max(b.early_listed.max(), b.reported.max()) * 1.35)
    fig.tight_layout(w_pad=2)
    save(fig, "fig07_lags")


def fig_pressure():
    pr = pd.read_csv(T / "kev_category_profile.csv", index_col=0)
    pr = pr.sort_values("pressure")
    fig, ax = plt.subplots(figsize=(W, 3.6))
    y = np.arange(len(pr))
    zd = pr.zero_day_like * pr.weight
    nd = pr.pressure - zd
    ax.barh(y, zd, color=RED, alpha=0.85, label="Zero-day-like (listed within 7 days)")
    ax.barh(y, nd, left=zd, color=NAVY, alpha=0.85, label="Later-listed (n-day)")
    for yi, (_, r) in zip(y, pr.iterrows()):
        ax.text(r.pressure + 1.5, yi, f"w={r.weight:.1f}", va="center", fontsize=6.8, color=GREY)
    ax.set_yticks(y)
    ax.set_yticklabels(pr.index)
    ax.set_xlabel("Bank-weighted exploitation pressure (KEV entries x banking-relevance weight)")
    ax.set_xlim(0, pr.pressure.max() * 1.15)
    ax.legend(frameon=False, loc="lower right")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig08_bank_pressure")


def fig_incidents():
    inc = pd.read_csv(C / "financial_incidents.csv")
    import sys
    sys.path.insert(0, str(ROOT / "src"))
    from s05_cases import vector_class
    inc["vc"] = inc.zero_day.map(vector_class)
    order = ["Zero-day in commercial product", "Supply-chain compromise", "Known (n-day) vulnerability",
             "Non-malicious common-mode failure", "Credentials, fraud or misconfiguration", "Vector not disclosed"]
    cols = [RED, ORANGE, "#6c8ebf", GREY, NAVY, LIGHT]
    fig, ax = plt.subplots(figsize=(W, 2.7))
    rng = np.random.default_rng(3)
    for i, (vc, col) in enumerate(zip(order, cols)):
        g = inc[inc.vc == vc]
        jitter = rng.uniform(-0.18, 0.18, len(g))
        g = g.assign(year=g.year + rng.uniform(-0.28, 0.28, len(g)))
        cb = g.victim_type.isin(["Central bank", "Supervisor"]).to_numpy()
        th = (g.thailand == 1).to_numpy()
        ax.scatter(g.year[~cb & ~th], (i + jitter)[~cb & ~th], color=col, s=30, edgecolor="#333333", lw=0.4, zorder=3)
        ax.scatter(g.year[cb], (i + jitter)[cb], color=col, s=60, marker="D", edgecolor="black", lw=0.8, zorder=4)
        ax.scatter(g.year[th], (i + jitter)[th], color=col, s=60, marker="*", edgecolor="black", lw=0.6, zorder=4)
    ax.set_yticks(range(len(order)))
    ax.set_yticklabels([wrap(o, 26) for o in order])
    ax.invert_yaxis()
    ax.set_xlim(2010, 2026)
    ax.set_xlabel("Year")
    ax.scatter([], [], marker="D", color="white", edgecolor="black", s=40, label="Central bank or supervisor")
    ax.scatter([], [], marker="*", color="white", edgecolor="black", s=60, label="Thailand")
    ax.scatter([], [], marker="o", color="white", edgecolor="black", s=25, label="Other financial victim")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.22), ncol=3)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig09_incidents")


def fig_thai():
    g = pd.read_csv(T / "thai_group_scores.csv")
    fig, axes = plt.subplots(1, 2, figsize=(W, 3.4), gridspec_kw={"width_ratios": [1.05, 1]})
    ax = axes[0]
    size = 30 + 40 * g.systemic_importance
    ax.scatter(g.vulnerability_index, g.target_index, s=size, color=NAVY, alpha=0.75, edgecolor="white", lw=0.8, zorder=3)
    pos = {"Payment FMIs": (2.08, 5.25, "left"), "D-SIBs": (3.41, 5.25, "left"),
           "Central bank IT": (2.15, 4.3, "left"), "SFIs": (3.84, 3.84, "left"),
           "Shared providers": (4.14, 4.5, "left"), "Digital assets": (4.14, 3.5, "left"),
           "PSPs/e-money": (4.47, 3.12, "left"), "Mid banks": (3.52, 3.0, "right"),
           "Virtual banks": (4.45, 2.25, "left"), "Customers": (4.72, 2.76, "center"),
           "Non-bank lenders": (4.14, 1.88, "left"), "Foreign banks": (2.8, 2.3, "left")}
    for _, r in g.iterrows():
        tx, ty, ha = pos[r.short]
        ax.text(tx, ty, r.short, fontsize=6.8, color="#222222", ha=ha, va="center")
    ax.set_xlim(1.6, 5.65)
    ax.set_ylim(1.6, 5.5)
    ax.set_xlabel("Vulnerability index V")
    ax.set_ylabel("Target index T")
    ax.set_title("(a) Target vs vulnerability", loc="left")
    xx = np.linspace(1.6, 5.65, 50)
    for lvl in [0.4, 0.6]:
        ax.plot(xx, 25 * lvl / xx, color=GREY, lw=0.7, ls=":")
        ax.text(5.6, 25 * lvl / 5.6 - 0.16, f"R={lvl}", fontsize=6.5, color=GREY, ha="right")
    ax = axes[1]
    g2 = g.sort_values("risk")
    y = np.arange(len(g2))
    ax.barh(y, g2.risk, color=[RED if r <= 3 else NAVY for r in g2["rank"]], alpha=0.85)
    for yi, (_, r) in zip(y, g2.iterrows()):
        ax.text(r.risk + 0.01, yi, f"P(top 3)={r.p_top3_pct:.0f}%", va="center", fontsize=6.5, color=GREY)
    ax.set_yticks(y)
    ax.set_yticklabels(g2.short)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Risk score R = T x V / 25")
    ax.set_title("(b) Ranking and robustness", loc="left")
    ax.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=1.5)
    save(fig, "fig10_thai_groups")


def fig_sim():
    s = pd.read_csv(T / "sim_scenarios.csv")
    labels = [wrap(x, 22) for x in s.scenario]
    fig, axes = plt.subplots(1, 3, figsize=(W, 3.0))
    specs = [("p_systemic", "(a) P(systemic event)\nper year", True),
             ("p_dsib_compromised", "(b) P(>=1 D-SIB\ncompromised) per year", True),
             ("mean_compromised", "(c) Institutions\ncompromised per year", False)]
    cols = [GREY, NAVY, RED, TEAL, "#8e3b33", "#1e6b62"]
    for ax, (col, title, pct) in zip(axes, specs):
        y = np.arange(len(s))[::-1]
        if col == "mean_compromised":
            v, lo, hi = s[col], s["mean_compromised_lo"], s["mean_compromised_hi"]
        else:
            v, lo, hi = s[col] * 100, s[col + "_lo"] * 100, s[col + "_hi"] * 100
        ax.barh(y, v, color=cols, alpha=0.9, xerr=[v - lo, hi - v], error_kw=dict(lw=0.8, capsize=2))
        ax.set_title(title, loc="left")
        ax.set_yticks(y)
        ax.set_yticklabels(labels if ax is axes[0] else [])
        ax.set_xlabel("%" if pct else "count")
        ax.set_xlim(0, (v.max() if not pct else min(100, v.max())) * 1.18)
        ax.grid(axis="y", visible=False)
    fig.tight_layout(w_pad=0.8)
    save(fig, "fig11_sim_scenarios")


def fig_grid():
    g = pd.read_csv(T / "sim_grid.csv")
    pv = g.pivot(index="beta", columns="m_disc", values="p_systemic") * 100
    pv = pv.sort_index(ascending=False)
    fig, ax = plt.subplots(figsize=(W * 0.72, 3.0))
    im = ax.imshow(pv.values, cmap="OrRd", aspect="auto", vmin=0, vmax=pv.values.max())
    ax.set_xticks(range(pv.shape[1]))
    ax.set_xticklabels([f"x{c:g}" for c in pv.columns])
    ax.set_yticks(range(pv.shape[0]))
    ax.set_yticklabels([f"{b:g}" for b in pv.index])
    for i in range(pv.shape[0]):
        for j in range(pv.shape[1]):
            v = pv.values[i, j]
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=7,
                    color="white" if v > pv.values.max() * 0.6 else "#222222")
    ax.set_xlabel("AI offence multiplier (zero-day discovery and exploitation throughput)")
    ax.set_ylabel("Patch-time factor (1 = today)")
    ax.grid(False)
    cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.set_label("P(systemic event) per year (%)")
    fig.tight_layout()
    save(fig, "fig12_sim_grid")


def main():
    fig_lifecycle()
    fig_cve_volume()
    fig_vendor_surge()
    fig_ai_monthly()
    fig_ai_breakdown()
    fig_kev_heatmap()
    fig_lags()
    fig_pressure()
    fig_incidents()
    fig_thai()
    fig_sim()
    fig_grid()
    print("figures written to", F)


if __name__ == "__main__":
    main()
