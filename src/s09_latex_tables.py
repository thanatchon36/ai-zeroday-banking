"""Step 9: Write LaTeX tables for the paper from outputs/tables and data/curated.

Output: paper/tables/*.tex (booktabs). The paper \\input{}s these files, so the
numbers in tables always match the code outputs.
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "outputs" / "tables"
C = ROOT / "data" / "curated"
OUT = ROOT / "paper" / "tables"
OUT.mkdir(parents=True, exist_ok=True)


def esc(s):
    s = str(s)
    for a, b in [("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"), ("_", r"\_"), ("#", r"\#"),
                 ("$", r"\$"), ("~", r"\textasciitilde{}"), ("^", r"\^{}")]:
        s = s.replace(a, b)
    return s


def brk(s):
    """Escape a regex for \\texttt and allow line breaks after each alternative."""
    return esc(s).replace("|", "|\\allowbreak{}")


def write(name, body):
    (OUT / f"{name}.tex").write_text(body)


def t_vendor():
    v = pd.read_csv(T / "vendor_surge.csv", index_col=0)
    rows = []
    for name, r in v.iterrows():
        rows.append(f"{esc(name)} & {int(r['2025']):,} & {int(r['2026']):,} & {r.ratio:.1f} & "
                    f"{int(r.credit_pct_2026)} & {int(r.ai_credited_2026)} \\\\")
    body = (r"\begin{tabular}{lrrrrr}" "\n" r"\toprule" "\n"
            r"Assigning CNA & Jan--Oct 2025 & Jan--Oct 2026 & Ratio & Credited (\%) & AI-credited \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_vendor_surge", body)


def t_developer():
    d = pd.read_csv(T / "ai_by_developer.csv", index_col=0).fillna(0)
    d.index = [("Other AI tools/orgs" if i == "Various" else i) for i in d.index]
    rows = [f"{esc(i)} & {int(r.tier1)} & {int(r.tier2)} & {int(r.total)} \\\\" for i, r in d.head(12).iterrows()]
    rest = d.iloc[12:]
    if len(rest):
        rows.append(f"Other ({len(rest)} developers) & {int(rest.tier1.sum())} & {int(rest.tier2.sum())} & {int(rest.total.sum())} \\\\")
    body = (r"\begin{tabular}{lrrr}" "\n" r"\toprule" "\n" r"Developer credited & Tier 1 & Tier 2 & Total \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_ai_developers", body)


def t_severity():
    s = pd.read_csv(T / "ai_severity.csv")
    rows = [f"{esc(r.group)} & {int(r.n_scored):,} & {r.mean_cvss:.2f} & {r.share_high_pct:.1f} & {r.share_critical_pct:.1f} \\\\"
            for r in s.itertuples()]
    body = (r"\begin{tabular}{lrrrr}" "\n" r"\toprule" "\n"
            r"Group (CVEs published in 2026) & Scored & Mean CVSS & High+ (\%) & Critical (\%) \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_ai_severity", body)


def t_ai_kev():
    x = pd.read_csv(T / "ai_credited_in_kev.csv")
    rows = [f"{esc(r.cveID)} & {esc(r.vendorProject)} {esc(r.product)} & {esc(r.ai_label)} & {r.date_published} & {r.dateAdded} & {int(r.lag_days)} \\\\"
            for r in x.itertuples()]
    body = (r"\begin{tabular}{llllrr}" "\n" r"\toprule" "\n"
            r"CVE & Product & Credited AI party & Published & KEV listed & Lag (d) \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_ai_in_kev", body)


def t_lag():
    l = pd.read_csv(T / "kev_lag_by_year.csv")
    h = pd.read_csv(T / "kev180_per_1000_by_half.csv")
    b = pd.read_csv(T / "zero_day_proxy_benchmark.csv").set_index("year_pub")
    rows = []
    for r in l.itertuples():
        y = int(r.year_pub)
        rep = b.loc[y, "reported"] if y in b.index else float("nan")
        rep_s = "--" if pd.isna(rep) else f"{int(rep)}"
        early = int(b.loc[y, "early_listed"]) if y in b.index else 0
        rows.append(f"{y}{'$^a$' if y == 2021 else ''}{'$^b$' if y == 2026 else ''} & {int(r.n)} & {r.median_lag:.1f} & "
                    f"[{r.p25:.0f}, {r.p75:.0f}] & {r.share_le0_pct:.1f} & {r.share_le7_pct:.1f} & {early} & {rep_s} \\\\")
    body = (r"\begin{tabular}{lrrrrrrr}" "\n" r"\toprule" "\n"
            r" & \multicolumn{5}{c}{Cohort: listed within 180 days} & \multicolumn{2}{c}{Zero-day counts} \\" "\n"
            r"\cmidrule(lr){2-6}\cmidrule(lr){7-8}" "\n"
            r"CVE year & $n$ & Median lag & IQR & $\le 0$ d (\%) & $\le 7$ d (\%) & Proxy & Reported \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_lags", body)
    rows = [f"{r.half} & {int(r.cves):,} & {int(r.kev_within_180d)} & {r.per_1000:.2f} \\\\" for r in h.itertuples()]
    body = (r"\begin{tabular}{lrrr}" "\n" r"\toprule" "\n"
            r"Publication half-year & CVEs & In KEV within 180 d & Per 1,000 \\" "\n" r"\midrule" "\n"
            + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_k180", body)


def t_profile():
    p = pd.read_csv(T / "kev_category_profile.csv")
    rows = [f"{esc(r.category)} & {int(r.n)} & {r.early_pct:.1f} & {r.median_lag:.1f} & {r.ransomware_pct:.1f} & {r.weight:.1f} & {r.pressure:.1f} \\\\"
            for r in p.itertuples()]
    body = (r"\begin{tabular}{lrrrrrr}" "\n" r"\toprule" "\n"
            r"Product category & $n$ & Zero-day-like (\%) & Median lag (d) & Ransomware (\%) & Weight $w_c$ & Pressure \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_category_profile", body)


def t_incidents():
    inc = pd.read_csv(C / "financial_incidents.csv")
    rows = []
    for r in inc.itertuples():
        th = r"\textsuperscript{TH}" if r.thailand == 1 else ""
        rows.append(f"{r.year} & {esc(r.victim)}{th} & {esc(r.vector)} & {esc(r.zero_day)} \\\\")
    body = (r"\begin{longtable}{p{0.05\textwidth}p{0.28\textwidth}p{0.40\textwidth}p{0.13\textwidth}}" "\n"
            r"\caption{Curated financial-sector incident set (purposive sample of well-documented public cases, author-coded; \textsuperscript{TH} = Thailand). Details should be verified against primary sources before citation.}\label{tab:incidents}\\" "\n"
            r"\toprule" "\n" r"Year & Victim & Initial vector (as publicly reported) & Zero-day? \\" "\n" r"\midrule" "\n"
            r"\endfirsthead" "\n" r"\toprule" "\n" r"Year & Victim & Initial vector (as publicly reported) & Zero-day? \\" "\n"
            r"\midrule" "\n" r"\endhead" "\n" r"\bottomrule" "\n" r"\endfoot" "\n" + "\n".join(rows) + "\n" r"\end{longtable}")
    write("tab_incidents", body)
    s = pd.read_csv(T / "incident_vector_summary.csv")
    rows = [f"{esc(r.vector_class)} & {int(r.cases)} & {r.share_pct:.1f} & {int(r.central_bank_or_supervisor)} & {int(r.thailand)} \\\\"
            for r in s.itertuples()]
    body = (r"\begin{tabular}{lrrrr}" "\n" r"\toprule" "\n"
            r"Initial-vector class & Cases & Share (\%) & Central bank / supervisor & Thailand \\" "\n" r"\midrule" "\n"
            + "\n".join(rows) + "\n" r"\midrule" "\n" f"Total & {int(s.cases.sum())} & 100.0 & {int(s.central_bank_or_supervisor.sum())} & {int(s.thailand.sum())} \\\\" "\n"
            r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_incident_summary", body)


def t_hardware():
    h = pd.read_csv(C / "hardware_trust_anchors.csv")
    rows = [f"{r.year} & {esc(r.target)} & {esc(r.attack_class)} & {esc(r.access_required)} & {esc(r.banking_analogue)} \\\\"
            for r in h.itertuples()]
    body = (r"\begin{tabular}{p{0.05\textwidth}p{0.19\textwidth}p{0.24\textwidth}p{0.16\textwidth}p{0.24\textwidth}}" "\n"
            r"\toprule" "\n" r"Year & Target & Attack class & Access required & Banking analogue \\" "\n" r"\midrule" "\n"
            + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_hardware", body)


def t_thai():
    g = pd.read_csv(T / "thai_group_scores.csv")
    rows = [f"{esc(r.group)} & {r.attractiveness} & {r.systemic_importance} & {r.exposure} & {r.concentration} & {r.defensive_capacity} & "
            f"{r.risk:.2f} & {int(r['rank'])} & {int(r.rank_p05)}--{int(r.rank_p95)} & {r.p_top3_pct:.0f} \\\\" for _, r in g.iterrows()]
    body = (r"\begin{tabular}{p{0.30\textwidth}rrrrrrrrr}" "\n" r"\toprule" "\n"
            r"Group & $A$ & $S$ & $E$ & $K$ & $D$ & $R$ & Rank & 90\% rank & P(top 3) \\" "\n" r"\midrule" "\n"
            + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_thai", body)


def t_sim():
    p = pd.read_csv(T / "sim_params.csv")
    rows = [f"{esc(r.scenario)} & {r.m_disc:g} & {r.tau:g} & {r.kappa:g} & {r.p_mass:g} & {r.m_ops:g} & {r.beta:g} & {r.detect:g} & {r.preempt:g} & {esc(r.shares)} \\\\"
            for r in p.itertuples()]
    body = (r"\begin{tabular}{lrrrrrrrrl}" "\n" r"\toprule" "\n"
            r"Scenario & $m_d$ & $\tau$ & $\kappa$ & $p_{\text{mass}}$ & $m_o$ & $\beta$ & $\delta$ & $\phi$ & Vendor shares \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_sim_params", body)
    s = pd.read_csv(T / "sim_scenarios.csv")
    rows = []
    for r in s.itertuples():
        rows.append(f"{esc(r.scenario)} & {r.events_per_year:.0f} & {r.mean_compromised:.1f} & "
                    f"{100 * r.p_dsib_compromised:.1f} & {100 * r.p_fmi_compromised:.1f} & "
                    f"{100 * r.p_systemic:.1f} [{100 * r.p_systemic_lo:.1f}, {100 * r.p_systemic_hi:.1f}] & {r.rr_systemic_vs_S1:.2f} \\\\")
    body = (r"\begin{tabular}{lrrrrrr}" "\n" r"\toprule" "\n"
            r"Scenario & Events/yr & Compromised & P(D-SIB) \% & P(FMI) \% & P(systemic) \% [95\% CI] & RR vs S1 \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_sim_results", body)
    g = pd.read_csv(T / "sim_groups.csv")
    rows = [f"{esc(r.group)} & {int(r.n)} & {r.pay:.2f} & {r.patch:g} & {r.succ:.2f} & {r.disrupt:.2f} & {r.attract:g} \\\\" for r in g.itertuples()]
    body = (r"\begin{tabular}{lrrrrrr}" "\n" r"\toprule" "\n"
            r"Group & Nodes & Payment share & Patch median (d) & Success $s_g$ & P(disrupt) & Attractiveness \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_sim_groups", body)
    c = pd.read_csv(T / "sim_layer_calibration.csv")
    cols = [x for x in c.columns if x != "parameter"]
    rows = [esc(row["parameter"]) + " & " + " & ".join(f"{row[x]:g}" for x in cols) + r" \\"
            for _, row in c.iterrows()]
    body = (r"\begin{tabular}{l" + "r" * len(cols) + "}" "\n" r"\toprule" "\n"
            "Layer & " + " & ".join(esc(x) for x in cols) + r" \\" "\n" r"\midrule" "\n" + "\n".join(rows) + "\n"
            r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_sim_layers", body)
    rb = pd.read_csv(T / "sim_robustness.csv")
    rows = [f"{r.deploy:g} & {r.c_mass:g} & {100 * r.S1:.1f} & {100 * r.S2:.1f} & {100 * r.S3:.1f} & {100 * r.S4:.1f} & {100 * r.S5:.1f} & "
            f"{r.rr_S2_S1:.2f} & {r.rr_S3_S2:.2f} & {r.rr_S4_S2:.2f} & {r.rr_S5_S3:.2f} \\\\" for r in rb.itertuples()]
    body = (r"\begin{tabular}{rrrrrrrrrrr}" "\n" r"\toprule" "\n"
            r"$\rho$ & $c_{\text{mass}}$ & S1 & S2 & S3 & S4 & S5 & S2/S1 & S3/S2 & S4/S2 & S5/S3 \\" "\n"
            r"\midrule" "\n" + "\n".join(rows) + "\n" r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_sim_robust", body)


def t_lexicon():
    lx = pd.read_csv(C / "ai_credit_lexicon.csv")
    rows = [f"{esc(r.label)} & {esc(r.developer)} & {int(r.tier)} & \\texttt{{{brk(r.pattern[:70])}}} \\\\" for r in lx.itertuples()]
    body = (r"\begin{longtable}{p{0.24\textwidth}p{0.13\textwidth}p{0.04\textwidth}p{0.45\textwidth}}" "\n"
            r"\caption{AI-credit lexicon (case-insensitive regular expressions applied to CVE credit text).}\label{tab:lexicon}\\" "\n"
            r"\toprule" "\n" r"Label & Developer & Tier & Pattern (truncated) \\" "\n" r"\midrule" "\n" r"\endfirsthead" "\n"
            r"\toprule" "\n" r"Label & Developer & Tier & Pattern (truncated) \\" "\n" r"\midrule" "\n" r"\endhead" "\n"
            r"\bottomrule" "\n" r"\endfoot" "\n" + "\n".join(rows) + "\n" r"\end{longtable}")
    write("tab_lexicon", body)
    rel = pd.read_csv(C / "banking_relevance.csv")
    rows = [f"{esc(r.category)} & {r.weight:.1f} & {esc(r.rationale)} \\\\" for r in rel.itertuples()]
    body = (r"\begin{longtable}{p{0.26\textwidth}p{0.06\textwidth}p{0.56\textwidth}}" "\n"
            r"\caption{Banking-relevance weights $w_c$ by product category (author judgement; sensitivity analysed in Section~\ref{sec:exploitation}).}\label{tab:weights}\\" "\n"
            r"\toprule" "\n" r"Category & $w_c$ & Rationale \\" "\n" r"\midrule" "\n" r"\endfirsthead" "\n"
            r"\toprule" "\n" r"Category & $w_c$ & Rationale \\" "\n" r"\midrule" "\n" r"\endhead" "\n"
            r"\bottomrule" "\n" r"\endfoot" "\n" + "\n".join(rows) + "\n" r"\end{longtable}")
    write("tab_weights", body)


def t_milestones():
    m = pd.read_csv(C / "ai_milestones.csv")
    rows = [f"{r.date} & {esc(r.event)} & {esc(r.actor)} & {esc(r.kind)} \\\\" for r in m.itertuples()]
    body = (r"\begin{tabular}{p{0.07\textwidth}p{0.55\textwidth}p{0.15\textwidth}p{0.13\textwidth}}" "\n"
            r"\toprule" "\n" r"Date & Event & Actor & Kind \\" "\n" r"\midrule" "\n" + "\n".join(rows) + "\n"
            r"\bottomrule" "\n" r"\end{tabular}")
    write("tab_milestones", body)


def t_rules():
    r = pd.read_csv(C / "kev_category_rules.csv").sort_values("priority")
    rows = [f"{int(x.priority)} & {esc(x.category)} & \\texttt{{{brk(x.pattern[:80])}\\ldots}} \\\\" for x in r.itertuples()]
    body = (r"\begin{longtable}{p{0.04\textwidth}p{0.26\textwidth}p{0.58\textwidth}}" "\n"
            r"\caption{KEV product-category rules (ordered; first match on vendor and product, then on vulnerability name). Patterns truncated; full rules in \texttt{data/curated/kev\_category\_rules.csv}.}\label{tab:rules}\\" "\n"
            r"\toprule" "\n" r"\# & Category & Pattern (truncated) \\" "\n" r"\midrule" "\n" r"\endfirsthead" "\n"
            r"\toprule" "\n" r"\# & Category & Pattern (truncated) \\" "\n" r"\midrule" "\n" r"\endhead" "\n"
            r"\bottomrule" "\n" r"\endfoot" "\n" + "\n".join(rows) + "\n" r"\end{longtable}")
    write("tab_rules", body)


def main():
    t_milestones()
    t_rules()
    t_vendor()
    t_developer()
    t_severity()
    t_ai_kev()
    t_lag()
    t_profile()
    t_incidents()
    t_hardware()
    t_thai()
    t_sim()
    t_lexicon()
    print("tables written:", sorted(p.name for p in OUT.glob("*.tex")))


if __name__ == "__main__":
    main()
