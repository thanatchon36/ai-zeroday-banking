"""Dark README banner (docs/assets/banner.png), styled after thainowcast."""
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

BG, AMBER, TEXT, MUTED = "#03060d", "#f5a623", "#e8ecf4", "#8e9ab3"
root = Path(__file__).resolve().parents[1]
m = pd.read_csv(root / "outputs/tables/cve_monthly_ai.csv")

fig = plt.figure(figsize=(16.8, 6.24), dpi=100, facecolor=BG)
ax = fig.add_axes([0.04, 0.10, 0.36, 0.80], facecolor=BG)
x = range(len(m))
for w, a in [(9, 0.06), (6, 0.12), (3.5, 0.25)]:          # glow
    ax.bar(x, m["cves"], width=0.8, color=AMBER, alpha=a, linewidth=w, edgecolor=AMBER)
ax.bar(x, m["cves"], width=0.7, color=AMBER, alpha=0.9)
ax.bar(x, m["ai_any"] * 5, width=0.7, color="#fff4d6")      # AI-credited, scaled x5
ax.set_axis_off()
ax.text(0, -0.04, f"{m['ym'].iloc[0]}", color=MUTED, fontsize=10, transform=ax.transAxes)
ax.text(1, -0.04, f"{m['ym'].iloc[-1]}", color=MUTED, fontsize=10, ha="right", transform=ax.transAxes)

fig.text(0.45, 0.56, "Zero-Days at\nMachine Speed", color=AMBER, fontsize=48, weight="bold", linespacing=1.05)
fig.text(0.45, 0.33, "AI-driven vulnerability discovery, systemic cyber risk in banking,\n"
         "and implications for central banks", color=TEXT, fontsize=17, linespacing=1.6)
fig.text(0.45, 0.20, "405,375 CVEs · CISA KEV · 33 financial incidents · Monte Carlo for Thailand",
         color=MUTED, fontsize=13)
fig.text(0.985, 0.04, "Monthly CVE publications (amber) and AI-credited CVEs ×5 (white) · "
         "CVE List V5 snapshot 2026-11-12", color=MUTED, fontsize=9, ha="right")
out = root / "docs/assets/banner.png"
fig.savefig(out, facecolor=BG)
print(out)
