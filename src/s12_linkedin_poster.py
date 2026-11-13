"""LinkedIn poster (docs/assets/linkedin_poster.png, 1440x1800), styled after thainowcast."""
import json
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import pandas as pd
from matplotlib import font_manager

BG, AMBER, CREAM, TEXT, MUTED, BOX = "#03060d", "#f5a623", "#ffe8a3", "#e8ecf4", "#8e9ab3", "#0a1222"
W, H = 1440, 1800
root = Path(__file__).resolve().parents[1]
for f in (root / "docs/assets/fonts").glob("FiraSans-*.ttf"):   # Fira Sans, SIL OFL
    font_manager.fontManager.addfont(str(f))
FONT = "Fira Sans"
m = pd.read_csv(root / "outputs/tables/cve_monthly_ai.csv")
k = json.loads((root / "outputs/key_numbers.json").read_text())

fig = plt.figure(figsize=(W / 100, H / 100), dpi=100, facecolor=BG)
bg = fig.add_axes([0, 0, 1, 1]); bg.set_xlim(0, W); bg.set_ylim(H, 0); bg.set_axis_off()

def t(x, y, s, size, color=TEXT, weight="normal", ha="left", va="baseline", **kw):
    bg.text(x, y, s, fontsize=size * 0.72, color=color, weight=weight, ha=ha, va=va, family=FONT, **kw)

# soft glow behind the chart
for r, a in [(620, 0.05), (470, 0.06), (320, 0.07)]:
    bg.add_patch(plt.Circle((1120, 1000), r, color="#0d2147", alpha=a, lw=0))

# chart: monthly CVEs (amber) and AI-credited CVEs x10 (cream)
X0, X1, Y0, Y1 = 760, 1370, 1270, 150
n, top = len(m), m["cves"].max()
bw = (X1 - X0) / n
def bar(i, v, color, alpha, width, lw=0):
    h = v / top * (Y0 - Y1)
    bg.add_patch(plt.Rectangle((X0 + i * bw + (bw - width) / 2, Y0 - h), width, h, color=color,
                               alpha=alpha, lw=lw, ec=color))
for i, v in enumerate(m["cves"]):
    for lw, a in [(14, 0.05), (8, 0.09), (4, 0.16)]:
        bar(i, v, AMBER, a, bw * 0.72, lw)
    bar(i, v, AMBER, 0.95, bw * 0.72)
    bar(i, m["ai_any"].iloc[i] * 10, "#fff6dc", 1.0, bw * 0.72)
t(X0, Y0 + 34, m["ym"].iloc[0], 17, MUTED)
t(X1, Y0 + 34, m["ym"].iloc[-1], 17, MUTED, ha="right")

# header + hero
t(95, 92, "ZERO-DAYS AT MACHINE SPEED", 25, AMBER, "semibold")
t(95, 132, "AI, vulnerabilities and systemic risk in banking", 22, MUTED)
t(80, 385, f"{k['cve_growth_jan_oct']:.2f}×", 230, AMBER, "bold")
t(105, 470, "more CVEs", 64, CREAM, "medium")
for i, s in enumerate(["Software vulnerabilities published", "in Jan–Oct 2026 than in the same", "months of 2025."]):
    t(105, 545 + i * 48, s, 31, TEXT)
t(105, 705, "AI now finds bugs at machine speed.", 31, AMBER, "bold")
t(105, 755, "What does it mean for banks and", 31, AMBER, "bold")
t(105, 805, "central banks?", 31, AMBER, "bold")

# callouts
def callout(y, title, lines, tx, ty, color=CREAM, tcol=TEXT):
    t(715, y, title, 27, color, "semibold", ha="right")
    for j, s in enumerate(lines):
        t(712, y + 44 + j * 33, s, 20, tcol, ha="right")
    if tx is not None:
        bg.plot([725, tx], [y - 8, ty], color=CREAM, lw=1.2, alpha=0.7)
        bg.add_patch(plt.Circle((tx, ty), 5, fill=False, ec=CREAM, lw=1.2))
last_h = m["cves"].iloc[-1] / top * (Y0 - Y1)
ai_h = m["ai_any"].iloc[-1] * 10 / top * (Y0 - Y1)
tx = X1 - bw * 1.4
t(tx, 178, f"{m['cves'].iloc[-1]:,} CVEs in one month", 27, CREAM, "semibold", ha="right")
t(tx, 218, "October 2026, four times October 2025", 20, TEXT, ha="right")
bg.plot([tx + 10, X1 - bw * 0.5 - 8], [170, Y0 - last_h + 4], color=CREAM, lw=1.2, alpha=0.7)
callout(960, f"{k['ai_total']:,} credited to AI",
        ["cream bars (×10); doubling every", f"~{k['ai_doubling_months']:.0f} months, as severe as human finds"], None, None)
callout(1135, "Exploitation lags discovery",
        ["exploited within 180 days fell from", "3.9 to 2.6 per 1,000 new CVEs"], None, None, MUTED, MUTED)

# stats row
bg.plot([95, 1345], [1330, 1330], color="#1e2a44", lw=1.5)
stats = [(f"{k['cve_published_total']:,}", ["CVE records", "analysed"]),
         ("~5×", ["systemic payment risk", "if AI offence triples"]),
         ("50–75%", ["of that increase removed", "by AI-enabled defence"]),
         ("+36–64%", ["added by vendor", "concentration"])]
for i, (big, lab) in enumerate(stats):
    x = 95 + i * 324
    t(x, 1430, big, 60, AMBER, "semibold")
    for j, s in enumerate(lab):
        t(x, 1482 + j * 31, s, 20, MUTED)

# link box
bg.add_patch(FancyBboxPatch((88, 1555), 1264, 165, boxstyle="round,pad=0,rounding_size=18",
                            fc=BOX, ec="#1e2a44", lw=1.5))
t(130, 1605, "Code + data", 19, MUTED); t(130, 1645, "github.com/thanatchon36/ai-zeroday-banking", 25, TEXT)
t(790, 1605, "Read the paper", 19, MUTED); t(790, 1645, "thanatchon36.github.io/ai-zeroday-banking", 25, TEXT)
t(130, 1695, "Public data only (CVE List V5, CISA KEV). Scenarios describe a stylised Thai-like system, not forecasts.",
  17.5, MUTED)

# footer
t(95, 1775, "Thanatchon Chongmankhong  ·  views are my own  ·  DOI 10.5281/zenodo.24184069", 19, MUTED)
t(1345, 1775, f"CVE List V5 · {k['snapshot_date']}", 16, "#5d6884", ha="right")
t((X0 + X1) / 2, Y0 + 34, "CVEs published per month", 16, "#5d6884", ha="center")

out = root / "docs/assets/linkedin_poster.png"
fig.savefig(out, facecolor=BG, dpi=100)
print(out)
