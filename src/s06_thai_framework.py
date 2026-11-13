"""Step 6: Group-level targeting and vulnerability framework for the Thai financial system.

Input : data/curated/thai_groups.csv (author scores on a 1-5 rubric; see paper Table 6)
Output: outputs/tables/thai_group_scores.csv; updates outputs/key_numbers.json

Target index        T = mean(attractiveness, systemic importance)
Vulnerability index V = mean(exposure, concentration, 6 - defensive capacity)
Risk                R = (T x V) / 25, in [0.04, 1]

Robustness: 10,000 draws in which (i) each score moves by -1/0/+1 with
probabilities 0.25/0.5/0.25 (clipped to 1-5) and (ii) the component weights
inside T and V are drawn from a Dirichlet(5) distribution. We report the
median rank, a 90% rank interval and the probability of ranking in the top 3.
These are structured expert judgements, not measurements of any institution.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "data" / "curated"
T = ROOT / "outputs" / "tables"
N_DRAWS = 10_000
SEED = 2026


def indices(a, s, e, c, d, wt=None, wv=None):
    wt = np.array([0.5, 0.5]) if wt is None else wt
    wv = np.array([1 / 3] * 3) if wv is None else wv
    t = wt[..., 0] * a + wt[..., 1] * s
    v = wv[..., 0] * e + wv[..., 1] * c + wv[..., 2] * (6 - d)
    return t, v, t * v / 25.0


def main():
    g = pd.read_csv(C / "thai_groups.csv")
    cols = ["attractiveness", "systemic_importance", "exposure", "concentration", "defensive_capacity"]
    X = g[cols].to_numpy(dtype=float)
    t, v, r = indices(*X.T)
    g["target_index"] = t.round(2)
    g["vulnerability_index"] = v.round(2)
    g["risk"] = r.round(3)
    g["rank"] = g.risk.rank(ascending=False, method="min").astype(int)

    rng = np.random.default_rng(SEED)
    k = len(g)
    noise = rng.choice([-1, 0, 1], p=[0.25, 0.5, 0.25], size=(N_DRAWS, k, len(cols)))
    Xp = np.clip(X[None, :, :] + noise, 1, 5)
    wt = rng.dirichlet([5, 5], size=N_DRAWS)[:, None, :]
    wv = rng.dirichlet([5, 5, 5], size=N_DRAWS)[:, None, :]
    _, _, rp = indices(Xp[..., 0], Xp[..., 1], Xp[..., 2], Xp[..., 3], Xp[..., 4], wt, wv)
    ranks = (-rp).argsort(axis=1).argsort(axis=1) + 1
    g["rank_median"] = np.median(ranks, axis=0).astype(int)
    g["rank_p05"] = np.quantile(ranks, 0.05, axis=0).astype(int)
    g["rank_p95"] = np.quantile(ranks, 0.95, axis=0).astype(int)
    g["p_top3_pct"] = (100 * (ranks <= 3).mean(axis=0)).round(1)
    g = g.sort_values("risk", ascending=False)
    g.to_csv(T / "thai_group_scores.csv", index=False)

    kn_path = ROOT / "outputs" / "key_numbers.json"
    kn = json.loads(kn_path.read_text()) if kn_path.exists() else {}
    top = g.head(3)
    kn["thai_top3"] = "; ".join(top.short)
    for _, row in g.iterrows():
        key = row.short.replace("/", "_").replace(" ", "_").replace("-", "_").lower()
        kn[f"thai_ptop3_{key}"] = float(row.p_top3_pct)
        kn[f"thai_rank_{key}"] = int(row["rank"])
    kn_path.write_text(json.dumps(kn, indent=1, default=str))
    print(g[["short", "target_index", "vulnerability_index", "risk", "rank", "rank_median",
             "rank_p05", "rank_p95", "p_top3_pct"]].to_string(index=False))


if __name__ == "__main__":
    main()
