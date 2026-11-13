"""Step 7: Shared-vendor zero-day / n-day contagion model for a stylised Thai-like financial system.

This is a comparative scenario model, not a forecast. Institution counts follow the
group structure of the Thai system; payment shares, patch speeds and attack
parameters are stylised assumptions listed in PARAMS and reported in the paper
(Table 8). Event rates per technology layer are calibrated to the CISA KEV panel
(publication years 2023-2025) by step 4.

Mechanics (one simulated year):
  1. Each institution runs one product vendor per technology layer, drawn from the
     vendor market-share vector of that layer (the concentration scenario).
  2. Exploited-vulnerability events arrive per layer as Poisson(lambda_l * m_disc).
     Each event hits one vendor (probability = market share). A fraction p_zd_l of
     events are exploited before disclosure (zero-day phase); the rest are n-days.
  3. Zero-day phase: mass campaigns (prob p_mass) hit exposed users of the product
     broadly; targeted campaigns pick a Poisson number of attractive victims.
  4. n-day phase: copycat exploitation starts after a time-to-exploit draw; each
     vulnerable institution stays exposed until its own patch time.
  5. A compromised shared IT provider passes compromise to its clients.
  6. A compromise disrupts payments with a group-specific probability. An event is
     "systemic" if it disrupts >= 10% of system payment value or any payment FMI.

Outputs: outputs/tables/sim_scenarios.csv, outputs/tables/sim_grid.csv,
         outputs/tables/sim_params.csv, data/processed/sim_draws.csv.gz
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "data" / "processed"
T = ROOT / "outputs" / "tables"
SEED = 20261112
SYSTEMIC = 0.10

LAYERS = ["Enterprise edge & network infrastructure", "Managed file transfer",
          "Email & collaboration", "IT management & remote access tools",
          "Virtualisation & backup", "Enterprise applications & web frameworks"]
LAYER_SHORT = ["Edge/VPN", "MFT", "Email/collab", "IT mgmt/RMM", "Virtualisation", "Enterprise apps"]

# group: n, total payment share, median patch days (critical, internet-facing),
# attack success given exposure, P(disruption | compromise), attractiveness,
# layer exposure factors (same order as LAYERS)
GROUPS = {
    "D-SIBs":           dict(n=6,  pay=0.66, patch=4,  succ=0.35, disrupt=0.15, attract=5, expo=[1, 1, 1, 1, 1, 1]),
    "Mid banks":        dict(n=8,  pay=0.10, patch=10, succ=0.60, disrupt=0.25, attract=3, expo=[1, 1, 1, 1, 1, 1]),
    "Foreign banks":    dict(n=12, pay=0.06, patch=7,  succ=0.45, disrupt=0.20, attract=3, expo=[1, 1, 1, 1, 1, 1]),
    "SFIs":             dict(n=6,  pay=0.10, patch=14, succ=0.60, disrupt=0.30, attract=4, expo=[1, 1, 1, 1, 1, 1]),
    "Virtual banks":    dict(n=3,  pay=0.01, patch=5,  succ=0.60, disrupt=0.30, attract=3, expo=[0.5, 0.5, 0.3, 1, 0.2, 1]),
    "PSPs/e-money":     dict(n=25, pay=0.05, patch=21, succ=0.80, disrupt=0.35, attract=3, expo=[1, 1, 1, 1, 1, 1]),
    "Shared providers": dict(n=5,  pay=0.00, patch=10, succ=0.60, disrupt=0.00, attract=4, expo=[1, 1, 1, 1, 1, 1]),
    "Payment FMIs":     dict(n=2,  pay=0.00, patch=5,  succ=0.25, disrupt=0.10, attract=5, expo=[0.3, 1, 1, 1, 1, 0.5]),
}
FMI_PASS = [0.50, 0.25]          # payment value disrupted if the RTGS / retail switch is disrupted
CLIENTS_PER_PROVIDER = 8
PROPAGATION = 0.25               # P(client compromised | its provider compromised)
DEPLOY = 0.05                    # P(a user of the vendor runs the affected product version, exposed)
C_MASS = 0.30                    # hit rate of mass campaigns on exposed instances
K_TARGETED = 0.30                # mean targeted victims in Thailand per targeted zero-day
H_NDAY = 0.004                   # n-day compromise hazard per exposed day
PATCH_SIGMA = 0.9

SHARES = {
    "baseline":     np.array([0.35, 0.25, 0.20, 0.12, 0.08]),
    "concentrated": np.array([0.60, 0.15, 0.10, 0.10, 0.05]),
    "diversified":  np.array([0.20, 0.20, 0.20, 0.20, 0.20]),
}

SCENARIOS = {
    "S0 Pre-2022 baseline":            dict(m_disc=0.6, tau=32, kappa=1.3, p_mass=0.25, m_ops=1.0, beta=1.0, detect=1.0, preempt=0.0, shares="baseline"),
    "S1 Current (2023-26)":            dict(m_disc=1.0, tau=5,  kappa=1.0, p_mass=0.35, m_ops=1.0, beta=1.0, detect=1.0, preempt=0.0, shares="baseline"),
    "S2 AI offence":                   dict(m_disc=3.0, tau=1,  kappa=0.2, p_mass=0.50, m_ops=3.0, beta=1.0, detect=1.0, preempt=0.0, shares="baseline"),
    "S3 AI offence + AI defence":      dict(m_disc=3.0, tau=1,  kappa=0.2, p_mass=0.50, m_ops=3.0, beta=0.35, detect=0.6, preempt=0.3, shares="baseline"),
    "S4 AI offence + concentration":   dict(m_disc=3.0, tau=1,  kappa=0.2, p_mass=0.50, m_ops=3.0, beta=1.0, detect=1.0, preempt=0.0, shares="concentrated"),
    "S5 AI offence + defence + diversified": dict(m_disc=3.0, tau=1, kappa=0.2, p_mass=0.50, m_ops=3.0, beta=0.35, detect=0.6, preempt=0.3, shares="diversified"),
}


def calibrate():
    kev = pd.read_csv(P / "kev_panel.csv")
    pl = kev[kev.post_launch & kev.year_pub.between(2023, 2025)]
    lam, pzd = [], []
    for l in LAYERS:
        sub = pl[pl.category == l]
        lam.append(len(sub) / 3.0)
        pzd.append(sub.early_listed.mean())
    nd = pl[pl.category.isin(LAYERS) & ~pl.early_listed].lag_days.to_numpy(dtype=float)
    return np.array(lam), np.array(pzd), nd


def build_nodes():
    rows = []
    for g, d in GROUPS.items():
        for k in range(d["n"]):
            rows.append(dict(group=g, pay=d["pay"] / d["n"] if d["n"] else 0, patch=d["patch"],
                             succ=d["succ"], disrupt=d["disrupt"], attract=d["attract"],
                             expo=d["expo"], fmi_pass=FMI_PASS[k] if g == "Payment FMIs" else 0.0))
    nd = pd.DataFrame(rows)
    nd["pay"] = nd.pay / nd.pay.sum()
    return nd


def simulate(sc, n_sims, rng, lam, pzd, nday_lags, nodes, chunk=200):
    N, L = len(nodes), len(LAYERS)
    pay = nodes.pay.to_numpy()
    patch = nodes.patch.to_numpy(dtype=float)
    succ = nodes.succ.to_numpy() * sc["detect"]
    disrupt = nodes.disrupt.to_numpy()
    attract = nodes.attract.to_numpy(dtype=float)
    expo = np.vstack(nodes.expo.to_numpy())                 # (N, L)
    fmi_pass = nodes.fmi_pass.to_numpy()
    is_dsib = (nodes.group == "D-SIBs").to_numpy()
    is_fmi = (nodes.group == "Payment FMIs").to_numpy()
    prov_idx = np.where(nodes.group == "Shared providers")[0]
    client_pool = np.where(~nodes.group.isin(["Shared providers", "Payment FMIs"]))[0]
    shares = SHARES[sc["shares"]]
    V = len(shares)
    w_target = attract * (pay + 0.01)
    out = []
    done = 0
    while done < n_sims:
        S = min(chunk, n_sims - done)
        vendor = rng.choice(V, size=(S, N, L), p=shares)
        clients = np.zeros((S, len(prov_idx), N), dtype=bool)
        for s in range(S):
            for j in range(len(prov_idx)):
                clients[s, j, rng.choice(client_pool, CLIENTS_PER_PROVIDER, replace=False)] = True
        counts = rng.poisson(lam * sc["m_disc"] * (1 - sc["preempt"]), size=(S, L))
        ev_sim = np.repeat(np.repeat(np.arange(S), L), counts.ravel())
        ev_layer = np.repeat(np.tile(np.arange(L), S), counts.ravel())
        E = len(ev_sim)
        if E == 0:
            out.append(np.zeros((S, 6)))
            done += S
            continue
        ev_vendor = rng.choice(V, size=E, p=shares)
        ev_zd = rng.random(E) < pzd[ev_layer]
        ev_mass = rng.random(E) < sc["p_mass"]
        vuln = (vendor[ev_sim[:, None], np.arange(N)[None, :], ev_layer[:, None]] == ev_vendor[:, None])
        vuln &= rng.random((E, N)) < DEPLOY
        ex = expo[:, ev_layer].T                              # (E, N)
        vuln &= ex > 0
        ps = succ[None, :] * ex
        # zero-day phase
        comp = np.zeros((E, N), dtype=bool)
        mass = (ev_zd & ev_mass)[:, None]
        comp |= mass & vuln & (rng.random((E, N)) < C_MASS * ps)
        tgt_ev = ev_zd & ~ev_mass
        k = rng.poisson(K_TARGETED * sc["m_ops"], size=E)
        keys = np.where(vuln, np.log(w_target)[None, :] + rng.gumbel(size=(E, N)), -np.inf)
        order = (-keys).argsort(axis=1).argsort(axis=1)
        chosen = (order < k[:, None]) & vuln & tgt_ev[:, None]
        comp |= chosen & (rng.random((E, N)) < ps)
        # n-day phase
        tte = np.where(ev_zd, rng.exponential(sc["tau"], E),
                       rng.choice(nday_lags, E) * sc["kappa"])
        ptime = np.exp(np.log(patch * sc["beta"])[None, :] + PATCH_SIGMA * rng.standard_normal((E, N)))
        window = np.clip(ptime - tte[:, None], 0, None)
        p_n = 1 - np.exp(-H_NDAY * sc["m_ops"] * ps * window)
        comp |= vuln & (rng.random((E, N)) < p_n)
        # shared-provider propagation
        pc = comp[:, prov_idx]                                # (E, Pv)
        if pc.any():
            reach = (pc[:, :, None] & clients[ev_sim]).any(axis=1)
            comp |= reach & (rng.random((E, N)) < PROPAGATION)
        disr = comp & (rng.random((E, N)) < disrupt[None, :])
        share = np.clip((disr * pay[None, :]).sum(1) + (disr * fmi_pass[None, :]).sum(1), 0, 1)
        fmi_hit = (disr & is_fmi[None, :]).any(1)
        ever = np.zeros((S, N), dtype=np.int32)
        np.add.at(ever, ev_sim, comp.astype(np.int32))
        ever = ever > 0
        systemic = np.zeros(S, dtype=bool)
        np.logical_or.at(systemic, ev_sim, (share >= SYSTEMIC) | fmi_hit)
        maxshare = np.zeros(S)
        np.maximum.at(maxshare, ev_sim, share)
        res = np.column_stack([ever.sum(1), ever[:, is_dsib].any(1), ever[:, is_fmi].any(1),
                               systemic, maxshare, np.bincount(ev_sim, minlength=S)])
        out.append(res)
        done += S
    return pd.DataFrame(np.vstack(out), columns=["n_compromised", "dsib_compromised", "fmi_compromised",
                                                 "systemic", "max_event_share", "n_events"])


def summarise(df):
    n = len(df)
    def ci(p):
        se = np.sqrt(p * (1 - p) / n)
        return p, max(0.0, p - 1.96 * se), min(1.0, p + 1.96 * se)
    m = df.n_compromised.mean()
    se = df.n_compromised.std() / np.sqrt(n)
    out = {"events_per_year": df.n_events.mean(), "mean_compromised": m,
           "mean_compromised_lo": m - 1.96 * se, "mean_compromised_hi": m + 1.96 * se}
    for col in ["dsib_compromised", "fmi_compromised", "systemic"]:
        p, lo, hi = ci(df[col].mean())
        out[f"p_{col}"], out[f"p_{col}_lo"], out[f"p_{col}_hi"] = p, lo, hi
    out["max_share_p95"] = df.max_event_share.quantile(0.95)
    return out


def main(n_main=4000, n_grid=1200, n_rob=1000):
    lam, pzd, nd_lags = calibrate()
    nodes = build_nodes()
    rng = np.random.default_rng(SEED)
    rows, draws = [], []
    for name, sc in SCENARIOS.items():
        df = simulate(sc, n_main, rng, lam, pzd, nd_lags, nodes)
        df["scenario"] = name
        draws.append(df)
        rows.append({"scenario": name, **summarise(df)})
        print(name, {k: round(v, 3) for k, v in rows[-1].items() if k != "scenario"})
    res = pd.DataFrame(rows)
    base = res.set_index("scenario").loc["S1 Current (2023-26)"]
    res["rr_systemic_vs_S1"] = res.p_systemic / base.p_systemic
    res["rr_compromised_vs_S1"] = res.mean_compromised / base.mean_compromised
    res.to_csv(T / "sim_scenarios.csv", index=False)
    pd.concat(draws).to_csv(P / "sim_draws.csv.gz", index=False, compression="gzip")

    grid = []
    base_sc = SCENARIOS["S2 AI offence"]
    for md in [1.0, 1.5, 2.0, 3.0, 4.0, 5.0]:
        for beta in [0.25, 0.5, 0.75, 1.0, 1.25, 1.5]:
            sc = dict(base_sc, m_disc=md, m_ops=md, beta=beta)
            df = simulate(sc, n_grid, rng, lam, pzd, nd_lags, nodes)
            s = summarise(df)
            grid.append({"m_disc": md, "beta": beta, "p_systemic": s["p_systemic"],
                         "p_dsib": s["p_dsib_compromised"],
                         "mean_compromised": s["mean_compromised"]})
    pd.DataFrame(grid).to_csv(T / "sim_grid.csv", index=False)

    # Robustness of scenario ordering to the two least-anchored parameters
    global DEPLOY, C_MASS
    d0, c0 = DEPLOY, C_MASS
    rob = []
    for dep in [0.03, 0.05, 0.08]:
        for cm in [0.2, 0.3, 0.5]:
            DEPLOY, C_MASS = dep, cm
            ps = {}
            for name, sc in SCENARIOS.items():
                ps[name.split()[0]] = summarise(simulate(sc, n_rob, rng, lam, pzd, nd_lags, nodes))["p_systemic"]
            rob.append({"deploy": dep, "c_mass": cm, **{k: round(v, 4) for k, v in ps.items()},
                        "rr_S2_S1": ps["S2"] / ps["S1"], "rr_S3_S2": ps["S3"] / ps["S2"],
                        "rr_S4_S2": ps["S4"] / ps["S2"], "rr_S5_S3": ps["S5"] / ps["S3"]})
    DEPLOY, C_MASS = d0, c0
    rob = pd.DataFrame(rob)
    rob.to_csv(T / "sim_robustness.csv", index=False)

    prm = [{"parameter": "Event rate per year (KEV-calibrated)", **{s: round(v, 1) for s, v in zip(LAYER_SHORT, lam)}},
           {"parameter": "Share exploited as zero-day", **{s: round(v, 2) for s, v in zip(LAYER_SHORT, pzd)}}]
    pd.DataFrame(prm).to_csv(T / "sim_layer_calibration.csv", index=False)
    g = pd.DataFrame([{"group": k, **{kk: vv for kk, vv in v.items() if kk != "expo"}} for k, v in GROUPS.items()])
    g.to_csv(T / "sim_groups.csv", index=False)
    pd.DataFrame([{"scenario": k, **v} for k, v in SCENARIOS.items()]).to_csv(T / "sim_params.csv", index=False)

    kn_path = ROOT / "outputs" / "key_numbers.json"
    kn = json.loads(kn_path.read_text()) if kn_path.exists() else {}
    r = res.set_index("scenario")
    for name in r.index:
        key = name.split()[0].lower()
        kn[f"sim_{key}_psys"] = round(100 * r.loc[name, "p_systemic"], 1)
        kn[f"sim_{key}_pdsib"] = round(100 * r.loc[name, "p_dsib_compromised"], 1)
        kn[f"sim_{key}_pfmi"] = round(100 * r.loc[name, "p_fmi_compromised"], 1)
        kn[f"sim_{key}_ncomp"] = round(r.loc[name, "mean_compromised"], 2)
        kn[f"sim_{key}_rr"] = round(r.loc[name, "rr_systemic_vs_S1"], 2)
        kn[f"sim_{key}_events"] = round(r.loc[name, "events_per_year"], 1)
    kn["rob_rr_S2_S1_min"] = round(float(rob.rr_S2_S1.min()), 2)
    kn["rob_rr_S2_S1_max"] = round(float(rob.rr_S2_S1.max()), 2)
    kn["rob_rr_S3_S2_max"] = round(float(rob.rr_S3_S2.max()), 2)
    kn["rob_rr_S3_S2_min"] = round(float(rob.rr_S3_S2.min()), 2)
    kn["rob_rr_S4_S2_min"] = round(float(rob.rr_S4_S2.min()), 2)
    kn["rob_rr_S4_S2_max"] = round(float(rob.rr_S4_S2.max()), 2)
    kn["rob_rr_S5_S3_max"] = round(float(rob.rr_S5_S3.max()), 2)
    kn["rob_rr_S5_S3_min"] = round(float(rob.rr_S5_S3.min()), 2)
    kn["rob_n"] = n_rob
    kn["sim_n_main"] = n_main
    kn["sim_n_grid"] = n_grid
    kn["sim_lambda_total"] = round(float(lam.sum()), 1)
    kn["sim_nday_lag_median"] = float(np.median(nd_lags))
    kn_path.write_text(json.dumps(kn, indent=1, default=str))


if __name__ == "__main__":
    main()
