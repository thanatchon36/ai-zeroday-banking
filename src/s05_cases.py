"""Step 5: Summarise the curated financial-sector incident and hardware trust-anchor datasets.

Inputs : data/curated/financial_incidents.csv, data/curated/hardware_trust_anchors.csv
Outputs: outputs/tables/incident_vector_summary.csv, outputs/tables/incident_zero_day_cases.csv,
         outputs/tables/hardware_access_summary.csv; updates outputs/key_numbers.json

The incident list is a purposive sample of well-documented public cases, coded by
the author from public reporting. It is not a random sample and its shares are
descriptive only.
"""
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
C = ROOT / "data" / "curated"
T = ROOT / "outputs" / "tables"


def vector_class(z):
    z = str(z)
    if z.startswith("Yes"):
        return "Zero-day in commercial product"
    if z.startswith("Supply"):
        return "Supply-chain compromise"
    if "n-day" in z:
        return "Known (n-day) vulnerability"
    if z.startswith("Common"):
        return "Non-malicious common-mode failure"
    if z.startswith("Unknown"):
        return "Vector not disclosed"
    return "Credentials, fraud or misconfiguration"


def main():
    inc = pd.read_csv(C / "financial_incidents.csv")
    inc["vector_class"] = inc.zero_day.map(vector_class)
    summ = inc.groupby("vector_class").agg(cases=("case_id", "size"),
                                           central_bank_or_supervisor=("victim_type", lambda s: int(s.isin(["Central bank", "Supervisor"]).sum())),
                                           thailand=("thailand", "sum"))
    summ["share_pct"] = (100 * summ.cases / summ.cases.sum()).round(1)
    summ = summ.sort_values("cases", ascending=False)
    summ.to_csv(T / "incident_vector_summary.csv")
    zd = inc[inc.vector_class == "Zero-day in commercial product"][["year", "victim", "product_category", "impact"]]
    zd.to_csv(T / "incident_zero_day_cases.csv", index=False)

    hw = pd.read_csv(C / "hardware_trust_anchors.csv")
    hw["remote"] = hw.access_required.str.contains("Remote|Network", case=False)
    hsum = hw.groupby("remote").size()
    hw.to_csv(T / "hardware_cases.csv", index=False)

    kn_path = ROOT / "outputs" / "key_numbers.json"
    kn = json.loads(kn_path.read_text()) if kn_path.exists() else {}
    kn.update({
        "inc_n": int(len(inc)),
        "inc_zero_day": int((inc.vector_class == "Zero-day in commercial product").sum()),
        "inc_supply_chain": int((inc.vector_class == "Supply-chain compromise").sum()),
        "inc_nday": int((inc.vector_class == "Known (n-day) vulnerability").sum()),
        "inc_cred": int((inc.vector_class == "Credentials, fraud or misconfiguration").sum()),
        "inc_unknown": int((inc.vector_class == "Vector not disclosed").sum()),
        "inc_central": int(inc.victim_type.isin(["Central bank", "Supervisor"]).sum()),
        "inc_thai": int(inc.thailand.sum()),
        "inc_zero_day_mft": int(((inc.vector_class == "Zero-day in commercial product") &
                                 (inc.product_category == "Managed file transfer")).sum()),
        "hw_n": int(len(hw)),
        "hw_remote": int(hsum.get(True, 0)),
        "hw_physical": int(hsum.get(False, 0)),
    })
    kn_path.write_text(json.dumps(kn, indent=1, default=str))
    print(summ)
    print(zd)
    print("hardware remote/physical:", dict(hsum))


if __name__ == "__main__":
    main()
