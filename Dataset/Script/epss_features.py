import os, json, math, sys
from datetime import datetime, timezone
import pandas as pd
import numpy as np

INPUT_PARQUET = "your_path"
INPUT_CSV     = "your_path"

OUT_SCORES_CSV      = "your_path"
OUT_EXPLAIN_JSONL   = "your_path"
OUT_TOP20_CSV       = "your_path"
OUT_TOP30_CSV       = "your_path"
OUT_PORT_BUDGET_CSV = "your_path"

WEIGHTS = {"wE":0.35, "wI":0.25, "wX":0.30, "wC":0.10}        # SRS weights
LEVEL_THRESH = {"L4":85.0, "L3":70.0, "L2":50.0, "L1":30.0}   # Level threshold
PVS_PARAMS = {"a":1.0, "b":0.8, "c":0.6, "d":0.4}             # PVS coefficient
PATCH_EFFECTIVENESS = 0.50                                    # The patch reduces the exploitability ratio.
NO_PATCH_COMP_CTRL_GAIN = 0.25                                # No patch compensation: Reduce SRS ratio

TOPK_LIST = [20, 30]             # TopK Size
BUDGET_K  = 300.0                # Budget cap (measured on the K_total scale)
BUNDLE_GAIN_PER_HIT = 5.0        # The margin added for each bundleable item hit (illustrated).

AGREE_EPS_THRESH = 0.75          # EPSS compliance is considered one of the consistent signals.
RECENCY_HALFLIFE_DAYS = 30.0     # Freshness half-life
NOISE_DEFAULT = 0.0              # If there is no evidence_conflict field, then 0
AGE_FALLBACK_DAYS = 14.0         # The default value when the last_seen_days field is not present.
RHO_BASELINE = 0.0               # To avoid rho being all zeros, you can set it to 0.05.

DEFAULTS = {
    "internet_exposed": False,
    "asset_criticality": "Medium",
    "edr_coverage": 0.2,
    "siem_detection": 0.2,
    "implementation_complexity": "medium",
    "reboot_required": False,
    "dependency_risk": "low",
    "rollback_ready": True,
    "bundle_opportunity": False,
}

POLICY_VERSION = "2025-11-07"

def load_super_table():
    if os.path.exists(INPUT_PARQUET):
        try:
            return pd.read_parquet(INPUT_PARQUET)  
        except Exception as e:
            print(f"[WARN] Failed to read parquet ({e}); fallback to CSV: {INPUT_CSV}", file=sys.stderr)
    return pd.read_csv(INPUT_CSV)

def normalize_columns(df: pd.DataFrame):
    alias_map = {
        "cvss_base": ["cvss_base","cvss_base_score","cvss","cvss_v3_base","base_score","basescore"],
        "epss_percentile": ["epss_percentile","epss_percentile_latest","epss_pctl","epss_percent"],
        "epss_score": ["epss_score","epss_latest","epss"],
        "kev": ["kev","is_kev","in_kev","cisa_kev","is_cisa"],
        "has_poc": ["has_poc","has_exploit","has_exploit_ref","exploit_poc"],
        "attackerkb": ["attackerkb","akb","has_attackerkb"],
        "internet_exposed": ["internet_exposed","network_exploitable","is_external","internet_exposure","externally_facing"],
        "asset_criticality": ["asset_criticality","business_criticality","asset_tier"],
        "edr_coverage": ["edr_coverage","edr_cov","edr"],
        "siem_detection": ["siem_detection","siem_cov","siem"],
        "affected_count": ["affected_count","affected_assets","deployment_scope"],
        "has_patch": ["has_patch","patch_available","triage_hint"],
        "implementation_complexity": ["implementation_complexity","impl_complexity"],
        "dependency_risk": ["dependency_risk"],
        "reboot_required": ["reboot_required","needs_reboot","reboot"],
        "rollback_ready": ["rollback_ready","has_rollback"],
        "bundle_opportunity": ["bundle_opportunity","bundle"],
        "cwe_id": ["cwe_id","cwe","cwe_list"],
        "vendor": ["vendor","vendor_name"],
        "product": ["product","product_name"],
        "package_name": ["package_name","package","pkg"],
        "component": ["component"],
        "cpe23uri": ["cpe23uri","cpe"],
        "last_seen_days": ["last_seen_days","age_days","last_seen"],
        "evidence_conflict": ["evidence_conflict","conflict_score"],
        "kev_due_date": ["kev_due_date","due_date"]
    }
    cols_lower = {c.lower(): c for c in df.columns}
    mapping_report = {}
    for canon, aliases in alias_map.items():
        found = None
        for a in aliases:
            if a.lower() in cols_lower:
                found = cols_lower[a.lower()]
                break
        if found:
            if found != canon and canon not in df.columns:
                df.rename(columns={found: canon}, inplace=True)
                mapping_report[canon] = found
            else:
                mapping_report[canon] = found if found == canon else f"existing:{canon}; alias:{found}"
        else:
            mapping_report[canon] = None

    # If epss_percentile is unavailable but epss_score is available, perform quantile calibration or directly crop to 0.1.
    if ("epss_percentile" not in df.columns or df["epss_percentile"].isnull().all()) and ("epss_score" in df.columns):
        try:
            s = pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0)
            if s.max() > 1.0:
                df["epss_percentile"] = s.rank(method="average", pct=True).clip(0,1)
            else:
                df["epss_percentile"] = s.clip(0,1)
            mapping_report["epss_percentile"] = (mapping_report.get("epss_percentile") or "") + " (derived_from_epss_score)"
        except Exception as e:
            mapping_report["epss_percentile"] = f"derive_failed:{e}"
    return mapping_report

def safe_bool_series(s, default=False):
    if s is None: return pd.Series([], dtype=bool)
    return s.fillna(str(default)).astype(str).str.strip().str.lower().isin(["1","true","yes","y","t"])

def safe_float_series(s, default=0.0):
    return pd.to_numeric(s, errors="coerce").fillna(default)

def cols_map(df): return {c.lower(): c for c in df.columns}
def find_col(m, *names):
    for n in names:
        if n and n.lower() in m: return m[n.lower()]
    return None

def quantile_calibrate(x: pd.Series) -> pd.Series:
    try:
        r = x.rank(method="average", pct=True)
        if r.notna().sum() == 0: return pd.Series(np.zeros(len(x)))
        return r.fillna(0.0).clip(0,1)
    except Exception:
        return pd.Series(np.zeros(len(x)))

def compute_E(row):
    e = 0.0
    if bool(row.get("kev", False)):        e += 40
    if bool(row.get("has_poc", False)):    e += 20
    if bool(row.get("attackerkb", False)): e += 15
    e += float(row.get("epss_percentile", 0.0))*25  
    return min(100.0, e)

def compute_I(row):
    cvss = float(row.get("cvss_base", 0.0))
    i = (cvss/10.0)*100.0
    cwe = str(row.get("cwe_id","")).upper()
    if "CWE-119" in cwe: i += 5
    if "CWE-79"  in cwe: i += 2
    return min(100.0, i)

def compute_X(row):
    score = 0.0
    score += 60 if bool(row.get("internet_exposed", DEFAULTS["internet_exposed"])) else 20
    crit = str(row.get("asset_criticality", DEFAULTS["asset_criticality"])).lower()
    score += {"critical":30,"high":20,"medium":10,"low":0}.get(crit,10)
    try:
        cnt = int(float(row.get("affected_count", 0)))
        score += min(10.0, np.log1p(cnt)*2.0)
    except: pass
    return min(100.0, score)

def compute_C(row):
    edr = float(row.get("edr_coverage", DEFAULTS["edr_coverage"]))
    siem= float(row.get("siem_detection", DEFAULTS["siem_detection"]))
    waf = 10.0 if bool(row.get("waf_in_place", False)) else 0.0
    return min(100.0, edr*40.0 + siem*30.0 + waf)

def calc_srs(row):
    srs = WEIGHTS["wE"]*row["E"] + WEIGHTS["wI"]*row["I"] + WEIGHTS["wX"]*row["X"] - WEIGHTS["wC"]*row["C"]
    if bool(row.get("kev", False)) and bool(row.get("internet_exposed", False)): srs = max(srs, 90.0)
    if bool(row.get("ransomware_use", False)): srs = max(srs, 95.0)
    if float(row.get("epss_percentile", 0.0)) >= 0.90: srs = max(srs, 80.0)
    return float(max(0.0, min(100.0, srs)))

def srs_to_level(srs):
    if srs >= LEVEL_THRESH["L4"]: return "L4"
    if srs >= LEVEL_THRESH["L3"]: return "L3"
    if srs >= LEVEL_THRESH["L2"]: return "L2"
    if srs >= LEVEL_THRESH["L1"]: return "L1"
    return "L0"

def estimate_srs_after_patch(row, eff=PATCH_EFFECTIVENESS):
    E_after = row["E"]*(1.0-eff)
    C_after = min(100.0, row["C"] + 5.0)
    srs_after = WEIGHTS["wE"]*E_after + WEIGHTS["wI"]*row["I"] + WEIGHTS["wX"]*row["X"] - WEIGHTS["wC"]*C_after
    return float(max(0.0, min(100.0, srs_after)))

def compute_cost_K(row):
    comp = str(row.get("implementation_complexity", DEFAULTS["implementation_complexity"])).lower()
    if comp == "low": k = 10
    elif comp == "high": k = 45
    else: k = 25
    if bool(row.get("reboot_required", DEFAULTS["reboot_required"])): k += 10
    dep = str(row.get("dependency_risk", DEFAULTS["dependency_risk"])).lower()
    if dep == "high": k += 25
    elif dep == "medium": k += 10
    if not bool(row.get("rollback_ready", DEFAULTS["rollback_ready"])): k += 20
    return float(min(100.0, k))

def compute_pvs_terms(row):
    if bool(row.get("has_patch", False)):
        srs_after = estimate_srs_after_patch(row, eff=PATCH_EFFECTIVENESS)
    else:
        srs_after = max(0.0, row["srs"] - NO_PATCH_COMP_CTRL_GAIN*row["srs"])
    delta = max(0.0, row["srs"] - srs_after)

    S_boost = 0.0
    due = str(row.get("kev_due_date","")).strip()
    if bool(row.get("kev", False)) and due:
        for fmt in ("%Y-%m-%d","%m/%d/%Y","%Y/%m/%d"):
            try:
                d = datetime.strptime(due, fmt)
                days = (d - datetime.now(timezone.utc).replace(tzinfo=None)).days
                if days <= 14: S_boost += 15
                elif days <= 30: S_boost += 8
                break
            except: pass

    K_total = compute_cost_K(row)
    B_gain = BUNDLE_GAIN_PER_HIT if bool(row.get("bundle_opportunity", DEFAULTS["bundle_opportunity"])) else 0.0

    raw = PVS_PARAMS["a"]*delta + PVS_PARAMS["b"]*S_boost - PVS_PARAMS["c"]*K_total + PVS_PARAMS["d"]*B_gain
    pvs = (raw + 100.0) * 100.0 / 300.0
    pvs = float(max(0.0, min(100.0, pvs)))
    return pvs, float(delta), float(K_total), float(S_boost), float(B_gain)

def compute_rho(row):
    agree_bits = [
        float(bool(row.get("kev", False))),
        float(bool(row.get("has_poc", False))),
        float(bool(row.get("attackerkb", False))),
        float(float(row.get("epss_percentile", 0.0)) >= AGREE_EPS_THRESH),
    ]
    agree = np.mean(agree_bits)

    age_days = row.get("last_seen_days", None)
    try:
        age_days = float(age_days) if age_days is not None else AGE_FALLBACK_DAYS
        age_days = max(0.0, age_days)
    except Exception:
        age_days = AGE_FALLBACK_DAYS
    lam = math.log(2.0) / max(1e-6, RECENCY_HALFLIFE_DAYS)  # ln2/half-life
    recency = math.exp(-lam * age_days)

    noise = row.get("evidence_conflict", NOISE_DEFAULT)
    try:
        noise = float(noise)
        noise = min(max(noise, 0.0), 1.0)
    except Exception:
        noise = NOISE_DEFAULT

    rho = agree * recency * (1.0 - noise)
    rho = max(rho, RHO_BASELINE)   
    return float(min(max(rho, 0.0), 1.0))

def score_all(df):
    mapping_report = normalize_columns(df)
    print("Column normalization (canonical <- source):")
    for k, v in sorted(mapping_report.items()):
        print(f"  {k:22s} <- {v}")

    m = cols_map(df)
    def col(*names): return find_col(m, *names)

    # CVSS
    cvss_col = col("cvss_base","cvss","cvss_v3_base","basescore","base_score")
    df["cvss_base"] = safe_float_series(df[cvss_col]) if cvss_col else 0.0

    # EPSS：Prioritize percentile, otherwise score -> percentile calibration
    epss_p = col("epss_percentile","epss_pctl","epss_p","epss_percent")
    epss_s = col("epss_score","epss")
    if epss_p:
        df["epss_percentile"] = safe_float_series(df[epss_p]).clip(0,1)
    elif epss_s:
        s = safe_float_series(df[epss_s])
        df["epss_percentile"] = s.clip(0,1) if s.max() <= 1.0 else quantile_calibrate(s)
    else:
        df["epss_percentile"] = 0.0

    def set_bool(name, default, *aliases):
        c = col(*aliases)
        df[name] = safe_bool_series(df[c], default=default) if c else default

    set_bool("kev", False, "kev","is_kev","in_kev","cisa_kev","is_cisa")
    set_bool("has_poc", False, "has_poc","poc","has_exploit","exploit_poc","has_exploit_ref")
    set_bool("attackerkb", False, "attackerkb","akb","has_attackerkb")
    set_bool("has_patch", False, "has_patch","patch_available","patch","triage_hint")
    set_bool("ransomware_use", False, "ransomware_use","known_ransomware_campaign_use","ransomware")
    set_bool("internet_exposed", DEFAULTS["internet_exposed"], "internet_exposed","internet_exposure","is_external","externally_facing","network_exploitable")
    set_bool("waf_in_place", False, "waf_in_place","waf","has_waf")
    set_bool("rollback_ready", DEFAULTS["rollback_ready"], "rollback_ready","has_rollback")
    set_bool("reboot_required", DEFAULTS["reboot_required"], "reboot_required","needs_reboot","reboot")
    set_bool("bundle_opportunity", DEFAULTS["bundle_opportunity"], "bundle_opportunity","bundle")

    acrit = col("asset_criticality","business_criticality","asset_tier")
    df["asset_criticality"] = df[acrit].fillna(DEFAULTS["asset_criticality"]) if acrit else DEFAULTS["asset_criticality"]

    edr = col("edr_coverage","edr","edr_cov")
    df["edr_coverage"] = safe_float_series(df[edr]) if edr else DEFAULTS["edr_coverage"]

    siem = col("siem_detection","siem_cov")
    df["siem_detection"] = safe_float_series(df[siem]) if siem else DEFAULTS["siem_detection"]

    cwe = col("cwe_id","cwe","cwe_list")
    df["cwe_id"] = df[cwe].fillna("") if cwe else ""

    aff = col("affected_count","deployment_scope","affected_assets")
    try: df["affected_count"] = safe_float_series(df[aff]).fillna(0).astype(int) if aff else 0
    except: df["affected_count"] = 0

    due = col("kev_due_date","due_date")
    df["kev_due_date"] = df[due].fillna("") if due else ""

    for g in ["product","vendor","cpe23uri","cpe","package_name","component"]:
        if col(g):
            df[g] = df[col(g)]
        else:
            df[g] = ""
          
    df["E"] = df.apply(compute_E, axis=1)
    df["I"] = df.apply(compute_I, axis=1)
    df["X"] = df.apply(compute_X, axis=1)
    df["C"] = df.apply(compute_C, axis=1)

    df["srs"] = df.apply(calc_srs, axis=1)
    df["level"] = df["srs"].apply(srs_to_level)

    pvs_terms = df.apply(compute_pvs_terms, axis=1, result_type="expand")
    df["pvs"] = pvs_terms[0]
    df["delta_risk"] = pvs_terms[1]
    df["K_total"] = pvs_terms[2]
    df["S_boost"] = pvs_terms[3]
    df["B_gain"] = pvs_terms[4]

    # Uncertainty rho and rho*ΔRisk
    df["rho"] = df.apply(compute_rho, axis=1)
    df["rho_delta"] = df["rho"] * df["delta_risk"]

    df["action"] = df.apply(lambda r: action_route(r["level"], r["pvs"]), axis=1)
    return df

def action_route(level, pvs):
    if level == "L4":
        if pvs >= 70: return "EMERGENCY: hotfix/isolate -> canary -> rolling"
        if pvs >= 40: return "FAST: compensate -> fast-window patch"
        return "ISOLATE & REVIEW"
    if level == "L3":
        if pvs >= 60: return "HIGH: blue-green/rolling in 72h"
        if pvs >= 30: return "SCHEDULE: bundle in near window"
        return "COMPENSATE -> monthly"
    if level == "L2":
        if pvs >= 50: return "BUNDLE in next window"
        return "REGULAR release"
    return "MONTHLY or accept risk w/ monitoring"

def greedy_topk(df_scores, k=20):
    eps = 1e-6
    tmp = df_scores.copy()
    tmp["ratio"] = tmp["rho_delta"] / (tmp["K_total"] + eps)
    return tmp.sort_values(["ratio","rho_delta","pvs","srs"], ascending=False).head(k)

def bundle_key(row):
    key = "|".join([
        str(row.get("vendor","")).strip().lower(),
        str(row.get("product","")).strip().lower(),
        str(row.get("package_name","")).strip().lower(),
        str(row.get("component","")).strip().lower(),
        str(row.get("cpe23uri","")).strip().lower()
    ])
    return key

def bundle_marginal_gain(current_groups, cand_row):
    key = bundle_key(cand_row)
    return BUNDLE_GAIN_PER_HIT if (key and key not in current_groups) else 0.0

def greedy_budget_portfolio(df_scores, budget=BUDGET_K):
    eps = 1e-6
    used = set()
    picked_rows = []
    cost_sum = 0.0
    covered_groups = set()

    df = df_scores.copy().reset_index(drop=True)
    while True:
        best_idx, best_ratio, best_row = None, -1.0, None
        for i, r in df.iterrows():
            if i in used: continue
            k = float(r["K_total"])
            if cost_sum + k > budget: continue
            mg = float(r["rho_delta"]) + bundle_marginal_gain(covered_groups, r)
            ratio = mg / (k + eps)
            if (ratio > best_ratio) or (
                math.isclose(ratio, best_ratio) and
                (mg, r["pvs"], r["srs"]) >
                ((0.0,0.0,0.0) if best_row is None else (float(best_row["rho_delta"]), float(best_row["pvs"]), float(best_row["srs"])))
            ):
                best_idx, best_ratio, best_row = i, ratio, r

        if best_idx is None: break
        used.add(best_idx)
        picked_rows.append(best_row)
        cost_sum += float(best_row["K_total"])
        key = bundle_key(best_row)
        if key: covered_groups.add(key)

    if not picked_rows:
        return pd.DataFrame(columns=df.columns)
    return pd.DataFrame(picked_rows)

def main():
    df = load_super_table()
    scored = score_all(df)

    id_col = None
    for c in ["cve_id","CVE_ID","cve","vuln_id","id"]:
        if c in scored.columns:
            id_col = c; break

    cols = ([id_col] if id_col else []) + [
        "cvss_base","srs","level","pvs","action",
        "E","I","X","C","delta_risk","rho","rho_delta",
        "K_total","S_boost","B_gain",
        "epss_percentile","kev","has_poc","attackerkb",
        "internet_exposed","asset_criticality",
        "vendor","product","package_name","component","cpe23uri"
    ]
    cols = [c for c in cols if c in scored.columns]
    os.makedirs(os.path.dirname(OUT_SCORES_CSV), exist_ok=True)
    scored[cols].to_csv(OUT_SCORES_CSV, index=False)

    # explain（timezone-aware）
    with open(OUT_EXPLAIN_JSONL,"w",encoding="utf-8") as f:
        for _, r in scored.iterrows():
            ex = {
                "id": str(r[id_col]) if id_col else "",
                "E": round(float(r["E"]),2), "I": round(float(r["I"]),2),
                "X": round(float(r["X"]),2), "C": round(float(r["C"]),2),
                "srs": round(float(r["srs"]),2), "level": r["level"],
                "pvs": round(float(r["pvs"]),2),
                "pvs_terms": {
                    "delta_risk": round(float(r["delta_risk"]),2),
                    "rho": round(float(r["rho"]),2),
                    "rho_delta": round(float(r["rho_delta"]),2),
                    "K_total": round(float(r["K_total"]),2),
                    "S_boost": round(float(r["S_boost"]),2),
                    "B_gain": round(float(r["B_gain"]),2),
                },
                "weights": WEIGHTS, "pvs_params": PVS_PARAMS,
                "policy_version": POLICY_VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
            }
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # Top-K
    for k in TOPK_LIST:
        topk_df = greedy_topk(scored, k=k)
        outp = OUT_TOP20_CSV if k == 20 else (OUT_TOP30_CSV if k == 30 else f"{os.path.splitext(OUT_TOP20_CSV)[0]}_{k}.csv")
        topk_df.to_csv(outp, index=False)

    # Portfolio with budget (total K ≤ BUDGET_K)
    portfolio = greedy_budget_portfolio(scored, budget=BUDGET_K)
    portfolio.to_csv(OUT_PORT_BUDGET_CSV, index=False)

    print(f"[OK] Wrote:\n  {OUT_SCORES_CSV}\n  {OUT_EXPLAIN_JSONL}\n  {OUT_TOP20_CSV}\n  {OUT_TOP30_CSV}\n  {OUT_PORT_BUDGET_CSV}")

if __name__ == "__main__":
    main()
