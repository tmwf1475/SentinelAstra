from pathlib import Path
import pandas as pd
import numpy as np
import json, re, sys, math
from typing import List, Optional, Iterable, Dict

ROOT = Path("your_path")
YEARS: List[str] = ["2024", "2025"]

EPSS_PATH = Path("your_path")

OUT_PREFIX = "cve_master_2024_2025_enriched"

SEARCH_EXTS = (".json", ".jsonl", ".csv", ".parquet", ".txt", ".md")
EXPLOIT_DB_URL = "https://www.exploit-db.com/exploits/{id}"

# Preliminary weighting of risk score
W_EPSS = 0.7
W_CVSS = 0.3

CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

def read_json(fp: Path):
    try:
        text = fp.read_text(encoding="utf-8", errors="ignore")
        return json.loads(text)
    except Exception:
        return None


def normalize_cve(s: str) -> Optional[str]:
    if not isinstance(s, str):
        return None
    m = CVE_RE.search(s)
    if not m:
        return None
    return m.group(1).upper()


def iter_files(base: Path, years: Iterable[str]) -> Iterable[Path]:
    for y in years:
        d = base / y
        if not d.exists():
            continue
        for fp in d.rglob("*"):
            if fp.is_file() and fp.suffix.lower() in SEARCH_EXTS:
                yield fp


def read_any(fp: Path) -> pd.DataFrame:
    try:
        suf = fp.suffix.lower()
        if suf == ".parquet":
            return pd.read_parquet(fp)
        if suf == ".jsonl":
            return pd.read_json(fp, lines=True)
        if suf == ".csv":
            return pd.read_csv(fp)
        if suf == ".json":
            raw = read_json(fp)
            if raw is None:
                return pd.DataFrame()
            if isinstance(raw, dict):
                return pd.json_normalize(raw)
            if isinstance(raw, list):
                return pd.json_normalize(raw)
        if suf in (".txt", ".md"):
            text = fp.read_text(encoding="utf-8", errors="ignore")
            urls = URL_RE.findall(text)
            if urls:
                cve = normalize_cve(fp.name) or normalize_cve(text)
                if cve:
                    return pd.DataFrame([{"cve_id": cve, "urls_extracted": urls}])
    except Exception:
        return pd.DataFrame()
    return pd.DataFrame()


def to_list(x):
    # None / NaN
    if x is None:
        return []
    # pandas's NaN / NA
    try:
        if isinstance(x, float) and pd.isna(x):
            return []
    except Exception:
        pass

    # list: The processing may involve dict / list.
    if isinstance(x, list):
        cleaned = []
        seen_hashable = set()
        for i in x:
            # Skip NA types (non-dict/list)
            is_na = False
            if not isinstance(i, (dict, list, set)):
                try:
                    if pd.isna(i):
                        is_na = True
                except Exception:
                    is_na = False
            if is_na:
                continue

            # dict / list / set: retain but do not deduplicate, to avoid the unhashable problem.
            if isinstance(i, (dict, list, set)):
                cleaned.append(i)
            else:
                # Only hashable data is deduplicated.
                if i not in seen_hashable:
                    seen_hashable.add(i)
                    cleaned.append(i)
        return cleaned

    # 字串：可能是 JSON list
    if isinstance(x, str):
        s = x.strip()
        if s.startswith("[") and s.endswith("]"):
            try:
                return to_list(json.loads(s))
            except Exception:
                pass
        return [s]

    # Other types: directly packaged into a list
    return [x]


def safe_str(x):
    return x if isinstance(x, str) else ("" if x is None else str(x))


# ---------- 1. cve-database ----------

def load_cve_database() -> pd.DataFrame:
    base = ROOT / "cve-database"
    items = []
    used = 0
    for fp in iter_files(base, YEARS):
        df = read_any(fp)
        if df.empty:
            continue
        if "cve_id" not in df.columns:
            cid = normalize_cve(fp.name)
            if cid:
                df["cve_id"] = cid
        if "cve_id" not in df.columns:
            continue
        items.append(df)
        used += 1
    print(f"[LOAD] cve-database: files_used={used}, rows_total_approx={sum(len(x) for x in items)}")
    if not items:
        return pd.DataFrame(columns=["cve_id"])
    out = pd.concat(items, ignore_index=True, copy=False)
    out["cve_id"] = out["cve_id"].astype(str).str.strip().str.upper()

    for old, new in [
        ("published", "published_date"),
        ("publishedDate", "published_date"),
        ("lastModified", "last_modified"),
    ]:
        if old in out.columns and new not in out.columns:
            out = out.rename(columns={old: new})

    for col in ("cwe_list", "cpe_list", "references"):
        if col in out.columns:
            out[col] = out[col].apply(to_list)
        else:
            out[col] = [[] for _ in range(len(out))]

    return out


# ---------- 2. nvd-database (CVSS + description + CWE + CPE) ----------

def extract_cvss_from_json(raw: dict) -> Dict[str, Optional[object]]:
    base = None
    vec = None

    def pick(d):
        nonlocal base, vec
        if not isinstance(d, dict):
            return
        # New format: metrics.cvssMetricV31/30/2
        metrics = d.get("metrics") or d
        if isinstance(metrics, dict):
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key)
                if isinstance(arr, list) and arr:
                    obj = arr[0]
                    cd = obj.get("cvssData") or obj.get("cvssV3") or obj
                    base = base or cd.get("baseScore") or cd.get("base_score")
                    vec = vec or cd.get("vectorString") or cd.get("vector")
        # Old format: impact.baseMetricV3.cvssV3
        impact = d.get("impact")
        if isinstance(impact, dict):
            bm3 = impact.get("baseMetricV3") or impact.get("cvssMetricV31") or impact.get("cvss")
            if isinstance(bm3, dict):
                cv3 = bm3.get("cvssV3") or bm3.get("cvssData") or bm3.get("cvss")
                if isinstance(cv3, dict):
                    base = base or cv3.get("baseScore")
                    vec = vec or cv3.get("vectorString")
            bm2 = impact.get("baseMetricV2") or impact.get("cvssMetricV2")
            if isinstance(bm2, dict):
                cd = bm2.get("cvssData") or bm2
                base = base or cd.get("baseScore")
                vec = vec or cd.get("vectorString")

    pick(raw)
    for k in ("result", "vulnerabilities", "cve"):
        v = raw.get(k)
        if isinstance(v, dict):
            pick(v)

    if base is None or vec is None:
        try:
            s = json.dumps(raw)
            m = re.search(r'"baseScore"\s*:\s*([0-9.]+)', s)
            if m and base is None:
                base = float(m.group(1))
            m = re.search(r'"vectorString"\s*"\s*:\s*"([^"]+)"', s)
            if m and vec is None:
                vec = m.group(1)
        except Exception:
            pass

    return {"cvss_base_score": base, "cvss_vector": vec}


def extract_nvd_enriched(raw: dict) -> Dict[str, Optional[object]]:
    info = extract_cvss_from_json(raw)
    description: Optional[str] = None
    cwe_list: List[str] = []
    cpe_list: List[str] = []

    def get_cve_obj(d: dict) -> dict:
        if not isinstance(d, dict):
            return {}
        vulns = d.get("vulnerabilities")
        if isinstance(vulns, list) and vulns:
            v0 = vulns[0]
            if isinstance(v0, dict):
                cve = v0.get("cve") or v0
                if isinstance(cve, dict):
                    return cve
        cve = d.get("cve")
        if isinstance(cve, dict):
            return cve
        return d

    cve = get_cve_obj(raw)

    # description
    desc_field = cve.get("descriptions") or cve.get("description")
    if isinstance(desc_field, list):
        en_vals = [
            x.get("value")
            for x in desc_field
            if isinstance(x, dict) and str(x.get("lang", "")).lower() == "en" and x.get("value")
        ]
        any_vals = [x.get("value") for x in desc_field if isinstance(x, dict) and x.get("value")]
        if en_vals:
            description = en_vals[0]
        elif any_vals:
            description = any_vals[0]
    elif isinstance(desc_field, dict):
        v = desc_field.get("value")
        if isinstance(v, str) and v:
            description = v
    elif isinstance(desc_field, str) and desc_field:
        description = desc_field

    # CWE list
    weaknesses = cve.get("weaknesses") or []
    if isinstance(weaknesses, list):
        for w in weaknesses:
            if not isinstance(w, dict):
                continue
            descs = w.get("description") or w.get("descriptions") or []
            if isinstance(descs, list):
                for d in descs:
                    if not isinstance(d, dict):
                        continue
                    val = d.get("value") or d.get("cweId")
                    if isinstance(val, str) and "CWE-" in val:
                        cwe_list.append(val.strip())
            cid = w.get("cweId")
            if isinstance(cid, str) and "CWE-" in cid:
                cwe_list.append(cid.strip())

    # CPE list
    def collect_cpe(obj):
        if isinstance(obj, dict):
            crit = obj.get("criteria") or obj.get("cpe23Uri") or obj.get("cpe23uri")
            if isinstance(crit, str) and crit.startswith("cpe:"):
                cpe_list.append(crit)
            for key in ("nodes", "children", "cpeMatch", "cpe_match"):
                child = obj.get(key)
                if isinstance(child, list):
                    for it in child:
                        collect_cpe(it)
        elif isinstance(obj, list):
            for it in obj:
                collect_cpe(it)

    conf = raw.get("configurations") or raw.get("config") or {}
    collect_cpe(conf)

    cwe_list = sorted({x for x in cwe_list if x})
    cpe_list = sorted({x for x in cpe_list if x})

    info.update(
        {
            "description": description,
            "cwe_list": cwe_list,
            "cpe_list": cpe_list,
        }
    )
    return info


def load_nvd_database() -> pd.DataFrame:
    base = ROOT / "nvd-database"
    rows: List[Dict[str, object]] = []
    scanned = 0

    for y in YEARS:
        year_dir = base / f"CVE-{y}"
        if not year_dir.exists():
            continue
        for fp in year_dir.rglob("*.json"):
            scanned += 1
            raw = read_json(fp)
            if not raw:
                continue

            # First, try to retrieve the data from the JSON file; if that's not found, then try to deduce the data from the filename/path.
            cid = (
                normalize_cve(json.dumps(raw))
                or normalize_cve(fp.stem)
                or normalize_cve(fp.name)
                or normalize_cve(" ".join(fp.parts))
            )
            if not cid:
                continue

            info = extract_nvd_enriched(raw)
            rows.append({"cve_id": cid, **info})

    print(f"[LOAD] nvd-database: files_scanned={scanned}, rows_extracted={len(rows)}")

    if not rows:
        return pd.DataFrame(
            columns=["cve_id", "cvss_base_score", "cvss_vector", "description", "cwe_list", "cpe_list"]
        )

    nvd = pd.DataFrame(rows)
    nvd["cve_id"] = nvd["cve_id"].astype(str).str.upper()

    def merge_list_series(s: pd.Series) -> List[str]:
        acc: List[str] = []
        for v in s:
            if isinstance(v, list):
                acc.extend(v)
            elif isinstance(v, str) and v:
                acc.append(v)
        seen = set()
        out: List[str] = []
        for x in acc:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    agg = {
        "cvss_base_score": "max",
        "cvss_vector": "first",
        "description": "first",
        "cwe_list": merge_list_series,
        "cpe_list": merge_list_series,
    }
    existing_cols = {k: v for k, v in agg.items() if k in nvd.columns}
    if existing_cols:
        nvd = nvd.groupby("cve_id", as_index=False).agg(existing_cols)
    else:
        nvd = nvd.drop_duplicates(subset=["cve_id"])
    return nvd


    def merge_list_series(s: pd.Series) -> List[str]:
        acc: List[str] = []
        for v in s:
            if isinstance(v, list):
                acc.extend(v)
            elif isinstance(v, str) and v:
                acc.append(v)
        seen = set()
        out: List[str] = []
        for x in acc:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    agg = {
        "cvss_base_score": "max",
        "cvss_vector": "first",
        "description": "first",
        "cwe_list": merge_list_series,
        "cpe_list": merge_list_series,
    }
    existing_cols = {k: v for k, v in agg.items() if k in nvd.columns}
    if existing_cols:
        nvd = nvd.groupby("cve_id", as_index=False).agg(existing_cols)
    else:
        nvd = nvd.drop_duplicates(subset=["cve_id"])
    return nvd


# ---------- 3. exploit-db-database (PoC) ----------

def load_exploit_db() -> pd.DataFrame:
    base = ROOT / "exploit-db-database"
    fed = base / "files_exploits.json"
    rows = []
    if fed.exists():
        try:
            data = json.loads(fed.read_text(encoding="utf-8", errors="ignore"))
            it = list(data.values()) if isinstance(data, dict) else data
            for rec in it:
                if not isinstance(rec, dict):
                    continue
                cves = rec.get("cve") or rec.get("CVE") or rec.get("cves")
                lst = to_list(cves)
                if not lst:
                    for f in ("description", "file"):
                        if isinstance(rec.get(f), str):
                            lst += [m.upper() for m in CVE_RE.findall(rec[f])]
                lst = sorted({c.upper() for c in lst if str(c).upper().startswith("CVE-")})
                if not lst:
                    continue
                eid = rec.get("id") or rec.get("exploitdb_id") or rec.get("edb-id") or rec.get("edb_id")
                url = None
                if eid:
                    try:
                        url = EXPLOIT_DB_URL.format(id=int(eid))
                    except Exception:
                        url = EXPLOIT_DB_URL.format(id=str(eid))
                if not url:
                    url = rec.get("url") or rec.get("source")
                if not url:
                    continue
                for cv in lst:
                    rows.append({"cve_id": cv, "poc_urls": [url]})
        except Exception as e:
            print(f"[WARN] files_exploits.json parse failed: {e}")

    exd = base / "exploits"
    if exd.exists():
        for fp in exd.rglob("*"):
            if fp.is_file() and fp.suffix.lower() in (".txt", ".py", ".c", ".rb", ".sh", ".php", ".js", ".md", ".json"):
                txt = fp.read_text(encoding="utf-8", errors="ignore")
                found = {m.upper() for m in CVE_RE.findall(txt)}
                if found:
                    url = f"file://{fp}"
                    for cv in found:
                        rows.append({"cve_id": cv, "poc_urls": [url]})
    if not rows:
        print("[LOAD] exploit-db-database: no rows found")
        return pd.DataFrame(columns=["cve_id", "poc_urls", "has_exploit_ref"])
    exp = pd.DataFrame(rows)
    exp = exp.groupby("cve_id", as_index=False).agg(
        {"poc_urls": lambda s: sorted(list({u for lst in s for u in lst if u}))}
    )
    exp["has_exploit_ref"] = exp["poc_urls"].apply(lambda x: len(x) > 0)
    print(f"[LOAD] exploit-db-database: rows={len(exp)}")
    return exp


# ---------- 4. patch-database ----------

def load_patch_database() -> pd.DataFrame:
    base = ROOT / "patch-database"
    if not base.exists():
        print("[LOAD] patch-database: directory not found, skip")
        return pd.DataFrame(columns=["cve_id", "patch_refs", "patch_sources", "patch_descriptions", "has_patch"])

    rows = []
    files_used = 0

    for y in YEARS:
        year_dir = base / y
        if not year_dir.exists():
            continue

        # Each CVE-YYYY-NNNN folder
        for cve_dir in sorted(p for p in year_dir.iterdir() if p.is_dir()):
            cid = normalize_cve(cve_dir.name)
            if not cid:
                continue

            urls: List[str] = []
            # For now, we won't specifically extract vendor/description entries; we'll leave the list empty.
            patch_sources: List[str] = []
            patch_descriptions: List[str] = []

            # Scan all files under this CVE folder (including hash files without extensions).
            for fp in cve_dir.rglob("*"):
                if fp.is_dir():
                    continue
                files_used += 1
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                urls.extend(URL_RE.findall(text))

            urls = sorted(set(urls))

            # As long as this CVE folder exists, it is considered that has_patch=True.
            rows.append(
                {
                    "cve_id": cid,
                    "patch_refs": urls,             
                    "patch_sources": patch_sources, 
                    "patch_descriptions": patch_descriptions,
                    "has_patch": True,
                }
            )

    if not rows:
        print("[LOAD] patch-database: no usable patch rows found")
        return pd.DataFrame(columns=["cve_id", "patch_refs", "patch_sources", "patch_descriptions", "has_patch"])

    patch = pd.DataFrame(rows)
    print(f"[LOAD] patch-database: cve_dirs={len(patch)}, files_used={files_used}")

    def merge_list(col_series: pd.Series) -> List[str]:
        acc: List[str] = []
        for v in col_series:
            acc.extend(to_list(v))
        seen = set()
        out: List[str] = []
        for x in acc:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    patch = patch.groupby("cve_id", as_index=False).agg(
        {
            "patch_refs": merge_list,
            "patch_sources": merge_list,
            "patch_descriptions": merge_list,
            "has_patch": "max",  # If at least one column is True, then it is True.
        }
    )

    # Ensure that has_patch is a bool
    patch["has_patch"] = patch["has_patch"].fillna(False).map(bool)

    print(f"[LOAD] patch-database: merged_rows={len(patch)}")
    return patch

    def merge_list(col_series: pd.Series) -> List[str]:
        acc: List[str] = []
        for v in col_series:
            acc.extend(to_list(v))
        # Deduplication while maintaining order
        seen = set()
        out: List[str] = []
        for x in acc:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    patch = patch.groupby("cve_id", as_index=False).agg(
        {
            "patch_refs": merge_list,
            "patch_sources": merge_list,
            "patch_descriptions": merge_list,
        }
    )
    patch["has_patch"] = patch["patch_refs"].apply(lambda x: len(x) > 0)
    print(f"[LOAD] patch-database: merged_rows={len(patch)}")
    return patch


# ---------- 5. Derivative Positions & Preliminary Risk Calculation ----------

def cvss_sev(score):
    if score is None or (isinstance(score, float) and math.isnan(score)):
        return "NA"
    try:
        s = float(score)
    except Exception:
        return "NA"
    if s >= 9:
        return "Critical"
    if s >= 7:
        return "High"
    if s >= 4:
        return "Medium"
    if s > 0:
        return "Low"
    return "None"


def epss_bucket(p):
    if p is None or (isinstance(p, float) and math.isnan(p)):
        return "NA"
    try:
        v = float(p)
    except Exception:
        return "NA"
    if v >= 0.9:
        return "very_high"
    if v >= 0.7:
        return "high"
    if v >= 0.4:
        return "medium"
    if v > 0:
        return "low"
    return "none"


# ---------- main ----------

def main():
    print("=== Merge & Enrich (v2+) : VulZoo 2024-2025 + NVD + ExploitDB + PatchDB + EPSS ===")

    cve = load_cve_database()
    print(f"[OK] cve rows={len(cve)}")

    nvd = load_nvd_database()
    print(f"[OK] nvd rows={len(nvd)}")

    exp = load_exploit_db()
    print(f"[OK] exploit rows={len(exp)}")

    patch = load_patch_database()
    print(f"[OK] patch rows={len(patch)}")

    if not EPSS_PATH.exists():
        print(f"[ERROR] EPSS file not found: {EPSS_PATH}")
        sys.exit(1)
    epss = pd.read_parquet(EPSS_PATH)
    epss["cve_id"] = epss["cve_id"].astype(str).str.upper()
    if "epss_model_used" not in epss.columns:
        epss["epss_model_used"] = "unknown"
    print(f"[OK] epss rows={len(epss)}")

    # Order: CVE → NVD → Exploit → Patch → EPSS
    df = (
        cve.merge(nvd, on="cve_id", how="left")
        .merge(exp, on="cve_id", how="left")
        .merge(patch, on="cve_id", how="left")
        .merge(epss, on="cve_id", how="left")
    )

    # ---- Merge text / list type fields ----

    # Text field: description
    if "description_x" in df.columns or "description_y" in df.columns:
        def merge_desc(row):
            for col in ("description_x", "description_y", "description"):
                if col in row and isinstance(row[col], str) and row[col].strip():
                    return row[col].strip()
            return None

        df["description"] = df.apply(merge_desc, axis=1)
        df = df.drop(
            columns=[c for c in ("description_x", "description_y") if c in df.columns],
            errors="ignore",
        )

    # List-type fields: cwe_list (possibly derived from cve + nvd)
    cwe_cols = [c for c in df.columns if c.startswith("cwe_list")]
    if cwe_cols:
        def merge_cwe_lists(row):
            merged: List[str] = []
            for col in cwe_cols:
                vals = to_list(row.get(col))
                for v in vals:
                    if v not in merged:
                        merged.append(v)
            return merged

        df["cwe_list"] = df.apply(merge_cwe_lists, axis=1)
        drop_cols = [c for c in cwe_cols if c != "cwe_list"]
        df = df.drop(columns=drop_cols, errors="ignore")
    else:
        df["cwe_list"] = [[] for _ in range(len(df))]

    # cpe_list
    cpe_cols = [c for c in df.columns if c.startswith("cpe_list")]
    if cpe_cols:
        def merge_cpe_lists(row):
            merged: List[str] = []
            for col in cpe_cols:
                vals = to_list(row.get(col))
                for v in vals:
                    if v not in merged:
                        merged.append(v)
            return merged

        df["cpe_list"] = df.apply(merge_cpe_lists, axis=1)
        drop_cols = [c for c in cpe_cols if c != "cpe_list"]
        df = df.drop(columns=drop_cols, errors="ignore")
    else:
        df["cpe_list"] = [[] for _ in range(len(df))]

    # References (from cve-database / nvd, etc.)
    ref_cols = [c for c in df.columns if c.startswith("references")]
    if ref_cols:
        def merge_refs(row):
            merged: List[str] = []
            for col in ref_cols:
                vals = to_list(row.get(col))
                for v in vals:
                    if v not in merged:
                        merged.append(v)
            return merged

        df["references"] = df.apply(merge_refs, axis=1)
        drop_cols = [c for c in ref_cols if c != "references"]
        df = df.drop(columns=drop_cols, errors="ignore")
    else:
        df["references"] = [[] for _ in range(len(df))]

    if "has_exploit_ref" not in df.columns:
        df["has_exploit_ref"] = False
    df["has_exploit_ref"] = df["has_exploit_ref"].fillna(False).map(bool)

    if "patch_refs" not in df.columns:
        df["patch_refs"] = [[] for _ in range(len(df))]
    else:
        df["patch_refs"] = df["patch_refs"].apply(to_list)

    if "patch_sources" not in df.columns:
        df["patch_sources"] = [[] for _ in range(len(df))]
    else:
        df["patch_sources"] = df["patch_sources"].apply(to_list)

    if "patch_descriptions" not in df.columns:
        df["patch_descriptions"] = [[] for _ in range(len(df))]
    else:
        df["patch_descriptions"] = df["patch_descriptions"].apply(to_list)

    if "has_patch" not in df.columns:
        df["has_patch"] = df["patch_refs"].apply(lambda x: len(x) > 0)
    else:
        df["has_patch"] = df["has_patch"].fillna(False).map(bool)

    # Ensure that poc_urls is a list
    df["poc_urls"] = df.get("poc_urls", [[]]).apply(lambda v: to_list(v) if not pd.isna(v) else [])

    # ---- EPSS column cleanup ----
    for col in ("epss_latest", "epss_d7_mean", "epss_d30_max", "epss_trend_7d", "epss_percentile_latest"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if "epss_d7_mean" in df.columns and "epss_latest" in df.columns:
        df["epss_d7_mean"] = df["epss_d7_mean"].fillna(df["epss_latest"])
    if "epss_d30_max" in df.columns:
        df["epss_d30_max"] = df["epss_d30_max"].fillna(df[["epss_latest", "epss_d7_mean"]].max(axis=1))
    if "epss_trend_7d" in df.columns:
        df["epss_trend_7d"] = df["epss_trend_7d"].fillna(0)

    # ---- CVSS Numericalization + Bucket ----
    df["cvss_base_score"] = pd.to_numeric(df.get("cvss_base_score"), errors="coerce")
    df["cvss_severity"] = df["cvss_base_score"].apply(cvss_sev)
    df["epss_bucket"] = df.get("epss_latest").apply(epss_bucket)

    # ---- Risk score v0/v1 ----
    df["risk_score_v0"] = (df.get("epss_latest", 0).fillna(0) * W_EPSS) + (
        df.get("cvss_base_score", 0).fillna(0) / 10.0 * W_CVSS
    )

    # Is it AV:N (network_exploitable)?
    df["network_exploitable"] = df.get("cvss_vector", "").apply(lambda v: "AV:N" in safe_str(v))

    def is_priv_esc(vec):
        v = safe_str(vec)
        return any(tag in v for tag in ["PR:L", "PR:N"]) and (
            "S:U" in v or "C:H" in v or "I:H" in v or "A:H" in v
        )

    df["priv_esc"] = df.get("cvss_vector", "").apply(is_priv_esc)
    df["has_poc_bonus"] = df["has_exploit_ref"].astype(int)
    poc_w, net_w = 0.05, 0.05
    df["risk_score_v1"] = (
        df["risk_score_v0"]
        + df["has_poc_bonus"] * poc_w
        + df["network_exploitable"].astype(int) * net_w
    ).clip(0, 1)

    def triage_hint(row):
        s = []
        rs = row.get("risk_score_v1", 0)
        s.append("High" if rs >= 0.75 else ("Medium" if rs >= 0.40 else "Low"))
        if row.get("network_exploitable"):
            s.append("AV:N")
        if row.get("has_exploit_ref"):
            s.append("PoC")
        if row.get("has_patch"):
            s.append("Patch")
        if row.get("cvss_severity") in ("Critical", "High"):
            s.append(row.get("cvss_severity"))
        if isinstance(row.get("epss_model_used"), str) and row["epss_model_used"] != "unknown":
            s.append(row["epss_model_used"])
        return "|".join(s)

    df["triage_hint"] = df.apply(triage_hint, axis=1)

    keep = [
        "cve_id",
        "published_date",
        "last_modified",
        "description",
        "cwe_list",
        "cpe_list",
        "references",
        "cvss_base_score",
        "cvss_vector",
        "cvss_severity",
        "has_exploit_ref",
        "poc_urls",
        "network_exploitable",
        "priv_esc",
        "patch_refs",
        "patch_sources",
        "patch_descriptions",
        "has_patch",
        "epss_latest",
        "epss_percentile_latest",
        "epss_d7_mean",
        "epss_d30_max",
        "epss_trend_7d",
        "epss_data_points",
        "epss_model_used",
        "epss_bucket",
        "risk_score_v0",
        "risk_score_v1",
        "triage_hint",
    ]
    for k in keep:
        if k not in df.columns:
            df[k] = None
    final = df[keep].drop_duplicates(subset=["cve_id"]).reset_index(drop=True)

    out_csv = ROOT / f"{OUT_PREFIX}.csv"
    out_parquet = ROOT / f"{OUT_PREFIX}.parquet"
    final.to_csv(out_csv, index=False)
    final.to_parquet(out_parquet, index=False)
    print(f"[DONE] wrote: {out_csv}, {out_parquet}")


if __name__ == "__main__":
    main()
