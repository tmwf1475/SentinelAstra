import requests
from datetime import datetime, timedelta
from pathlib import Path
import gzip
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

START_DATE = "your_date"
END_DATE = "your_date"
OUTDIR = Path("your_path")
URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"
WORKERS = 6        
TIMEOUT = 30       
RETRIES = 2        
BACKOFF = 2.0      
OVERWRITE = False  
KEEP_GZ = False     


def daterange(start_date, end_date):
    d = start_date
    while d <= end_date:
        yield d
        d += timedelta(days=1)


def download_one(date_obj):
    datestr = date_obj.isoformat()
    gz_path = OUTDIR / f"epss-{datestr}.csv.gz"
    csv_path = OUTDIR / f"epss-{datestr}.csv"

    if csv_path.exists() and not OVERWRITE:
        return (datestr, "skipped", "csv exists")

    url = URL_TEMPLATE.format(date=datestr)
    last_err = None
    for attempt in range(1, RETRIES + 2):  
        try:
            resp = requests.get(url, timeout=TIMEOUT)
            if resp.status_code == 200 and resp.content:
                OUTDIR.mkdir(parents=True, exist_ok=True)
                gz_path.write_bytes(resp.content)
                with gzip.open(gz_path, "rb") as f_in, open(csv_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                if not KEEP_GZ:
                    gz_path.unlink(missing_ok=True)
                return (datestr, "ok", "")
            elif resp.status_code == 404:
                last_err = "404 not found"
                break 
            else:
                last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)
        time.sleep(BACKOFF * attempt)
    return (datestr, "failed", last_err)


def main():
    sdate = datetime.fromisoformat(START_DATE).date()
    edate = datetime.fromisoformat(END_DATE).date()
    dates = list(daterange(sdate, edate))
    OUTDIR.mkdir(parents=True, exist_ok=True)

    print(f"Downloading EPSS:{START_DATE} → {END_DATE}（Total {len(dates)} days）")
    print(f"Output Directory：{OUTDIR}")
    print(f"Workers: {WORKERS}, Timeout: {TIMEOUT}s, Retries: {RETRIES}\n")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(download_one, d): d for d in dates}
        for fut in as_completed(futures):
            d = futures[fut]
            try:
                date_str, status, msg = fut.result()
            except Exception as e:
                date_str = d.isoformat()
                status, msg = "failed", str(e)
            results.append((date_str, status, msg))
            print(f"[{date_str}] {status} {msg}")

    ok_count = sum(1 for _, s, _ in results if s == "ok")
    skipped = sum(1 for _, s, _ in results if s == "skipped")
    failed = sum(1 for _, s, _ in results if s == "failed")
    print("\nStatistics:")
    print(f" Success: {ok_count}")
    print(f" Skipped: {skipped}")
    print(f" Failed: {failed}")
    if failed > 0:
        print("\nFailed List:")
        for d, s, m in sorted(results):
            if s == "failed":
                print(f"  - {d}: {m}")


if __name__ == "__main__":
    main()
