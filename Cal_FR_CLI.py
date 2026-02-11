#!/usr/bin/env python3
"""CLI version of the Testing Summary Tool for WSL environments."""

import os
import sys
import argparse
import threading
import queue
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Use lxml for faster HTML parsing if available, fallback to html.parser
try:
    import lxml  # noqa: F401
    HTML_PARSER = "lxml"
except ImportError:
    HTML_PARSER = "html.parser"

# ------------------ COLUMN CONFIG ------------------ #
SN_COL = "SerialNumber"
TIME_COL = "StartTime"
STATUS_COL = "TestStatus"
STAGE_COL = "Stage"
ERROR_COL = "ErrorCode"
# ---------------------------------------------------- #

# ------------------ REPAIR PORTAL CONFIG ------------------ #
LOGIN_URL = "https://mic-556.wmx.wistron/Portal/Login.aspx"
BARCODE_URL = "https://mic-556.wmx.wistron/MIBASIC000/MIBASIC003.aspx"

USER_ID = "11109117"
PASSWORD_HASH = "8342e22038d745507a72d74a0b68b02a"
PASSWORD_PLAIN = "!iJk975351"

VERIFY_SSL = False
# ---------------------------------------------------------- #

# ------------------ TEST DATA PORTAL CONFIG ------------------ #
TEST_BASE_URL = "http://10.121.186.180"
TEST_LOGIN_URL = f"{TEST_BASE_URL}/member/login/"
TEST_SEARCH_URL = f"{TEST_BASE_URL}/search/search_action/"
TEST_COUNT_URL = f"{TEST_BASE_URL}/search/search_action_get_count/"
TEST_SEARCH_PAGE = f"{TEST_BASE_URL}/search/"

TEST_USERNAME = "Chris"
TEST_PASSWORD = "!iJk975351"

TEST_PRODUCT_NAMES = ["Gaines2.0-F1"]
TEST_STAGES = ["NH", "NX", "N2", "TP", "NI", "UA"]
TEST_STATUS = ["0", "1", "2", "3", "4"]
TEST_TYPES = ["MP"]
TEST_START_TIME = "2026-02-09 18:00"
TEST_END_TIME = "2026-02-10 18:00"
TEST_PAGE_CAP = 200000
# ------------------------------------------------------------- #

# ------------------ TEST DATA PORTAL HELPERS ------------------ #
STATUS_PASS_VALUES = {"pass", "0"}
STATUS_FAIL_VALUES = {"fail", "1", "unfinish", "unfinished"}
STATUS_TESTING_VALUES = {"testing", "2"}


def _status_masks(series: pd.Series) -> tuple[pd.Series, pd.Series, pd.Series]:
    status = series.astype(str).str.strip().str.lower()
    pass_mask = status.isin(STATUS_PASS_VALUES) | status.str.contains("pass", na=False)
    fail_mask = status.isin(STATUS_FAIL_VALUES) | status.str.contains("fail", na=False)
    testing_mask = status.isin(STATUS_TESTING_VALUES) | status.str.contains("testing", na=False)
    return pass_mask, fail_mask, testing_mask


def _test_browser_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
    })
    return s


def _test_login_and_get_session(username: str, password: str) -> requests.Session:
    s = _test_browser_session()

    r0 = s.get(TEST_LOGIN_URL, timeout=30)
    r0.raise_for_status()

    csrf = s.cookies.get("csrftoken")
    if not csrf:
        raise RuntimeError("csrftoken not found after GET /member/login/")

    login_payload = {
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf,
    }
    login_headers = {
        "Referer": TEST_LOGIN_URL,
        "Origin": TEST_BASE_URL,
        "X-CSRFToken": csrf,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    r1 = s.post(TEST_LOGIN_URL, data=login_payload, headers=login_headers, allow_redirects=True, timeout=30)
    r1.raise_for_status()

    s.get(TEST_BASE_URL + "/", timeout=30)
    return s


def _test_csrf_headers(s: requests.Session, referer: str) -> dict:
    csrf = s.cookies.get("csrftoken")
    if not csrf:
        raise RuntimeError("csrftoken missing; login likely failed")

    return {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer,
        "Origin": TEST_BASE_URL,
        "X-CSRFToken": csrf,
        "X-Requested-With": "XMLHttpRequest",
        "Connection": "keep-alive",
    }


def _test_base_payload() -> dict:
    return {
        "part_number": "",
        "product_name[]": TEST_PRODUCT_NAMES,
        "serial_number": "",
        "tester_sn": "",
        "stage[]": TEST_STAGES,
        "test_status[]": TEST_STATUS,
        "test_type[]": TEST_TYPES,
        "start_time": TEST_START_TIME,
        "end_time": TEST_END_TIME,
        "error_code": "",
        "error_description": "",
        "opid": "",
        "workOrder": "",
        "sku_name": "",
        "page_length": "40",
        "queryTestRecordId": "0",
        "queryCompare": ">",
    }


def _test_post_json(s: requests.Session, url: str, payload: dict, referer: str):
    r = s.post(url, data=payload, headers=_test_csrf_headers(s, referer), timeout=60)
    r.raise_for_status()
    return r.json()


def _test_get_all_records_once(log) -> tuple[dict, object]:
    s = _test_login_and_get_session(TEST_USERNAME, TEST_PASSWORD)
    payload = _test_base_payload()

    count_resp = _test_post_json(s, TEST_COUNT_URL, payload, referer=TEST_SEARCH_PAGE)
    total = int(count_resp.get("all_record_count", 0))
    log(f"Total records: {total} | page_count: {count_resp.get('page_count')}")

    if total <= 0:
        return count_resp, None

    page_len = min(total, TEST_PAGE_CAP)
    payload["page_length"] = str(page_len)
    payload["queryTestRecordId"] = "0"
    payload["queryCompare"] = ">"

    records_resp = _test_post_json(s, TEST_SEARCH_URL, payload, referer=TEST_SEARCH_PAGE)
    return count_resp, records_resp


def _records_to_dataframe(records: object) -> pd.DataFrame:
    if records is None:
        return pd.DataFrame()

    if isinstance(records, list):
        data_list = records
    elif isinstance(records, dict):
        data_list = None
        for key in ("data", "records", "rows", "result", "items", "ret_lis"):
            val = records.get(key)
            if isinstance(val, list):
                data_list = val
                break
        if data_list is None:
            data_list = records.get("data_list") if isinstance(records.get("data_list"), list) else None
        if data_list is None:
            raise ValueError(f"Unexpected records format (keys: {list(records.keys())})")
    else:
        raise ValueError(f"Unexpected records type: {type(records)}")

    return pd.DataFrame(data_list)


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    col_map = {c.lower().strip(): c for c in df.columns}

    def pick(*candidates):
        for name in candidates:
            if name in col_map:
                return col_map[name]
        return None

    sn_col = pick("serialnumber", "serial_number", "sn", "usn", "unit_sn", "unit s/n", "unit_sn")
    time_col = pick("starttime", "start_time", "time", "test_time", "datetime", "start_time_str")
    status_col = pick("teststatus", "test_status", "status", "result")
    stage_col = pick("stage", "test_stage", "process_stage")

    missing = [SN_COL if sn_col is None else None,
               TIME_COL if time_col is None else None,
               STATUS_COL if status_col is None else None,
               STAGE_COL if stage_col is None else None]
    missing = [m for m in missing if m]
    if missing:
        raise ValueError(f"Missing columns in test records: {missing}. Available: {list(df.columns)}")

    df = df.rename(columns={
        sn_col: SN_COL,
        time_col: TIME_COL,
        status_col: STATUS_COL,
        stage_col: STAGE_COL,
    })
    return df
# ------------------------------------------------------------- #

# ------------------ REPAIR PORTAL HELPERS ------------------ #
def extract_form_fields(html, form_selector="form"):
    soup = BeautifulSoup(html, HTML_PARSER)
    form = soup.select_one(form_selector)
    if not form:
        raise RuntimeError("No form found on repair page.")
    data = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if name:
            data[name] = inp.get("value", "")
    return data


def login(session: requests.Session, log) -> bool:
    resp = session.get(LOGIN_URL, verify=VERIFY_SSL)
    resp.raise_for_status()

    login_data = extract_form_fields(resp.text)
    login_data["_VIEWSTATE"] = ""
    login_data["_EVENTVALIDATION"] = (
        "/wEdAAqvVXD1oYELeveMr0vHCmYP0jQ9vppYCxAQWfCmE/x2Lv3Vqw5XZsL40jZDizLHlCXcqaj6i4HaaYTcyD0yJuxuyayO07utlcUUWjT2C96qlZmwQuK4jOhIMZwBSEV0hc9XaafFuF1uNlexCLn5/BuXj+PhL/LIKSmutuM61w8VqHG6HSNBxdJVxosoBvoN+jJ9putR3vuxsEf+qXN68vOHXcP+XVcrh/odVfFHARa/jIx5NNp1ZYbUVmF+onOfhFo="
    )

    login_data["UserIdText"] = USER_ID
    login_data["PasswordText"] = PASSWORD_HASH
    login_data["CultureName"] = ""
    login_data["LanguageList"] = "auto"
    login_data["LoginButton"] = "\u767b\u5165"
    login_data["txtPasswordLength"] = "10"
    login_data["txtUnencryptedPassword"] = PASSWORD_PLAIN

    resp = session.post(LOGIN_URL, data=login_data, verify=VERIFY_SSL)
    resp.raise_for_status()

    if "Portal/Login.aspx" in resp.url:
        log("Login might have failed (still on login page).")
        return False

    return True


def query_barcode(session: requests.Session, barcode: str) -> str:
    # GET first to establish server-side session state (required by ASP.NET WebForms)
    resp = session.get(BARCODE_URL, verify=VERIFY_SSL)
    resp.raise_for_status()

    form_data = extract_form_fields(resp.text)
    form_data["ddlFltMFGTYPE"] = "FA"
    form_data["rblFltTYPE"] = "USN"
    form_data["txtFltBARCODE"] = barcode
    form_data["cmdQuery"] = "Query"

    resp = session.post(BARCODE_URL, data=form_data, verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.text


def _normalize_header(text: str) -> str:
    return " ".join(text.lower().split())


def _parse_production_history(html: str) -> tuple[list[list[str]], int, int, int, int | None]:
    """Parse Production History table from repair portal HTML.

    Returns (data_rows, stage_idx, result_idx, data_idx, repair_row_idx).
    Returns ([], -1, -1, -1, None) when table not found or invalid.
    """
    soup = BeautifulSoup(html, HTML_PARSER)

    heading = soup.find(lambda tag: tag.name == "div" and "Production History" in tag.get_text())
    if not heading:
        return [], -1, -1, -1, None

    table = None
    for t in heading.find_all_next("table"):
        header_row = t.find("tr")
        if not header_row:
            continue
        headers = [
            _normalize_header(c.get_text(" ", strip=True))
            for c in header_row.find_all(["td", "th"])
        ]
        if {"stage", "result", "data"}.issubset(set(headers)):
            table = t
            break

    if not table:
        return [], -1, -1, -1, None

    rows = table.find_all("tr")
    if len(rows) < 2:
        return [], -1, -1, -1, None

    header_cells = [c.get_text(" ", strip=True) for c in rows[0].find_all(["td", "th"])]
    col_map = {_normalize_header(name): idx for idx, name in enumerate(header_cells)}
    stage_idx = col_map.get("stage")
    result_idx = col_map.get("result")
    data_idx = col_map.get("data")
    has_header = any(idx is not None for idx in (stage_idx, result_idx, data_idx))

    data_rows: list[list[str]] = []
    for r in rows[1:] if has_header else rows:
        cells = [c.get_text(" ", strip=True) for c in r.find_all("td")]
        if not cells:
            continue
        if not has_header and len(cells) > 7:
            stage_idx, result_idx, data_idx = 4, 5, 7
        if None in (stage_idx, result_idx, data_idx):
            continue
        if len(cells) <= max(stage_idx, result_idx, data_idx):
            continue
        data_rows.append(cells)

    if not data_rows or None in (stage_idx, result_idx, data_idx):
        return [], -1, -1, -1, None

    # Locate "FAE Repair(RN)" row
    repair_row_idx = None
    for idx, cells in enumerate(data_rows):
        if stage_idx < len(cells) and "fae repair(rn)" in cells[stage_idx].lower():
            repair_row_idx = idx
            continue
        if any("fae repair(rn)" in c.lower() for c in cells):
            repair_row_idx = idx

    return data_rows, stage_idx, result_idx, data_idx, repair_row_idx


def extract_repair_errorcode(html: str) -> str:
    data_rows, stage_idx, result_idx, data_idx, repair_row_idx = _parse_production_history(html)
    if not data_rows:
        return ""

    # "Pre Test 1(TN)" before repair => I2C pretest
    if repair_row_idx is not None and repair_row_idx > 0:
        prev_stage = data_rows[repair_row_idx - 1][stage_idx].strip().lower()
        if prev_stage == "pre test 1(tn)":
            return "I2C pretest"

    search_rows = data_rows[:repair_row_idx] if repair_row_idx is not None else data_rows

    # 3+ consecutive fails => use that error code
    consecutive_fail = 0
    consecutive_candidate = ""
    consecutive_code = ""
    for cells in search_rows:
        result = cells[result_idx].strip().lower()
        data = cells[data_idx].strip()
        if "fail" in result:
            consecutive_fail += 1
            if data and data.upper() != "N/A":
                consecutive_candidate = data
        else:
            consecutive_fail = 0
        if consecutive_fail >= 3 and consecutive_candidate:
            consecutive_code = consecutive_candidate
    if consecutive_code:
        return consecutive_code

    # Last fail row before repair
    for cells in reversed(search_rows):
        result = cells[result_idx].strip().lower()
        data = cells[data_idx].strip()
        if "fail" in result and data and data.upper() != "N/A":
            return data

    # Fallback: last row data
    last_data = data_rows[-1][data_idx].strip()
    if last_data and last_data.upper() != "N/A":
        return last_data

    return ""


def extract_repair_prev_stage(html: str) -> str:
    data_rows, stage_idx, _, _, repair_row_idx = _parse_production_history(html)
    if not data_rows:
        return ""

    if repair_row_idx is None or repair_row_idx == 0:
        return ""

    return data_rows[repair_row_idx - 1][stage_idx].strip()


def has_repair_record(session: requests.Session, sn: str, log) -> tuple[int, str, str]:
    try:
        html = query_barcode(session, sn)
        html_lower = html.lower()
        has_repair = 1 if "fae repair(rn)" in html_lower else 0
        error_code = extract_repair_errorcode(html) if has_repair else ""
        prev_stage = extract_repair_prev_stage(html) if has_repair else ""
        return has_repair, error_code, prev_stage
    except Exception as e:
        log(f"Error querying {sn}: {e}")
        return 0, "", ""
# ------------------------------------------------------------ #

def _errorcode_summary(
    df_last: pd.DataFrame,
    mask: pd.Series,
    total_units: int,
    error_col: str = ERROR_COL,
) -> pd.DataFrame:
    if error_col not in df_last.columns:
        return pd.DataFrame(columns=[error_col, "Count", "FailRate(%)"])

    sub = df_last[mask & df_last[error_col].notna()].copy()
    if not sub.empty:
        sub = sub[sub[error_col].astype(str).str.strip() != ""]
    if sub.empty:
        return pd.DataFrame(columns=[error_col, "Count", "FailRate(%)"])

    out = sub.groupby(error_col).size().reset_index(name="Count").sort_values("Count", ascending=False)
    out["FailRate(%)"] = (out["Count"] / total_units * 100.0) if total_units else 0.0
    return out


def _create_repair_session(log) -> requests.Session:
    """Create and log in a new repair portal session."""
    session = requests.Session()
    if not login(session, log):
        raise RuntimeError("Repair portal login failed.")
    return session


def _query_sn_with_pool(pool: queue.Queue, sn: str, log) -> tuple[str, int, str, str]:
    """Borrow a session from the pool, query repair record, return session."""
    session = pool.get()
    try:
        has_repair, repair_error, prev_stage = has_repair_record(session, sn, log)
        return sn, has_repair, repair_error, prev_stage
    finally:
        pool.put(session)


def run_yield_and_errorcode_summary(log, excel_path: str = "", workers: int = 10):
    log(f"Running Repair ErrorCode summary... (parser={HTML_PARSER}, workers={workers})")

    log(f"{'── Test Data ':─<60}")
    if excel_path:
        if not os.path.isfile(excel_path):
            raise FileNotFoundError(f"Excel file not found: {excel_path}")
        log(f"Loading local file: {excel_path}")
        df = pd.read_excel(excel_path)
        df = _normalize_columns(df)
    else:
        log("Fetching test records from portal...")
        _, records = _test_get_all_records_once(log)
        df = _records_to_dataframe(records)
        df = _normalize_columns(df)
    for c in [SN_COL, TIME_COL, STATUS_COL, STAGE_COL]:
        if c not in df.columns:
            raise ValueError(f"Missing column in test file: {c}")

    # last record per SN
    df = df.sort_values([SN_COL, TIME_COL])
    last_df = df.groupby(SN_COL, as_index=False).tail(1).reset_index(drop=True)
    total_units = int(last_df[SN_COL].nunique())

    # Build session pool (parallel login)
    log(f"{'── Repair Lookup ':─<60}")
    log(f"Logging in {workers} sessions...")
    session_pool: queue.Queue[requests.Session] = queue.Queue()
    t0 = time.monotonic()
    login_done = [0]
    login_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=workers) as login_executor:
        login_futures = [login_executor.submit(_create_repair_session, log) for _ in range(workers)]
        for f in as_completed(login_futures):
            session_pool.put(f.result())
            with login_lock:
                login_done[0] += 1
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\r[{ts}] Sessions ready: {login_done[0]}/{workers}", end="", flush=True)
    print()  # end progress line
    log(f"All {workers} sessions ready ({time.monotonic() - t0:.1f}s)")

    # Concurrent repair lookup per SN
    sn_list = list(dict.fromkeys(last_df[SN_COL].tolist()))  # deduplicated, order preserved
    repair_map = {}
    repair_error_map = {}
    repair_prev_stage_map = {}
    total_sns = len(sn_list)
    log(f"Checking {total_sns} units with {workers} workers...")

    progress_lock = threading.Lock()
    progress_counter = [0]

    # Throttle progress: update every 10 units or on completion
    progress_interval = max(1, min(10, total_sns // 20))

    def _worker(sn: str) -> tuple[str, int, str, str]:
        result = _query_sn_with_pool(session_pool, sn, log)
        with progress_lock:
            progress_counter[0] += 1
            done = progress_counter[0]
            if done % progress_interval == 0 or done == total_sns:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\r[{ts}] Progress: {done}/{total_sns} ({done*100//total_sns}%)", end="", flush=True)
        return result

    t1 = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_worker, sn): sn for sn in sn_list}
            for future in as_completed(futures):
                sn, has_repair, repair_error, prev_stage = future.result()
                repair_map[sn] = has_repair
                repair_error_map[sn] = repair_error
                repair_prev_stage_map[sn] = prev_stage
    finally:
        # Cleanup session pool
        while not session_pool.empty():
            try:
                session_pool.get_nowait().close()
            except queue.Empty:
                break
    print()  # end progress line
    elapsed = time.monotonic() - t1
    log(f"Done. {total_sns} units in {elapsed:.1f}s ({elapsed / max(total_sns, 1):.2f}s/unit)")

    last_df["HasRepair"] = last_df[SN_COL].map(repair_map).fillna(0).astype(int)
    last_df["RepairErrorCode"] = last_df[SN_COL].map(repair_error_map).fillna("")
    last_df["PrevRepairStage"] = last_df[SN_COL].map(repair_prev_stage_map).fillna("")

    # FCT stage filter
    fct_stage_codes = {"nh", "nx", "n2", "tp", "ni", "ua"}
    prev_stage_code = (
        last_df["PrevRepairStage"]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.extract(r"\((\w+)\)$", expand=False)
        .fillna("")
    )
    fct_repair_mask = (last_df["HasRepair"] == 1) & prev_stage_code.isin(fct_stage_codes)
    fct_repaired_count = int(fct_repair_mask.sum())

    # ErrorCode summary for all repaired units
    ec_repair = _errorcode_summary(last_df, last_df["HasRepair"] == 1, total_units, error_col="RepairErrorCode")
    if "RepairErrorCode" in ec_repair.columns and ERROR_COL not in ec_repair.columns:
        ec_repair.rename(columns={"RepairErrorCode": ERROR_COL}, inplace=True)

    # ErrorCode summary for FCT repaired units only
    ec_repair_fct = _errorcode_summary(last_df, fct_repair_mask, total_units, error_col="RepairErrorCode")
    if "RepairErrorCode" in ec_repair_fct.columns and ERROR_COL not in ec_repair_fct.columns:
        ec_repair_fct.rename(columns={"RepairErrorCode": ERROR_COL}, inplace=True)

    # Serial number listing (repaired units only)
    sn_cols = [SN_COL, STATUS_COL, STAGE_COL, TIME_COL, "HasRepair", "RepairErrorCode", "PrevRepairStage"]
    sn_repair = last_df[last_df["HasRepair"] == 1][sn_cols].copy()
    sn_repair_fct = last_df[fct_repair_mask][sn_cols].copy()

    pass_mask, fail_mask, testing_mask = _status_masks(last_df[STATUS_COL])
    pass_count = int(pass_mask.sum())
    pass_fail_count = int((pass_mask | fail_mask).sum())
    pass_no_repair_count = int((pass_mask & (last_df["HasRepair"] == 0)).sum())
    testing_count = int(testing_mask.sum())
    pass_no_fct_repair_count = int((pass_mask & ~fct_repair_mask).sum())
    fail_count = int(fail_mask.sum())
    # YR(FCT) denominator: pass (excluding FCT-repaired) + fail (excluding FCT-repaired)
    fail_no_fct_repair_count = int((fail_mask & ~fct_repair_mask).sum())
    yr_fct_denom = pass_no_fct_repair_count + fail_no_fct_repair_count

    summary_df = pd.DataFrame([{
        "TotalUnits": total_units,
        "RepairedUnits": int(last_df["HasRepair"].sum()),
        "RepairedUnits(FCT)": fct_repaired_count,
        "PassUnits": pass_count,
        "FailUnits": fail_count,
        "TestingUnits": testing_count,
        "FPYP": (pass_no_repair_count / total_units) if total_units else 0.0,
        "YR": (pass_count / pass_fail_count) if pass_fail_count else 0.0,
        "FPY(FCT)": (pass_no_fct_repair_count / total_units) if total_units else 0.0,
        "YR(FCT)": (pass_no_fct_repair_count / yr_fct_denom) if yr_fct_denom else 0.0,
    }])

    # Print summary (vertical key-value layout)
    log("")
    log("=" * 60)
    log("  SUMMARY")
    log("=" * 60)
    rate_keys = {"FPYP", "YR", "FPY(FCT)", "YR(FCT)"}
    for col in summary_df.columns:
        val = summary_df[col].iloc[0]
        if col in rate_keys:
            val_str = f"{val * 100:.2f}%"
        else:
            val_str = str(int(val))
        log(f"  {col:<22s}: {val_str:>8s}")
    log("=" * 60)

    def _print_ec_table(ec_df: pd.DataFrame):
        if ec_df.empty:
            log("  (none)")
            return
        display = ec_df.reset_index(drop=True)
        display.insert(0, "#", range(1, len(display) + 1))
        display["FailRate(%)"] = display["FailRate(%)"].map(lambda x: f"{x:.2f}")
        for line in display.to_string(index=False).splitlines():
            log(line)

    log("")
    log("-" * 60)
    log("  ERRORCODES — All Repaired Units")
    log("-" * 60)
    _print_ec_table(ec_repair)
    log("")
    log("-" * 60)
    log(f"  ERRORCODES — FCT Repaired Units ({'/'.join(sorted(fct_stage_codes, key=str.upper))})")
    log("-" * 60)
    _print_ec_table(ec_repair_fct)

    # Save Excel
    ts = datetime.now().strftime("%Y%m%d%H%M")
    out_name = f"yield_errorcode_summary_{ts}.xlsx"
    with pd.ExcelWriter(out_name) as writer:
        summary_df.to_excel(excel_writer=writer, sheet_name="Summary", index=False)
        excel_last_df = last_df.drop(columns=[c for c in [ERROR_COL] if c in last_df.columns])
        excel_last_df.to_excel(excel_writer=writer, sheet_name="Last_Record_Per_SN", index=False)
        ec_repair.to_excel(excel_writer=writer, sheet_name="ErrorCode_Repaired", index=False)
        ec_repair_fct.to_excel(excel_writer=writer, sheet_name="ErrorCode_Repaired(FCT)", index=False)
        sn_repair.to_excel(excel_writer=writer, sheet_name="SN_Repaired", index=False)
        sn_repair_fct.to_excel(excel_writer=writer, sheet_name="SN_Repaired(FCT)", index=False)

    log(f"Saved: {out_name}")
    return out_name


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _validate_date(date_str: str) -> str:
    """Validate YYYY-MM-DD format and return 'YYYY-MM-DD 18:00'."""
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid date format: '{date_str}'. Expected YYYY-MM-DD.")
    return f"{date_str} 18:00"


def main():
    global TEST_START_TIME, TEST_END_TIME

    parser = argparse.ArgumentParser(description="Testing Summary Tool (CLI)")
    parser.add_argument("-f", "--file", default="", help="Path to local Excel file (skip portal fetch)")
    parser.add_argument("-s", "--start-date", default="", help="Start date (YYYY-MM-DD), auto-appends 18:00")
    parser.add_argument("-e", "--end-date", default="", help="End date (YYYY-MM-DD), auto-appends 18:00")
    parser.add_argument("-w", "--workers", type=int, default=10, choices=range(1, 21),
                        metavar="[1-20]", help="Number of concurrent repair workers (default: 10)")
    args = parser.parse_args()

    if not args.file and not (args.start_date and args.end_date):
        parser.error("Either -f/--file or both -s/--start-date and -e/--end-date are required.")

    if args.start_date:
        TEST_START_TIME = _validate_date(args.start_date)
        log(f"Start time: {TEST_START_TIME}")
    if args.end_date:
        TEST_END_TIME = _validate_date(args.end_date)
        log(f"End time: {TEST_END_TIME}")

    try:
        run_yield_and_errorcode_summary(log, excel_path=args.file, workers=args.workers)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
