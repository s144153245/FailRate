#!/usr/bin/env python3
"""Manufacturing yield & fail-rate CLI tool for Wistron test data.

Architecture / Data Flow
========================
1. **Test Data Portal** (Django, CSRF-protected HTTP API)
   - Authenticate via GET (extract csrftoken) -> POST login
   - Fetch paginated JSON test records filtered by product, stage, date range
   - Convert JSON -> pandas DataFrame, normalize column names

2. **Repair Portal** (ASP.NET WebForms with ViewState)
   - Login via form POST with ViewState + credentials
   - For each serial number, POST barcode query -> parse "Production History" HTML table
   - Extract: has_repair flag, error code (heuristic), FCT-specific error code, previous stage

3. **Analysis Pipeline** (pandas)
   - Keep last test record per serial number (sort by time, groupby tail)
   - Join repair data (HasRepair, RepairErrorCode, RepairErrorCodeFCT, PrevRepairStage)
   - Compute yield metrics: FPY, YR, FPY(FCT), YR(FCT)
   - Compute per-stage fail rates and error code rankings from raw test data
   - Compute repair-sourced error code summaries (all repaired + FCT-only)

4. **Output**
   - CLI: formatted tables via tabulate (rounded_grid)
   - Excel: multi-sheet workbook with summary, detail, and ranking sheets

Subsystem Dependencies
----------------------
- Test Portal helpers: _test_* functions, _records_to_dataframe, _normalize_columns
- Repair Portal helpers: extract_form_fields, login, query_barcode, _parse_production_history,
  extract_repair_errorcode, extract_repair_prev_stage, has_repair_record
- Analysis: _status_masks (shared), _stage_failrate_summary, _stage_errorcode_ranking,
  _errorcode_summary, run_yield_and_errorcode_summary
- CLI: main, log, _validate_datetime
"""

import os
import sys
import re
import argparse
import threading
import queue
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import time
from bs4 import BeautifulSoup
from tabulate import tabulate
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

# FCT stage codes used to identify FCT-repaired units
FCT_STAGE_CODES = {"nh", "nx", "n2", "tp", "ni", "ua"}

# Display order for per-stage fail rate table
STAGE_DISPLAY_ORDER = ["FLA", "FLC", "PreTest", "FCT", "FINT", "OS Installation"]

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
STATUS_FAIL_VALUES = {"fail", "1"}
STATUS_TESTING_VALUES = {"testing", "2", "unfinish", "unfinished"}


def _status_masks(series: pd.Series) -> tuple[pd.Series, pd.Series, pd.Series]:
    """Create boolean masks classifying test status as pass/fail/testing.

    Normalizes the series to lowercase, then matches against STATUS_PASS_VALUES,
    STATUS_FAIL_VALUES, STATUS_TESTING_VALUES (exact match) plus substring fallback
    (e.g. "pass" in "pass_with_warning"). Used by both per-stage analysis and yield
    metric computation.

    Returns:
        (pass_mask, fail_mask, testing_mask) — each a boolean pd.Series aligned to input.
    """
    status = series.astype(str).str.strip().str.lower()
    pass_mask = status.isin(STATUS_PASS_VALUES) | status.str.contains("pass", na=False)
    fail_mask = status.isin(STATUS_FAIL_VALUES) | status.str.contains("fail", na=False)
    testing_mask = status.isin(STATUS_TESTING_VALUES) | status.str.contains("testing", na=False)
    return pass_mask, fail_mask, testing_mask


def _test_browser_session() -> requests.Session:
    """Create a requests.Session with browser-like User-Agent header.

    The test data portal rejects requests without a realistic UA string.
    """
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
    """Authenticate with the Django test data portal using CSRF flow.

    Flow: GET login page -> extract csrftoken cookie -> POST credentials with
    CSRF token in both form data and header -> follow redirect -> GET base URL
    to finalize session. Returns an authenticated Session for subsequent API calls.
    """
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
    """Build AJAX request headers with CSRF token for the test data portal.

    Extracts csrftoken from session cookies and returns headers dict suitable
    for XMLHttpRequest-style POST calls (JSON responses).
    """
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
    """Build the default query payload for the test data portal search API.

    Uses module-level constants (TEST_PRODUCT_NAMES, TEST_STAGES, TEST_STATUS,
    TEST_START_TIME, TEST_END_TIME) as filter criteria. The caller overrides
    page_length and queryTestRecordId as needed for pagination.
    """
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
    """POST form-encoded payload to the test portal and return parsed JSON response."""
    r = s.post(url, data=payload, headers=_test_csrf_headers(s, referer), timeout=60)
    r.raise_for_status()
    return r.json()


def _test_get_all_records_once(log) -> tuple[dict, object]:
    """Fetch all test records from the portal in a single paginated request.

    Steps: login -> get total count -> set page_length to min(total, cap) ->
    fetch all records in one POST. Returns (count_response, records_response).
    records_response is None when total <= 0.
    """
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
    """Convert JSON test records (list or dict with nested list) to DataFrame.

    Handles multiple response formats: bare list, or dict with data under keys
    like "data", "records", "rows", "result", "items", "ret_lis", "data_list".
    Returns empty DataFrame for None input.
    """
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
    """Rename DataFrame columns to canonical names (SN_COL, TIME_COL, etc.).

    Maps common column name variants (e.g. "serial_number", "sn", "usn") to the
    standard names used throughout the pipeline. ErrorCode column is optional.
    Raises ValueError if required columns (SerialNumber, StartTime, TestStatus,
    Stage) cannot be found.
    """
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
    error_col = pick("errorcode", "error_code", "errcode")

    missing = [SN_COL if sn_col is None else None,
               TIME_COL if time_col is None else None,
               STATUS_COL if status_col is None else None,
               STAGE_COL if stage_col is None else None]
    missing = [m for m in missing if m]
    if missing:
        raise ValueError(f"Missing columns in test records: {missing}. Available: {list(df.columns)}")

    rename_map = {
        sn_col: SN_COL,
        time_col: TIME_COL,
        status_col: STATUS_COL,
        stage_col: STAGE_COL,
    }
    # ErrorCode is optional (some Excel files may lack it)
    if error_col is not None and error_col != ERROR_COL:
        rename_map[error_col] = ERROR_COL
    df = df.rename(columns=rename_map)
    return df
# ------------------------------------------------------------- #

# ------------------ REPAIR PORTAL HELPERS ------------------ #
def extract_form_fields(html, form_selector="form"):
    """Extract all hidden input fields from an HTML form (ASP.NET ViewState etc.).

    Parses the first form matching form_selector and returns a dict of
    {input_name: input_value} for all <input> elements with a name attribute.
    """
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
    """Log into the ASP.NET WebForms repair portal.

    Flow: GET login page -> extract form fields (ViewState) -> override with
    hardcoded EventValidation + credentials -> POST. Returns True if login
    succeeded (URL no longer on login page), False otherwise.
    """
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
    """Query the repair portal for a serial number's production history.

    GETs the barcode page first (required to establish ASP.NET server-side state),
    then POSTs the barcode query. Returns raw HTML response containing the
    Production History table.
    """
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
    """Normalize HTML table header text: lowercase, collapse whitespace."""
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


def _extract_stage_code(stage_text: str) -> str:
    """Extract code from parentheses: 'FCT 1(nh)' -> 'nh'."""
    m = re.search(r"\((\w+)\)$", stage_text.strip())
    return m.group(1).lower() if m else ""


def extract_repair_errorcode(html: str, stage_filter: set[str] | None = None) -> str:
    """Extract the most relevant error code from a unit's repair production history.

    Heuristic (applied to rows before the "FAE Repair(RN)" row):
    1. Special case: if the row immediately before repair is "Pre Test 1(TN)",
       return "I2C pretest" (only when no stage_filter).
    2. If stage_filter is set, restrict search rows to matching FCT stages.
    3. "3+ consecutive fails" rule: scan forward; if 3+ consecutive fail results
       are found, use the last non-N/A error code from that streak.
    4. "Last fail before repair" fallback: scan backward from repair row for the
       last fail with a non-N/A data field.
    5. Final fallback: return the data field of the last row.

    Args:
        html: Raw HTML from query_barcode() containing Production History table.
        stage_filter: If set (e.g. FCT_STAGE_CODES), only consider rows whose
            stage code (extracted via _extract_stage_code) is in this set.

    Returns:
        Error code string, or "" if no meaningful code found.
    """
    data_rows, stage_idx, result_idx, data_idx, repair_row_idx = _parse_production_history(html)
    if not data_rows:
        return ""

    # "Pre Test 1(TN)" before repair => I2C pretest (checked before stage filtering)
    if repair_row_idx is not None and repair_row_idx > 0:
        prev_stage = data_rows[repair_row_idx - 1][stage_idx].strip().lower()
        if prev_stage == "pre test 1(tn)":
            return "I2C pretest" if stage_filter is None else ""

    search_rows = data_rows[:repair_row_idx] if repair_row_idx is not None else data_rows

    # Filter to specific stages when requested (e.g. FCT stages only)
    if stage_filter:
        search_rows = [
            cells for cells in search_rows
            if _extract_stage_code(cells[stage_idx]) in stage_filter
        ]
        if not search_rows:
            return ""

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

    # Fallback: last row data (restricted to filtered rows if stage_filter is set)
    fallback_rows = search_rows if stage_filter else data_rows
    if fallback_rows:
        last_data = fallback_rows[-1][data_idx].strip()
        if last_data and last_data.upper() != "N/A":
            return last_data

    return ""


def extract_repair_prev_stage(html: str) -> str:
    """Extract the test stage immediately before "FAE Repair(RN)" in production history.

    Returns the stage text of the row just before the repair row, or "" if no
    repair row exists or it's the first row.
    """
    data_rows, stage_idx, _, _, repair_row_idx = _parse_production_history(html)
    if not data_rows:
        return ""

    if repair_row_idx is None or repair_row_idx == 0:
        return ""

    return data_rows[repair_row_idx - 1][stage_idx].strip()


def has_repair_record(session: requests.Session, sn: str, log) -> tuple[int, str, str, str]:
    """Check if a serial number has a repair record and extract repair details.

    Queries the repair portal, checks for "FAE Repair(RN)" in the response,
    then extracts error codes (all-stage and FCT-only) and previous repair stage.

    Returns:
        (has_repair, error_code, error_code_fct, prev_stage) where has_repair is
        0 or 1, and the rest are strings (empty if no repair).
    """
    try:
        html = query_barcode(session, sn)
        html_lower = html.lower()
        has_repair = 1 if "fae repair(rn)" in html_lower else 0
        error_code = extract_repair_errorcode(html) if has_repair else ""
        error_code_fct = extract_repair_errorcode(html, stage_filter=FCT_STAGE_CODES) if has_repair else ""
        prev_stage = extract_repair_prev_stage(html) if has_repair else ""
        return has_repair, error_code, error_code_fct, prev_stage
    except Exception as e:
        log(f"Error querying {sn}: {e}")
        return 0, "", "", ""
# ------------------------------------------------------------ #

def _stage_failrate_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Per-stage pass/fail/testing/total summary from all records."""
    pass_mask, fail_mask, testing_mask = _status_masks(df[STATUS_COL])
    df = df.copy()
    df["_pass"] = pass_mask.astype(int)
    df["_fail"] = fail_mask.astype(int)
    df["_testing"] = testing_mask.astype(int)
    grouped = df.groupby(STAGE_COL).agg(
        Total=(SN_COL, "count"),
        Pass=("_pass", "sum"),
        Fail=("_fail", "sum"),
        Testing=("_testing", "sum"),
    ).reset_index()
    grouped["FailRate(%)"] = (grouped["Fail"] / grouped["Total"] * 100.0).where(grouped["Total"] > 0, 0.0)
    grouped[STAGE_COL] = pd.Categorical(grouped[STAGE_COL], categories=STAGE_DISPLAY_ORDER, ordered=True)
    return grouped.sort_values(STAGE_COL).reset_index(drop=True)


def _stage_errorcode_ranking(last_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """ErrorCode ranking from raw test data fail records.

    Returns (all_stages_df, per_stage_df).
    all_stages_df: ErrorCode, Count, FailRate(%) across all stages.
    per_stage_df: Stage, ErrorCode, Count, FailRate(%) per stage.
    """
    empty_all = pd.DataFrame(columns=[ERROR_COL, "Count", "FailRate(%)"])
    empty_per = pd.DataFrame(columns=[STAGE_COL, ERROR_COL, "Count", "FailRate(%)"])

    if ERROR_COL not in last_df.columns:
        return empty_all, empty_per

    _, fail_mask, _ = _status_masks(last_df[STATUS_COL])
    fails = last_df[fail_mask].copy()
    fails = fails[fails[ERROR_COL].notna() & (fails[ERROR_COL].astype(str).str.strip() != "")]
    if fails.empty:
        return empty_all, empty_per

    total_units = int(last_df[SN_COL].nunique())

    # All stages combined
    all_ec = fails.groupby(ERROR_COL).size().reset_index(name="Count").sort_values("Count", ascending=False)
    all_ec["FailRate(%)"] = (all_ec["Count"] / total_units * 100.0) if total_units else 0.0

    # Per stage
    stage_totals = last_df.groupby(STAGE_COL)[SN_COL].count()
    per_ec = fails.groupby([STAGE_COL, ERROR_COL]).size().reset_index(name="Count")
    per_ec["FailRate(%)"] = per_ec.apply(
        lambda r: (r["Count"] / stage_totals.get(r[STAGE_COL], 1) * 100.0), axis=1
    )
    per_ec[STAGE_COL] = pd.Categorical(per_ec[STAGE_COL], categories=STAGE_DISPLAY_ORDER, ordered=True)
    per_ec = per_ec.sort_values([STAGE_COL, "Count"], ascending=[True, False]).reset_index(drop=True)

    return all_ec.reset_index(drop=True), per_ec


def _errorcode_summary(
    df_last: pd.DataFrame,
    mask: pd.Series,
    total_units: int,
    error_col: str = ERROR_COL,
) -> pd.DataFrame:
    """Generic error code frequency summary for a filtered subset of units.

    Filters df_last by mask, groups by error_col, counts occurrences, computes
    FailRate(%) = Count/total_units*100. Used for both all-repaired and
    FCT-repaired error code summaries.
    """
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


def _query_sn_with_pool(pool: queue.Queue, sn: str, log) -> tuple[str, int, str, str, str]:
    """Borrow a session from the pool, query repair record, return session."""
    session = pool.get()
    try:
        has_repair, repair_error, repair_error_fct, prev_stage = has_repair_record(session, sn, log)
        return sn, has_repair, repair_error, repair_error_fct, prev_stage
    finally:
        pool.put(session)


def run_yield_and_errorcode_summary(log, excel_path: str = "", workers: int = 10):
    """Main analysis pipeline: fetch data, query repairs, compute metrics, output results.

    Pipeline stages:
    1. Load test data (from Excel file or portal API)
    2. Normalize columns to canonical names
    3. Keep last record per serial number (sort by StartTime, groupby tail)
    4. Compute per-stage fail rate and error code rankings from raw test data
    5. Create repair portal session pool (parallel login)
    6. Concurrently query repair status for each unique SN
    7. Join repair data onto last_df (HasRepair, RepairErrorCode, etc.)
    8. Compute yield metrics:
       - FPY = pass_without_any_repair / total_units
       - YR = pass / (pass + fail)
       - FPY(FCT) = pass_without_fct_repair / total_units
       - YR(FCT) = pass_no_fct / (pass_no_fct + fail_no_fct)
    9. Print CLI tables (tabulate rounded_grid format)
    10. Export multi-sheet Excel workbook

    Args:
        log: Callable for timestamped logging (typically the module-level log()).
        excel_path: Path to local Excel file. If empty, fetches from test data portal.
        workers: Number of concurrent repair portal query sessions (1-20).

    Returns:
        Output Excel filename (str).

    Side effects:
        - Writes Excel file to current directory
        - Prints tables and progress to stdout
    """
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

    # Per-stage fail rate summary (from raw test data)
    stage_fr = _stage_failrate_summary(df)
    stage_ec_all, stage_ec_per = _stage_errorcode_ranking(last_df)

    # Shared table printer: consistent indent, optional rank column, formatted FailRate
    def _print_table(df: pd.DataFrame, indent: str = "  ", ranked: bool = False):
        if df.empty:
            log(f"{indent}(none)")
            return
        disp = df.reset_index(drop=True)
        if ranked:
            disp.insert(0, "#", range(1, len(disp) + 1))
        if "FailRate(%)" in disp.columns:
            disp["FailRate(%)"] = disp["FailRate(%)"].map(lambda x: f"{x:.2f}")
        right_cols = {"#", "Total", "Pass", "Fail", "Testing", "Count", "FailRate(%)"}
        colalign = tuple("right" if c in right_cols else "left" for c in disp.columns)
        table = tabulate(disp.values, headers=disp.columns, tablefmt="rounded_grid",
                         colalign=colalign, disable_numparse=True)
        for line in table.splitlines():
            log(f"{indent}{line}")

    def _section(title: str, subtitle: str = ""):
        log("")
        log(f"{'── ' + title + ' ':─<60}")
        if subtitle:
            log(f"  {subtitle}")

    _section("Per-Stage Summary (All Records)")
    _print_table(stage_fr)
    if not stage_fr.empty:
        total_pass = stage_fr["Pass"].sum()
        all_records_total = stage_fr["Total"].sum()
        final_yield = (total_pass / all_records_total * 100) if all_records_total > 0 else 0.0
        log(f"  Final Yield: {final_yield:.2f}%")
    log("  Note: Counts all test records in date range (not deduplicated by SN).")

    _section("ErrorCode Ranking — All Stages",
             "(Data source: raw test data — last record per SN)")
    _print_table(stage_ec_all, ranked=True)
    log("  Note: Based on last record per SN.")

    _section("ErrorCode Ranking by Stage",
             "(Data source: raw test data — last record per SN)")
    if not stage_ec_per.empty:
        for stage_name in STAGE_DISPLAY_ORDER:
            grp = stage_ec_per[stage_ec_per[STAGE_COL] == stage_name]
            if grp.empty:
                continue
            log(f"  [{stage_name}]")
            _print_table(grp.drop(columns=[STAGE_COL]), indent="    ", ranked=True)
            log("")
    else:
        log("  (none)")
    log("  Note: Based on last record per SN.")

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
    repair_error_fct_map = {}
    repair_prev_stage_map = {}
    total_sns = len(sn_list)
    log(f"Checking {total_sns} units with {workers} workers...")

    progress_lock = threading.Lock()
    progress_counter = [0]

    # Throttle progress: update every 10 units or on completion
    progress_interval = max(1, min(10, total_sns // 20))

    def _worker(sn: str) -> tuple[str, int, str, str, str]:
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
                sn, has_repair, repair_error, repair_error_fct, prev_stage = future.result()
                repair_map[sn] = has_repair
                repair_error_map[sn] = repair_error
                repair_error_fct_map[sn] = repair_error_fct
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
    last_df["RepairErrorCodeFCT"] = last_df[SN_COL].map(repair_error_fct_map).fillna("")
    last_df["PrevRepairStage"] = last_df[SN_COL].map(repair_prev_stage_map).fillna("")

    # FCT stage filter
    prev_stage_code = (
        last_df["PrevRepairStage"]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.extract(r"\((\w+)\)$", expand=False)
        .fillna("")
    )
    fct_repair_mask = (last_df["HasRepair"] == 1) & prev_stage_code.isin(FCT_STAGE_CODES)
    fct_repaired_count = int(fct_repair_mask.sum())

    # ErrorCode summary for all repaired units
    ec_repair = _errorcode_summary(last_df, last_df["HasRepair"] == 1, total_units, error_col="RepairErrorCode")
    if "RepairErrorCode" in ec_repair.columns and ERROR_COL not in ec_repair.columns:
        ec_repair.rename(columns={"RepairErrorCode": ERROR_COL}, inplace=True)

    # ErrorCode summary for FCT repaired units only (using FCT-filtered error codes)
    ec_repair_fct = _errorcode_summary(last_df, fct_repair_mask, total_units, error_col="RepairErrorCodeFCT")
    if "RepairErrorCodeFCT" in ec_repair_fct.columns and ERROR_COL not in ec_repair_fct.columns:
        ec_repair_fct.rename(columns={"RepairErrorCodeFCT": ERROR_COL}, inplace=True)

    # Serial number listing (repaired units only)
    sn_cols = [SN_COL, STATUS_COL, STAGE_COL, TIME_COL, "HasRepair", "RepairErrorCode", "RepairErrorCodeFCT", "PrevRepairStage"]
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

    # --- Yield metric computation ---
    summary_df = pd.DataFrame([{
        "TotalUnits": total_units,
        "RepairedUnits": int(last_df["HasRepair"].sum()),
        "RepairedUnits(FCT)": fct_repaired_count,
        "PassUnits": pass_count,
        "FailUnits": fail_count,
        "TestingUnits": testing_count,
        "FPY": (pass_no_repair_count / total_units) if total_units else 0.0,
        "YR": (pass_count / pass_fail_count) if pass_fail_count else 0.0,
        "FPY(FCT)": (pass_no_fct_repair_count / total_units) if total_units else 0.0,
        "YR(FCT)": (pass_no_fct_repair_count / yr_fct_denom) if yr_fct_denom else 0.0,
    }])

    # Print summary as tabulate table (vertical key-value layout)
    rate_keys = {"FPY", "YR", "FPY(FCT)", "YR(FCT)"}
    summary_rows = []
    for col in summary_df.columns:
        val = summary_df[col].iloc[0]
        val_str = f"{val * 100:.2f}%" if col in rate_keys else str(int(val))
        summary_rows.append([col, val_str])
    _section("SUMMARY")
    table = tabulate(summary_rows, headers=["Metric", "Value"],
                     tablefmt="rounded_grid", colalign=("left", "right"))
    for line in table.splitlines():
        log(f"  {line}")
    log("  FPY = Pass without any repair / Total  |  YR = Pass / (Pass + Fail)")
    log("  FPY(FCT) = Pass without FCT-stage repair / Total  |  YR(FCT) excludes FCT-repaired units")
    log("  FCT stages: NH, NX, N2, TP, NI, UA")

    _section("ERRORCODES — All Repaired Units",
             "(Data source: Repair portal — units with FAE Repair(RN) record)")
    _print_table(ec_repair, ranked=True)
    log("  Note: Error codes from repair portal.")

    _section(f"ERRORCODES — FCT Repaired Units ({'/'.join(sorted(FCT_STAGE_CODES, key=str.upper))})",
             "(Data source: Repair portal — units repaired at FCT stages only)")
    _print_table(ec_repair_fct, ranked=True)
    log("  Note: Filtered to FCT-stage repairs only.")

    # Save Excel with header rows (timestamp + description)
    ts = datetime.now().strftime("%Y%m%d%H%M")
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_range_str = f"{TEST_START_TIME} ~ {TEST_END_TIME}"
    header_line1 = f"Generated: {gen_time} | Date range: {date_range_str}"

    sheet_descriptions = {
        "Summary": "Yield metrics: FPY, YR, FPY(FCT), YR(FCT). FCT stages: NH/NX/N2/TP/NI/UA",
        "Last_Record_Per_SN": "Last test record per SN joined with repair portal data",
        "ErrorCode_Repaired": "Error code frequency for all units with repair history",
        "ErrorCode_Repaired(FCT)": "Error code frequency for FCT-stage repaired units only",
        "SN_Repaired": "Detail listing of all repaired serial numbers",
        "SN_Repaired(FCT)": "Detail listing of FCT-stage repaired serial numbers",
        "Stage_FailRate": "Per-stage pass/fail/testing from all records (not deduplicated by SN)",
        "Stage_ErrorCode_All": "Error code ranking across all stages (last record per SN)",
        "Stage_ErrorCode": "Error code ranking per stage (last record per SN)",
    }

    out_name = f"yield_errorcode_summary_{ts}.xlsx"
    with pd.ExcelWriter(out_name) as writer:
        excel_last_df = last_df.drop(columns=[c for c in [ERROR_COL] if c in last_df.columns])
        for data, name in [
            (summary_df, "Summary"),
            (excel_last_df, "Last_Record_Per_SN"),
            (ec_repair, "ErrorCode_Repaired"),
            (ec_repair_fct, "ErrorCode_Repaired(FCT)"),
            (sn_repair, "SN_Repaired"),
            (sn_repair_fct, "SN_Repaired(FCT)"),
            (stage_fr, "Stage_FailRate"),
            (stage_ec_all, "Stage_ErrorCode_All"),
            (stage_ec_per, "Stage_ErrorCode"),
        ]:
            # Write data starting at row 4 (startrow=3) to leave room for headers
            data.to_excel(excel_writer=writer, sheet_name=name, index=False, startrow=3)
            # Insert header rows above the data
            ws = writer.sheets[name]
            ws.cell(row=1, column=1, value=header_line1)
            ws.cell(row=2, column=1, value=sheet_descriptions.get(name, ""))

    log(f"Saved: {out_name}")
    return out_name


def log(msg: str):
    """Print a timestamped log message to stdout (format: [HH:MM:SS] msg)."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def _validate_datetime(date_str: str) -> str:
    """Validate date/datetime and return 'YYYY-MM-DD HH:MM'.

    Accepts:
      - YYYY-MM-DD        -> defaults to 18:00
      - YYYY-MM-DD HH:MM  -> used as-is
    """
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(date_str, fmt)
            if fmt == "%Y-%m-%d":
                parsed = parsed.replace(hour=18, minute=0)
            return parsed.strftime("%Y-%m-%d %H:%M")
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid format: '{date_str}'. Expected YYYY-MM-DD or 'YYYY-MM-DD HH:MM'."
    )


def main():
    """CLI entry point: parse args, set date range, invoke analysis pipeline."""
    global TEST_START_TIME, TEST_END_TIME

    parser = argparse.ArgumentParser(description="Testing Summary Tool (CLI)")
    parser.add_argument("-f", "--file", default="", help="Path to local Excel file (skip portal fetch)")
    parser.add_argument("-s", "--start-date", nargs="+", default=[], help="Start: YYYY-MM-DD [HH:MM] (default time 18:00)")
    parser.add_argument("-e", "--end-date", nargs="+", default=[], help="End: YYYY-MM-DD [HH:MM] (default time 18:00)")
    parser.add_argument("-w", "--workers", type=int, default=10, choices=range(1, 21),
                        metavar="[1-20]", help="Number of concurrent repair workers (default: 10)")
    args = parser.parse_args()

    if not args.file and not (args.start_date and args.end_date):
        parser.error("Either -f/--file or both -s/--start-date and -e/--end-date are required.")

    if args.start_date:
        TEST_START_TIME = _validate_datetime(" ".join(args.start_date))
        log(f"Start time: {TEST_START_TIME}")
    if args.end_date:
        TEST_END_TIME = _validate_datetime(" ".join(args.end_date))
        log(f"End time: {TEST_END_TIME}")

    try:
        run_yield_and_errorcode_summary(log, excel_path=args.file, workers=args.workers)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
