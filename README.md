# FailRate - Testing Summary Tool (CLI)

Manufacturing yield and fail-rate analysis tool for Wistron test data.

## Architecture

```
                          Cal_FR_CLI.py
                               |
            +------------------+------------------+
            |                                     |
    Test Data Portal                      Repair Portal
    (Django, HTTP API)                  (ASP.NET WebForms)
            |                                     |
     JSON test records               Production History HTML
            |                                     |
            +------------------+------------------+
                               |
                     pandas DataFrame join
                               |
              +----------------+----------------+
              |                |                |
        Yield Metrics    ErrorCode Summary   Per-Stage Summary
              |                |                |
              +----------------+----------------+
                               |
                  CLI tables (tabulate) + Excel export
```

## Requirements

```bash
pip install pandas requests beautifulsoup4 openpyxl tabulate
# Optional: pip install lxml  (faster HTML parsing)
```

## Usage

```bash
# From portal with date range
python3 Cal_FR_CLI.py -s 2026-02-09 -e 2026-02-10

# From local Excel file
python3 Cal_FR_CLI.py -f Test_Record_Search_20260210_134452.xlsx

# Custom worker count (1-20)
python3 Cal_FR_CLI.py -s 2026-02-09 -e 2026-02-10 -w 15

# Sequential (single worker)
python3 Cal_FR_CLI.py -f data.xlsx -w 1
```

## Arguments

| Flag | Description | Required |
|------|-------------|----------|
| `-f` / `--file` | Path to local Excel file (skips portal fetch) | Either `-f` or both `-s`/`-e` |
| `-s` / `--start-date` | Start date (`YYYY-MM-DD`, time defaults to 18:00) | With `-e` when no `-f` |
| `-e` / `--end-date` | End date (`YYYY-MM-DD`, time defaults to 18:00) | With `-s` when no `-f` |
| `-w` / `--workers` | Concurrent repair query workers (default: 10, range: 1-20) | No |

## Output

### CLI Tables

The tool prints formatted tables to the terminal using `tabulate` (`rounded_grid` format):

- **Per-Stage Summary** — pass/fail/testing/total/fail-rate per test stage (all records, not deduplicated by SN)
- **ErrorCode Ranking (All Stages)** — error code frequency from raw test data
- **ErrorCode Ranking by Stage** — error code frequency broken down per stage
- **Summary** — vertical key-value table of all yield metrics
- **ErrorCodes (All Repaired)** — error codes from repair portal data
- **ErrorCodes (FCT Repaired)** — error codes for FCT-stage repairs only

### Excel File

Generates `yield_errorcode_summary_YYYYMMDDHHMM.xlsx` with sheets. Each sheet includes a timestamp header and data description in the first two rows:

- **Summary** — TotalUnits, RepairedUnits, RepairedUnits(FCT), PassUnits, FailUnits, TestingUnits, FPYP, YR, FPY(FCT), YR(FCT)
- **Last_Record_Per_SN** — Last test record per serial number with repair info
- **ErrorCode_Repaired** — Error code frequency for all repaired units
- **ErrorCode_Repaired(FCT)** — Error code frequency for FCT-stage repaired units
- **SN_Repaired** — Detail listing of all repaired serial numbers
- **SN_Repaired(FCT)** — Detail listing of FCT-stage repaired serial numbers
- **Stage_FailRate** — Per-stage pass/fail/testing/total/fail-rate from all records (not deduplicated by SN)
- **Stage_ErrorCode_All** — Error code ranking across all stages
- **Stage_ErrorCode** — Error code ranking broken down per stage

## Yield Metrics

| Metric | Formula |
|--------|---------|
| **FPYP** (First Pass Yield w/o repair) | Pass units without any repair / Total units |
| **YR** (Yield Rate) | Pass units / (Pass + Fail units) |
| **FPY(FCT)** | FCT pass without FCT repair / FCT total (units that reached FCT stage) |
| **YR(FCT)** | FCT pass / (FCT pass + FCT fail) (units that reached FCT stage) |

FCT stages: NH, NX, N2, TP, NI, UA

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection timeout / refused | Ensure VPN is connected to Wistron internal network |
| Login failed (still on login page) | Credentials may have expired; update `USER_ID` / `PASSWORD_HASH` / `PASSWORD_PLAIN` in script |
| `ModuleNotFoundError: lxml` | Install with `pip install lxml`, or ignore (falls back to `html.parser`) |
| `Missing column in test file` | Excel column names changed; check `_normalize_columns()` candidate list |
| Slow repair lookups | Increase workers with `-w 15` or `-w 20` |
