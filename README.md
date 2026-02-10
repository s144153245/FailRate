# FailRate - Testing Summary Tool (CLI)

Manufacturing yield and fail-rate analysis tool for Wistron test data.

## Requirements

```bash
pip install pandas requests beautifulsoup4 openpyxl
```

## Usage

```bash
# From local Excel file (default 5 concurrent workers)
python3 Cal_FR_CLI.py -f Test_Record_Search_20260210_134452.xlsx

# From portal with date range
python3 Cal_FR_CLI.py -s 2026-02-09 -e 2026-02-10

# Custom worker count (1-10)
python3 Cal_FR_CLI.py -f data.xlsx -w 8

# Sequential (single worker)
python3 Cal_FR_CLI.py -f data.xlsx -w 1
```

## Arguments

| Flag | Description | Required |
|------|-------------|----------|
| `-f` / `--file` | Path to local Excel file (skips portal fetch) | Either `-f` or both `-s`/`-e` |
| `-s` / `--start-date` | Start date (`YYYY-MM-DD`, time fixed at 18:00) | With `-e` when no `-f` |
| `-e` / `--end-date` | End date (`YYYY-MM-DD`, time fixed at 18:00) | With `-s` when no `-f` |
| `-w` / `--workers` | Concurrent repair query workers (default: 5, range: 1-10) | No |

## Output

Generates `yield_errorcode_summary_YYYYMMDDHHMM.xlsx` with sheets:

- **Summary** - FPYP, YR, pass/fail/testing counts
- **Last_Record_Per_SN** - Last test record per serial number with repair info
- **ErrorCode_Repaired** - Error code frequency for repaired units
- **SN_Repaired** - Detail listing of repaired serial numbers
