# FailRate - Testing Summary Tool (CLI)

Manufacturing yield and fail-rate analysis tool for Wistron test data.

## Requirements

```bash
pip install pandas requests beautifulsoup4 openpyxl
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
| `-s` / `--start-date` | Start date (`YYYY-MM-DD`, time fixed at 18:00) | With `-e` when no `-f` |
| `-e` / `--end-date` | End date (`YYYY-MM-DD`, time fixed at 18:00) | With `-s` when no `-f` |
| `-w` / `--workers` | Concurrent repair query workers (default: 10, range: 1-20) | No |

## Output

Generates `yield_errorcode_summary_YYYYMMDDHHMM.xlsx` with sheets:

- **Summary** — TotalUnits, RepairedUnits, RepairedUnits(FCT), PassUnits, FailUnits, TestingUnits, FPYP, YR, FPY(FCT), YR(FCT)
- **Last_Record_Per_SN** — Last test record per serial number with repair info
- **ErrorCode_Repaired** — Error code frequency for all repaired units
- **ErrorCode_Repaired(FCT)** — Error code frequency for FCT-stage repaired units
- **SN_Repaired** — Detail listing of all repaired serial numbers
- **SN_Repaired(FCT)** — Detail listing of FCT-stage repaired serial numbers

## Yield Metrics

| Metric | Formula |
|--------|---------|
| **FPYP** (First Pass Yield w/o repair) | Pass units without any repair / Total units |
| **YR** (Yield Rate) | Pass units / (Pass + Fail units) |
| **FPY(FCT)** | Pass units without FCT-stage repair / Total units |
| **YR(FCT)** | Pass units without FCT repair / (Pass without FCT repair + Fail without FCT repair) |

FCT stages: NH, NX, N2, TP, NI, UA
