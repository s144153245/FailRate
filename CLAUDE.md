# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file Python CLI tool (`Cal_FR_CLI.py`) for calculating manufacturing yield and fail-rate metrics at Wistron. It:

1. **Fetches test records** from an internal Django-based test data portal (HTTP API with CSRF auth)
2. **Queries a repair portal** (ASP.NET WebForms) to check if each serial number has repair history
3. **Computes yield metrics** (FPYP, YR, FPY(FCT), YR(FCT)) and error code summaries for repaired units
4. **Exports results** to a timestamped Excel file with multiple sheets

## Running

```bash
python3 Cal_FR_CLI.py -s 2026-02-09 -e 2026-02-10
python3 Cal_FR_CLI.py -f data.xlsx -w 15
```

Requires: `pandas`, `requests`, `beautifulsoup4`, `openpyxl`, `tabulate`. Optional: `lxml` (faster HTML parsing).

## Architecture

- **Test Data Portal integration** (`_test_*` functions): Login via CSRF-protected Django endpoint, fetch paginated test records, convert JSON response to DataFrame
- **Repair Portal integration** (`login`, `query_barcode`, `_parse_production_history`, `extract_repair_*`): ASP.NET WebForms with ViewState; shared `_parse_production_history()` parses HTML table once, both `extract_repair_errorcode()` and `extract_repair_prev_stage()` consume the parsed result
- **Analysis pipeline** (`run_yield_and_errorcode_summary`): Joins test records with repair data per serial number, computes pass/fail/testing counts, FPYP, YR, FPY(FCT), YR(FCT)
- **CLI** (`main`): argparse with `-f`, `-s`, `-e`, `-w` flags; timestamped log output with section dividers

## Key Constants

- `STATUS_PASS_VALUES`, `STATUS_FAIL_VALUES`, `STATUS_TESTING_VALUES` — define how test status strings map to pass/fail/testing
- `TEST_PRODUCT_NAMES`, `TEST_STAGES` — filter criteria for test record queries
- `fct_stage_codes` — set of FCT stage codes (nh, nx, n2, tp, ni, ua) used to identify FCT-repaired units

## Yield Metric Definitions

- **FPYP** (First Pass Yield w/o repair): Pass units without any repair history / Total units
- **YR** (Yield Rate): Pass units / (Pass + Fail units) — excludes Testing units
- **FPY(FCT)**: FCT pass without FCT repair / FCT total — scoped to units that reached FCT stage (last stage >= FCT)
- **YR(FCT)**: FCT pass / (FCT pass + FCT fail) — scoped to units that reached FCT stage
- FCT stages: NH, NX, N2, TP, NI, UA (defined in `FCT_STAGE_CODES`)

## Security Warning

Credentials are hardcoded in the file (lines 37-39, 51-52). These MUST be externalized to environment variables before committing to any public repository.
