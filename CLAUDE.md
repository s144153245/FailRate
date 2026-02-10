# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file Python tkinter GUI tool (`Cal_FR_20260115.py`) for calculating manufacturing yield and fail-rate metrics at Wistron. It:

1. **Fetches test records** from an internal Django-based test data portal (HTTP API with CSRF auth)
2. **Queries a repair portal** (ASP.NET WebForms) to check if each serial number has repair history
3. **Computes yield metrics** (FPYP, YR) and error code summaries for repaired units
4. **Exports results** to a timestamped Excel file with multiple sheets

## Running

```bash
python Cal_FR_20260115.py
```

Requires: `pandas`, `requests`, `beautifulsoup4`, `openpyxl`, `tkinter` (stdlib).

## Architecture

- **Test Data Portal integration** (`_test_*` functions): Login via CSRF-protected Django endpoint, fetch paginated test records, convert JSON response to DataFrame
- **Repair Portal integration** (`login`, `query_barcode`, `extract_repair_*`): ASP.NET WebForms with ViewState; scrapes HTML tables for production history, identifies "FAE Repair(RN)" rows, extracts error codes and previous stage
- **Analysis pipeline** (`run_yield_and_errorcode_summary`): Joins test records with repair data per serial number, computes pass/fail/testing counts, FPYP (first-pass yield without repair), YR (yield rate)
- **GUI** (`App` class): Minimal tkinter wrapper with log output and single action button

## Key Constants

- `STATUS_PASS_VALUES`, `STATUS_FAIL_VALUES`, `STATUS_TESTING_VALUES` — define how test status strings map to pass/fail/testing
- `TEST_PRODUCT_NAMES`, `TEST_STAGES` — filter criteria for test record queries
- `prev_stage_set` (line ~589) — hardcoded set of stage names used to count test-repaired units

## Security Warning

Credentials are hardcoded in the file (lines 20-28, 37-38). These MUST be externalized to environment variables before committing to any repository.
