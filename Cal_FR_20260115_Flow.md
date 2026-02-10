# Cal_FR_20260115.py 腳本完整流程說明

## 目錄 (Table of Contents)

1. [概述 (Overview)](#1-概述-overview)
2. [常數與設定 (Constants & Configuration)](#2-常數與設定-constants--configuration)
3. [測試資料入口 (Test Data Portal)](#3-測試資料入口-test-data-portal)
4. [維修入口 (Repair Portal)](#4-維修入口-repair-portal)
5. [分析流程 (Analysis Pipeline)](#5-分析流程-analysis-pipeline)
6. [Excel 輸出 (Excel Output)](#6-excel-輸出-excel-output)
7. [GUI 介面 (GUI Interface)](#7-gui-介面-gui-interface)
8. [完整執行流程圖 (Full Execution Flow)](#8-完整執行流程圖-full-execution-flow)

---

## 1. 概述 (Overview)

此腳本是一個 **製造良率與錯誤碼分析工具**，用於：

- 從內部 **測試資料入口 (Test Data Portal)** 抓取測試紀錄
- 從內部 **維修入口 (Repair Portal)** 查詢每個序號 (Serial Number) 是否有維修歷史
- 計算良率指標：**FPYP (First Pass Yield without repair)** 與 **YR (Yield Rate)**
- 將結果匯出為帶有多個工作表的 **Excel 檔案**

技術棧 (Tech Stack)：
- `tkinter`：GUI 框架
- `pandas`：資料處理與分析
- `requests`：HTTP 請求
- `BeautifulSoup`：HTML 解析
- `openpyxl`：Excel 寫入（由 pandas 內部調用）

---

## 2. 常數與設定 (Constants & Configuration)

### 2.1 欄位名稱對應 (Column Name Mapping)

| 常數 | 值 | 用途 |
|------|---|------|
| `SN_COL` | `"SerialNumber"` | 統一後的序號欄位名 |
| `TIME_COL` | `"StartTime"` | 統一後的測試開始時間欄位名 |
| `STATUS_COL` | `"TestStatus"` | 統一後的測試狀態欄位名 |
| `STAGE_COL` | `"Stage"` | 統一後的測試站別欄位名 |
| `ERROR_COL` | `"ErrorCode"` | 統一後的錯誤碼欄位名 |

### 2.2 維修入口設定 (Repair Portal Config, Lines 19-28)

| 設定 | 說明 |
|------|------|
| `LOGIN_URL` | 維修入口登入頁面 (ASP.NET WebForms) |
| `BARCODE_URL` | 條碼查詢頁面 |
| `USER_ID` / `PASSWORD_HASH` / `PASSWORD_PLAIN` | 登入憑證 |
| `VERIFY_SSL` | 設為 `False`，跳過 SSL 驗證 |

### 2.3 測試資料入口設定 (Test Data Portal Config, Lines 30-47)

| 設定 | 說明 |
|------|------|
| `TEST_BASE_URL` | Django 測試資料伺服器 IP |
| `TEST_LOGIN_URL` | 登入端點 `/member/login/` |
| `TEST_SEARCH_URL` | 搜尋 API `/search/search_action/` |
| `TEST_COUNT_URL` | 計數 API `/search/search_action_get_count/` |
| `TEST_PRODUCT_NAMES` | 產品名稱過濾條件，例如 `["Gaines2.0-F1"]` |
| `TEST_STAGES` | 測試站別過濾條件 `["NH", "NX", "N2", "TP", "NI", "UA"]` |
| `TEST_STATUS` | 狀態碼 `["0", "1", "2", "3", "4"]`（全部狀態） |
| `TEST_TYPES` | 測試類型 `["MP"]`（量產） |
| `TEST_START_TIME` / `TEST_END_TIME` | 查詢的時間範圍 |
| `TEST_PAGE_CAP` | 單次查詢最大筆數上限 `200000` |

### 2.4 狀態值定義 (Status Value Definitions, Lines 50-52)

腳本將測試狀態字串分成三類：

| 分類 | 匹配值 | 額外匹配邏輯 |
|------|--------|-------------|
| **Pass** | `{"pass", "0"}` | 或包含 `"pass"` 子字串 |
| **Fail** | `{"fail", "1", "unfinish", "unfinished"}` | 或包含 `"fail"` 子字串 |
| **Testing** | `{"testing", "2"}` | 或包含 `"testing"` 子字串 |

`_status_masks()` 函式 (Line 55) 接收一個 pandas Series，回傳三個布林遮罩 (boolean masks)。

---

## 3. 測試資料入口 (Test Data Portal)

### 3.1 建立瀏覽器模擬 Session (`_test_browser_session`, Line 63)

```
建立 requests.Session
  → 設定 User-Agent 標頭模擬 Chrome 瀏覽器
  → 回傳 Session 物件
```

### 3.2 登入流程 (`_test_login_and_get_session`, Line 75)

```
步驟 1: GET /member/login/
  → 伺服器回傳登入頁面
  → Session 自動接收 cookies（包含 csrftoken）

步驟 2: 從 cookies 取得 csrftoken
  → 若不存在，拋出 RuntimeError

步驟 3: POST /member/login/
  → 傳送 payload: username, password, csrfmiddlewaretoken
  → 傳送 headers: Referer, Origin, X-CSRFToken, Content-Type
  → 允許重導向 (allow_redirects=True)

步驟 4: GET / (首頁)
  → 確保 session cookies 完整建立

步驟 5: 回傳已登入的 Session
```

### 3.3 CSRF 標頭產生器 (`_test_csrf_headers`, Line 104)

每次 POST 請求都需要附帶 CSRF 標頭：

- `X-CSRFToken`：從 cookies 取得
- `Referer`：指向來源頁面
- `X-Requested-With: XMLHttpRequest`：模擬 AJAX 請求

### 3.4 查詢 Payload 建構 (`_test_base_payload`, Line 121)

建構搜尋 API 所需的 POST 表單資料：

```python
{
    "part_number": "",
    "product_name[]": TEST_PRODUCT_NAMES,   # 產品名稱
    "serial_number": "",
    "tester_sn": "",
    "stage[]": TEST_STAGES,                  # 測試站別
    "test_status[]": TEST_STATUS,            # 全部狀態
    "test_type[]": TEST_TYPES,               # MP (量產)
    "start_time": TEST_START_TIME,           # 開始時間
    "end_time": TEST_END_TIME,               # 結束時間
    "error_code": "",
    "error_description": "",
    "opid": "",
    "workOrder": "",
    "sku_name": "",
    "page_length": "40",                     # 每頁筆數 (之後會覆蓋)
    "queryTestRecordId": "0",                # 分頁游標
    "queryCompare": ">",                     # 游標比較方向
}
```

### 3.5 取得全部測試紀錄 (`_test_get_all_records_once`, Line 149)

```
步驟 1: 呼叫 _test_login_and_get_session() 登入
步驟 2: 建構 base payload
步驟 3: POST /search/search_action_get_count/
  → 回傳 JSON: { "all_record_count": N, "page_count": M }
  → 取得總筆數 total

步驟 4: 若 total <= 0，回傳空結果

步驟 5: 設定 page_length = min(total, 200000)
  → 一次取回所有紀錄（或最多 200000 筆）

步驟 6: POST /search/search_action/
  → 回傳 JSON，包含測試紀錄陣列

步驟 7: 回傳 (count_response, records_response)
```

### 3.6 JSON 轉 DataFrame (`_records_to_dataframe`, Line 169)

```
輸入: API 回傳的 JSON 物件

若為 list → 直接轉為 DataFrame

若為 dict → 依序嘗試以下 key 取出資料陣列:
  "data" → "records" → "rows" → "result" → "items" → "ret_lis" → "data_list"

若都找不到 → 拋出 ValueError

回傳: pd.DataFrame
```

### 3.7 欄位名稱正規化 (`_normalize_columns`, Line 192)

由於 API 回傳的欄位名稱可能不一致，此函式將各種可能的名稱統一對應：

| 目標欄位 | 可能的原始名稱 (按優先順序) |
|----------|--------------------------|
| `SerialNumber` | serialnumber, serial_number, sn, usn, unit_sn, unit s/n |
| `StartTime` | starttime, start_time, time, test_time, datetime, start_time_str |
| `TestStatus` | teststatus, test_status, status, result |
| `Stage` | stage, test_stage, process_stage |

若任一必要欄位找不到對應，拋出 `ValueError`。

---

## 4. 維修入口 (Repair Portal)

### 4.1 登入流程 (`login`, Line 240)

維修入口使用 ASP.NET WebForms，登入步驟：

```
步驟 1: GET Login.aspx
  → 取得 HTML 頁面
  → 呼叫 extract_form_fields() 解析所有 <input> 欄位

步驟 2: 覆蓋表單欄位值
  → _VIEWSTATE = "" (清空)
  → _EVENTVALIDATION = 硬編碼的 base64 字串
  → UserIdText = "11109117"
  → PasswordText = MD5 hash
  → txtUnencryptedPassword = 明文密碼
  → LoginButton = "登入"
  → LanguageList = "auto"
  → txtPasswordLength = "10"

步驟 3: POST Login.aspx
  → 帶上所有表單欄位

步驟 4: 檢查回傳 URL
  → 若仍在 Login.aspx → 登入失敗
  → 否則 → 登入成功
```

### 4.2 條碼查詢 (`query_barcode`, Line 271)

```
步驟 1: GET MIBASIC003.aspx
  → 取得查詢頁面 HTML
  → 解析所有表單欄位

步驟 2: 覆蓋表單欄位
  → _VIEWSTATE = 硬編碼的超長 base64 字串（包含 session 狀態）
  → _VIEWSTATEGENERATOR = "61BD1585"
  → ddlFltMFGTYPE = "FA"
  → rblFltTYPE = "USN" (以 Unit Serial Number 查詢)
  → txtFltBARCODE = 要查詢的序號
  → cmdQuery = "Query"

步驟 3: POST MIBASIC003.aspx
  → 回傳包含生產歷史的 HTML 頁面
```

### 4.3 錯誤碼萃取 (`extract_repair_errorcode`, Line 291)

此函式是整個腳本最複雜的部分，負責從 HTML 表格中萃取錯誤碼。

#### 4.3.1 內部輔助函式

- `_normalize_header(text)`：將表頭文字標準化（小寫、合併空白）
- `_find_production_history_table()`：找到 "Production History" 標題後的表格
- `_find_table_with_headers(required_headers)`：找到包含指定表頭的表格
- `_extract_from_production_history(prod_table)`：從生產歷史表格萃取錯誤碼

#### 4.3.2 錯誤碼萃取邏輯 (`_extract_from_production_history`)

```
步驟 1: 解析表頭列
  → 建立 col_map: { 正規化表頭名 → 欄位索引 }
  → 找到 stage_idx, result_idx, data_idx

步驟 2: 解析所有資料列
  → 跳過空列、欄位不足的列
  → 若無表頭，且欄位數 > 7，使用固定索引 (4, 5, 7)

步驟 3: 尋找 "FAE Repair(RN)" 列
  → 掃描每一列的 stage 欄位
  → 記錄最後一個匹配的列索引為 repair_row_idx

步驟 4: 特殊邏輯 — I2C pretest 檢測
  → 若 repair 列的前一列 stage 為 "Pre Test 1(TN)"
  → 直接回傳 "I2C pretest"

步驟 5: 決定搜尋範圍
  → 若有 repair 列 → 只搜尋 repair 列之前的紀錄
  → 若無 repair 列 → 搜尋全部紀錄

步驟 6: 連續失敗檢測（≥ 3 次）
  → 遍歷搜尋範圍
  → 若連續 3 筆以上 result 包含 "fail" 且 data 欄位有值（非 "N/A"）
  → 記錄該錯誤碼

步驟 7: 若找到連續失敗錯誤碼 → 回傳

步驟 8: 回退邏輯 — 最後一筆失敗紀錄
  → 從搜尋範圍尾端向前掃描
  → 找到第一筆 result 包含 "fail" 且 data 有值的紀錄
  → 回傳其 data 欄位

步驟 9: 最終回退
  → 回傳最後一列的 data 欄位值

步驟 10: 若以上皆無 → 回傳空字串
```

#### 4.3.3 主函式邏輯 (Line 408-429)

```
步驟 1: 收集所有包含 "stage" 和 "data" 表頭的表格

步驟 2: 呼叫 _find_table_after_heading("Production History")
  → 注意：此處存在一個 BUG — 函式名為 _find_table_after_heading
    但定義的是 _find_production_history_table，名稱不一致
  → 若找到，插入到表格清單最前面（優先處理）

步驟 3: 依序對每個表格呼叫 _extract_from_production_history()
  → 找到第一個有錯誤碼的結果即回傳

步驟 4: 若全部都沒有 → 回傳空字串
```

### 4.4 前一站別萃取 (`extract_repair_prev_stage`, Line 432)

```
步驟 1: 找到 "Production History" 表格
步驟 2: 解析表頭，找到 stage 欄位索引
步驟 3: 遍歷資料列，尋找 "FAE Repair(RN)" 列
步驟 4: 回傳 repair 列的前一列的 stage 值
  → 若找不到 repair 列或 repair 是第一列 → 回傳空字串
```

### 4.5 維修紀錄查詢整合 (`has_repair_record`, Line 499)

```
輸入: session, 序號 (sn), log 函式

步驟 1: 呼叫 query_barcode() 取得 HTML
步驟 2: 檢查 HTML 中是否包含 "fae repair(rn)" 字串
  → 有 → has_repair = 1
  → 無 → has_repair = 0

步驟 3: 若有維修紀錄
  → 呼叫 extract_repair_errorcode() 萃取錯誤碼
  → 呼叫 extract_repair_prev_stage() 萃取前一站別

步驟 4: 回傳 (has_repair, error_code, prev_stage)
  → 若發生例外 → 回傳 (0, "", "")
```

---

## 5. 分析流程 (Analysis Pipeline)

### 5.1 錯誤碼統計 (`_errorcode_summary`, Line 512)

```
輸入: df_last (每個 SN 最後一筆紀錄), mask (篩選遮罩),
      total_units (總機台數), error_col (錯誤碼欄位名)

步驟 1: 篩選符合 mask 且錯誤碼非空的紀錄
步驟 2: 移除空白字串的錯誤碼
步驟 3: 依錯誤碼分組計數 (groupby + size)
步驟 4: 計算 FailRate(%) = Count / total_units * 100
步驟 5: 依計數降序排序

回傳: DataFrame [ErrorCode, Count, FailRate(%)]
```

### 5.2 主分析函式 (`run_yield_and_errorcode_summary`, Line 533)

這是整個腳本的核心函式，串接所有步驟：

```
═══════════════════════════════════════════════════
  階段 1: 取得測試紀錄
═══════════════════════════════════════════════════

步驟 1.1: 呼叫 _test_get_all_records_once()
  → 登入測試資料入口
  → 取得總筆數
  → 下載全部測試紀錄

步驟 1.2: 呼叫 _records_to_dataframe()
  → 將 JSON 轉為 DataFrame

步驟 1.3: 呼叫 _normalize_columns()
  → 統一欄位名稱

步驟 1.4: 檢查必要欄位是否存在
  → SerialNumber, StartTime, TestStatus, Stage

═══════════════════════════════════════════════════
  階段 2: 取得每個 SN 的最後一筆紀錄
═══════════════════════════════════════════════════

步驟 2.1: 依 [SerialNumber, StartTime] 排序

步驟 2.2: 對每個 SerialNumber 取最後一筆 (groupby + tail(1))
  → 這代表每個序號的「最新測試結果」

步驟 2.3: 計算不重複的總機台數 (nunique)

═══════════════════════════════════════════════════
  階段 3: 查詢維修紀錄
═══════════════════════════════════════════════════

步驟 3.1: 登入維修入口 (呼叫 login())

步驟 3.2: 對每個序號逐一查詢 (迴圈)
  → 已查詢過的 SN 會跳過（快取機制）
  → 呼叫 has_repair_record() 取得:
    - has_repair: 0 或 1
    - repair_error: 錯誤碼字串
    - prev_stage: 維修前站別字串

步驟 3.3: 將結果映射回 DataFrame
  → 新增三個欄位:
    - HasRepair: 0/1
    - RepairErrorCode: 字串
    - PrevRepairStage: 字串

═══════════════════════════════════════════════════
  階段 4: 計算良率指標
═══════════════════════════════════════════════════

步驟 4.1: 呼叫 _errorcode_summary()
  → 針對 HasRepair == 1 的機台
  → 統計 RepairErrorCode 的分佈

步驟 4.2: 建立維修機台序號清單
  → 篩選 HasRepair == 1 的紀錄
  → 欄位: SN, TestStatus, Stage, StartTime,
          HasRepair, RepairErrorCode, PrevRepairStage

步驟 4.3: 計算狀態統計
  → pass_mask: 最後一筆狀態為 Pass 的機台
  → fail_mask: 最後一筆狀態為 Fail 的機台
  → testing_mask: 最後一筆狀態為 Testing 的機台
  → pass_count: Pass 機台數
  → pass_fail_count: Pass + Fail 機台數
  → pass_no_repair_count: Pass 且無維修紀錄的機台數
  → testing_count: Testing 中的機台數

步驟 4.4: 計算測試站維修數
  → 定義 prev_stage_set (允許的前一站別):
    - flash(nh)
    - flc(nx)
    - finaltest3(ua)
    - fct1(n2)
    - finaltest1(tp)
  → 正規化 PrevRepairStage（小寫、去空白）
  → test_repaired_count = HasRepair==1 且 PrevRepairStage 在允許集合中

步驟 4.5: 組裝 Summary DataFrame
  → TotalUnits: 總機台數
  → RepairedUnits: 有維修紀錄的機台數
  → PassUnits: Pass 機台數
  → FailUnits: Fail 機台數
  → TestingUnits: Testing 中的機台數
  → FPYP = pass_no_repair_count / total_units
    (First Pass Yield w/o repair: 一次通過且無維修的比率)
  → YR = pass_count / pass_fail_count
    (Yield Rate: 通過數 / (通過+失敗)，排除 testing)
```

---

## 6. Excel 輸出 (Excel Output)

### 6.1 檔案命名

格式：`yield_errorcode_summary_YYYYMMDDHHmm.xlsx`

例如：`yield_errorcode_summary_202602101430.xlsx`

### 6.2 工作表結構

| 工作表名稱 | 內容 | 欄位 |
|-----------|------|------|
| **Summary** | 良率摘要（1 列） | TotalUnits, RepairedUnits, PassUnits, FailUnits, TestingUnits, FPYP, YR |
| **Last_Record_Per_SN** | 每個 SN 的最後一筆測試紀錄 + 維修資訊 | SerialNumber, StartTime, TestStatus, Stage, HasRepair, RepairErrorCode, PrevRepairStage, ... (原始欄位，移除 ErrorCode) |
| **ErrorCode_Repaired** | 維修機台的錯誤碼統計 | ErrorCode, Count, FailRate(%) |
| **SN_Repaired** | 有維修紀錄的序號清單 | SerialNumber, TestStatus, Stage, StartTime, HasRepair, RepairErrorCode, PrevRepairStage |

---

## 7. GUI 介面 (GUI Interface)

### 7.1 視窗配置 (`App.__init__`, Line 639)

```
┌─────────────────────────────────────────────┐
│  [Run Summary (Yield + ErrorCodes)]  [Clear] │  ← 按鈕列
├─────────────────────────────────────────────┤
│                                             │
│  (Log 輸出區域，唯讀 Text widget)            │
│  高度 22 行                                  │
│                                             │
└─────────────────────────────────────────────┘
```

### 7.2 功能說明

| 元件 | 功能 |
|------|------|
| **Run Summary 按鈕** | 呼叫 `run_yield_and_errorcode_summary()`，傳入 `self.log` 作為日誌回呼 |
| **Clear Prompt 按鈕** | 清除 log 區域的所有文字 |
| **Log 區域** | 唯讀 Text widget，即時顯示處理進度 |

### 7.3 錯誤處理

若 `run_yield_and_errorcode_summary()` 拋出例外：
1. 在 log 區域顯示 `ERROR: <訊息>`
2. 彈出 `messagebox.showerror` 對話框

---

## 8. 完整執行流程圖 (Full Execution Flow)

```
使用者點擊 [Run Summary]
│
├── 1. 登入測試資料入口 (Django)
│   ├── GET /member/login/ → 取得 csrftoken
│   ├── POST /member/login/ → 帶 username/password/csrf
│   └── GET / → 確認 session
│
├── 2. 查詢測試紀錄
│   ├── POST /search/search_action_get_count/
│   │   └── 取得 total record count
│   ├── POST /search/search_action/
│   │   └── 下載全部測試紀錄 (JSON)
│   ├── JSON → DataFrame
│   └── 正規化欄位名稱
│
├── 3. 資料前處理
│   ├── 依 [SN, Time] 排序
│   └── 每個 SN 取最後一筆紀錄 → last_df
│
├── 4. 登入維修入口 (ASP.NET)
│   ├── GET Login.aspx → 取得表單欄位
│   └── POST Login.aspx → 帶 UserID/Password/ViewState
│
├── 5. 逐一查詢維修紀錄 (迴圈)
│   │
│   ├── 對每個 SN:
│   │   ├── POST MIBASIC003.aspx → 取得生產歷史 HTML
│   │   ├── 搜尋 "FAE Repair(RN)" 字串 → 判斷是否有維修
│   │   ├── 若有維修:
│   │   │   ├── 解析 Production History 表格
│   │   │   ├── 萃取錯誤碼 (連續3次失敗優先/最後失敗回退)
│   │   │   └── 萃取前一站別
│   │   └── 快取結果，避免重複查詢
│   │
│   └── 將結果映射回 last_df
│       → HasRepair, RepairErrorCode, PrevRepairStage
│
├── 6. 計算良率指標
│   ├── 狀態分類: Pass / Fail / Testing
│   ├── FPYP = Pass且無維修 / 總機台
│   ├── YR = Pass / (Pass + Fail)
│   └── 錯誤碼統計 (僅維修機台)
│
├── 7. 輸出 Excel 檔案
│   ├── Summary 工作表
│   ├── Last_Record_Per_SN 工作表
│   ├── ErrorCode_Repaired 工作表
│   └── SN_Repaired 工作表
│
└── 8. 在 GUI Log 區域顯示結果摘要
```

---

## 附註 (Notes)

### 已知問題 (Known Issues)

1. **函式名稱不一致 (Line 420)**：主函式呼叫 `_find_table_after_heading("Production History")`，但實際定義的是 `_find_production_history_table()`。這會導致 `NameError` 例外。

2. **未定義變數 (Line 392)**：在 `_extract_from_production_history` 中，`print(prev_stage, consecutive_candidate)` 使用了 `prev_stage` 變數，但此變數未在該函式作用域內定義，會導致 `NameError`。

3. **憑證硬編碼**：使用者名稱、密碼、密碼雜湊值直接寫在原始碼中，應改用環境變數或設定檔。

4. **SSL 驗證停用**：`VERIFY_SSL = False` 且全域停用了 urllib3 的 InsecureRequestWarning。

5. **無分頁處理**：測試紀錄若超過 `TEST_PAGE_CAP` (200,000)，超出部分會被截斷。

6. **同步阻塞 GUI**：維修入口的逐一查詢在主執行緒執行，查詢期間 GUI 會凍結無回應。
