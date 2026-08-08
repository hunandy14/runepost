# runepost 落地設計書

> ## ⚠ 部分內容已被取代(架構已改為標準 PowerShell 模組)
>
> 本文件描述的是 **`src/` fragment + `build.ps1` 組裝 → `dist/` 單檔產物** 那套架構。
> 該架構已整個移除,改為標準 PowerShell 模組:`RunePost/`(`.psd1` + `.psm1` +
> `Public/` + `Private/`,一檔一函式)加上 repo 根目錄兩支薄入口腳本
> `rune-seal.ps1` / `rune-open.ps1`。**單檔部署已放棄**,加密端改為複製整個
> `RunePost/` 資料夾。
>
> | 章節 | 現況 |
> |---|---|
> | §1 容器格式、金鑰管理、錯誤路徑、指紋 | **仍然有效**,是規格的權威來源 |
> | §4 / §6 及所有提到 `build.ps1` / `dist/` / fragment 的段落 | **已失效**,僅供理解歷史決策 |
> | §4.3 UTF-8 BOM 的理由 | **仍然有效**,現套用於模組檔與入口腳本 |
>
> 本文件依現行架構重寫屬於階段二的工作。在那之前,實作以程式碼與
> `tests/verify.ps1` 為準,本文件只在「容器格式與金鑰管理規格」這件事上具權威性。

> **本文件為實作唯一依據。**
> 實作者只需閱讀本文件;所有結論、行號、行數與取捨理由都已收錄在此,不需回頭參考任何對話紀錄。
> 若實作過程中發現本文件與現況不符,**先回報再動手**,不要自行推測。

| 項目 | 內容 |
|---|---|
| 專案／repo 名 | **runepost**(不加連字號,與工具命名空間區隔) |
| 工具產物 | `rune-seal.ps1`(加密端)、`rune-open.ps1`(解密端 + 金鑰管理);未來 `rune-clip.ps1` |
| 容器 magic | `RUNE`(4 bytes ASCII) |
| 容器 version | `0x02` |
| 私鑰檔 | `~\.rune\private.key`(三種儲存格式共用同一路徑,由內容判別,見 §1.7.7) |
| 公鑰檔 | `~\.rune\public.pem`(明文 PEM,**執行期讀取,不內嵌**) |
| 命名前綴 | 常數與函式由 `Ctxt` 改為 `Rune` |
| 現況起點 | 單檔 `transfer.ps1`,871 行,SHA-256 `1B2301F1…`,分支 `agent/main` @ `9f53082` |
| 架構 | `src/` fragment + `build.ps1` 組裝 → `dist/` 單檔產物 |

本文件內所有「原 NNN 行」皆指**現況的 `transfer.ps1`(871 行)**。

---

## 0. 已核准的設計修正

以下皆已經協調者確認採納,實作時以本文件為準。

### 0-A. 產生檔檔頭放「來源 digest」,不放 commit hash

產物內容一旦依賴 git 狀態,則(1)包含該 hash 的 commit 本身無法自我一致(雞生蛋);(2)每 commit 一次所有產物立刻 stale,`build.ps1 -Check` 永久紅燈。
**改為寫入「所有來源 fragment 串接後的 SHA-256 前 12 碼」。** 自我一致、可重現、可被 `-Check` 完整涵蓋。溯源需求由 `git log dist/` + `git blame src/` 滿足。

### 0-B. contentType 必須進 HKDF info,且合法性檢查移到 GCM 驗證之後

若 contentType 不綁進金鑰派生,這是一個**實質的 content-type confusion 漏洞**。詳見 §1.3 / §1.4。

### 0-C. 取消公鑰內嵌,改為執行期讀檔

repo 公開且 `dist/` 進版控,內嵌公鑰只有兩種爛結果:committed 產物帶著使用者的公鑰(別人抓下來就是加密給他),或維持空字串(抓下來不能用,人人都得編輯腳本)。**改讀檔兩者皆解。** 詳見 §1.7。

### 0-D.(已撤回)裸座標取代 SPKI DER

曾評估把 ephemeral 公鑰改存裸座標 X‖Y(64 bytes)並移除長度欄位,以省 29 bytes。**已撤回,不實作。** 節省幅度不值得動到金鑰匯入路徑並新增一整組 invalid-curve 安全測試。容器維持 §1.1 的 SPKI DER 佈局,`BinaryPrimitives` 的 uint16 讀寫保留,繼續沿用 `ImportSubjectPublicKeyInfo` 由平台驗證公鑰的既有路徑。壓縮座標議題一併結案。

---

## 1. 容器格式規格 RUNE v2

### 1.1 二進位佈局

| 位移 | 長度 | 欄位 | 說明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `RUNE` |
| 4 | 1 | version | `0x02` |
| **5** | **1** | **contentType** | **新增。`0x01` = 檔案樹、`0x02` = UTF-8 純文字** |
| 6 | 2 | ephPubKeyLen | uint16 **Little Endian**(用 `BinaryPrimitives`,對應原 354 / 520 行) |
| 8 | n | ephPubKey | ephemeral ECDH P-256 **SubjectPublicKeyInfo DER** |
| 8+n | 12 | nonce | |
| 20+n | 16 | tag | AES-GCM |
| 36+n | — | ciphertext | |

明文側被加密的內容:
- contentType `0x01`:`Brotli( Zip( 輸入 ) )`
- contentType `0x02`:`Brotli( UTF8( 文字 ) )` — **無 ZIP 層**

編碼後整體 Base64(`InsertLineBreaks`,每 76 字元換行)。

必要的位移修改(相對現況):
- 原 503 行 `$headerMin = 4 + 1 + 2` → `4 + 1 + 1 + 2`(= **8**)
- 原 519 行 `Get-ByteRange … -Offset 5` → `-Offset 6`
- 原 521 行 `$offset = 7` → `$offset = 8`

M0 實測基準:`ephPubKeyLen = 91`,舊格式 `nonce@98 / tag@110`;新格式應為 `nonce@99 / tag@111`。

### 1.2 為什麼 contentType 放在 version 之後、1 byte、明文

- **緊接 version**:version 的職責是「決定後續怎麼解析」,任何新欄位都必須被 version 管到。放 byte 5 讓 `magic + version`(byte 0–4)成為**所有版本共通、永遠可解析的前綴**;未來 v3 可自 byte 5 起全部重新定義,而不失去「這是 Rune 檔、版本是 N」的判讀能力。放在結尾則必須讀完全檔才知型別。
- **1 byte**:值域是小型封閉列舉,uint16 純屬浪費;且 header 最小長度從 7 變 8,恰好對齊 8 bytes。
- **明文而非藏進密文**:唯一代價是洩漏「這是檔案還是文字」。但**負載大小早就把這件事喊出來了**(一則便條 vs 一個 2 MB 封存),在此威脅模型下這 1 bit 的額外洩漏可忽略。換得的是解密端可在動用任何金鑰前就知道解出來要怎麼處理。

### 1.3 contentType 必須進 HKDF info —— 這是安全必要條件

現行 `info = magic(4) + version(1) + ephPubKeyDer`(原 291–300 行)。
**必須改為 `info = magic(4) + version(1) + contentType(1) + ephPubKeyDer`。**

理由:現行 AES-GCM 呼叫**完全沒有使用 AAD**(原 326 行 `$aesGcm.Encrypt($Nonce, $PlainBytes, $cipherBytes, $tag)` 只有四個引數;M0 基線的 C08 亦獨立確認 `AAD=none`),所以 tag 只涵蓋 ciphertext,涵蓋不到 header 任何一個 byte。

若 contentType 不進 info:攻擊者把 `0x01` 翻成 `0x02`,**GCM tag 依然驗過**,解密端會把一串 ZIP 位元組當成 UTF-8 文字處理 —— content-type confusion 的教科書案例。

綁進 info 之後:翻位元 → 派生金鑰不同 → tag 不符 → 走既有的 `AuthenticationTagMismatchException` 路徑(原 760–762 行),**零額外程式碼**。

`Get-RuneHkdfInfo` 由 10 行變 ~13 行:多一個 `$ContentType` 參數、配置長度 `+1`、寫入該 byte、後續 `BlockCopy` 目標位移 `+1`。

### 1.4 型別合法性檢查必須在 GCM 解密**之後**

| 檢查位置 | 「位元被竄改」的訊息 | 「較新版本產生」的訊息 |
|---|---|---|
| 解析時(`ConvertFrom-RuneContainer`) | ❌ 誤報成「不支援的內容型別」 | ✓ |
| **解密成功後(`Invoke-RuneOpen`,原 765 行之後、768 行之前)** | ✓「內容驗證失敗…可能被竄改或損壞」 | ✓「本容器的內容型別 0xNN 由較新版本的 Rune 產生,請更新 `rune-open.ps1`」 |

因為 contentType 已進 info,**tag 驗過就等於這個 byte 是真品**;此時若值仍未知,才能斷定是版本落後而非資料損毀。

**實作規則:**
- `ConvertFrom-RuneContainer` **只擷取,不驗證**(回傳物件新增 `ContentType` 欄位,任何 0x00–0xFF 值都不報錯)。
- 驗證放在 `Invoke-RuneOpen`,GCM 解密成功之後、Brotli 解壓之前,約 6 行。

### 1.5 新舊互斥(CTXT ↔ RUNE)

沿用 version `0x02` 是安全的,因為 **magic 檢查排在 version 檢查之前**(原 509–511 早於 513–516):

- 舊 `CTXT` 密文餵給 `rune-open.ps1` → magic 不符立即拒絕,永遠到不了 version 比對。
- 反向亦然。
- 縱深防禦:magic 亦在 HKDF info 內,即使強行跳過檢查,派生金鑰也不同 → tag 不符。

格式註解必須明寫:
> **RUNE v2 與 CTXT v2 無血緣關係,version 編號重用純屬巧合,兩者靠 magic 互斥。**

實證由 M0 凍結的樣本提供,見 §11。
**注意**:magic 檢查發生在任何金鑰操作之前,所以驗證「舊容器被拒絕」**不需要有效私鑰**。M1 實作時優先採用硬編碼 header 位元組樣板(可攜),M0 的 blob 作為備援。

### 1.6 純文字負載(contentType `0x02`)編碼規格 — 供下一輪實作

管線:`UTF-8 bytes → Brotli → AES-GCM → base64`。**無 ZIP 層。**
只有 ZIP 是條件式的;Brotli / 加密 / 編碼三層在兩種型別間完全共用。

| 規則 | 內容 |
|---|---|
| 編碼 | UTF-8,**不含 BOM** |
| 編碼器 | seal 側用 `[System.Text.UTF8Encoding]::new($false, $true)`,即 **`throwOnInvalidBytes = $true`**。否則不可編碼的輸入(unpaired surrogate)會被靜默替換成 U+FFFD,破壞逐位元組可逆性且無任何提示 |
| 正規化 | **一律不做**。不動換行(CRLF / LF / CR 原樣)、不 trim 前後或尾端空白、不做 Unicode NFC/NFD 正規化、不移除零寬字元 |
| U+FEFF | 若出現在文字中(含開頭)視為一般字元原樣保存,**不剝除** |
| 還原 | 逐位元組還原;輸出時不補尾隨換行、不加 BOM |
| 可逆性判準 | 以**位元組**比對,不以字串比對 |
| 空字串 | 建議拒絕,與 `-Pack` 拒絕空資料夾(原 160–162 行)行為一致 |
| 短字串膨脹 | Brotli 對極短輸入會略微變大,**接受**;管線一致性優先 |

未來測試案例:T01 CRLF/LF/CR 混用 roundtrip 位元組全等 · T02 尾端空白與連續換行保留 · T03 emoji(BMP 外 surrogate pair)+ CJK + 零寬字元 · T04 空字串行為 · T05 開頭 U+FEFF 不被剝除 · T06 單字元(Brotli 後變大)仍可 roundtrip · T07 1 MB 大文字 · T08 NFC/NFD 兩版本各自正確還原。

### 1.7 金鑰管理(公鑰執行期讀檔、私鑰儲存與匯出)

#### 1.7.1 取消內嵌

**刪除 `$PublicKeyPem` 常數(原 50–66 整段)。** 公鑰改為執行期取得。

理由:repo 公開且 `dist/` 進版控,內嵌只有兩種爛結果 —— committed 產物帶著使用者的公鑰(別人抓下來就是加密給他),或維持空字串(抓下來不能用,人人都得先編輯腳本)。改讀檔後 `dist/` 產物是**與金鑰無關的通用工具**,任何人抓下來配自己的金鑰即可用。這同時強化了 §5「dist 應該 commit」的論證。

#### 1.7.2 解析順序

`rune-seal.ps1` 取得公鑰的順序:

1. 若指定了 `-PublicKey <string>`:
   - 字串含 `-----BEGIN` → **視為 PEM 內容本體**
   - 否則 → **視為檔案路徑**
2. 未指定 → 讀預設路徑 `~\.rune\public.pem`

`-PublicKey` 的用途是一次性使用免落檔(例如腳本內以 here-string 帶入)。
**實務提醒**:多行 PEM 直接當命令列引數傳遞很彆扭(換行處理因 shell 而異),主要使用情境是變數或 here-string;文件應如此建議。

#### 1.7.3 錯誤路徑

| 情況 | 行為 |
|---|---|
| 公鑰檔不存在 | 明確報:「找不到公鑰:`<path>`。請先在解密端執行 `rune-open.ps1 -GenerateKeys`,把印出的 `public.pem` 複製到本機 `<path>`,或用 `-PublicKey` 指定路徑或 PEM 字串。」 |
| 檔案存在但非合法 PEM | 沿用原 277–280 行的訊息:「公鑰 PEM 格式無效,無法載入:…」 |
| 曲線非 P-256 | 沿用原 283–286 行的訊息:「公鑰不是 P-256:曲線 OID 為 …,本工具僅支援 P-256(…)」 |

三者皆 exit 1 且**不產生任何輸出檔**。

#### 1.7.4 公鑰指紋(防掉包)

**威脅**:公鑰檔被掉包會讓使用者靜默地把資料加密給攻擊者。**資料檔被換比腳本被改更難察覺** —— 腳本有 git、有 digest 檔頭,而 `~\.rune\public.pem` 什麼都沒有。指紋是這條路徑上唯一的防線。

**演算法(規格,必須逐條照做):**

| 步驟 | 內容 |
|---|---|
| 輸入 | 收件人公鑰的 `ExportSubjectPublicKeyInfo()` **DER 位元組** |
| 雜湊 | SHA-256 |
| 取樣 | 前 **16 bytes**(128 bits) |
| 呈現 | 大寫 hex,每 4 字元一組、以 `-` 連接,共 8 組 |
| 完整格式 | `RUNE-KEY A1B2-C3D4-E5F6-0789-1A2B-3C4D-5E6F-7081` |

**為什麼輸入取 SPKI DER 而非 PEM 文字或裸座標:**
- SPKI DER 是**正規、唯一**的序列化;PEM 文字會因換行、尾隨空白、標頭大小寫而變動,不可用。
- SPKI DER **內含曲線 OID**,所以指紋天生跨曲線域分離 —— 一把 P-384 金鑰在構造上不可能與 P-256 金鑰的指紋相撞。
- **可用標準工具獨立驗證**:`openssl pkey -pubin -in public.pem -outform DER | openssl dgst -sha256` 得到相同摘要,使用者不必信任我們的腳本。

**為什麼取 16 bytes 而非更短(此處刻意強化):**
指紋是公鑰替換攻擊的**唯一**防線。8 hex 字元(32 bits)可在筆電上分鐘級磨出碰撞金鑰;16 hex 字元(64 bits)約 2^64,昂貴但非不可及。32 hex 字元(128 bits)則永久出局。代價僅是單行 39 個字元,分組後仍可目視比對 —— 快速檢查可只比對首尾兩組,需要嚴謹時再比對全串。

**印出時機:**
- `rune-seal.ps1` **每次執行都印**(在「打包中」之前),讓使用者每次都有機會發現異常。
- `rune-open.ps1 -GenerateKeys` 與 `-ExportPublicKey` 印**相同格式**,供兩端目視比對。

#### 1.7.5 `-GenerateKeys` 與公鑰檔的覆蓋策略

> **本節已修訂,不再是「私鑰存在即整段拒絕」。** 原始版本(沿用原 871 行單檔
> `transfer.ps1` 的 811–813 行)在私鑰存在時一律拒絕、不做任何事。落地後改為
> 仿 `ssh-keygen` 的互動確認 + 改名備份,理由與規則如下。

**成功輸出精簡為 4 行**(路徑 + 指紋,不再預設印出公鑰 PEM 全文;要看內容用
`Get-Content ~\.rune\public.pem`;原本較長的備份/遺失警語移到
`shell/open-help.ps1` 的 comment-based help)。`-ExportPublicKey` 的輸出比照
同一風格。

| 情境 | 行為 | 理由 |
|---|---|---|
| `private.key` 已存在、互動環境、未帶 `-Force` | **印出現有指紋 + 互動提示確認是否繼續**,預設為「不繼續」(直接 Enter、`n`,或任何非 `y`/`yes` 皆取消,以 exit 0 印「已取消,未變更任何檔案」結束) | 覆蓋不再是不可逆的資料遺失動作(見下一列的改名備份),但仍應讓使用者明確確認自己在動哪一把金鑰——提示同時印出現有指紋,供比對 |
| `private.key` 已存在、非互動環境(`[Console]::IsInputRedirected`)且未帶 `-Force` | **一律拒絕,exit 1**,訊息指引改用 `-Force` 或手動處理 | 非互動子行程(例如 `tests/verify.ps1` 用子行程跑腳本並關閉 stdin)不得卡在等輸入,否則整套測試掛死 |
| 確認繼續(互動輸入 `y`/`yes`,或帶 `-Force`) | **不刪除舊金鑰,改為改名保留**:`private.key` 改名為 `private.key.bak-<時間戳>`;若 `public.pem` 存在,以**同一個時間戳**一併改名為 `public.pem.bak-<時間戳>`(時間戳格式 `yyyyMMdd-HHmmss`,同秒碰撞則退避加 4 碼亂數尾碼),兩者改名成功後才產生並寫入新金鑰對 | 舊金鑰改名保留而非刪除,代表舊密文仍可用 `-KeyFile` 指向備份路徑解密——「覆蓋」不再是不可逆動作,只是換了一把預設金鑰。互動提示與成功輸出都必須把備份路徑講清楚,讓使用者知道救援手段還在 |
| 備份改名任一步失敗 | **中止,不產生新金鑰**;若私鑰已改名但公鑰改名失敗,會先把私鑰名稱還原回原位再報錯 | 不得留下「舊檔已搬走但新金鑰沒有真的產生」的半套狀態 |
| `private.key` 不存在、`public.pem` 存在 | **直接覆蓋 `public.pem`**(不改名備份) | 孤兒 `public.pem`(私鑰已遺失)比沒有檔案**更危險** —— seal 會持續加密給一把沒人持有的金鑰,產出永久無法解讀的密文。覆蓋才是安全動作;此分支不涉及私鑰,無需經過上面的確認/備份流程 |
| 寫入順序 | **先寫 `private.key`,再寫 `public.pem`** | 若 `public.pem` 寫入失敗,`private.key` 仍在,可用 `-ExportPublicKey` 補救。反序則會留下一把無對應私鑰的公鑰 |

`-GenerateKeys` 新增 `-Force` 開關:跳過互動提示直接以上述「改名備份→產生新
金鑰」流程執行,供非互動使用(腳本、排程)。

#### 1.7.6 新增 `-ExportPublicKey` 模式(`rune-open.ps1`)

讀取既有的 `private.key`,重新導出公鑰,**自由覆寫** `public.pem`,並印出路徑與指紋
(精簡輸出,不再預設印出 PEM 全文,理由同 §1.7.5;要看 PEM 內容用 `Get-Content`)。

存在的必要性:
- `public.pem` 由 `private.key` **可完全重現**,因此不珍貴、覆寫無風險。
- 但 `-GenerateKeys` 只有在明確確認(或帶 `-Force`)後才會動既有私鑰,**若沒有這個模式,使用者一旦刪掉或遺失 `public.pem` 就再也生不回來**。
- 兼作「再印一次我的指紋」的工具,供隨時與加密端比對。

#### 1.7.7 私鑰儲存格式(`-GenerateKeys -Protect`)

私鑰寫到 `~\.rune\private.key`,靜態保護方式由 `-Protect` 決定,共三種,**預設 `None`**:

| `-Protect` | 落地內容 | 可否備份 | 產生時的輸出 |
|---|---|---|---|
| `None`(預設) | 未加密的 PKCS#8 PEM(`ExportPkcs8PrivateKeyPem`),標頭 `-----BEGIN PRIVATE KEY-----` | 可,直接複製 | 摘要 + **未加密警告**(三行,走警告串流) |
| `Passphrase` | 密碼保護的 PKCS#8 PEM(`ExportEncryptedPkcs8PrivateKeyPem`,PBKDF2-HMAC-SHA256 600000 次 + AES-256-CBC),標頭 `-----BEGIN ENCRYPTED PRIVATE KEY-----` | 可,還原需密碼 | 摘要 |
| `Dpapi` | DPAPI(CurrentUser,無 entropy)保護的 PKCS#8 位元組 | **否** | 摘要 |

**為什麼預設是 `None`。** 密文張貼到公開管道後即為永久存在,而私鑰是唯一的還原手段
—— 私鑰遺失等同所有歷來密文永久無法解密。DPAPI 的靜態保護最強,但綁定本機與本
Windows 帳號,重灌或換帳號後即無法還原,也**無法備份**。此處把可攜性放在靜態加密之前,
代價是未加密的私鑰檔,因此 `None` 每次產生都必須印出警告:檔案未加密、任何能讀取它的人
都能解開所有以對應公鑰加密的密文、不要放進雲端同步資料夾或版本控管目錄。

**密碼的取得。** 模組函式與入口腳本皆接受 `[securestring] $Passphrase`;未提供時於互動
環境以 `Read-Host -AsSecureString` 詢問,並要求輸入兩次比對(密碼打錯即永久無法還原該檔)。
**非互動環境(`[Console]::IsInputRedirected`)且未提供密碼時一律擲回錯誤、exit 1,不得
顯示提示** —— 排程工作與以子行程執行本工具的測試都會關閉標準輸入,顯示提示會讓行程
永不結束。

**取得密碼的時機。** `-GenerateKeys` 必須在任何檔案被改名或寫入**之前**取得密碼:這一步
會因非互動、兩次輸入不一致或空密碼而失敗,此時既有的 `private.key` / `public.pem` 必須
維持原狀。

**載入端自動判別格式。** 三種格式共用 `~\.rune\private.key` 這一個路徑,**不依格式分檔名**;
`Get-RunePrivateKey` 由檔案內容判別(`Get-RunePrivateKeyFormat`):

1. 內容含 `-----BEGIN ENCRYPTED PRIVATE KEY-----` → 密碼保護的 PKCS#8 PEM
2. 內容含 `-----BEGIN PRIVATE KEY-----` → 未加密的 PKCS#8 PEM
3. 其餘 → DPAPI 位元組

比對順序必須先 1 後 2:後者的標記是前者的子字串,順序相反會把加密 PEM 誤判為未加密 PEM。
DPAPI 位元組是二進位,以 UTF-8 解碼後不會命中任何標記。三種格式匯入後一律驗證曲線為 P-256。

**相容性硬性要求:既有的 DPAPI 私鑰不需任何轉換,必須繼續可用。** DPAPI 的位元組格式與
`Unprotect(CurrentUser, entropy = null)` 的呼叫方式皆不得改變。

#### 1.7.8 `-ExportPrivateKey` 模式(`rune-open.ps1`)

從既有私鑰匯出成可備份的 PKCS#8 PEM,**來源包含 DPAPI 私鑰** —— 這是把 DPAPI 私鑰離機
保存的唯一途徑,也是本模式存在的理由。

| 參數 | 規則 |
|---|---|
| `-OutFile` | **必填,不給預設值**。輸出路徑若已存在則拒絕,加 `-Force` 才覆蓋(與 `-Pack` 的 `-OutFile` 一致) |
| `-KeyFile` | 來源私鑰,預設 `~\.rune\private.key`;三種格式皆可作為來源 |
| `-Protect` | 匯出格式,`None`(預設)或 `Passphrase`。**不支援 `Dpapi`**,明確拒絕並說明:DPAPI 檔案在其他機器或帳號無法還原,不具備份用途 |
| `-Passphrase` | **來源私鑰**的密碼(來源為加密 PEM 時需要) |
| `-OutPassphrase` | **匯出檔**的密碼(`-Protect Passphrase` 時需要)。與 `-Passphrase` 分開,因為來源與備份是兩個各自獨立的密碼,共用一個參數無法在非互動環境下同時指定 |
| `-Force` | 略過確認提示,並允許覆蓋已存在的 `-OutFile` |

**確認提示。** 匯出會把受保護的私鑰寫成一個新的、可攜的檔案,`-Protect None` 產生的檔案
沒有任何加密保護,是提高私鑰暴露面的動作,因此預設為不繼續。規則與 `-GenerateKeys` 的
覆蓋確認完全一致:印出來源、輸出路徑與格式 → 預設 `N` → `-Force` 略過 → 非互動且無
`-Force` 則拒絕。此處**不使用 `ShouldProcess`**;全專案確認機制改用標準寫法是後續獨立
的一輪,混用兩種風格比統一使用手刻更難維護。

**檢查順序。** 先擋輸出檔已存在(便宜且與確認無關),再顯示確認提示,最後才載入來源私鑰
與取得匯出密碼。被拒絕時不得產生任何檔案。

成功輸出:來源路徑、輸出路徑與格式、公鑰指紋(與來源相同)、以 `-KeyFile` 使用該備份的
命令;`-Protect None` 另印未加密警告。

---

## 2. `src/` 切檔佈局

### 2.1 命名軸:依「能力」分目錄,不依產物

不使用 `seal-*` / `open-*` 檔名前綴 —— 那會把「屬於哪個產物」寫死進檔名,第三個產物一來就全錯。**改用能力分類,產物歸屬完全由 manifest 決定:**

```
src/
  container/   容器格式常數與讀寫（跨產物、跨負載型別）
  crypto/      ECDH、HKDF、AES-GCM
  codec/       Brotli 壓／解（跨負載型別）
  filemode/    ZIP 打包／解包／路徑安全 —— 僅 contentType 0x01
  textmode/    （下一輪）UTF-8 編／解 —— 僅 contentType 0x02
  keystore/    金鑰路徑、公鑰載入、私鑰載入、指紋、金鑰生命週期
  flow/        各模式主流程
  shell/       各產物的 help / param / entry
```

### 2.2 fragment 清單

「可載入」欄 = 是否可被單獨 dot-source 而不產生副作用(規則見 §2.4)。

| fragment | 原 transfer.ps1 行號 | 估行 | 可載入 | seal | open | (clip) |
|---|---|---|:---:|:---:|:---:|:---:|
| `container/format-spec.ps1` | 68–81 註解(擴充)+ 82–85, 88 + 2 個 ContentType 常數 | 35 | ✅ | ● | ● | ● |
| `container/write.ps1` | 342–365 `New-RuneContainer`(+2 寫 contentType) | 30 | ✅ | ● | | ● |
| `container/read.ps1` | 94–106 `Get-ByteRange` + 500–542 `ConvertFrom-RuneContainer`(+4) | 66 | ✅ | | ● | ● |
| `crypto/ecdh-keygen.ps1` | 264–268 `New-RuneEcdhKeyPair` | 9 | ✅ | ● | ● | ● |
| `crypto/kdf.ps1` | 291–311 `Get-RuneHkdfInfo`(+3) + `Get-RuneDerivedAesKey` | 27 | ✅ | ● | ● | ● |
| `crypto/ecdh-agree.ps1` | 469–494 `Get-RuneSharedSecretForDecrypt` | 30 | ✅ | | ● | ● |
| `crypto/aes-seal.ps1` | 313–336 `Protect-RuneAesGcm` | 28 | ✅ | ● | | ● |
| `crypto/aes-open.ps1` ⓂM7 | 750–758 內聯 → 抽成 `Unprotect-RuneAesGcm` | 14 | ✅ | | ● | ● |
| `codec/brotli-compress.ps1` | 246–258 `Compress-RuneBrotli` | 17 | ✅ | ● | | ● |
| `codec/brotli-expand.ps1` | 450–463 `Expand-RuneBrotli` | 18 | ✅ | | ● | ● |
| `codec/base64.ps1` ⓂM7 | 435–436 / 723–734 內聯 → 抽成兩函式 | 20 | ✅ | ● | ● | ● |
| **`filemode/entry-path.ps1`** ⭐新 | 567–582 抽出 `Resolve-RuneSafeEntryPath`(§2.5) | 22 | ✅ | | ● | |
| `filemode/pack-plan.ps1` | 112–204 `Get-RunePackPlan` | 97 | ✅ | ● | | |
| `filemode/zip-write.ps1` | 206–240 `New-RuneZipBytes` | 39 | ✅ | ● | | |
| `filemode/zip-read.ps1` | 548–616 `Expand-RuneZip`(−16 抽出) + 618–646 `Move-RuneExtractedTree` | 90 | ✅ | | ● | |
| **`keystore/paths.ps1`** ⭐新 | 86–87 常數(→ `~\.rune\`)+ `public.pem` 路徑 | 14 | ✅ | ● | ● | ● |
| **`keystore/fingerprint.ps1`** ⭐新 | 無前身;`Get-RuneKeyFingerprint`(§1.7.4) | 20 | ✅ | ● | ● | ● |
| **`keystore/public-key.ps1`** ⭐新 | 吸收 270–289 `Get-RuneStaticPublicKey`,改為 `Get-RunePublicKey`(路徑／PEM 字串判別 + 讀檔 + 解析 + 曲線檢查) | 38 | ✅ | ● | | ● |
| `keystore/private-key.ps1` | 652–706 `Get-RunePrivateKey`(常數已移出) | 61 | ✅ | | ● | ● |
| `keystore/generate-keys.ps1` | 810–846 `Invoke-RuneGenerateKeys`(+寫 public.pem、印指紋、覆蓋策略) | 52 | ✅ | | ● | |
| **`keystore/export-public-key.ps1`** ⭐新 | 無前身;`Invoke-RuneExportPublicKey`(§1.7.6) | 26 | ✅ | | ● | |
| `flow/seal-main.ps1` | 371–444 `Invoke-RuneSeal`(+公鑰解析、+印指紋) | 84 | ✅ | ● | | |
| `flow/open-main.ps1` | 712–804 `Invoke-RuneOpen`(+6 contentType 檢查) | 104 | ✅ | | ● | |
| `shell/seal-help.ps1` | 1–21 改寫 | 16 | ⚪ | ● | | |
| `shell/seal-param.ps1` | 23–32, 47–48(+`-PublicKey`) | 18 | ❌ | ● | | |
| `shell/seal-entry.ps1` | 852–871 單分支 | 12 | ❌ | ● | | |
| `shell/open-help.ps1` | 1–21 改寫 | 18 | ⚪ | | ● | |
| `shell/open-param.ps1` | 23–24, 34–45, 47–48(+`-ExportPublicKey`) | 22 | ❌ | | ● | |
| `shell/open-entry.ps1` | 852–871 三分支 | 18 | ❌ | | ● | |

✅ 可單獨 dot-source · ⚪ 純註解,載入無意義但無害 · ❌ 不可載入

**src/ 合計 28 個 fragment(M7 後 30 個)、~1005 行、重複 0 行。**

> **退場**:`shell/seal-pubkey.ps1`(原 50–66 的 `$PublicKeyPem` 區塊)與 `crypto/recipient-key.ps1`(原 270–289)不再存在,後者的邏輯被 `keystore/public-key.ps1` 吸收。

### 2.3 歸類決定的理由

- **`keystore/paths.ps1` 獨立且兩產物共用**:`~\.rune\` 這個路徑必須被 seal(讀 public.pem)與 open(讀寫 private.key / public.pem)同時知道。放在單一 fragment 讓它**結構性地只定義一次**,而不是「請兩邊保持一致」。這正是 build 架構相對於複製貼上的價值。
- **`keystore/fingerprint.ps1` 獨立**:seal 與 open 都要印,但 open 不需要 `keystore/public-key.ps1` 的 PEM 檔案載入邏輯(它從私鑰導出公鑰)。拆開才不會讓 open 拖進用不到的程式碼。
- **`codec/brotli-*` 獨立於 `filemode/`**:兩種負載型別共用 Brotli 層。
- **`filemode/zip-read.ps1` 整組僅檔案模式**:純文字產物整組不收 —— 一個只處理剪貼簿文字的工具本來就不該帶著任意檔案寫入的能力。這是攻擊面上的實質收益,不只是行數。
- **`filemode/entry-path.ps1` 獨立成檔**:讓單元測試能只載入這 22 行純函式,不必拖進 `Expand-RuneZip` 的檔案 I/O。詳見 §2.5。

### 2.4 【硬性約束】fragment 純度:可單獨 dot-source

> **除 param fragment 與 entry fragment 外,每個 fragment 都必須是「純定義、零副作用」。**
> 只允許 `function` 定義與 `$Script:` 常數賦值。
> **不得有頂層執行語句;不得在「載入時」依賴其他 fragment 已載入。**

#### 載入期 vs 執行期(唯一的歧義,必須釐清)

`container/read.ps1` 中的 `ConvertFrom-RuneContainer` 會引用 `$Script:RuneMagic`(定義於 `container/format-spec.ps1`)。這**不違反**約束:

- **載入時**該 fragment 只定義函式,不求值任何常數 → 單獨 dot-source 成功。
- **呼叫時**才需要常數存在 → 那是執行期依賴,由單元測試自行宣告所需的 fragment 集合。

**規則:載入期獨立 ≠ 呼叫期獨立。** 每個單元測試檔在開頭以陣列宣告它要載入的 fragment 清單並依序 dot-source。

#### 唯一需要留意的載入期求值

`keystore/paths.ps1` 內的常數含 `Join-Path $HOME '.rune'`,在載入時求值。這是純計算(無 I/O、無狀態變更),符合約束;但單元測試若要換路徑,必須在 dot-source **之後**覆寫,不能靠環境變數。

> 註:公鑰內嵌取消後,原先「`$PublicKeyPem` 需改為 `$Script:` 範圍」的問題自動消失 —— 該常數已完全刪除。

#### 四個不可載入的 fragment —— 為什麼,以及邏輯是否該再往下抽

| fragment | 不可載入的原因 | 是否該再抽一層 |
|---|---|---|
| `shell/seal-param.ps1`<br>`shell/open-param.ps1` | (1) `param()` 內有 `Mandatory = $true` 參數,dot-source 會觸發互動提示或繫結失敗;(2) `Set-StrictMode` 與 `$ErrorActionPreference` 會**變更呼叫端的工作階段狀態**,是明確的副作用 | **不需要。** 參數繫結與互斥邏輯由 PowerShell 的參數繫結器負責,不是我們的程式碼;既有黑箱案例 C29(參數集互斥)、C30(缺 `-Destination` 不得卡互動)已完整覆蓋 |
| `shell/seal-entry.ps1`<br>`shell/open-entry.ps1` | 純頂層執行:`try { switch … } catch { …; exit 1 }`。載入即執行,且 `exit 1` 會直接殺掉測試 runner | **不需要,因為「往下一層」已經存在。** `flow/seal-main.ps1` 與 `flow/open-main.ps1` 提供的 `Invoke-RuneSeal` / `Invoke-RuneOpen` 已經是接受明確參數的普通函式(對應原 371–376 / 712–717 行的 param 區塊),完全可 dot-source、可直接呼叫。entry fragment 只是 12–18 行的轉接器,其行為(exit code、單行 stderr)已由既有黑箱案例覆蓋 |

`shell/*-help.ps1` 是純註解 + `#Requires`,dot-source 無害但也無意義,標為 ⚪。

### 2.5 【為可測性所需】抽出 zip-slip 路徑安全判斷

#### 現況與問題

路徑安全判斷目前內嵌在 `Expand-CtxtZip`(原 548–616 行)的 `foreach` 迴圈裡:

- 原 567–570 行:entry 名稱含反斜線 → 擲 `SecurityException`
- 原 572–573 行:`/` 轉為系統分隔符 → `Join-Path` 出 `$destPath`
- 原 578–582 行:`[Path]::GetFullPath($destPath)` 正規化後,要求開頭必須是 `$destRootWithSep`(原 561 行),否則擲 `SecurityException`

**問題:要測一條惡意路徑,目前必須先偽造一個密碼學上完全合法的完整容器。** `verify.ps1` 的 `New-ForgedCtxt`(855–893 行,39 行)才做得到,且還依賴 C08 先反推出 KDF 參數(857 行 `Assert ($null -ne $script:KdfInfo)`)。單案邊際成本極高,所以現在只測了 4 條路徑(C37 / C41 / C46 / C47)。

#### 抽取規格

新增純函式 `Resolve-RuneSafeEntryPath`,置於 `filemode/entry-path.ps1`:

- **輸入**:`-EntryName <string>`(ZIP entry 全名)、`-DestRoot <string>`(已解析的絕對目的資料夾路徑)
- **輸出**:正規化後的絕對目標路徑字串
- **失敗**:擲 `[System.Security.SecurityException]`,訊息文字與現行完全相同(兩種:「entry 名稱含反斜線」、「跳脫目的資料夾」)
- **純度**:**零 I/O**。`[Path]::GetFullPath` 對不存在的路徑只做字串正規化。`$destRootWithSep` 改為在函式內部計算(每 entry 兩次字串運算,成本可忽略),使函式只靠兩個字串即可測試 —— 這正是抽取的目的
- 呼叫端 `Expand-RuneZip` 以 1 行呼叫取代原 567–582 的 16 行

#### 成本

`+22` 行新 fragment,`−16` 行內聯,`+1` 行呼叫 → **淨 +7 行**。

#### 風險與必須保留的行為

| 項目 | 要求 |
|---|---|
| 例外型別 | **必須維持 `System.Security.SecurityException`**。`Invoke-RuneOpen`(原 781–785 行)專門攔截此型別並原樣上拋,避免被包裝成「封裝格式錯誤或已損壞」而讓使用者忽略安全問題。型別改了會同時打掉 C37 / C41 / C46 / C47 |
| 呼叫順序 | 必須在「尾隨 `/` 判定為目錄」的分支(原 584 行)**之前**呼叫。C46 / C47 專門驗證目錄 entry 也要走檢查 |
| 訊息文字 | 兩則訊息逐字保留 |
| 綠燈判準 | C37、C41、C44、C46、C47 五案必須維持 PASS |

**風險等級:低。** 機械式 extract-method,無演算法變更,有 5 個既有黑箱案例當護欄。

#### 一併修正的潛在弱點(非 bug,是紀律問題)

現行程式碼**檢查的是 `$fullResolved`(原 578 行),實際寫入用的卻是 `$destPath`(原 585 / 596 行)**。兩者在此情境下等價,但「檢查一個字串、使用另一個字串」是不該依賴的假設。

**建議:抽取後讓函式回傳正規化路徑,呼叫端一律使用回傳值做 I/O** —— 檢查什麼就用什麼。這是嚴格朝更安全方向的微小行為變更,五個既有案例應維持綠燈。

#### 抽取後才測得動的東西(抽取的真正回報)

一條惡意路徑的成本從「39 行偽造容器 + 依賴 C08」降為**一行表格資料**。可低成本建立攻擊語料庫:

`../evil` · `..\evil` · `a/../../evil` · `/abs/evil` · `C:\abs\evil` · `\\?\C:\evil` · `\\server\share\evil` · `....//evil` · 尾隨點或空白 `evil.` / `evil ` · 保留名稱 `CON` / `NUL` / `COM1` · 交替資料串流 `a.txt:bad` · 超長路徑 · 單獨的 `.` 與 `..` · 空字串
必須放行的:`./ok` · `a/b/c/d.txt` · 含中文與空白的檔名 · 尾隨 `/` 的目錄 entry

**特別值得指出:同層前綴逃逸。**
`DestRoot = C:\out`、entry = `../outevil/x.txt` 正規化為 `C:\outevil\x.txt`。現行程式碼因 `$destRootWithSep` 帶尾隨分隔符(`C:\out\`)而正確拒絕;若哪天有人「簡化」掉那個尾隨分隔符,`C:\outevil\x.txt`.StartsWith(`C:\out`) 會回傳 **true**,直接造成逃逸。

**這條目前 55 案完全沒有覆蓋** —— C47 用的 `../evil2/` 在有無尾隨分隔符兩種寫法下都會被拒,驗證不到這個性質。這是單元層存在價值最具體的證據。

### 2.6 容器解析的可測性評估:**不需要抽取**

`ConvertFrom-CtxtContainer`(原 500–542 行)**已經是純函式**:`param([byte[]]$Bytes)` → 回傳 `pscustomobject`,零 I/O,只依賴四個 `$Script:` 常數與同檔的 `Get-ByteRange`。

在 §2.4 的規則下,單元測試只要依序 dot-source `container/format-spec.ps1` 與 `container/read.ps1`,即可用手工位元組陣列直接呼叫。**生產端零改動。**

同理已是純函式、可直接單元測試:`Get-ByteRange`(94–106)、`New-RuneContainer`(342–365)、`Get-RuneHkdfInfo`(291–300)、`Get-RuneDerivedAesKey`(302–311)、`Protect-RuneAesGcm`(313–336)、`Get-RuneKeyFingerprint`(新)。

**不適合單元測試**(重度 I/O,且黑箱已覆蓋良好):`Get-RunePackPlan`(C02/C03/C25–C27/C42/C43)、`Move-RuneExtractedTree`(C44/C48)、`Get-RunePrivateKey`(C15/C16/C31–C33)、`Expand-RuneZip` 的 I/O 部分。

### 2.7 PowerShell 硬限制與由此推導的組裝規則

| 限制 | 規則 |
|---|---|
| `param()` 必須是**第一個語句**(其前僅得有 `#Requires`、註解、空行) | `shell/*-help.ps1`(含 `#Requires`)**必須**是每個產物的第 1 個 fragment,`shell/*-param.ps1` **必須**緊接其後,兩者之間不得插入任何 fragment |
| `[CmdletBinding()]` 是 param 語句的一部分 | 兩者必須同檔,不可拆 |
| comment-based help 必須位於檔案開頭,且 `.EXAMPLE` 內含**自己的檔名** | 每產物一份專屬 help fragment;`.EXAMPLE` 寫 `.\rune-seal.ps1` / `.\rune-open.ps1`,不得交叉引用 |
| help 區塊若緊鄰 `function` 關鍵字會被綁到該函式而非腳本 | help 之後必接 param fragment |
| 函式定義先於執行;`$Script:` 常數依序賦值 | **唯一的排序硬需求是:help → param → …(任意順序)… → 所有 `$Script:` 常數 → entry**。函式彼此之間順序無關 |
| 遞迴函式(`Move-RuneExtractedTree`,原 636 行自呼叫) | **一個函式不得跨 fragment** |

「函式順序無關」很重要:manifest 只需保證 help / param / 常數 / entry 四個位置,中間任意排列,新增 fragment 幾乎不可能排錯。

### 2.8 順序機制:manifest 明確列序,**不使用**數字前綴

1. 同一 fragment 在不同產物中的相對位置可能不同,單一全域數字序無法同時表達多個產物。
2. 數字前綴誘導 glob-based build,那代表**任何掉進 `src/` 的檔案都會靜默進入產物** —— 對密碼學工具是不可接受的失效模式。
3. 插入新 fragment 需重新編號或留空號,都是持續的維護稅。
4. manifest 集中一處,review 時一眼看完全部產物組成。

> **強制規則:`build.ps1` 絕不 glob `src/`**,只讀 manifest 明列的路徑;另加反向孤兒檢查(§4.2 第 5 步)。

---

## 3. manifest 設計

### 3.1 形式

`build.ps1` 內的一個 `[ordered]` hashtable(**不引入 JSON**:零依賴、可寫註解、可用 PowerShell 陣列語法),約 48 行含註解。

- key = 產物基底名(`rune-seal` → `dist/rune-seal.ps1`)
- value = 依序組裝的 fragment 相對路徑(相對 `src/`)有序陣列
- 陣列內以註解分段(shell / container / crypto / codec / mode / keystore / flow / entry),讓排序意圖自明

### 3.2 為第三產物預留 —— 現在就要避開的兩個陷阱

manifest **結構**零改動即可支援 `rune-clip.ps1`(新增一個 key 即可)。但下列兩處若照直覺寫死,下一輪就得改 `build.ps1`:

| 陷阱 | 現在就要這樣寫 |
|---|---|
| `-Product` 用 `[ValidateSet('rune-seal','rune-open')]` | **改為在函式內對 `$Manifest.Keys` 驗證**(`ValidateSet` 無法引用執行期變數)。錯誤訊息列出可用產物 |
| `dist/` 的 `.gitattributes` / 清理邏輯逐檔列名 | **一律用 `dist/*.ps1` glob** |

> 原本的第三個陷阱「PEM 注入寫死 fragment 檔名」已隨 §0-C 取消公鑰內嵌而消失 —— build 不再需要任何注入邏輯。

---

## 4. `build.ps1` 規格

### 4.1 參數

| 參數 | 說明 |
|---|---|
| `-Product <string[]>` | 要建的產物;預設 = 全部。對 `$Manifest.Keys` 驗證(§3.2) |
| `-OutDir <string>` | 預設 `<repoRoot>\dist`,由 `$PSScriptRoot` 推導 |
| `-Check` | **只驗不寫**。記憶體組裝後與磁碟上產物逐位元組比對;不符則 exit 1,印出產物名與第一個相異行號 |

> **`-PublicKeyPem` 參數已取消**(§0-C)。build 不碰任何金鑰,產物是與金鑰無關的通用工具。

### 4.2 組裝流程

1. 由 `$PSScriptRoot` 解析 repo root;載入 manifest。
2. 逐 fragment:檔案不存在 → **硬失敗**並列出缺漏路徑(不容忍、不跳過)。
3. 讀 bytes → UTF-8 解碼 → **剝除任何前導 BOM** → CRLF / CR 正規化為 LF → 確保恰好以一個 `\n` 結尾 → 附加。同時記錄 `(產物行號 → fragment + fragment 內行號)` 對照表。
4. 前置產生檔檔頭(§4.4)。
5. **孤兒檢查**:`src/` 底下每個 `.ps1` 必須至少被一個產物引用,否則失敗。抓「新增了 fragment 卻忘了寫進 manifest」。
6. **組裝後語法檢查**:以 `[Parser]::ParseInput` 解析整份產物;有錯則用第 3 步的對照表把行號**映回來源 fragment** 再報。這約 30 行是整個 build 最值錢的部分 —— 沒有它,「param 不在最前面」這類錯誤會指向一個沒人編輯過的產生檔行號。
7. 寫檔;或 `-Check` 時改為比對。

### 4.3 編碼與換行

| 項目 | 決定 | 理由 |
|---|---|---|
| `src/` fragment | UTF-8 **無 BOM** | 串接後 BOM 會落在檔案中段變成 U+FEFF 亂字元,讓 PowerShell 報出無法對應的解析錯誤。build 仍主動剝除以防呆 |
| `dist/` 產物 | UTF-8 **含 BOM** | 腳本含大量中文錯誤訊息與 help。PowerShell 7 預設以 UTF-8 讀無 BOM 檔沒問題,但 **Windows PowerShell 5.1 / ISE 會以系統 ANSI(zh-TW 為 cp950)解讀無 BOM 檔** → 中文全毀;更糟的是部分 Big5 雙位元組字的**次位元組是 `0x5C`(反斜線)**,會被當跳脫字元,產生無法理解的解析錯誤。而 `#Requires -Version 7.4` 是**在解析之後**才生效,使用者看到的會是亂碼解析錯誤而非「請用 7.4」。BOM 讓每個 host 都正確解碼。另外 `verify.ps1` 現行寫副本已用 `$script:Utf8Bom`(48 行,567 行使用),BOM 是已被 55 案驗證過的路徑 |
| 換行 | 一律 **LF**,並加 `.gitattributes`:`*.ps1 text eol=lf` | 沒有這條,開發者機器上的 `core.autocrlf` 會讓 `-Check` 隨機紅燈。build 讀取時主動正規化,寫出時固定 LF,雜湊在任何 clone 上都穩定 |

BOM 對 `pwsh -File` 完全透明,不影響 `#Requires` 解析。

### 4.4 產生檔檔頭(5 行)

1. 「本檔由 `build.ps1` 自 `src/` 組裝產生,請勿直接編輯 —— 請改 `src/` 後重跑 `build.ps1`」
2. `source-digest: <來源 fragment 串接後 SHA-256 前 12 碼>`
3. `format: RUNE v2`
4. fragment 數量

**不放 commit hash**(§0-A)。檔頭本身被 `-Check` 涵蓋,因為 digest 只依賴來源內容,自我一致。

### 4.5 失敗行為

一律 `exit 1` + `[Console]::Error.WriteLine` 單行訊息(與產物的頂層錯誤出口風格一致,對應原 869 行)。任何一個產物失敗即整體失敗;**寫檔採「全部組裝並通過語法檢查後才開始寫」**,避免留下半套 `dist/`。

### 4.6 行數估算

| 區塊 | 行 |
|---|---|
| help + param | 22 |
| manifest hashtable(2 產物 + 註解) | 48 |
| fragment 讀取 / 正規化 / BOM 剝除 | 25 |
| 行號對照表 + 語法檢查 + 映射報錯 | 30 |
| 孤兒檢查 | 12 |
| 檔頭產生(含 digest) | 12 |
| 寫檔 / `-Check` 比對與差異報告 | 30 |
| 進入點與錯誤處理 | 15 |
| **合計** | **≈ 195–200** |

---

## 5. `dist/` 版控

**要 commit,明確建議。**

決定性理由:**這個工具的產品就是那個單檔。** 使用者情境是「腳本要帶到任意機器、甚至靠純文字管道貼過去」。若 `dist/` 不進版控,每個人都得先 clone + 裝 pwsh 7.4 + 跑 build 才能拿到能用的東西 —— 等於摧毀整個散布故事。

**取消公鑰內嵌後這個論證更強**(§0-C):`dist/` 產物不含任何人的金鑰,是與金鑰無關的通用工具,任何人抓下來配自己的 `public.pem` 即可用。原本「committed 產物帶著使用者公鑰」的疑慮完全消失。

| 代價 | 對策 |
|---|---|
| 每次 src 改動都產生 dist diff 噪音 | `.gitattributes` 加 `dist/*.ps1 linguist-generated=true` → **GitHub 在 PR 中預設摺疊這些 diff** |
| 有人直接編輯 `dist/` | 產生檔檔頭警語 + `build -Check` 進測試 → 下一次跑測試就紅 |
| dist 與 src 不同步的 commit | **鐵律:dist 必須與造成它的 src 改動在同一顆 commit**,不得有獨立的「rebuild」commit。這樣每顆 commit 都自我一致,`git bisect` 才可用 |
| dist 的 merge conflict | 不手工解:`git checkout --ours dist/` 後重跑 `build.ps1`。寫進 CONTRIBUTING |

**追加建議**:公開後上一個約 20 行的 GitHub Actions,在 PR 上跑 `build.ps1 -Check`。這才是把「產物過期」**結構性**消滅。並用 git tag + Release 附上 `.ps1` 作為資產。

---

## 6. 測試架構(分層)

### 6.0 分層原則 —— 兩層,物理隔離,philosophy 相反

| | 第一層:黑箱驗收 | 第二層:單元測試 |
|---|---|---|
| 檔案 | `tests/verify.ps1` | `tests/unit/*.tests.ps1` |
| 受測對象 | **`dist/*.ps1`,視為不透明的可執行檔** | **`src/` 的個別 fragment,dot-source 進來直接呼叫** |
| 撰寫依據 | **只依凍結規格盲寫**,不讀實作 | 依實作的邊界條件寫 |
| 覆蓋 | 端到端行為、錯誤訊息、exit code、檔案系統效果 | 邊界值、惡意輸入、位元組佈局 |
| 規模 | 68 案 | ~110 個斷言 |

> **鐵律:`tests/verify.ps1` 永遠不得 dot-source `src/`。**
> 它的全部價值來自「照凍結規格盲寫、只看得到產物」這個獨立性(見其檔頭 7–9 行的自述)。
> 單元層是**新增的第二層**,不是它的替代品,也不得與它合併。既有案例一個都不准改成單元測試。

### 6.1 第一層:`tests/verify.ps1` 改造估算

基準:現況 1658 行 / 55 案(M0 實測 PASS 54 / FAIL 0 / SKIP 0 / INFO 1)。

**取消公鑰內嵌帶來的結構性簡化:**

| 刪除項 | 位置 | 行 |
|---|---|---|
| `Find-PublicKeyAssignment` + `New-ScriptCopy`(AST 注入公鑰到腳本副本) | 541–569 | **−29** |
| `$script:SutEmpty` 變數與其建立 | 678, 748 | **−2** |
| 原 P6「把公鑰注入受測腳本副本」案 | 744–755 | **−12** |

**不再需要製作任何腳本副本 —— 測試直接對 `dist/rune-seal.ps1` 原檔執行,只要在沙箱家目錄放好 `public.pem` 即可。** 這是整份改造中最大的單一簡化。

| 新增／修改項 | 位置 | 行 |
|---|---|---|
| param 由 `-TransferScript` 改為 `-RepoRoot`(推導 dist 兩檔) | 17–33 | 15 |
| **新 P0:`build.ps1 -Check` 必須綠,否則 gate 全部**(沿用 757 行 `$script:CanRun` 模式) | 新 | 15 |
| P1 拆 P1a / P1b(兩產物存在且可解析) | 689–697 | 12 |
| **P2 改性質**:原本檢查 `$PublicKeyPem` 初值為空 → 改為斷言產物中**不存在任何 `$PublicKeyPem` 賦值**(確認內嵌已徹底移除) | 699–708 | 5 |
| P4 / P5 `-GenerateKeys` 改用 open 產物,並擷取其產生的 `public.pem` | 720–743 | 8 |
| **新 P6**:把 `public.pem` 佈署到沙箱家目錄的 helper | 新 | 8 |
| **26 個 `$script:SutKeyed` 呼叫點改指 Seal / Open**(11 個 `-Pack`、14 個 `-Unpack`、1 個混用;808 / 812 / 830 位於既有 helper 內) | 808…1570 | 26 |
| **C23 改性質**:`$PublicKeyPem` 為空 → 改為「`~\.rune\public.pem` 不存在時報明確錯誤且不產生輸出檔」 | 1197–1203 | 8 |
| **C45 改性質**:注入 P-384 到腳本副本 → 改為「`public.pem` 內容為 P-384 時拒絕」(不再需要腳本副本,大幅簡化) | 1514–1553 | 6 |
| C29 換成「各產物拒絕對方參數」 | 1262–1265 | 10 |
| C34 / C35 指向 open;C35 提示文字改為指向 `public.pem` 複製流程 | 1315–1332 | 8 |
| C40 → `src/` + `dist/` 雜湊未變 | 1604–1610 | 8 |
| **`CTXT`→`RUNE`:11 處**(198 `ErrPatterns.format`、**451 / 457–459 `Get-KdfCandidates` 的 salt / info 候選**、868 與 1362 手造 header、949 / 958 / 1089 / 1186 / 1232 斷言) | | 15 |
| **`.ctxt`→`.rune`:10 處**(588 沙箱 KeyPath、593 真實家目錄偵測、710 / 723 / 1301 / 1304 / 1312 文案與路徑、**1579 / 1599 / 1601 `.ctxt-tmp-*` 前綴**) | | 10 |
| **contentType**:`Read-Container`(312–348)與 C04(946–960)位移 +1;新增 4 案(byte[5] == 0x01;翻成 0x02 / 0xFF 須報**竄改**而非型別不支援;造合法 0x03 容器須報**較新版本**) | | 55 |
| **M1 專用**:舊 `CTXT` 容器須以 magic 不符被拒(§11) | 新 | 10 |
| **新案**:`-PublicKey` 收 PEM 字串本體可正常運作 | 新 | 10 |
| **新案**:`-PublicKey` 收檔案路徑可正常運作 | 新 | 8 |
| **新案**:seal 印出的指紋格式穩定,且與 `-GenerateKeys` 印的**逐字一致** | 新 | 14 |
| **新案**:`-ExportPublicKey` 可從既有私鑰重建 `public.pem`,指紋不變 | 新 | 10 |
| **新案**:`public.pem` 被換成另一把金鑰 → 指紋**必須改變**(證明防線有效) | 新 | 12 |
| 負面符號掃描(seal 不得含 `ImportPkcs8PrivateKey` / `ProtectedData` / `Expand-RuneZip`;open 不得含 `Get-RunePublicKey`) | 新 | 12 |
| **小計(新增／修改)** | | **285** |
| **小計(刪除)** | | **−43** |
| **淨受影響** | | **≈ 314 行,佔 1658 的 18.9%** |

案數:55 → **68**
(+1 P0、+1 P1 拆分、+4 contentType、+1 magic 互斥、+2 `-PublicKey`、+1 指紋一致、+1 `-ExportPublicKey`、+1 指紋改變偵測、+1 負面掃描;P2 / C23 / C45 / C29 為改性質不增減;原 P6 改性質不增減)

> **最容易漏改的一處:`Get-KdfCandidates`(443–471)。**
> 它枚舉 HKDF 的 salt / info 候選組合來反推實作用的是哪一種,`'magic'`(451)與 `'CTXT'` / `'CTXTv2'` / `'CTXT-v2'` / `'lowerctxt'`(457–460)全是候選鍵,468 行還有 `'transfer' = 'transfer.ps1'`。漏改會讓 C08 從 PASS 變成「找不到候選」的 FAIL,**而錯誤訊息不會指向 magic**,除錯成本很高。
> contentType 進 info 之後,候選集合還需**新增 `magic+ver+ctype+epk` 一項**,否則 C08 同樣找不到。
> M0 基線的 C08 證據為 `HKDF(salt=nonce, info=magicver+epk), AAD=none`,改造後應變為 `info=magicver+ctype+epk`。

122 / 159 行的 `CTXT_TARGET` 環境變數與 783 行的 `'CTXT-COMPRESSION-TEST-'` 填充字串是 verify 自用,**不需改**。

### 6.2 第二層:單元測試(新增)

#### 檔案配置

```
tests/
  verify.ps1                        ← 第一層，68 案黑箱裁判（不得引用 src/）
  _work/                            ← verify 沙箱（.gitignore）
  unit/
    run-unit.ps1                    ← 第二層 runner
    byte-range.tests.ps1
    container-read.tests.ps1
    container-roundtrip.tests.ps1
    hkdf-info.tests.ps1
    zip-entry-path.tests.ps1
    fingerprint.tests.ps1
  run-all.ps1                       ← build -Check → unit → verify，任一紅則 exit 1
```

**不使用 Pester。** 全案零外部依賴、repo 即將公開,不該為測試層引入套件安裝步驟。約 70 行的自製 runner 即可產生與 `verify.ps1` 同風格的 PASS / FAIL 彙總與 exit code。

#### runner 契約

- 每個 `*.tests.ps1` 開頭以陣列宣告所需 fragment(相對 `src/`),runner 依序 dot-source 到一個乾淨的子工作階段。
- 測試以 `It '<名稱>' { … }` 形式登記(runner 自行提供,約 15 行),擲例外即 FAIL。
- runner 回報總數 / PASS / FAIL,非零 FAIL 則 exit 1。

#### 測試檔內容與估行

| 檔案 | 載入的 fragment | 內容 | 行 |
|---|---|---|---|
| `run-unit.ps1` | — | fragment 載入器、`It` 登記與執行、彙總、exit code | 70 |
| `byte-range.tests.ps1` | `container/read` | offset / length 邊界、零長度(對應原 102–104 的 `-gt 0` 防護)、整段擷取、來源不被修改 | 35 |
| `container-read.tests.ps1` | `container/format-spec`, `container/read` | 長度 0–7 全部須拒(`headerMin` = 8);magic 四個 byte 各自翻錯;version 0x00 / 0x01 / 0x03 / 0xFF;`ephPubKeyLen` = 0;= 0xFFFF(宣告超長);恰好使 `minTotal == Bytes.Length`(**零長度 ciphertext 邊界,目前未測**);off-by-one;**uint16 LE 而非 BE 的判別向量**;contentType 全 256 值皆須解析成功不報錯(§1.4) | 110 |
| `container-roundtrip.tests.ps1` | `container/format-spec`, `container/write`, `container/read` | `ConvertFrom(New-Container(x)) == x`,對隨機化欄位長度與固定向量各跑一輪。**直接守住讀寫鏡像對的漂移,比任何雜湊比對都強** | 55 |
| `hkdf-info.tests.ps1` | `container/format-spec`, `crypto/kdf` | info 位元組佈局逐欄斷言:magic@0–3、version@4、**contentType@5**、DER 自 6 起;總長 = 6 + DER 長;**contentType 不同必須產生不同 info**(§1.3 的直接驗證);已知答案向量 | 50 |
| `zip-entry-path.tests.ps1` | `filemode/entry-path` | §2.5 攻擊語料庫(表格驅動,~40 條惡意 + ~10 條合法),含**同層前綴逃逸 `C:\out` vs `C:\outevil`**;斷言例外型別為 `SecurityException` 且訊息分辨兩種原因 | 120 |
| `fingerprint.tests.ps1` | `keystore/fingerprint` | 分組格式(8 組 ×4 hex、`-` 連接)、大寫、長度 39;同一金鑰恆定;不同金鑰必異;**與 `openssl` 路徑等價的已知答案向量**;P-256 與 P-384 同座標不可能相撞(SPKI 含 OID) | 60 |
| **合計** | | **~110 個斷言** | **500** |

`tests/run-all.ps1` 另計 **30 行**。

#### 生產端為此付出的代價

只有 §2.5 的抽取:**淨 +7 行**,新增 1 個 fragment。其餘全部靠 §2.4 的 fragment 純度約束達成,零改動。

### 6.3 測試面總計

| 層 | 行數 |
|---|---|
| 第一層 `verify.ps1` | 1658 現況 + ~314 淨改動,68 案 |
| 第二層 `tests/unit/` | ~500 新增,~110 斷言 |
| `tests/run-all.ps1` | ~30 |
| **測試面合計** | **≈ 2190 行**,對 1005 行 src,比例 2.2 : 1 |

對密碼學工具而言這個比例是恰當的。

---

## 7. 遷移 commit 序列

原則:**每一顆 commit 結束時測試必須全綠**;除明列的變更外禁止行為變更,其餘重構統一延到 M7。

| # | 內容 | 如何保住覆蓋 |
|---|---|---|
| **M0** | ✅ **已完成。** 基線凍結,不改碼。見 §11 | — |
| **M1** | **純改名,仍是單檔。** `Ctxt`→`Rune` 前綴、magic `CTXT`→`RUNE`、`~\.ctxt`→`~\.rune`、`.ctxt-tmp-`→`.rune-tmp-`;同批改 verify 的 21 處(約 25 行) | 改名穿透 verify 的**獨立規格實作層**,必須單獨成一顆才能在紅燈時分辨「改名錯」與「切檔錯」。diff 是純機械替換,review 最省力。**必須在此顆新增 magic 互斥案例** |
| **M2** | **加 contentType 欄位。** 仍是單檔。格式改動 8 處(503 / 519 / 521 / 536–541 / 342–365 / 291–300 / 371–444 / 712–804);verify 加 4 案 + 位移調整(約 55 行) | 格式變更與檔案結構變更分離。此時只有一份實作,寫錯立刻被 C08 的獨立規格實作抓到 |
| **M3** | **公鑰外部化(§1.7)。** 仍是單檔。刪除 `$PublicKeyPem`(50–66);新增 `-PublicKey` 參數、`~\.rune\public.pem` 讀取、指紋函式與印出、`-GenerateKeys` 寫公鑰檔與覆蓋策略、`-ExportPublicKey` 模式。**同批刪除 verify 的 541–569 共 29 行注入基礎設施**,改性質 P2 / C23 / C45,新增 5 案 | **放在切檔之前的理由**:這顆會**刪掉**一個未來的 fragment(`shell/seal-pubkey.ps1`)並**吸收**另一個(`crypto/recipient-key.ps1`)。先做完,M4 的切檔就直接切到最終形狀,不必先建一個註定要刪的 fragment 再刪掉。同時它讓 verify 少 29 行注入邏輯,後續改造更輕 |
| **M4** | **建 `src/` + `build.ps1` + `.gitattributes`,產物先只有一個「合體版」`dist/rune-all.ps1`** | **保命招:`-Check` 斷言 `dist/rune-all.ps1` 與 M3 的單檔除產生檔檔頭外逐位元組相同**,證明切檔沒掉字。verify **一行都不用改**,繼續以單檔模式跑全綠 |
| **M5a** | manifest 加入 `rune-seal` / `rune-open` 兩個真產物,`rune-all` **保留**;verify 改雙軌(既跑 all 也跑 seal / open) | 雙軌期間 all 是對照組:若 seal / open 紅而 all 綠,問題必在 manifest 收錄而非程式邏輯 |
| **M5b** | 移除 `rune-all`、刪 `transfer.ps1`、verify 拆單軌;完成 §6.1 其餘改造 | 上一顆已證明雙軌等價,此顆只是拆鷹架 |
| **M6** | **§2.5 的 zip-slip 抽取 + 建立第二層測試。** `tests/` 重整、`run-unit.ps1`、6 個測試檔、`run-all.ps1`;`build -Check` 進 P0 與 run-all;負面符號掃描 | 抽取由 C37 / C41 / C44 / C46 / C47 五案護航;單元層是純新增,不動產物 |
| **M7** | **行為性重構(僅此顆允許)**:抽出 `Unprotect-RuneAesGcm`(750–758)、base64 編/解(435–436 / 723–734)、選用的 `Assert-RuneP256` | 為 clip 鋪路。兩層測試全綠 + `-Check` 綠才動,每抽一個函式跑一次全案 |

M5a / M5b 拆兩顆是刻意的:那是唯一同時動產物結構與測試的階段,爆炸半徑最大。

---

## 8. 第三產物 `rune-clip.ps1` 前瞻

### 8.1 manifest 零改動即可支援

新增一個 key 即可,前提是 §3.2 的兩個調整現在就做。

### 8.2 假想組成與複用率(M7 之後)

| 來源 | fragment | 行 |
|---|---|---|
| **零改動複用** | `container/format-spec` 35、`container/write` 30、`container/read` 66、`crypto/ecdh-keygen` 9、`crypto/kdf` 27、`crypto/ecdh-agree` 30、`crypto/aes-seal` 28、`crypto/aes-open` 14、`codec/brotli-compress` 17、`codec/brotli-expand` 18、`codec/base64` 20、`keystore/paths` 14、`keystore/fingerprint` 20、`keystore/public-key` 38、`keystore/private-key` 61 | **427** |
| **新寫** | `shell/clip-help` 16、`shell/clip-param` 16、`shell/clip-entry` 14、`textmode/utf8-codec` ~25、`flow/clip-main` ~72 | **143** |
| **明確不收** | `filemode/*`(248 行,含全部路徑安全防護與檔案系統列舉)、`keystore/generate-keys` 52、`keystore/export-public-key` 26 | — |
| | **`rune-clip.ps1` ≈ 575 行,新寫僅 143 行** | |

**複用 427 行是 build 架構在此兌現的具體數字** —— 在「兩支獨立腳本」的作法下,這 427 行要嘛第三次複製貼上,要嘛在那個當下被迫做一次大重構。

### 8.3 clip 的阻塞項

clip **不阻塞於 manifest,阻塞於 M7 的兩個 extract-method**(`Unprotect-RuneAesGcm`、base64 編 / 解)。在 M7 之前硬做,clip 會重複約 35 行內聯程式碼。

---

## 9. 行數估算總表

| 項目 | 行數 |
|---|---|
| `src/` 28 個 fragment | ~1005(**重複 0 行**) |
| `build.ps1` | ~200 |
| **生產端維護總面** | **~1205** |
| `dist/rune-seal.ps1` | ~489 |
| `dist/rune-open.ps1` | ~631 |
| `dist/rune-clip.ps1`(下一輪) | ~575,其中新寫 143 |
| 第一層 `verify.ps1` 淨改動 | ~314 / 1658(18.9%),55 案 → 68 案 |
| 第二層 `tests/unit/` | ~500 新增,~110 斷言 |
| `tests/run-all.ps1` | ~30 |
| **測試面合計** | **~2190** |
| 估時(M1–M6) | **12–16 小時** |

加密端部署量:871 → **~489 行單檔**,且不含 DPAPI 私鑰讀取、ZIP 解包與路徑安全邏輯,亦不含任何人的金鑰。

---

## 10. 風險點

1. **【最高】檔頭放 commit hash 會使 `-Check` 結構性失效**(§0-A)。已改為 src 內容 digest。
2. **contentType 若未進 HKDF info,是實質的 content-type confusion 漏洞**(§1.3)。現行 GCM 完全未使用 AAD(原 326 行;M0 的 C08 獨立確認 `AAD=none`),tag 保護不到 header 任何一個 byte。
3. **型別檢查若放在解析階段,「被竄改」會被誤報成「不支援的型別」**(§1.4)。必須放在 GCM 驗證通過之後。
4. **公鑰檔掉包是取消內嵌後最主要的新增攻擊面**(§1.7.4)。`~\.rune\public.pem` 沒有 git、沒有 digest 檔頭,被換掉不會有任何跡象。**指紋是唯一防線**,因此 (a) seal 必須每次都印,(b) 指紋長度不可縮短到 64 bits 以下,(c) 使用者教育(README)必須說明第一次使用時要比對兩端指紋。
5. **孤兒 `public.pem`**(私鑰已遺失但公鑰檔還在)會讓 seal 持續產出永久無法解讀的密文。§1.7.5 的覆蓋策略必須照做。
6. **`Get-KdfCandidates`(443–471)漏改 magic 會讓 C08 以無關訊息失敗**(§6.1)。contentType 進 info 後還需新增候選項。
7. **抽取 `Resolve-RuneSafeEntryPath` 若改動例外型別,會同時打掉 C37 / C41 / C46 / C47**(§2.5)。必須維持 `System.Security.SecurityException` 與兩則訊息文字。
8. **fragment 帶 BOM → 串接後檔案中段出現 U+FEFF**,PowerShell 報出無法對應的解析錯誤。build 必須主動剝除;`.gitattributes` 需約束。
9. **`param()` 必須第一句**:任何人在 manifest 的 help 與 param 之間插一個 fragment,產物立刻壞。組裝後語法檢查 + 行號映回 fragment(§4.2 第 6 步)是必要投資。
10. **`dist/` 與 `src/` 不同步的 commit**:測試層的 P0 只在有人跑測試時擋得住。公開 repo 建議上 CI 才算結構性消滅。
11. **`Move-RuneExtractedTree` 是遞迴函式**(原 636 行自呼叫):切檔規則需明文「一個函式不得跨 fragment」。
12. **同層前綴逃逸(`C:\out` vs `C:\outevil`)目前 55 案完全未覆蓋**(§2.5)。`$destRootWithSep` 的尾隨分隔符是唯一防線,任何「簡化」都會造成逃逸。M6 的單元層必須補上。
13. **文字負載若 `throwOnInvalidBytes = $false`**,unpaired surrogate 會被靜默替換成 U+FFFD,破壞可逆性且無錯誤提示(§1.6)。
14. **第一層與第二層若被合併,黑箱獨立性即刻喪失**(§6.0)。`tests/verify.ps1` 永遠不得 dot-source `src/`。

---

## 11. 附錄:M0 基線凍結產物

M0 已執行完畢,產物位於 scratchpad(**不得進 repo**):

| 檔案 | 內容 |
|---|---|
| `M0-baseline-verify.txt` | 拆分前對 `transfer.ps1` 的完整 55 案結果:**PASS 54 / FAIL 0 / SKIP 0 / INFO 1**(C38「Destination 不存在時的行為」規格未定義,設計上即為 INFO) |
| `M0-sample-CTXT.txt` | 現行 CTXT 格式密文樣本 |
| `M0-sample-key.blob` | 能解開該樣本的 DPAPI CurrentUser 私鑰(358 B) |
| `M0-README.md` | 上述三者的說明與使用方式 |

指紋:

```
transfer.ps1   SHA-256 = 1B2301F11C13BB1D8F849A416444ADB455BD0745EB00A007FC514EB2050ED4BC
                         35509 bytes / 871 lines
樣本明文       SHA-256 = 5F5C4F928620438A7A538518C8207A82671E9022B00C7C319C9F78CFA96E1790 (182 B)
樣本容器       magic=CTXT version=0x02 ephPubKeyLen=91 nonce@98 tag@110 總長 340 B
M0 實測 KDF    HKDF(salt=nonce, info=magicver+epk), AAD=none
```

**M1 必須新增的案例**:以該樣本餵給改名後的解密腳本,必須以「容器格式錯誤:檔頭 magic 不符(讀到 'CTXT')」被拒絕、exit 1、Destination 不留任何檔案。

**可攜性提醒**:magic 檢查發生在任何金鑰操作之前(原 509–511 行早於一切),所以驗證「舊容器被拒絕」**不需要有效私鑰**。M1 實作時優先採用硬編碼 header 位元組樣板(可在任何機器重現),M0 的 DPAPI blob 僅作備援 —— 它只在產生它的那台機器、那個 Windows 帳號有效。
