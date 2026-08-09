# runepost 設計文件

本文件描述 runepost 的當前設計：容器格式、密碼學規格、金鑰管理、軟體結構、
安全性質與驗證方式。內容與 repo 內的程式碼描述同一件事；當本文件與實作不一致時，
以本文件的規範條文（§3、§4、§5）為準，並視為實作缺陷處理。

**語言分工。** 程式執行時印給使用者看的一切——摘要、進度、警告、錯誤訊息、確認
提示，以及 `Get-Help` 會印出來的 comment-based help——**一律英文**；程式碼註解與
本文件的敘述維持繁體中文。本文件引用或展示的輸出、錯誤訊息字串因此是英文原文。
英文文案的風格比照官方 PowerShell：陳述句、句首大寫、句尾句點，先陳述問題再給
補救動作，多個補救選項分行列出，參數與路徑原樣呈現，不對使用者做價值判斷。
`RUNE`、`RUNE-KEY`、參數名、檔名與路徑一律不翻譯。

| 項目 | 內容 |
|---|---|
| 專案名 | runepost |
| 入口腳本 | `rune-seal.ps1`（加密端）、`rune-open.ps1`（解密端與金鑰管理） |
| 實作 | `RunePost\` PowerShell 模組（`.psd1` + `.psm1` + `Public\` + `Private\`） |
| 容器 magic | `RUNE`（4 bytes ASCII） |
| 容器 version | `0x02` |
| 私鑰檔 | `~\.rune\private.key`（三種儲存格式共用同一路徑，由內容判別，見 §5.6） |
| 公鑰檔 | `~\.rune\public.pem`（明文 PEM，執行期讀取，不內嵌於程式碼） |
| 執行環境 | Windows、PowerShell 7.4 以上、零外部依賴 |

---

## 1. 概觀

### 1.1 用途與使用情境

runepost 把本機的檔案或資料夾封裝成一段 Base64 純文字，讓使用者能經由只接受文字的
公開管道（論壇貼文、pastebin、即時通訊、電子郵件內文）把資料送到自己的另一台機器，
在該機器上以私鑰還原成原始的檔案樹。

典型情境是「同一個人擁有兩台機器」的單向傳輸：解密端產生金鑰對並保管私鑰，把公鑰
交給加密端；此後加密端可持續產生只有解密端解得開的密文。工具本身不涉及任何網路
傳輸，密文如何送達完全由使用者決定。

### 1.2 設計目標

- **零外部依賴。** 僅使用 .NET 內建密碼學與壓縮類別，不安裝任何套件、不呼叫外部
  執行檔。使用者只要有 PowerShell 7.4 就能執行，也才有辦法在受限的機器上使用。
- **輸出是可貼上的純文字。** 最終產物是 Base64，可以直接貼進任何純文字欄位。
- **加密端不持有秘密。** 加密端只需要收件人公鑰；即使加密端整台機器被攻陷，也無法
  解開任何既有密文。
- **全程記憶體操作。** 打包、壓縮、加密在記憶體中完成，不落地任何中間檔案。
- **通用工具。** 公鑰不內嵌在程式碼裡，任何人取得這份 repo 後配上自己的公鑰即可使用。

### 1.3 非目標

本工具刻意不處理下列問題，相關的具體邊界見 §7.2：

- 不做寄件人認證，不提供簽章。
- 不提供前向保密。
- 不提供不可觀測性或抗流量分析。
- 不處理密文的傳輸、儲存與生命週期。
- 不支援跨平台；私鑰的 DPAPI 選項與檔案權限加固都是 Windows 專屬語意。

---

## 2. 資料流

### 2.1 加密（`rune-seal.ps1 -Pack`）

```
輸入路徑（單檔／萬用字元／資料夾）
  → 打包    ZipArchive，store（NoCompression），UTF-8 檔名
  → 壓縮    Brotli，SmallestSize
  → 加密    AES-256-GCM，金鑰由 ephemeral ECDH P-256 + HKDF-SHA256 派生
  → 組容器  RUNE v2 二進位佈局（§3.1）
  → 編碼    Base64，每 76 字元換行，以 ASCII 寫出
```

輸入型態由 `Get-RunePackPlan` 判斷：

| 輸入 | 行為 | 預設輸出檔名 |
|---|---|---|
| 單一檔案 | 單一 entry | `<檔名>.txt` |
| 萬用字元 | 僅展開當層，不遞迴；命中的目錄以警告略過 | `<所在資料夾名>.txt` |
| 資料夾 | 遞迴整棵樹，保留子目錄結構；不含任何檔案的子目錄另外列舉成目錄 entry，使解包端能還原空目錄 | `<資料夾名>.txt` |

ZIP 層採 store 而非 deflate：真正的壓縮由後面的 Brotli 負責，兩層壓縮沒有收益。
ZIP 在此只承擔「把多個檔案與目錄結構收攏成單一位元組串流」的職責。

輸出檔已存在時拒絕覆寫，需明確加上 `-Force`。

### 2.2 解密（`rune-open.ps1 -Unpack`）

```
輸入文字檔
  → 去除所有空白字元後 Base64 解碼
  → 解析容器（ConvertFrom-RuneContainer，只擷取欄位，不驗證內容型別）
  → 載入私鑰（三種儲存格式由內容判別）
  → ECDH + HKDF 派生金鑰
  → AES-256-GCM 解密（認證失敗即中止）
  → 檢查 contentType 是否為本版支援的型別（§4.5）
  → Brotli 解壓
  → 解到 Destination 底下的暫存資料夾，全部成功才搬到正式位置（§7.1）
```

Base64 解碼前先移除所有空白字元，因此經由論壇或郵件轉貼而換行位置改變的密文仍可
還原；除空白以外的任何改動都會在 Base64 解碼或 GCM 認證階段被擋下。

---

## 3. 容器格式 RUNE v2

### 3.1 二進位佈局

| 位移 | 長度 | 欄位 | 說明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `RUNE` |
| 4 | 1 | version | `0x02` |
| 5 | 1 | contentType | `0x01` = 檔案樹、`0x02` = UTF-8 純文字（保留） |
| 6 | 2 | ephPubKeyLen | uint16 **Little Endian** |
| 8 | n | ephPubKey | ephemeral ECDH P-256 SubjectPublicKeyInfo DER |
| 8+n | 12 | nonce | AES-GCM nonce |
| 20+n | 16 | tag | AES-GCM 認證標籤 |
| 36+n | — | ciphertext | |

header 最小長度為 8 bytes。`ephPubKeyLen` 的讀寫一律使用
`System.Buffers.Binary.BinaryPrimitives` 的 `WriteUInt16LittleEndian` /
`ReadUInt16LittleEndian`，明確指定位元組順序，不依賴 `BitConverter` 隨平台而定的
行為。

明文側被加密的內容依 contentType 而定：

- `0x01`：`Brotli( Zip( 輸入 ) )`
- `0x02`：`Brotli( UTF8( 文字 ) )`，無 ZIP 層

整體以 Base64 編碼（`InsertLineBreaks`，每 76 字元換行）後寫成文字檔。

**本版只產生也只接受 `0x01`。** `0x02` 是已定義但尚未實作的保留值，規格見 §3.3。

### 3.2 contentType 的位置、寬度與明文存放

- **緊接 version。** version 的職責是決定後續如何解析，任何新欄位都必須被 version
  管到。把 contentType 放在 byte 5，使 `magic + version`（byte 0–4）成為所有版本
  共通、永遠可解析的前綴：未來版本可自 byte 5 起全部重新定義，而不失去「這是 Rune
  檔、版本是 N」的判讀能力。若放在容器結尾，則必須讀完整個檔案才知道型別。
- **1 byte。** 值域是小型封閉列舉，uint16 純屬浪費；且 header 最小長度因此為 8，
  對齊 8 bytes。
- **明文而非藏進密文。** 代價是洩漏「這是檔案還是文字」一個位元的資訊，但負載大小
  早已洩漏同一件事（一則便條與一個 2 MB 封存差別顯著）。換得的是解密端在動用任何
  金鑰之前就知道解出來要如何處理。這個位元的完整性由 §4.4 保護。

### 3.3 純文字負載（contentType `0x02`）編碼規格

本節為保留型別的規範，供實作時遵循。管線為
`UTF-8 bytes → Brotli → AES-GCM → base64`，**無 ZIP 層**；Brotli、加密、編碼三層
與檔案樹型別完全共用，只有 ZIP 層是條件式的。

| 規則 | 內容 |
|---|---|
| 編碼 | UTF-8，不含 BOM |
| 編碼器 | 加密端使用 `[System.Text.UTF8Encoding]::new($false, $true)`，即 `throwOnInvalidBytes = $true`。否則不可編碼的輸入（unpaired surrogate）會被靜默替換成 U+FFFD，破壞逐位元組可逆性且無任何提示 |
| 正規化 | 一律不做。不動換行（CRLF / LF / CR 原樣）、不 trim 前後或尾端空白、不做 Unicode NFC/NFD 正規化、不移除零寬字元 |
| U+FEFF | 出現在文字中（含開頭）時視為一般字元原樣保存，不剝除 |
| 還原 | 逐位元組還原；輸出時不補尾隨換行、不加 BOM |
| 可逆性判準 | 以位元組比對，不以字串比對 |
| 空字串 | 拒絕，與檔案樹型別拒絕空資料夾一致 |
| 短字串膨脹 | Brotli 對極短輸入會略微變大，接受；管線一致性優先 |

### 3.4 與 CTXT v2 的互斥

runepost 的前身工具使用 magic `CTXT`，同樣以 version `0x02` 標記。兩種格式沒有
血緣關係，version 編號重用純屬巧合，兩者靠 magic 互斥：

- `ConvertFrom-RuneContainer` 的 **magic 檢查排在 version 檢查之前**，因此 `CTXT`
  容器餵給 `rune-open.ps1` 一定先被 magic 擋下，永遠到不了 version 比對。
- magic 檢查也排在所有金鑰操作之前，所以驗證「舊容器被拒絕」不需要任何有效私鑰。
- 互斥完全由上面這道解析檢查承擔，沒有第二道。HKDF `info` 裡雖然也有 magic，但那
  一段取自模組常數而不是容器讀到的位元組（§4.2），跳過解析檢查並不會讓派生出來的
  金鑰不同，因此它不構成縱深防禦。

---

## 4. 密碼學規格

### 4.1 金鑰交換

每次加密產生一組一次性（ephemeral）ECDH P-256 金鑰對，與執行期載入的收件人靜態
公鑰做 `DeriveRawSecretAgreement`，得到原始共享祕密（共享點的 x 座標，32 bytes）。
ephemeral 公鑰以 SubjectPublicKeyInfo DER 隨容器攜帶；解密端以
`ImportSubjectPublicKeyInfo` 匯入，由平台負責公鑰的結構與曲線驗證。

公鑰與私鑰匯入後一律驗證曲線 OID 為 `1.2.840.10045.3.1.7`（P-256），不符即拒絕，
並在錯誤訊息中點名實際讀到的曲線。

### 4.2 金鑰派生（規範）

內容金鑰一律以 HKDF-SHA256 派生。以下參數全部定死，加密端、解密端與任何獨立驗證
實作都不得自行選擇：

| 項目 | 值 |
|---|---|
| 演算法 | HKDF，雜湊為 **SHA-256** |
| `ikm` | ECDH `DeriveRawSecretAgreement` 回傳的**原始共享祕密**（32 bytes），**不先經任何雜湊** |
| `salt` | 容器內的 **nonce**（12 bytes，§3.1 位移 `8+n`） |
| `info` | `magic(4) ‖ version(1) ‖ contentType(1) ‖ ephemeral 公鑰 SPKI DER` |
| 輸出長度 | **32 bytes**，直接作為 AES-256-GCM 的金鑰 |

逐項理由：

- **`ikm` 取原始共享祕密而非其雜湊。** HKDF 的 extract 階段本就是為「分布不均勻的
  原始金鑰材料」設計，自行先雜湊一次是多餘的一層，還會讓任何以標準工具重現派生的
  人對不上步驟。
- **`salt` 取 nonce。** nonce 每次加密重新隨機產生，且明文隨容器攜帶，解密端不需
  額外欄位就能重建 salt。**這使 nonce 的隨機性成為本規格的安全前提，而不只是 GCM
  的要求**：HMAC 會把短於 block size 的 salt 補零，nonce 一旦退化為全零位元組，
  `salt = nonce` 與 `salt = null` 會導出同一把金鑰。
- **輸出 32 bytes。** 對應 AES-256。
- **`info` 綁入三個 header 欄位。** 見 §4.4。
- **`info` 各段的來源。** magic 與 version 兩段取自**模組常數**（`$Script:RuneMagic`、
  `$Script:RuneVersion`），contentType 與 ephemeral 公鑰 SPKI DER 兩段取自**容器**。
  兩端因此對前兩段永遠使用本版的值。在所有可達路徑上這與「取自容器」等價——解析
  階段已經要求容器的那兩個欄位逐位元組等於同一組常數，不符就在動用任何金鑰之前
  被拒（§7.1(1)）——但兩者不是同一件事，讀規格時要知道實際綁進去的是哪一組位元組。

### 4.3 內容加密

以派生出的 32 bytes 金鑰、容器內的 12 bytes nonce 做 AES-256-GCM，tag 長度 16
bytes。**不使用 AAD**，tag 僅涵蓋 ciphertext。

header 中需要密碼學保護的只有 contentType，由 `info` 承擔（§4.4）；magic 與 version
由解析階段對模組常數的逐位元組比對負責，不靠密碼學（§7.1(1)）。`info` 與 AAD 兩者
擇一即可，同時使用不會提高保障，只會讓「哪個欄位保護哪一段」難以推理。

### 4.4 contentType 綁進 HKDF info 是安全必要條件

由於 GCM 不使用 AAD，tag 涵蓋不到 header 任何一個 byte。若 contentType 不進 `info`：

攻擊者把 `0x01` 翻成 `0x02`，**GCM tag 依然驗得過**，解密端會把一串 ZIP 位元組
當成 UTF-8 純文字處理——這是 content-type confusion 的教科書案例。

綁進 `info` 之後，翻動該位元會使派生金鑰不同、tag 不符，直接走既有的
`AuthenticationTagMismatchException` 路徑，不需要任何額外程式碼。

**這個機制只為 contentType 而設。** magic 與 version 不依賴它：兩者在解析階段就
逐位元組比對模組常數，不符即拒絕，走不到 GCM；而 `info` 內的這兩段本來也取自同一
組模組常數，不是容器讀到的位元組（§4.2）。三個欄位各自的拒絕階段見 §7.1(1)。

### 4.5 型別合法性檢查必須在 GCM 解密之後

| 檢查位置 | 「位元被竄改」的訊息 | 「較新版本產生」的訊息 |
|---|---|---|
| 解析時（`ConvertFrom-RuneContainer`） | 誤報成「內容型別不支援」 | 正確 |
| **解密成功後（`Invoke-RuneOpen`）** | 正確：`Content verification failed (the AES-GCM authentication tag does not match). The ciphertext may have been tampered with or corrupted in transit.` | 正確：`The content type 0xNN in this container was produced by a newer version of Rune. Update rune-open.ps1.` |

因為 contentType 已進 `info`，**tag 驗過就等於這個 byte 是真品**；此時若值仍未知，
才能斷定是本程式版本落後而非資料損毀。

實作規則：

- `ConvertFrom-RuneContainer` **只擷取，不驗證**——`ContentType` 欄位原樣回傳，
  0x00–0xFF 任何值都不報錯。
- 合法性檢查放在 `Invoke-RuneOpen`，GCM 解密成功之後、Brotli 解壓之前。

### 4.6 記憶體中的金鑰材料

- 共享祕密與派生的 AES 金鑰在用完後以 `[Array]::Clear` 歸零，**加密端與解密端一律
  把清零寫在 `finally`**，因此 HKDF 派生或 AES-GCM 加解密中途拋錯時一樣會清除，
  不會有金鑰材料因為走了例外路徑而留在記憶體裡。兩端各自的落點：加密端在同一個
  `finally` 內清共享祕密與 AES 金鑰；解密端在派生的 `finally` 內清共享祕密（該
  `finally` 同時 dispose 私鑰物件），在 GCM 解密的 `finally` 內清 AES 金鑰。
- 私鑰檔讀進來的位元組在載入結束後歸零；未加密 PEM 格式時，那就是明文私鑰。
- `SecureString` 還原成字串是必要的：.NET 的 PKCS#8 密碼保護 API 只接受
  `ReadOnlySpan<char>`，沒有 `SecureString` 多載。還原過程配置的非受管記憶體以
  `ZeroFreeGlobalAllocUnicode` 清零並釋放；由此產生的 `System.String` 不可變、
  無法主動清零，只能等待記憶體回收，因此呼叫端一律把它限制在單一運算式內。

---

## 5. 金鑰管理

### 5.1 檔案配置

| 路徑 | 內容 |
|---|---|
| `~\.rune\private.key` | 收件人私鑰。三種儲存格式共用此路徑，格式由內容判別 |
| `~\.rune\public.pem` | 收件人公鑰，明文 PEM |
| `~\.rune\private.key.bak-<時間戳>` | 金鑰輪替時保留的舊私鑰 |
| `~\.rune\public.pem.bak-<時間戳>` | 對應的舊公鑰，與私鑰使用同一個時間戳 |

公鑰不內嵌在程式碼中。內嵌只有兩種結果：交付出去的程式帶著某個人的公鑰（別人取得
後就是加密給他），或維持空字串（取得後不能用，人人都得先編輯程式）。改為執行期
讀檔後，本工具是與金鑰無關的通用工具。

### 5.2 公鑰的取得順序與錯誤路徑

`rune-seal.ps1` 取得收件人公鑰的順序：

1. 指定了 `-PublicKey <string>`：
   - 字串含 `-----BEGIN` → 視為 PEM 內容本體
   - 否則 → 視為檔案路徑
2. 未指定 → 讀預設路徑 `~\.rune\public.pem`

`-PublicKey` 的用途是一次性使用免落檔。多行 PEM 直接當命令列引數傳遞不便（換行
處理因 shell 而異），主要使用情境是變數或 here-string。

| 情況 | 行為 |
|---|---|
| 公鑰檔不存在（預設路徑） | 報 `Cannot find the recipient public key: <path> (default path).`，並分行指引到解密端執行 `rune-open.ps1 -GenerateKeys`、把 `public.pem` 複製到該路徑，或改用 `-PublicKey` |
| 公鑰檔不存在（`-PublicKey` 指定的路徑） | 報 `Cannot find the recipient public key: <path>.`，第二行 `The location was specified with -PublicKey. Verify that the path is correct.`。使用者已經指出要去哪找，缺的是那個檔案，不是「該把檔案放哪」，因此**不得出現**「把 `public.pem` 複製到該路徑」那句 |
| 檔案存在但非合法 PEM | 報 `The recipient public key PEM is not valid and cannot be loaded: …` |
| 曲線非 P-256 | 報 `The recipient public key is not P-256: the curve OID is …. This tool supports P-256 (…) only.` |

四者皆 exit 1 且不產生任何輸出檔。

### 5.3 公鑰指紋

**威脅。** 公鑰檔被掉包會讓使用者靜默地把資料加密給攻擊者。資料檔被換比程式被改
更難察覺——程式碼有版本控管，`~\.rune\public.pem` 什麼都沒有。指紋是這條路徑上
唯一的防線。

**演算法（規範）：**

| 步驟 | 內容 |
|---|---|
| 輸入 | 收件人公鑰的 `ExportSubjectPublicKeyInfo()` DER 位元組 |
| 雜湊 | SHA-256 |
| 取樣 | 前 16 bytes（128 bits） |
| 呈現 | 大寫 hex，每 4 字元一組、以 `-` 連接，共 8 組 |
| 完整格式 | `RUNE-KEY A1B2-C3D4-E5F6-0789-1A2B-3C4D-5E6F-7081` |

**輸入取 SPKI DER 而非 PEM 文字或裸座標的理由：**

- SPKI DER 是正規、唯一的序列化；PEM 文字會因換行、尾隨空白、標頭大小寫而變動。
- SPKI DER 內含曲線 OID，指紋因此天生跨曲線域分離——一把 P-384 金鑰在構造上不可能
  與 P-256 金鑰的指紋相撞。
- 可用標準工具獨立驗證，使用者不必信任本工具：
  `openssl pkey -pubin -in public.pem -outform DER | openssl dgst -sha256`

**取 16 bytes 的理由。** 指紋是公鑰替換攻擊的唯一防線。8 hex 字元（32 bits）可在
筆電上分鐘級磨出碰撞金鑰；16 hex 字元（64 bits）約 2^64，昂貴但非不可及；32 hex
字元（128 bits）則永久出局。代價僅是單行 39 個字元，分組後仍可目視比對——快速
檢查可只比對首尾兩組，需要嚴謹時再比對全串。

**印出時機。** `rune-seal.ps1` **每次執行都印**（在打包開始之前），讓使用者每次都
有機會發現異常；`rune-open.ps1` 的 `-GenerateKeys` 與 `-ExportPublicKey` 印出相同
格式，供兩端目視比對。

### 5.4 `-GenerateKeys` 與覆蓋策略

`New-RuneKeyPair` 宣告 `SupportsShouldProcess` 與 `ConfirmImpact = 'High'`。
高衝擊的是「覆蓋既有金鑰」而不是「產生金鑰」本身。

| 情境 | 行為 | 理由 |
|---|---|---|
| `private.key` 不存在 | 直接產生，不詢問 | 沒有既有檔案會被動到，沒有東西需要確認 |
| `private.key` 已存在、互動環境、未帶 `-Force` | 印出現有金鑰的指紋與備份後的檔名，以 `ShouldProcess` 要求確認（提示的行為見下方） | 覆蓋不再是不可逆的資料遺失（見下一列），但仍應讓使用者明確確認自己在動哪一把金鑰 |
| `private.key` 已存在、非互動環境（`[Console]::IsInputRedirected`）、未帶 `-Force` | 一律拒絕、exit 1，訊息指引改用 `-Force` | 非互動子行程不得卡在等待輸入 |
| 確認繼續，或帶 `-Force` | **不刪除舊金鑰，改名保留**：`private.key` → `private.key.bak-<時間戳>`；若 `public.pem` 存在，以**同一個時間戳**一併改名。兩者改名成功後才產生並寫入新金鑰對 | 舊私鑰仍在，`-KeyFile` 指向備份路徑即可解開舊密文。「覆蓋」因此只是換一把預設金鑰，不是資料遺失 |
| 備份改名任一步失敗 | 中止、不產生新金鑰；若私鑰已改名而公鑰改名失敗，先把私鑰名稱還原回原位再報錯 | 不留下「舊檔已搬走但新金鑰沒有真的產生」的半套狀態 |
| `private.key` 不存在但 `public.pem` 存在 | 直接覆蓋 `public.pem`，不備份 | 孤兒 `public.pem`（私鑰已遺失）比沒有檔案更危險——加密端會持續加密給一把沒人持有的金鑰，產出永久無法解讀的密文。覆蓋才是安全動作 |

**確認提示遵循 PowerShell 的標準確認行為。** `ShouldProcess` 由 host 呈現為
`PromptForChoice`，選項是 `Y`（是）／`A`（全部皆是）／`N`（否）／`L`（全部皆否）／
`S`（暫停），**預設選項是 `Y`——直接按 Enter 會繼續**，與 `Remove-Item -Confirm`
等內建 cmdlet 完全一致；不繼續必須明確選 `N`。改用 `ShouldProcess` 正是為了符合
這個慣例，因此刻意不為單一操作改成 default-No——偏離慣例只會製造另一種意外。
**這條路徑的安全性不來自提示的預設值，而來自「舊金鑰是改名保留而不是刪除」**：
即使誤按 Enter，舊私鑰仍在 `private.key.bak-<時間戳>`，`-KeyFile` 指過去就能解開
舊密文。

**寫入順序固定「先私鑰、後公鑰」。** 若 `public.pem` 寫入失敗，`private.key` 仍在，
可用 `-ExportPublicKey` 補救；反序則會留下一把沒有對應私鑰的公鑰。

時間戳格式為 `yyyyMMdd-HHmmss`；同秒內重複執行導致碰撞時，退避加上 4 碼亂數尾碼。

成功輸出為「保護方式 + 私鑰路徑 + 公鑰路徑 + 指紋」，有備份時多一行備份路徑。
不印出 PEM 全文——路徑已經給了，要看內容用 `Get-Content`；私鑰 PEM 更是絕對不能
出現在畫面上，終端機捲軸、CI log 與螢幕錄影都會把它帶走。

### 5.5 `-ExportPublicKey`

讀取既有私鑰，重新導出公鑰並寫成 `public.pem`，印出路徑與指紋。

存在的必要性：`public.pem` 由 `private.key` 可完全重現，因此不珍貴、覆寫無風險；
但 `-GenerateKeys` 只有在明確確認後才會動既有私鑰，**沒有這個模式，使用者一旦刪掉
或遺失 `public.pem` 就再也生不回來**。它同時兼作「再印一次我的指紋」的工具。

輸出位置跟著來源私鑰走：

- 未指定 `-KeyFile`（沿用預設 `~\.rune\private.key`）→ 寫回預設的 `~\.rune\public.pem`。
- 指定了非預設的 `-KeyFile` → 寫到**該私鑰檔所在目錄**下的 `public.pem`，不動預設
  路徑。「覆寫無風險」只對「這把私鑰對應的公鑰檔」成立；拿備用私鑰導出卻寫回預設
  路徑，會靜默覆蓋主金鑰的 `public.pem`，讓加密端此後預設加密給錯的收件人。

### 5.6 私鑰儲存格式與載入（`-Protect`）

私鑰寫到 `~\.rune\private.key`，靜態保護方式由 `-Protect` 決定，共三種，
**預設 `None`**：

| `-Protect` | 落地內容 | 可否備份 |
|---|---|---|
| `None`（預設） | 未加密的 PKCS#8 PEM（`ExportPkcs8PrivateKeyPem`），標頭 `-----BEGIN PRIVATE KEY-----` | 可，直接複製 |
| `Passphrase` | 密碼保護的 PKCS#8 PEM（`ExportEncryptedPkcs8PrivateKeyPem`，PKCS#5 v2.0：PBKDF2-HMAC-SHA256 600000 次 + AES-256-CBC），標頭 `-----BEGIN ENCRYPTED PRIVATE KEY-----` | 可，還原需密碼 |
| `Dpapi` | DPAPI（CurrentUser、entropy 為 null）保護的 PKCS#8 位元組 | **否** |

PBKDF2 迭代次數取 OWASP 對 PBKDF2-HMAC-SHA256 的建議值。該參數會寫進 PEM 的
`EncryptedPrivateKeyInfo` 結構，解密端由檔案本身讀取，日後調整不影響既有檔案的還原。

**為什麼預設是 `None`。** 密文張貼到公開管道後即為永久存在，而私鑰是唯一的還原
手段——私鑰遺失等同所有歷來密文永久無法解密。DPAPI 的靜態保護最強，但綁定本機與
本 Windows 帳號，重灌或換帳號後即無法還原，也無法備份。此處把可攜性放在靜態加密
之前；代價是未加密的私鑰檔，因此 `None` 每次產生或匯出都必須印出警告：檔案未加密、
任何能讀取它的人都能解開所有以對應公鑰加密的密文、不要放進雲端同步資料夾或版本
控管目錄。

**保護方式必須出現在成功輸出的第一行，且走一般輸出串流。** 只放在警告串流是不夠的
——警告串流在輸出被重新導向時可能被丟棄，使用者會不知道自己拿到的是不是明文私鑰。
入口腳本因此把模組發出的警告收進 `-WarningVariable`，等摘要印完才重播。

**相容性硬性要求：既有的 DPAPI 私鑰不需任何轉換，必須繼續可用。** DPAPI 的位元組
格式與 `Unprotect(CurrentUser, entropy = null)` 的呼叫方式皆不得改變。

**載入端自動判別格式。** 三種格式共用 `~\.rune\private.key` 這一個路徑，
**不依格式分檔名**；`Get-RunePrivateKey` 以 `Get-RunePrivateKeyFormat` 由檔案內容
判別：

1. 內容含 `-----BEGIN ENCRYPTED PRIVATE KEY-----` → 密碼保護的 PKCS#8 PEM
2. 內容含 `-----BEGIN PRIVATE KEY-----` → 未加密的 PKCS#8 PEM
3. 其餘 → DPAPI 位元組

**比對順序必須先 1 後 2**：後者的標記是前者的子字串，順序相反會把加密 PEM 誤判為
未加密 PEM。DPAPI 位元組是二進位，以 UTF-8 解碼後不會命中任何標記。

長度為 0 的私鑰檔在判別之前就先擋下，直接報
`Cannot read the private key: <path> is an empty file (0 bytes) and holds no key material.`
——落進第 3 條會報成 DPAPI 解保護失敗，與實情不符，使用者會去查 DPAPI 與使用者
設定檔，而真正的問題只是檔案是空的。訊息因此也不得提及 DPAPI。

三種格式匯入後一律驗證曲線為 P-256。

密碼保護的私鑰在未提供 `-Passphrase` 時於互動環境詢問；非互動環境一律擲回錯誤。
`Get-RunePrivateKey -NoPrompt` 供「讀不到就算了」的旁路使用（例如覆蓋確認時顯示
現有指紋），此時不會插入使用者沒有預期的密碼提示。

### 5.7 `-ExportPrivateKey`

從既有私鑰匯出成可備份的 PKCS#8 PEM，**來源包含 DPAPI 私鑰**——這是把 DPAPI 私鑰
離機保存的唯一途徑，也是本模式存在的理由。

| 參數 | 規則 |
|---|---|
| `-OutFile` | 必填，不給預設值。輸出路徑已存在則拒絕，加 `-Force` 才覆蓋 |
| `-KeyFile` | 來源私鑰，預設 `~\.rune\private.key`；三種格式皆可作為來源 |
| `-Protect` | 匯出格式，`None`（預設）或 `Passphrase`。**不支援 `Dpapi`**，明確拒絕並說明：DPAPI 檔案在其他機器或帳號無法還原，不具備份用途 |
| `-Passphrase` | **來源私鑰**的密碼 |
| `-OutPassphrase` | **匯出檔**的密碼。與 `-Passphrase` 分開，因為來源與備份是兩個各自獨立的密碼，共用一個參數無法在非互動環境下同時指定 |
| `-Force` | 允許覆蓋已存在的 `-OutFile` |

**確認提示。** 匯出會把私鑰寫成一份新的、可攜的檔案，`-Protect None` 產生的檔案
沒有任何加密保護，是提高私鑰暴露面的動作，因此宣告 `ConfirmImpact = 'High'`，
預設要求確認。模組層級的 `-Force` 只管覆蓋，不代表略過確認；略過確認要明確寫
`-Confirm:$false`。入口腳本的 `-Force` 一次表達兩件事，因此在該層翻譯成
`-Force` 加 `-Confirm:$false`。

**檢查順序。** 先擋 `-Protect Dpapi`、輸出路徑為空、來源不存在、輸出檔已存在、
輸出資料夾不存在（便宜且與確認無關），再顯示確認提示，最後才載入來源私鑰與取得
匯出密碼。被拒絕時不得產生任何檔案。

**原子寫入。** 先寫 `<out>.tmp-<guid>`、套好 §5.8 的權限，成功後才 `Move-Item -Force`
到正式位置，任何失敗都清掉暫存檔。直接寫目標路徑的話，寫到一半失敗會留下截斷的
PEM——截斷的 PKCS#8 前段仍含私鑰純量，而這是備份指令，使用者很可能就此以為備份已
完成。暫存檔與目標同資料夾，搬移是同磁碟區更名，權限會一併帶過去。

成功輸出：第一行標示匯出格式，其後為來源路徑、輸出路徑、公鑰指紋（與來源相同）、
以 `-KeyFile` 使用該備份的命令；`-Protect None` 另印未加密警告。

### 5.8 私鑰檔的存取權限

本工具寫出的私鑰檔一律收斂為「檔案擁有者 + `SYSTEM`」兩個帳號的完全控制，並以
`SetAccessRuleProtection($true, $false)` 中斷繼承——第二個參數為 `$false` 表示不把
繼承來的項目複製成明確項目，複製了就等於沒有收斂。

不設定的話，檔案完全繼承父目錄權限，一般資料夾繼承下來的項目包含
`BUILTIN\Administrators`、`NT AUTHORITY\SYSTEM`、AppContainer SID 與其他既有授權
對象；私鑰寫到 `C:\Temp` 或共用資料夾即他人可讀。

`-GenerateKeys` 的三種格式與 `-ExportPrivateKey` 的輸出檔都套用。DPAPI 格式本身
已綁定本機本帳號，仍一併套用作為縱深防禦，使「私鑰檔」這個類別只有一種權限狀態，
不必逐處判斷。`public.pem` 不套用：公鑰本來就是要交出去的。

目標磁碟不支援 ACL（例如 FAT32）時警告後繼續：私鑰仍然要寫出，只是無法加固權限。
為了權限而讓備份整個失敗，會把使用者推回「沒有備份」這個更糟的狀態。

### 5.9 確認提示與非互動環境

兩個破壞性動作（`New-RuneKeyPair` 覆蓋既有金鑰、`Export-RunePrivateKey` 產生新的
私鑰副本）都以 `SupportsShouldProcess` 實作確認，並遵守同一組規則：

- **不接受從呼叫端 session 繼承來的 `$ConfirmPreference` 作為「不用問」的依據。**
  自動化用的 profile 常把它設成 `None`，繼承下去就是沒帶 `-Force` 也靜默執行破壞性
  動作。未明確表態時一律問，要免除就寫 `-Force` 或 `-Confirm:$false`。
- **非互動防呆疊在 `ShouldProcess` 之外。** PowerShell 在真正的 NonInteractive host
  下呼叫確認會擲回例外而不是卡住，但那依賴 host 正確回報自己不可互動，沒有跨版本
  保證。標準輸入被重新導向（`[Console]::IsInputRedirected`）時一律主動拒絕，並在
  訊息中指出 `-Force` 或 `-Confirm:$false` 這條出路。
- **密碼在任何檔案被改名或寫入之前取得。** 取得密碼這一步會因非互動、兩次輸入
  不一致或空密碼而失敗，此時既有的 `private.key` 與 `public.pem` 必須維持原狀。
- **設定新密碼時要求輸入兩次並比對**（產生金鑰、匯出私鑰）。密碼一旦打錯，對應的
  私鑰檔即永久無法還原。讀取既有私鑰時不需要，密碼錯誤當場就會失敗。

---

## 6. 軟體結構

### 6.1 模組佈局

```
RunePost/
  RunePost.psd1        模組 manifest：版本、相依、明確的匯出清單
  RunePost.psm1        模組層級常數 + 載入器
  Public/              對外函式，5 檔
  Private/             內部函式，30 檔
rune-seal.ps1          加密端入口腳本
rune-open.ps1          解密端與金鑰管理入口腳本
```

**一檔一函式，且檔名等於函式名。** 這是載入器
（`Export-ModuleMember -Function $Public.BaseName`）正確運作的前提，由驗收套件與
CI 各自斷言一次。

模組層級常數（magic、version、contentType 列舉、nonce 與 tag 長度、金鑰檔路徑、
P-256 曲線 OID、PBKDF2 迭代次數）寫在 `.psm1` 本體而不是 `Private\` 底下的某個檔案：
`$Script:` 範圍在模組裡就是模組範圍，兩種寫法效果相同，但 `Private\` 的規則是
「一檔一函式、檔名 = 函式名」，塞一個沒有函式的檔案進去會破壞那條規則，也讓以檔名
為準的慣例出現例外。

`Private\` 載入先於 `Public\`。dot-source 只是定義函式，順序其實不影響解析；先私後
公純粹是讀起來合理。

### 6.2 匯出面

`FunctionsToExport` 是明確清單，**絕不使用 `'*'`**：萬用字元會讓模組自動載入器為了
做命令探索而解析整個模組，是有效能代價的。代價是新增或改名對外函式時必須手動同步
這份清單，忘了同步的後果是「函式存在但呼叫不到」或「清單列了不存在的函式」。這個
漂移風險由驗收套件的 P0 與 CI 各守一次（§8）。

對外函式共五個：

| 函式 | 對應入口 |
|---|---|
| `Invoke-RuneSeal` | `rune-seal.ps1 -Pack` |
| `Invoke-RuneOpen` | `rune-open.ps1 -Unpack` |
| `New-RuneKeyPair` | `rune-open.ps1 -GenerateKeys` |
| `Export-RunePublicKey` | `rune-open.ps1 -ExportPublicKey` |
| `Export-RunePrivateKey` | `rune-open.ps1 -ExportPrivateKey` |

`CmdletsToExport` / `VariablesToExport` / `AliasesToExport` 一律為空陣列。

### 6.3 模組層級的 StrictMode 與 ErrorActionPreference

`.psm1` 本體宣告 `Set-StrictMode -Version Latest` 與 `$ErrorActionPreference = 'Stop'`。
兩者的機制不同：

- **`Set-StrictMode`：呼叫端的設定不會傳進模組。** 不在模組宣告，模組就永遠跑在
  寬鬆模式。
- **`$ErrorActionPreference`：呼叫端的設定會被模組函式讀到。** 在模組範圍宣告是為了
  **不依賴呼叫端**——使用者 `Import-Module RunePost` 後直接呼叫 `Invoke-RuneSeal`
  時，session 預設是 `Continue`，沒有任何入口腳本替他設 `Stop`。在模組範圍宣告會
  覆蓋呼叫端的值，使模組行為與呼叫者的偏好無關、恆定為 `Stop`。

這是預防性的契約宣告：現有錯誤路徑幾乎都走顯式 `throw` 或 .NET 例外，與
`$ErrorActionPreference` 無關。這兩行宣稱的不是「不設就會壞」，而是「設了才不必
依賴呼叫端」。「模組被直接呼叫」這條路徑由 C67 / C68 覆蓋。

### 6.4 入口腳本與模組的分工

兩支入口腳本是薄殼，職責只有四件事：

1. 宣告 comment-based help 與參數集，由 PowerShell 的參數繫結器負責互斥與必填。
   **help 區塊必須排在 `#Requires` 之前。** comment-based help 只能被「註解與空行」
   前置，而 `#Requires` 在 AST 裡是 statement 不是註解；擺在 help 之前會讓
   `Get-Help` 完全看不到這段 help，只印出自動產生的語法列——而且不報任何錯，
   從程式行為上看不出來。`#Requires` 本身不必在第一行也照樣生效。
   兩支腳本的每個參數都要有 `.PARAMETER` 段：參數若沒有 `.PARAMETER`，`Get-Help`
   會改用宣告上方的一般註解當說明，於是繁中的程式碼註解會被印給使用者看。
2. `Import-Module (Join-Path $PSScriptRoot 'RunePost') -Force`，放在 `try` 內，
   使模組資料夾遺失或損壞也走同一個乾淨的錯誤出口。
3. 呼叫模組函式並把回傳物件排版印給使用者。
4. 頂層 `catch` 以 `[Console]::Error.WriteLine` 印出**例外訊息本身**並 `exit 1`。
   不用 `Write-Error`，以避免 PowerShell 錯誤記錄框架附加的呼叫堆疊與分類等雜訊。
   寫出的是精簡訊息而不必然是單行：`WriteLine` 只呼叫一次，但訊息本身可以內嵌
   換行——「先陳述問題、再分行給補救動作」這條文案原則（§9）本來就會產生多行訊息，
   例如「輸出檔已存在」與 `-Unpack` 的非互動密碼拒絕是兩行、
   `-ExportPrivateKey -Protect Dpapi` 的拒絕是三行、「找不到收件人公鑰」與
   `-GenerateKeys` 的非互動拒絕是四行。

**模組一律回傳物件、不印字；呈現只發生在入口腳本這一層。** `Write-Host` 在入口腳本
是正確的工具——訊息要無條件出現在畫面上，又不能混進任何回傳值；兩支腳本因此各自
掛上 `PSAvoidUsingWriteHost` 的抑制屬性。

逐步進度與收件人公鑰指紋走**資訊串流**（`Write-Information`），預設是靜音的；
`rune-seal.ps1` 以 `-InformationAction Continue` 打開，讓指紋與進度邊做邊出現。
以模組身分直接呼叫的使用者若想看到，同樣自行指定即可。

`-Force` 保留在 `Import-Module` 上，保證跑到的一定是磁碟上的版本：不帶 `-Force`
時，`Import-Module` 對同一 session 內已載入的同路徑模組是 no-op，會靜默沿用舊
程式碼。腳本的常態用法是全新 pwsh 行程，此時沒有東西可重載，`-Force` 不構成成本。

### 6.5 相依方向

加密端與解密端在同一個模組裡共存，但呼叫關係不得互相汙染：

- `Invoke-RuneSeal` 的遞移呼叫閉包**不得觸及**私鑰載入、密碼讀取、解封裝與路徑安全
  相關的函式。
- `Invoke-RuneOpen` 的遞移呼叫閉包**不得觸及**公鑰載入、打包、壓縮與加密相關的函式。

這條性質由 C63 / C64 以 AST 建構的模組相依圖靜態斷言。它守的是呼叫關係而非檔案
內容，改名、搬檔、加註解都不會讓它失準。涵蓋範圍與限制見 §7.2。

### 6.6 編碼與換行

| 項目 | 決定 | 理由 |
|---|---|---|
| 原始碼檔案 | **UTF-8 with BOM**，`.ps1` / `.psm1` / `.psd1` 全部一致，無例外 | 使用者可見輸出與 help 已全面英文化，但程式碼註解仍含大量中文。PowerShell 7 讀無 BOM 的 UTF-8 沒有問題，但使用者會直接執行入口腳本，BOM 讓非 PowerShell 7 的 host 也能正確解碼中文註解；模組檔一併統一，避免同一個目錄裡兩種編碼並存，也讓依檔案內容做替換的工具（`tests/mutate.ps1`）不必為編碼分歧特判 |
| 換行 | 一律 LF，由 `.gitattributes` 的 `*.ps1 / *.psm1 / *.psd1 text eol=lf` 固定 | 沒有這條，開發者機器上的 `core.autocrlf` 會讓任何以雜湊比對檔案內容的檢查隨機失敗 |
| 密文輸出檔 | ASCII | Base64 字元集本就在 ASCII 內，不引入編碼變因 |
| 私鑰與公鑰 PEM | UTF-8 無 BOM | PEM 是 ASCII 文字；BOM 會讓部分標準工具解析失敗 |

---

## 7. 安全性質

### 7.1 保證什麼

以下每一項都標明保證的範圍與其邊界。兩種宣稱的強度不同，閱讀時請分開看：

- **「保證」**指的是本工具明確實作、且由 §8 的驗收套件以案例驗證過的行為。
- **「邊界」**指的是保證涵蓋不到的地方。其中有些同樣有案例支持，有些則是由程式碼
  結構推導而來、目前沒有對應的測試（例如需要在執行途中強制終止行程才能觸發的
  情境）。**凡屬後者，條文會明白寫出「無測試涵蓋」**，不與已驗證的性質混為一談。
  這個標註不限於「邊界」：「保證」段落裡若有哪一條只由程式碼結構推導（第 (8) 項的
  原子性即是），同樣就地標明。

**（1）容器 header 的完整性。**
保證：magic、version、contentType 三個欄位被竄改時，解密必然失敗且不產生任何輸出。
三者的拒絕階段不同，這是分層的結果，不是同一個機制：

| 欄位 | 拒絕階段 | 錯誤表現 | 案例 |
|---|---|---|---|
| magic | 解析（`ConvertFrom-RuneContainer`），早於任何金鑰操作 | `The container format is not valid: the header magic does not match (read '…').` | C13、C50 |
| version | 解析，緊接 magic 之後 | `The container version does not match: …` | C14 |
| contentType | GCM 解密——解析階段只擷取不驗證（§4.5） | `Content verification failed (the AES-GCM authentication tag does not match).` | C52 |

contentType 是唯一走到 GCM 才被擋下的欄位，也因此是唯一**必須**綁進 HKDF `info`
的欄位（§4.4）；另外兩個在解析階段就已逐位元組比對過模組常數，`info` 裡的那兩段
本身也取自同一組常數而非容器（§4.2）。「即使跳過檢查、派生金鑰也會不同」對 magic
與 version **不成立**——在所有可達路徑上兩者等價，但機制只有解析檢查一道。

不保證：`ephPubKeyLen` 這個長度欄位沒有獨立的完整性保護。被竄改後一定失敗，但錯誤
分類隨改動幅度與容器大小而定，共三種模式：

| 竄改後的值 | 表現 |
|---|---|
| 大到 `8 + len + 12 + 16` 超過容器總長 | 解析階段的長度檢查擋下，報 `The container format is not valid: the length is too short to hold the complete ephemeral public key, nonce, and tag.` |
| 偏小 | 截短的位元組不是合法的 SubjectPublicKeyInfo DER，報 `The ephemeral public key in the container is not valid: …`（ASN.1 匯入失敗） |
| 偏大但仍在總長內 | ephemeral 公鑰段多吃了後面的位元組——`info` 與 nonce／tag／ciphertext 的分界一起位移，最終以 GCM 認證失敗告終 |

header 也沒有任何機密性，它本來就是明文。

**（2）內容的機密性與完整性。**
保證：ciphertext 由 AES-256-GCM 保護，任何位元改動都會使 tag 驗證失敗。
不保證：容器長度、產生時間、輸出檔名等中繼資料不受保護，見 §7.2。

**（3）zip-slip 兩道防線。**
保證：解包時，ZIP entry 名稱含反斜線一律拒絕（本工具自家產物一律以 `/` 當分隔符，
含反斜線就一定不是自家封裝）；entry 路徑正規化後必須仍在
「目的資料夾 + 目錄分隔符」之下，否則拒絕。兩道檢查都在「entry 是否為目錄」的分支
**之前**執行，因此目錄 entry 同樣受檢。違規一律擲
`System.Security.SecurityException`，訊息為
`Unsafe archive path detected (…): <entry>`。該型別在 `Invoke-RuneOpen` 被專門
攔截並原樣上拋，不會被包裝成 `ZIP extraction failed. The archive format is not
valid, or the archive is corrupted.`——否則使用者會把攻擊誤讀成檔案壞掉。
第二道檢查涵蓋第一道的全部輸入；第一道存在的價值是給出精確的錯誤原因。
四個分支（檔案 entry 的 `../` 與 `..\`、目錄 entry 的 `../` 與 `..\`）由
C37 / C41 / C46 / C47 各守一案，措辭一併驗；**例外型別**另由 C89 在模組直呼路徑上
斷言——入口腳本只把訊息寫到 stderr，型別在黑箱上看不見，而型別是比措辭更穩定的
契約。
不保證：解包出來的**檔案內容**是安全的。本工具不掃毒、不判斷副檔名、不限制檔案
大小或數量。

**（4）解包失敗的回滾。**
保證：解包先落在 `Destination` 底下的 `.rune-tmp-<GUID>` 暫存資料夾，全部 entry
成功後才搬到正式位置；解包階段任何一步失敗都清掉暫存資料夾，`Destination` 不留
半成品，也不留暫存資料夾本身，且 `Destination` 內既有的無關內容不受影響。
以上由兩案驗證：C44 在空的 `Destination` 上驗「中途失敗不留半成品、不留暫存資料夾」；
C88 在**已經有無關內容**的 `Destination` 上驗同一件事，並要求既有檔案（含子目錄，
以及一個與封存內第一筆 entry 同名的檔案）的 SHA-256 一個位元都不變。
C48 走的是**成功路徑**的合併搬移，證明搬移不破壞既有的無關內容；它不觸發回滾，
不能拿來當回滾的佐證。

邊界（**以下兩點由程式碼結構推導，無測試涵蓋**）：

- 搬移階段是逐項 `Move-Item`，不是交易。上述保證涵蓋的是「解包階段失敗」；
  **搬移已經開始之後才被外力中斷**（斷電、強制終止行程）仍可能在 `Destination`
  留下部分內容。這個情境本質上難以寫成案例——要在搬移途中精確地砍掉行程——
  因此只作記載，不宣稱有保證。
- 搬移是合併式的：`Destination` 內既有的同名檔案會被覆蓋。這是合併式搬移的固有
  語意，本規格未對它另作要求（C48 只記錄實際行為，不對此下斷言）。

**（5）私鑰檔的存取權限。**
保證：本工具寫出的每一個私鑰檔（三種格式與匯出檔）都中斷繼承，且只有檔案擁有者與
`SYSTEM` 具有存取權（§5.8）。
不保證：ACL 不防本機管理員（管理員可取得擁有權）、不防離線讀取磁碟、不防已在該
帳號下執行的惡意程式。目標磁碟不支援 ACL 時只警告不中止，此時檔案完全沒有權限
加固。使用者自行複製私鑰到別處時，權限不會跟著複製語意自動維持。

**（6）公鑰指紋防掉包。**
保證：`~\.rune\public.pem` 被換成另一把金鑰時，`rune-seal.ps1` 每次執行印出的指紋
必然改變（§5.3）。指紋是 SHA-256(SPKI DER) 的前 128 bits，可用標準工具獨立重算。
不保證：**指紋只有在使用者真的去比對時才是防線。** 工具無法強制使用者比對，也不
記憶上一次用的是哪一把金鑰。指紋改變時本工具不會拒絕執行、不會發出警告。

**（7）內容金鑰的一次性。**
保證：每次加密都產生全新的 ephemeral ECDH 金鑰對與全新的隨機 nonce，因此同樣的
輸入在兩次執行後產生完全不同的密文，內容金鑰不重複使用。
不保證：這帶來的是「相同明文不產生相同密文」與「單一金鑰不被重複使用」，**不是
前向保密**——收件人的靜態私鑰外洩時歷史密文全數可解，見 §7.2。

**（8）私鑰匯出的原子性。**
保證：`-ExportPrivateKey` 先寫暫存檔、套好權限，成功後才更名到目標位置，因此目標
路徑上不會出現截斷的 PEM（§5.7）。
**這一項的原子性本身無測試涵蓋**：C82 只證明成功路徑跑完不留 `.tmp-*` 殘留，套件
裡沒有任何案例讓寫入在「暫存檔已建立、尚未更名」之間失敗——要穩定停在那個時間點
得在寫入途中注入故障。原子性因此與第 (4) 項的兩點邊界同級，是由程式碼結構推導的
性質，不是驗過的性質。
不保證：暫存檔在寫入到更名之間短暫存在於同一個資料夾中，該期間它已套上私鑰權限，
但確實存在於磁碟上。

**（9）錯誤路徑不留半成品。**
保證：加密端的任何失敗都不產生輸出檔；解密端的任何失敗都讓 `Destination` 維持
乾淨；所有失敗一律 exit 1；錯誤訊息是例外訊息本身，不附 PowerShell 錯誤記錄框架的
呼叫堆疊與分類資訊（§9）。以上四條由驗收套件的 `Expect-SealRefused` /
`Expect-OpenRefused` 對每一個失敗案例統一把關（§8.1）——退出碼是等值比對，
「不附框架雜訊」是以否定樣式掃 stderr（`CategoryInfo`、`FullyQualifiedErrorId`、
`ScriptStackTrace` 等標記一個都不得出現）。
不保證：**訊息不保證是單行。** `[Console]::Error.WriteLine` 只呼叫一次，但訊息本身
可以內嵌換行（§6.4）。行數不是契約，也沒有斷言。
邊界：**保證只涵蓋程式自己走到錯誤出口的情形。** 外力中斷（斷電、強制終止行程）
下的殘留狀態未定義，且**無測試涵蓋**，理由同第 (4) 項。

### 7.2 不保證什麼

**無寄件人認證。** 收件人公鑰是公開資訊，任何取得它的人都能造出一個解得開的容器。
「解得開」只證明「有人用了你的公鑰」，不證明來源是誰，也不證明內容未被替換成另一
份合法內容。本工具沒有簽章機制。若需要來源保證，必須在本工具之外自行處理。

**無前向保密。** 收件人的靜態私鑰是所有密文的唯一解鑰。私鑰一旦外洩，攻擊者可以
解開他手上所有的歷史密文；ephemeral 金鑰對只保證「每則密文用不同的內容金鑰」，
不保證「舊密文在私鑰外洩後仍安全」。

**不提供不可觀測性。** 輸出是固定結構的 Base64，開頭必然是 `RUNE` 的編碼結果，
可被 `grep` 或任何樣式掃描直接辨識。容器長度與明文長度單調相關，洩漏負載規模；
contentType 以明文存放，洩漏「這是檔案還是文字」。本工具不是隱寫術，不試圖偽裝
成其他內容。

**輸出檔名沿用原始檔名。** 預設輸出是 `<原始檔名>.txt` 或 `<資料夾名>.txt`。檔名
本身就是明文，會洩漏內容線索。需要規避時請自行以 `-OutFile` 指定無意義的名稱。

**相依閉包斷言不涵蓋動態呼叫。** §6.5 的 C63 / C64 只看得到靜態字面呼叫，以及沿著
這些呼叫展開的遞移相依。透過變數的 `& $cmd`、`Invoke-Expression` 與別名三者都繞得
過——這是 `CommandAst.GetCommandName()` 只認得靜態字面名稱的本質限制。本專案的模組
程式碼一律直接具名呼叫，此限制目前不構成缺口；若日後引入動態派發，這兩案的結論就
不再涵蓋那條路徑。

**驗證只覆蓋被寫成案例的性質。** 驗收套件驗的是行為與訊息，變異測試驗的是這些斷言
是否咬得動（§8）。兩者都不是形式化證明，也不涵蓋未被寫成案例的性質。

**未經第三方密碼學稽核。** 本工具是個人自用的實作，密碼學原語全部來自 .NET 內建
類別，但「原語的組合方式」——容器格式、金鑰派生的參數選擇、錯誤處理順序——沒有
經過任何獨立的密碼學專業稽核。

**其他明確不在範圍內的事項。** 不防範記憶體被同帳號的其他行程讀取；不防範
side-channel；不處理密文送達之後的存取控制；不提供金鑰過期、撤銷或輪替通知機制
（`-GenerateKeys` 的輪替是純本機動作，加密端不會知道）。

---

## 8. 驗證

### 8.1 驗收套件 `tests/verify.ps1`

對 repo 根目錄的兩支入口腳本執行的黑箱驗收套件，共 **93 案**。

```
pwsh -File .\tests\verify.ps1 -RepoRoot <repo 根目錄> -Tier Core   # 安全性子集
pwsh -File .\tests\verify.ps1 -RepoRoot <repo 根目錄> -Tier Full   # 全部
```

**分層。** 每一案都必須表態 `-Tier`（`Core` 或 `Full`），沒表態就整套中止，不讓
案例以預設層級悄悄溜進來。`Core` 是安全性與前置子集，目標一分鐘內跑完；`Full` 是
全部。當前分佈為 Core 43 案 / Full-only 50 案。

**結構上的四條規矩：**

1. **啟動受測腳本的呼叫點只有 `Invoke-Seal` / `Invoke-Open` 兩處。** 案例一律透過
   這兩個語意動詞呼叫受測物，不自己拼參數陣列、不自己記得帶沙箱環境變數。受測腳本
   的**路徑**另外在檔案開頭解析成 `$script:SutSeal` / `$script:SutOpen` 兩個常數，
   P1a／P1b／P2／C40 等靜態案例會讀取它們——一處出現的是「啟動」這個動作，不是
   字面常數本身。
2. **「失敗案例必須同時成立」的紀律寫在 `Expect-SealRefused` / `Expect-OpenRefused`
   內部**，不做成呼叫端要記得加的開關。那組條件是：不得逾時（卡在互動提示等同永遠
   不會被發現的失敗）、必須真的失敗、**退出碼必須是 1**、**stderr 不得出現
   PowerShell 錯誤記錄框架的呼叫堆疊／分類標記**、不得留下產物、指定檔案不得被改動、
   訊息一律只比對 StdErr。退出碼要單獨釘住，是因為「必須真的失敗」的判準是
   「逾時 or exit≠0 or stderr 非空」，「exit 0 但 stderr 非空」也會通過，而那正是
   「有印錯誤卻回報成功」的缺陷形狀。只比對 StdErr 這一條同樣是必要的：受測物的
   成功輸出含有與錯誤分類重疊的字樣（seal 每次都印
   `Recipient public key fingerprint: RUNE-KEY …`），拿合併輸出比對會讓數種分類
   無條件命中。
3. **措辭斷言集中在 `$script:Msg` 這張期望訊息表**，案例本體只做行為斷言。值一律
   是正則，取用一律經 `Get-MsgPattern`，鍵名打錯會立刻拋錯而不是靜默退化成比對空
   樣式。使用者可見輸出換語系時只要改這張表。表內有三條與本工具文案無關、隨
   PowerShell host 的 UI 文化在地化的框架樣式（`stage.param`、`whatif.line`、
   `errorframe`），一律並列中英兩種說法。
   **反面樣式（`-Forbid`）與對應的正面樣式必須互不包含**，否則會靜默假綠。目前有
   兩組需要留意：`tampered` 只認 `tamper` 與 `authentication tag`，`typeorversion`
   只認 `content type` / `newer version` / `unsupported`；`contenttype` 一律寫成
   完整詞組 `content type`，不用 `content` 一個字——GCM 認證失敗的訊息開頭是
   `Content verification failed`，只比對 `content` 會讓 C52 的 `-Forbid` 無條件
   命中。
4. **共用素材是惰性 fixture**，案例以 `-Needs` 宣告相依，取用發生在案例本體之前，
   因此 `-Filter` / `-Tier` 篩出的任意子集都能單獨執行。fixture 建立失敗會被記住
   （負向記憶）：producer 不重跑，第一個撞上的案例拿到完整原因，其後依賴同一份素材
   的案例一律收到「前置 fixture 建立失敗（見 <該案號>）」，避免同一個原因在報表上
   化成一堆下游症狀。

**家目錄沙箱。** 所有會動到 `~\.rune` 的案例都在沙箱家目錄下執行。沙箱化只能靠
`ProcessStartInfo.Environment`：`$HOME` 在 pwsh session 啟動時就定案，行程內再改
`$env:HOME` 不會影響 `~` 的解析。逃逸偵測掛在 `Invoke-Sut`（入口腳本路徑）與
`Invoke-RuneProbe`（模組探針路徑）內部，凡經這兩者呼叫受測物，之後都會自動檢查
使用者的真實家目錄，不靠個別案例記得。**少數直接使用底層 `Invoke-Transfer` 的案例
（P0、P3、C67、C68）不經過這道檢查**——它們跑的是自己寫的探針腳本，且都以明確
路徑操作，不觸及 `~\.rune`。

**密碼學白盒。** C08 依 §4.2 的規格參數直接派生金鑰並要求通過 GCM 驗證，**不做任何
參數搜尋**：派生不出可用金鑰即判定為實作與規格不符。私鑰的獨立還原同樣照 §5.6 的
三種格式判別後匯入，讀不出來即判定為實作與 §5.6 不符。凡是「照規格寫的
驗證器讀不出實作寫出來的東西」一律判 FAIL，不判 INFO。

**靜態斷言。** P0 檢查模組可載入、manifest 匯出清單／實際匯出／`Public\` 檔名三方
一致、一檔一函式且檔名相符；P2 掃描兩支入口腳本與整個 `RunePost\`，要求不存在任何
公鑰內嵌；**P7 檢查 `tests/mutate.ps1` 的變異目錄與產品程式碼仍然同步**（見 §8.2）；
C63 / C64 以 AST 相依圖斷言 §6.5 的相依方向；C40 要求受測腳本自始至終未被改動。
這四案都不啟動子行程，純解析，成本接近零。

### 8.2 變異測試 `tests/mutate.ps1`

驗收套件全綠只證明「行為沒變」，不證明「斷言有效」——一條恆真的斷言、一個被路徑
字樣意外命中的樣式，在全綠的報表上看起來與真正的防線完全一樣。

變異測試反過來做：在產品程式碼裡刻意植入一個已知缺陷，跑一次驗收套件，檢查該紅的
案號真的紅了。目前收錄 **17 項變異**。

```
pwsh -File .\tests\mutate.ps1 -List              # 只列出變異與預期紅的案號
pwsh -File .\tests\mutate.ps1                    # 全部，預設 -Tier Core
pwsh -File .\tests\mutate.ps1 -Mutation M6 -Tier Full
```

每一項變異宣告 `MustRed`（一定要紅的案號，少一個就是斷言失效）與 `MayRed`
（連帶會紅，允許但不強制）。`MustRed ∪ MayRed` 之外多紅則是非預期的連鎖影響，
兩者都會在對照表上標出來。

**例外：M1 的 `MustRed` 刻意為空。** 它只停用 zip-slip 兩道檢查中的第一道，而第二道
涵蓋第一道的全部輸入，外部行為因此完全不變——「預期不紅」本身就是這一項要記錄的
結論（兩道檢查的涵蓋關係），要讓它紅只能斷言「哪一道檢查開火」，那是對實作細節
過度指定。兩道檢查各自的咬合力由 M1b 與 M1c 分別證明。除 M1 之外，`MustRed` 為空
就是斷言失效。

**覆蓋的斷言類別：**

| 類別 | 守的是什麼 |
|---|---|
| 路徑安全（M1 / M1b / M1c / M7） | zip-slip 兩道檢查各自確實被覆蓋，且錯誤訊息保有 `Unsafe archive path detected` 這個獨立語意，不可被 `Archive format error` 搪塞 |
| 密碼學規格符合性（M2 / M15） | contentType 確實綁進 HKDF info；DPAPI 保護的確實是 §5.6 所寫的 PKCS#8 位元組。這兩者在黑箱上都看不出差別，只有規格白盒抓得到 |
| 金鑰一次性（M3） | nonce 確實來自隨機來源 |
| 秘密不外洩（M4） | 私鑰 PEM 不得出現在畫面上 |
| 檔案權限（M5） | 私鑰檔的 ACL 收斂確實生效 |
| 完整性檢查（M6） | GCM tag 驗證失敗必須中止，且訊息必須點名 tampered 而非退化成下游的解壓失敗 |
| 相依方向（M8 / M9） | C63 / C64 咬的是靜態相依方向而非執行結果，因此植入的是永遠不會執行到的呼叫 |
| 確認機制（M10） | 呼叫端 session 的 `$ConfirmPreference` 不得讓確認被跳過 |
| 訊息語意（M11 / M12 / M13 / M14） | 有專屬語意要求的錯誤（曲線不符、非互動拒絕、空檔案、公鑰 PEM 無效）不得被一般錯誤搪塞。這一組都不動任何檢查：仍然拒絕、仍然不留下檔案、exit code 不變，只有措辭退化 |

**安全機制。** 植入與還原成對寫在 `try/finally`；還原一律以植入前的原始位元組寫回，
並以整份產品程式碼的雜湊確認逐位元組相同。植入期間在 `tests/_mutwork/` 留下
`RUNNING` 標記與 `.inflight` 原始位元組，行程被強制中斷時下一次啟動會自動還原。
正式開跑前先跑一次未植入任何變異的對照組並要求全綠——對照組不綠時，所有「植入後
有紅」的否定性結論都不可信。

`Old` 字串必須在目標檔案中逐字命中，找不到即報錯中止。**修改產品程式碼（含註解與
錯誤訊息文案）時，若動到某項變異所引用的那幾行，必須同步更新變異定義**，否則該項
變異會失效。17 項變異共引用 22 個 `Old` 片段，其中 9 個（M6、M7 兩個、M11、M12
三個、M13、M14）就是錯誤訊息的字面，動文案必然要一併改。

**這件事由驗收套件的 P7 每輪把關，不靠人記得。** `mutate.ps1` 自己只檢查 `Old` 是否
`Contains`（≥1 次），命中兩次會讓一次 `Replace` 靜默改掉兩處——植入的缺陷就不是目錄
上寫的那一個，而報表照樣顯示 OK。P7 補上三條：

| 斷言 | 防的是什麼 |
|---|---|
| 每個 `Old` **恰好命中一次**，且**逐對累進比對** | 命中兩次的靜默雙重替換。累進是必要的：`mutate.ps1` 是 `foreach ($p in $t.Pairs) { $mut = $mut.Replace(...) }`，第 2 對是對「已套過第 1 對」的文字替換，只數原始文字會漏掉「第 2 對的 `Old` 出現在第 1 對的 `New` 裡」這種對間干擾 |
| 每個 `New` 在**原始**文字中命中 **0 次** | 植入的必須是真正的新內容。刻意不用累進文字：M7 兩對的 `New` 是同一個字串，第 2 對套用時第 1 對的已經在了。這條今天靠「每個 `New` 都帶 `# MUTATION <名>` 標記」而自動成立，P7 的作用是把那個慣例從「大家都這樣寫」變成「寫錯就會紅」 |
| `Old ≠ New`，且整份檔案套完後內容確實改變 | `Old = New` 的筆誤會讓變異變成空操作。空操作在 `MustRed` 非空的項目上會報「斷言失效」還看得出來，但在 **`MustRed` 刻意為空的 M1 上會報 OK**——什麼都沒植入，卻宣稱「兩道檢查的涵蓋關係」這個否定性結論成立 |

P7 在變異植入期間以 `tests/_mutwork/RUNNING` 標記偵測並 SKIP（產品程式碼此時正處於
被刻意改壞的狀態，`Old` 當然找不到）；對照組跑在 `Set-RunLock` 之前，因此「未植入時
目錄是自洽的」這件事仍然每輪都被驗到。

### 8.3 CI

`.github/workflows/module-check.yml` 在每次 push 與 pull request 上執行：

1. 模組可載入，且 manifest 的 `FunctionsToExport`、實際匯出的函式、`Public\` 底下
   的檔名三方一致；不得匯出任何 cmdlet、alias 或變數。
2. 整個 `RunePost\` 底下每個 `.ps1` 都恰好一個函式，且函式名等於檔名。
3. 兩支入口腳本語法可解析。

這與驗收套件的 P0 檢查同一件事。P0 只在有人手動跑驗收時擋得住，CI 才是不依賴人的
防線。完整的驗收套件與變異測試需要 Windows 上的 DPAPI、NTFS ACL 與家目錄沙箱，
目前不在 CI 執行，由開發者在本機執行。

---

## 9. 錯誤處理與退出碼

| 情況 | 行為 |
|---|---|
| 成功 | exit 0；結果摘要寫到 stdout |
| 任何失敗 | exit 1；錯誤訊息寫到 stderr。寫出的是例外訊息本身，不附 PowerShell 錯誤記錄框架的呼叫堆疊與分類資訊；訊息可以內嵌換行，行數不是契約（§6.4） |
| 使用者在確認提示選擇不繼續 | exit 0；印 `Cancelled. No files were changed.` |

錯誤訊息的撰寫原則（**一律英文**，風格比照官方 PowerShell）：

- **陳述句，句首大寫，句尾句點。** 不用驚嘆號、不用表情符號、不對使用者做價值判斷
  （不寫 dangerous、never do this），要說後果就直接陳述後果。句點照打，即使該句
  以路徑或檔名結尾；**唯一例外是整行結尾為一段可直接複製執行的命令列**（例如
  `-ExportPrivateKey` 成功輸出的最後一行、覆蓋確認提示的救援指令），此時不加句點，
  免得使用者把句點一併複製進命令。
- **先陳述問題，再給補救動作。** 多個補救選項分行列出，不塞進同一句。常用句式：
  `Cannot find …`、`Cannot read …`、`Unable to …`、`… already exists.`、
  `Specify -Force to …`、`The … is not valid: …`。
- **參數、路徑、檔名原樣呈現**（`-GenerateKeys`、`public.pem`、`~\.rune\private.key`），
  不用 "that file"、"the parameter above" 這類指代。`RUNE`、`RUNE-KEY`、參數名、
  檔名與路徑一律不翻譯。
- **點名環節。** 使用者要能從訊息判斷失敗發生在打包、公鑰載入、私鑰載入、Base64
  解碼、GCM 認證、Brotli 解壓還是解包搬移。
- **給出路。** 凡是使用者有辦法處理的失敗，訊息必須說明下一步能做什麼（補上
  `-Force`、以 `-Passphrase` 傳入 SecureString、到解密端執行 `-GenerateKeys` 等）。
- **不以泛泛的失敗搪塞有專屬語意的錯誤。** `Unsafe archive path detected` 不可說成
  `Archive format error`；`is an empty file (0 bytes)` 不可說成
  `DPAPI unprotect failed`；`is not P-256: the curve OID is …` 不可說成
  `Cannot load the recipient public key`。這些語意由 §8.2 的變異測試逐一驗證。

全專案共用的術語表（同一個概念在訊息、help 與文件中一律用同一個詞）：

| 概念 | 用語 |
|---|---|
| 收件人公鑰 | recipient public key |
| 私鑰 | private key |
| 金鑰對 | key pair |
| 容器 | container |
| 密文 | ciphertext |
| 目的資料夾 | destination folder |
| 密碼 | passphrase |
| 指紋 | fingerprint |
| 私鑰的靜態保護方式 | protection mode |
| 封存（ZIP） | archive |
| 曲線 | curve |
| 內容型別 | content type |
| 非互動環境 | non-interactive session |
| 竄改 | tampered |
| 損壞 | corrupted |

模組本身不決定訊息如何呈現：所有錯誤以例外形式往上拋，由入口腳本的頂層 `catch`
統一輸出。
