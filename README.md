# runepost

把檔案加密成一段可以直接貼上的 Base64 純文字，經由公開管道送到自己的另一台機器，
在那裡用私鑰還原成原本的檔案樹。

## 這是什麼

runepost 解決的是「兩台自有機器之間只有純文字管道」這個情況：論壇貼文、pastebin、
即時通訊、只能貼文字的網頁表單。你在 A 機器把資料加密成一段文字，貼到任何地方，
再到 B 機器把那段文字取回來解開。

- **單向。** B 機器（解密端）產生金鑰對並保管私鑰，把公鑰交給 A 機器（加密端）。
  此後 A 可以持續產生只有 B 解得開的密文。反方向要另外產生一組金鑰。
- **加密端不持有秘密。** A 機器只有公鑰，即使整台被攻陷也解不開任何既有密文。
- **不碰網路。** 本工具只負責加密與解密，密文怎麼送達完全由你決定。

流程：ZIP（store）→ Brotli → AES-256-GCM（金鑰由一次性 ECDH P-256 + HKDF-SHA256
派生）→ Base64。全程記憶體操作，不落地任何中間檔案。

設計細節與規格見 `docs/DESIGN.md`。

## 環境需求

| 項目 | 需求 |
|---|---|
| 作業系統 | **僅限 Windows** |
| PowerShell | **7.4 以上**（`pwsh`，不是內建的 Windows PowerShell 5.1） |
| 外部依賴 | **無。** 只用 .NET 內建的密碼學與壓縮類別，不需安裝任何套件 |

僅限 Windows 有兩個具體原因：私鑰的 `-Protect Dpapi` 選項依賴 Windows 的 DPAPI；
私鑰檔的權限加固使用 NTFS ACL 語意。這兩者都沒有跨平台對應。

## 取得方式

沒有安裝步驟。取得整個 repo 即可使用：

```powershell
git clone <這個 repo 的網址>
```

不想用 git 就在 GitHub 頁面按 **Code → Download ZIP**，解壓縮到任何目錄。

### 執行期真正需要的檔案

repo 裡只有兩樣東西是執行期需要的：

```
rune-seal.ps1     加密端入口
rune-open.ps1     解密端與金鑰管理入口
RunePost\         實作模組（整個資料夾，含 .psd1 / .psm1 / Public\ / Private\）
```

`` `tests\` ``、`` `docs\` ``、`` `.github\` `` 只在開發時用得到，**不需要帶到
加密端**。入口腳本以 `$PSScriptRoot` 尋找模組，因此 `` `RunePost\` `` 必須與兩支
`.ps1` 放在同一層。

把工具部署到另一台機器時：

| 角色 | 需要帶的東西 |
|---|---|
| **加密端** | `rune-seal.ps1`（帶著 `rune-open.ps1` 也無妨）+ `` `RunePost\` `` + 一份收件人的 `` `public.pem` `` |
| **解密端** | `rune-open.ps1`（`rune-seal.ps1` 可選）+ `` `RunePost\` `` + 自己的 `` `~\.rune\private.key` `` |

模組本身不含任何人的金鑰，兩端可以直接複製同一份檔案。金鑰的放置位置見
「快速開始」。

## 快速開始

以下所有輸出都是實際執行結果，只把家目錄路徑縮寫成 `C:\Users\alice`。

### 1. 在解密端產生金鑰對

```powershell
pwsh .\rune-open.ps1 -GenerateKeys
```

```
已產生 ECDH P-256 金鑰對（私鑰保護方式：未加密的 PKCS#8 PEM）
  私鑰  C:\Users\alice\.rune\private.key   (未加密的 PKCS#8 PEM)
  公鑰  C:\Users\alice\.rune\public.pem
  指紋  RUNE-KEY BE1B-1948-2E90-4BD4-D377-52D2-978E-6436
WARNING: 私鑰以未加密的 PKCS#8 PEM 儲存於 C:\Users\alice\.rune\private.key。
WARNING: 任何能讀取此檔案的人，都能解開所有以對應公鑰加密的密文。
WARNING: 請勿將此檔案置於雲端同步資料夾或版本控管目錄。
```

**預設的私鑰是未加密的**，理由與其他兩種選項見「金鑰管理」。
請記下畫面上的**指紋**，稍後要與加密端比對。

### 2. 把公鑰複製到加密端

把 `` `C:\Users\alice\.rune\public.pem` `` 這個檔案（只有公鑰，可以公開）帶到加密端，
放到該機器的 `` `~\.rune\public.pem` ``。用隨身碟、雲端硬碟或直接貼文字都可以。

沒有這個檔案時，加密端會直接告訴你缺什麼：

```
找不到公鑰：C:\Users\alice\.rune\public.pem（預設路徑）。請先在解密端執行
rune-open.ps1 -GenerateKeys，把印出的 public.pem 複製到本機
C:\Users\alice\.rune\public.pem，或用 -PublicKey 指定其他路徑或 PEM 字串。
```

### 3. 在加密端加密

```powershell
cd C:\work
pwsh .\rune-seal.ps1 C:\data\report
```

```
收件人公鑰指紋：RUNE-KEY BE1B-1948-2E90-4BD4-D377-52D2-978E-6436
（請與解密端 -GenerateKeys / -ExportPublicKey 印出的指紋逐字比對；不符代表公鑰可能已被掉包）
打包中：共 2 個項目...
壓縮中（Brotli, SmallestSize）...
加密中（ECDH P-256 + HKDF-SHA256 + AES-256-GCM）...

完成：C:\work\report.txt
原始（打包後、壓縮前）: 229 bytes
壓縮後（Brotli）       : 117 bytes
Base64 後（輸出檔）    : 336 bytes
```

第一行的指紋**每次執行都會印**。第一次使用時務必與步驟 1 印出的逐字比對；
不一致就代表 `` `~\.rune\public.pem` `` 不是你以為的那一把。

輸入可以是單一檔案、資料夾（遞迴，保留目錄結構）或萬用字元（僅當層，不遞迴）。
輸出檔預設寫到**目前的工作目錄**，檔名沿用輸入名稱加 `.txt`；要指定位置用
`-OutFile`，目標已存在時要加 `-Force` 才會覆蓋。

### 4. 貼出去、取回來

`report.txt` 的內容就是純 Base64，每 76 字元換行：

```
UlVORQIBWwAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASPm/IcqX9SfcPlw/DDpQv80spQ8F1N
H+4R7EmN/nVfkAG+bhXpytT0sBZs+Lpl96ly74nRiH+1NPV/qNY9VNGGKlTsDCIhXbR11QAO+mPf
...
```

貼到任何純文字管道，在解密端存回一個文字檔即可。解碼前會先移除所有空白字元，
因此轉貼過程中換行位置改變不影響還原；除空白以外的任何改動都會被完整性檢查擋下。

### 5. 在解密端解密

```powershell
pwsh .\rune-open.ps1 -Unpack report.txt -Destination C:\out\restored
```

```
解密完成，檔案已還原至：C:\out\restored
```

`-Unpack` 與 `-Destination` 也可以省略參數名稱依序放位置：

```powershell
pwsh .\rune-open.ps1 report.txt C:\out\restored
```

## 金鑰管理

### 私鑰的三種儲存格式

`-GenerateKeys -Protect` 決定私鑰在磁碟上的保護方式。三種格式都寫到
`` `~\.rune\private.key` ``，解密時由檔案內容自動判別，不需要指定。

| `-Protect` | 落地內容 | 可否備份到別台機器 | 使用時要輸入密碼 |
|---|---|---|---|
| `None`（**預設**） | 未加密的 PKCS#8 PEM | 可，直接複製檔案 | 否 |
| `Passphrase` | 密碼保護的 PKCS#8 PEM（PBKDF2-HMAC-SHA256 600000 次 + AES-256-CBC） | 可，還原時需要密碼 | 是 |
| `Dpapi` | DPAPI（CurrentUser）位元組 | **不可** | 否 |

**預設是 `None`，也就是未加密的私鑰檔。** 這是刻意的取捨：密文一旦貼到公開管道就
永久存在，而私鑰是唯一的還原手段——私鑰遺失等同所有歷來密文永久無法解密。`Dpapi`
的靜態保護最強，但綁定本機與本 Windows 帳號，重灌或換帳號後就再也解不開，也無法
備份。預設把可攜性放在靜態加密之前，代價就是那個未加密的檔案，因此每次產生都會
印出三行警告。

檔案權限一律收斂：本工具寫出的每一個私鑰檔都會中斷繼承，只留下檔案擁有者與
`SYSTEM` 兩個帳號。

想要靜態加密又要能備份，用 `-Protect Passphrase`：

```powershell
pwsh .\rune-open.ps1 -GenerateKeys -Protect Passphrase
```

密碼會在畫面上詢問並要求輸入兩次確認（打錯就永久解不開那個檔案）。非互動環境請以
`-Passphrase (Read-Host -AsSecureString)` 傳入。

### 備份私鑰

```powershell
pwsh .\rune-open.ps1 -ExportPrivateKey -OutFile D:\backup\rune-private.pem -Force
```

```
已匯出私鑰（格式：未加密的 PKCS#8 PEM）
  來源  C:\Users\alice\.rune\private.key
  輸出  D:\backup\rune-private.pem
  指紋  RUNE-KEY BE1B-1948-2E90-4BD4-D377-52D2-978E-6436
還原方式：rune-open.ps1 -Unpack <密文檔> -Destination <目的資料夾> -KeyFile D:\backup\rune-private.pem
```

匯出**來源可以是 DPAPI 私鑰**——這是把 DPAPI 私鑰離機保存的唯一途徑。輸出格式用
`-Protect Passphrase` 可以加密（密碼以 `-OutPassphrase` 指定，與來源私鑰的
`-Passphrase` 分開）。

匯出會多一份私鑰落地，因此預設要求確認。非互動環境（例如把輸出導向檔案）不帶
`-Force` 會直接被拒絕：

```
私鑰匯出已中止：目前為非互動環境（標準輸入已重新導向），無法顯示確認提示。
請加上 -Confirm:$false 略過確認（rune-open.ps1 請用 -Force），或於互動環境重新執行。
```

### 補回或重印公鑰

`` `public.pem` `` 由 `` `private.key` `` 可以完全重現，刪掉了不要緊：

```powershell
pwsh .\rune-open.ps1 -ExportPublicKey
```

```
已重新導出公鑰
  私鑰  C:\Users\alice\.rune\private.key
  公鑰  C:\Users\alice\.rune\public.pem
  指紋  RUNE-KEY BE1B-1948-2E90-4BD4-D377-52D2-978E-6436
```

它同時是「再看一次我的指紋」的工具，隨時可以拿來與加密端核對。

### 重新產生金鑰（輪替）

`-GenerateKeys` 偵測到 `` `~\.rune\private.key` `` 已存在時不會直接覆蓋：互動環境下
先印出現有金鑰的指紋並詢問是否繼續（預設不繼續）；非互動環境直接拒絕，要輪替請帶
`-Force`。

確認之後，**舊金鑰是改名保留而不是刪除**：`` `private.key` `` 變成
`` `private.key.bak-<時間戳>` ``，`` `public.pem` `` 以同一個時間戳一併改名。舊密文
仍然解得開，只要指定備份路徑：

```powershell
pwsh .\rune-open.ps1 -Unpack old.txt -Destination C:\out -KeyFile ~\.rune\private.key.bak-20260809-121500
```

### 一次性指定公鑰

加密端不想在機器上放 `` `public.pem` `` 時，可以用 `-PublicKey`。字串含
`-----BEGIN` 視為 PEM 內容本體，否則視為檔案路徑：

```powershell
pwsh .\rune-seal.ps1 C:\data\report.docx -PublicKey D:\keys\bob.pem
```

多行 PEM 請用變數或 here-string 帶入，不要直接打在命令列上。

## ⚠ 安全須知

**請在第一次使用前讀完這一節。**

- **私鑰遺失 = 所有密文永久無法解開。** 沒有任何後門、沒有恢復碼、沒有備援金鑰。
  密文一旦貼到公開管道就永久存在，而私鑰是唯一的還原手段。
  **產生金鑰後請立刻用 `-ExportPrivateKey` 做一份離線備份。**
- **`-Protect Dpapi` 綁機器綁帳號。** 換機器、換 Windows 帳號、重灌系統之後，
  DPAPI 私鑰一律讀不開，而且無法複製備份。選它之前請先確認你已經用
  `-ExportPrivateKey` 匯出了一份可攜的 PEM。
- **預設的私鑰檔沒有加密。** `-Protect None` 產生的
  `` `~\.rune\private.key` `` 是明文 PKCS#8 PEM。任何能讀到這個檔案的人，都能解開
  所有以對應公鑰加密的密文。不要放進雲端同步資料夾或版本控管目錄。
- **無寄件人認證。** 公鑰是公開的，任何拿到它的人都能造出一個你解得開的容器。
  **「解得開」不代表「是你自己寄的」**，也不代表內容沒有被換成另一份合法內容。
  本工具沒有簽章機制。
- **無前向保密。** 私鑰一旦外洩，攻擊者可以解開他手上**所有**歷史密文。一次性的
  ECDH 金鑰對只保證每則密文用不同的內容金鑰，不保證舊密文在私鑰外洩後仍然安全。
- **不提供不可觀測性。** 輸出是固定結構的 Base64，開頭必然是 `UlVORQ`（`RUNE` 的
  編碼），可以被 grep 直接掃出來。容器長度與原始資料量單調相關，會洩漏負載規模。
  這不是隱寫術。
- **輸出檔名會洩漏原始檔名。** 預設輸出是 `<原始檔名>.txt`。檔名本身就是明文，
  需要規避時請用 `-OutFile` 指定一個無意義的名稱。
- **絕不要對來源不明的文字執行 `-Unpack`。** 解包會在你的磁碟上建立檔案。本工具
  對路徑逃逸（zip-slip）有兩道防線，解包失敗也會完整回滾，但它**不掃毒、不檢查
  副檔名、不限制檔案數量與大小**。
- **`-Destination` 請指向空資料夾。** 目的資料夾內既有的同名檔案會被覆蓋。
- **第一次使用時務必比對指紋。** 加密端每次執行都會印出所用公鑰的指紋，解密端的
  `-GenerateKeys` 與 `-ExportPublicKey` 印出相同格式。兩邊逐字一致才代表你加密給的
  是自己那把金鑰。**工具不會、也無法替你做這個比對。**

## 開發

### 驗收套件

```powershell
pwsh -File .\tests\verify.ps1 -RepoRoot . -Tier Core   # 安全性子集，約一分鐘
pwsh -File .\tests\verify.ps1 -RepoRoot . -Tier Full   # 全部
```

對兩支入口腳本執行的黑箱驗收，共 90 案（Core 40 / Full-only 50）。案例只透過命令列
呼叫受測物，不引用模組內部；金鑰派生與私鑰儲存格式另有依規格獨立實作的白盒驗證，
規格參數解不出來就直接判定為實作與 `docs/DESIGN.md` 不符。所有會動到
`` `~\.rune` `` 的案例都在沙箱家目錄下執行，並在每次呼叫後檢查真實家目錄未被污染。

`-Filter` 可以只跑編號符合正則的案例（例如 `-Filter 'C0[1-9]'`）。

### 變異測試

```powershell
pwsh -File .\tests\mutate.ps1 -List              # 只列出變異與預期變紅的案號
pwsh -File .\tests\mutate.ps1                    # 全部執行，預設 -Tier Core
pwsh -File .\tests\mutate.ps1 -Mutation M6 -Tier Full
```

驗收套件全綠只證明「行為沒變」，不證明「斷言有效」。變異測試在產品程式碼裡刻意
植入一個已知缺陷（停用 zip-slip 檢查、把 contentType 拿出 HKDF info、固定 nonce、
讓錯誤訊息退化成泛泛的失敗……），跑一次驗收套件，檢查該紅的案號真的紅了。目前
收錄 17 項。

植入與還原成對執行，還原後以整份程式碼的雜湊確認逐位元組相同；被強制中斷時下一次
啟動會自動還原。**修改產品程式碼時，若動到某項變異引用的那幾行（含註解），必須
同步更新 `tests/mutate.ps1` 的變異定義**，否則該項變異會找不到替換目標而失效。

### CI

`.github/workflows/module-check.yml` 在每次 push 與 pull request 檢查模組可載入、
manifest 的匯出清單與 `RunePost\Public\` 的實際檔案一致、一檔一函式且檔名等於函式名、
兩支入口腳本語法可解析。完整驗收與變異測試需要 Windows 上的 DPAPI 與 NTFS ACL，
在本機執行。

## 聲明

這是個人自用的工具。密碼學原語全部來自 .NET 內建類別，但這些原語的**組合方式**
——容器格式、金鑰派生的參數選擇、錯誤處理順序——**未經任何第三方密碼學稽核**。
請自行評估是否適用於你的威脅模型。

## 授權

授權條款待定。
