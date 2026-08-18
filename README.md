# runepost

把檔案加密成一段可以直接貼上的 Base64 純文字，經由公開管道送到自己的另一台機器，
在那裡用私鑰還原成原本的檔案樹。

本工具僅限 Windows + PowerShell 7.4+（`pwsh`），完整需求見下方〈環境需求〉。

## 快速使用

**程式印出來的一切都是英文**（摘要、進度、警告、錯誤訊息、確認提示，以及
`Get-Help` 看到的說明）；本文件的敘述維持中文，引用的輸出則原樣照抄。

除了「複製整個 `RunePost\` 資料夾 + 入口腳本」，每個 Release 另外提供**自足單檔**：
一支 `rune-seal.ps1`、一支 `rune-open.ps1`，各自把整個模組內聯進去，**不需要
`RunePost\` 資料夾**就能跑。加密端因此只要抓一個檔到任意機器就能用。以下是加密端的
標準落地方式。


### 先決條件：解密端已產生金鑰

加密前，解密端（保管私鑰的那台機器）要先有一組金鑰。在那台機器上執行（金鑰管理的
完整說明見下一節）：

```powershell
pwsh .\rune-open.ps1 -GenerateKeys
```

它會把私鑰寫到 `~\.rune\private.key`、公鑰寫到 `~\.rune\public.pem`，並在畫面上印出
**公鑰指紋**那一行（`Fingerprint  RUNE-KEY ...`）。稍後你需要兩樣東西：

- **公鑰內容**——在解密端用 `Get-Content ~\.rune\public.pem` 讀出整段 PEM，拿去加密端。
- **公鑰指紋**——記下畫面印的那一行，加密時用來逐字比對。

### 安裝與加密（裝到 `~\.rune\`，與金鑰同位置）

把單檔裝到 `~\.rune\`（和公鑰同一個資料夾），之後直接跑，不必每次都貼公鑰：

```powershell
# 1. 抓單檔到 ~\.rune\
New-Item -ItemType Directory -Force $HOME\.rune | Out-Null
irm https://github.com/hunandy14/runepost/releases/latest/download/rune-seal.ps1 -OutFile $HOME\.rune\rune-seal.ps1

# 2. 把解密端的公鑰存成 ~\.rune\public.pem（貼上內容，或直接把檔案複製過來）
@'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...（整段貼進來）...
-----END PUBLIC KEY-----
'@ | Set-Content $HOME\.rune\public.pem -Encoding ascii

# 3. 之後直接跑，seal 自動讀預設公鑰 ~\.rune\public.pem
pwsh $HOME\.rune\rune-seal.ps1 C:\data\report
```

加密時畫面第一行一定會印出所用公鑰的指紋：

```
Recipient public key fingerprint: RUNE-KEY 59FF-4DEB-3191-7BDB-1997-3588-57DB-8292
Compare it character by character with the fingerprint printed by -GenerateKeys or -ExportPublicKey on the decrypting machine. A mismatch means the public key may have been replaced.
```

**務必和解密端記下的指紋逐字比對**——這是察覺公鑰被掉包的唯一機會，理由見下方
「公鑰怎麼裝」。之後每次執行也都會印，隨時可再核對。

### 公鑰怎麼裝

- **公鑰來源固定是解密端。** 那台跑 `-GenerateKeys` 的機器，畫面印出公鑰**指紋**，
  公鑰**內容**則在 `~\.rune\public.pem`（用 `Get-Content ~\.rune\public.pem` 讀出）。
  加密端自己不產生、也不該產生公鑰。
- **公鑰不是祕密，傳輸走任何管道都行。** 隨身碟、雲端硬碟、即時通訊，甚至和密文貼在
  同一個公開版面上都無所謂。公鑰本來就是設計成可以公開的東西，不需要保密管道。
- **落地方式：存成 `~\.rune\public.pem`。** 之後 seal 自動讀取，不必每次指定
  `-PublicKey`。也可以用 `-PublicKey` 一次性指定其他位置的檔案，或直接傳入 PEM
  字串——這個參數仍是正式功能，只是不再是主推流程。
- **唯一必做的檢查：核對指紋。** 加密時 seal 每次都印出所用公鑰的指紋，拿它和解密端
  `-GenerateKeys` 或 `-ExportPublicKey` 印出的那一行逐字比對。一致，才代表你加密給的是
  自己那把金鑰；不一致，代表 `~\.rune\public.pem` 或你貼的內容被掉包了。**工具不會、
  也無法替你做這個比對。**

### 首次信任：核對單檔的 SHA-256（選讀）

擔心抓到的單檔在下載途中被動過手腳，可以在第一次使用前核對雜湊。每個 Release 頁面都
附了一份 `SHA256SUMS.txt`，列出兩支單檔的 SHA-256：

```powershell
Get-FileHash ~\.rune\rune-seal.ps1 -Algorithm SHA256
# 把印出的 Hash 和 Release 頁面 SHA256SUMS.txt 裡 rune-seal.ps1 那一行比對
```

一致就代表這支單檔和發布的位元組完全相同。**同一個版本驗過一次就夠了**，之後重抓
同一版不必再驗。

### 兩種雜湊別搞混

這裡有兩個各自獨立的核對動作，驗的是不同的東西：

| 驗什麼 | 用哪個 | 來源 |
|---|---|---|
| 工具是不是原版 | **檔案 SHA-256**（`Get-FileHash`） | Release 頁面的 `SHA256SUMS.txt` |
| 公鑰是不是我的 | **RUNE-KEY 指紋** | 解密端 `-GenerateKeys` 印出的那一行 |

**檔案 SHA-256** 防「單檔在下載途中被換掉」，**RUNE-KEY 指紋** 防「公鑰被掉包」。
兩者各管一件事，別拿其中一個當另一個用。

### 解密端：把檔案還原回來

密文就是一段純 Base64，每 76 字元換行，貼到任何純文字管道都行。在解密端把那段文字
取回、存成一個文字檔，再解開（解密端同樣可用自足單檔 `rune-open.ps1`，或整個模組）：

```powershell
pwsh .\rune-open.ps1 -Unpack report.txt -Destination C:\out\restored
```

```
Decryption complete. Restored 2 files to: C:\out\restored.
```

`-Unpack` 與 `-Destination` 也可以省略參數名稱依序放位置：

```powershell
pwsh .\rune-open.ps1 report.txt C:\out\restored
```

解密端與金鑰管理（產生、備份、輪替、匯出）的完整說明見下一節「金鑰管理」。

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
git clone https://github.com/hunandy14/runepost
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
「快速使用」。

不想帶整個 `RunePost\` 資料夾時，改用**自足單檔**：每個 Release 附了各自把模組內聯
進去的 `rune-seal.ps1` 與 `rune-open.ps1`，一個檔就能跑。落地方式見「快速使用」。

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
Exported the private key. Format: unencrypted PKCS#8 PEM.
  Source       C:\Users\alice\.rune\private.key
  Output       D:\backup\rune-private.pem
  Fingerprint  RUNE-KEY 59FF-4DEB-3191-7BDB-1997-3588-57DB-8292
To decrypt with this backup: rune-open.ps1 -Unpack <ciphertext file> -Destination <destination folder> -KeyFile D:\backup\rune-private.pem
WARNING: The private key is stored as an unencrypted PKCS#8 PEM at D:\backup\rune-private.pem.
WARNING: Anyone who can read this file can decrypt every ciphertext encrypted to the matching public key.
WARNING: Do not place this file in a cloud-sync folder or a version-control directory.
```

匯出**來源可以是 DPAPI 私鑰**——這是把 DPAPI 私鑰離機保存的唯一途徑。輸出格式用
`-Protect Passphrase` 可以加密（密碼以 `-OutPassphrase` 指定，與來源私鑰的
`-Passphrase` 分開）。

匯出會多一份私鑰落地，因此預設要求確認。非互動環境（例如把輸出導向檔案）不帶
`-Force` 會直接被拒絕：

```
Cannot export the private key: this is a non-interactive session (standard input is redirected), so the confirmation prompt cannot be displayed.
Specify -Confirm:$false to skip the confirmation (with rune-open.ps1, specify -Force), or run the command again in an interactive session.
```

### 補回或重印公鑰

`` `public.pem` `` 由 `` `private.key` `` 可以完全重現，刪掉了不要緊：

```powershell
pwsh .\rune-open.ps1 -ExportPublicKey
```

```
Re-exported the public key.
  Private key  C:\Users\alice\.rune\private.key
  Public key   C:\Users\alice\.rune\public.pem
  Fingerprint  RUNE-KEY 59FF-4DEB-3191-7BDB-1997-3588-57DB-8292
```

它同時是「再看一次我的指紋」的工具，隨時可以拿來與加密端核對。

### 重新產生金鑰（輪替）

`-GenerateKeys` 偵測到 `` `~\.rune\private.key` `` 已存在時不會直接覆蓋：互動環境下
先印出現有金鑰的指紋，再詢問是否繼續；非互動環境直接拒絕，要輪替請帶 `-Force`。

提示遵循 PowerShell 的標準確認行為，與 `Remove-Item -Confirm` 一樣：選項是
`Y`（是）／`A`（全部皆是）／`N`（否）／`L`（全部皆否）／`S`（暫停），**預設是
`Y`，直接按 Enter 就會繼續**。不想繼續請明確選 `N`。按錯也不會遺失金鑰——舊金鑰
是改名保留而不是刪除，見下一段。

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

對兩支入口腳本執行的黑箱驗收，共 93 案（Core 43 / Full-only 50）。案例只透過命令列
呼叫受測物，不引用模組內部；金鑰派生與私鑰儲存格式另有依規格獨立實作的白盒驗證，
規格參數解不出來就直接判定為實作與 `docs/DESIGN.md` 不符。所有會動到
`` `~\.rune` `` 的案例都在沙箱家目錄下執行，且每次經由統一呼叫點啟動受測物之後都會
檢查真實家目錄未被污染。

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

### 自足單檔

```powershell
pwsh -File .\tools\Build-Bundle.ps1 -Product all          # 產出 dist\rune-seal.ps1 與 rune-open.ps1
pwsh -File .\tools\Build-Bundle.ps1 -Check                # 只驗不寫：磁碟產物與現組是否逐位元組相同
pwsh -File .\tools\Test-BundleEquivalence.ps1             # 逐字元證明 bundle 內聯的函式與模組一致
```

`tools\Build-Bundle.ps1` 把模組 `RunePost\` 與一支入口腳本組成一支自足單檔：
comment-based help 在最前面、`#Requires` 其後、`param` 為第一個語句，接著內聯模組層級
常數與全部函式，最後接上入口腳本的分派本體（`Import-Module` 那行被移除）。產物為
UTF-8 with BOM、LF，檔頭標記來源內容的 SHA-256 前 12 碼以供溯源。

`dist\` 不進版控：單檔是發布產物，由上面的 bundler 從源碼現組，於打 tag 時由 CI 建置
並附到 Release。要在本機看產物，自己跑一次 bundler 即可。

bundle 與模組的等價由兩軌證明：`tests\verify.ps1` 以 `-SealScript` / `-OpenScript` 指向
dist 的單檔，可對 bundle 版跑同一批 93 案；`tools\Test-BundleEquivalence.ps1` 再以 AST
逐字元比對確認內聯沒有改動任何一個字。

### CI

`.github/workflows/module-check.yml` 在每次 push 與 pull request 檢查模組可載入、
manifest 的匯出清單與 `RunePost\Public\` 的實際檔案一致、一檔一函式且檔名等於函式名、
兩支入口腳本語法可解析。完整驗收與變異測試需要 Windows 上的 DPAPI 與 NTFS ACL，
在本機執行。

`.github/workflows/release.yml` 在推送 `v*` tag 時於 `windows-latest` 組出兩支自足單檔、
跑 `bundler -Check` 確認與源碼一致、算出 `SHA256SUMS.txt`，再把三個檔附到該 tag 的
GitHub Release。

## 聲明

這是個人自用的工具。密碼學原語全部來自 .NET 內建類別，但這些原語的**組合方式**
——容器格式、金鑰派生的參數選擇、錯誤處理順序——**未經任何第三方密碼學稽核**。
請自行評估是否適用於你的威脅模型。

## 授權

[MIT License](LICENSE)。
