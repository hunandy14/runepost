#Requires -Version 7.2
<#
.SYNOPSIS
    runepost 驗收套件的變異測試：證明 tests\verify.ps1 的斷言仍然咬得動。

.DESCRIPTION
    verify.ps1 全綠只證明「行為沒變」，不證明「斷言有效」——一條恆真的斷言、一個
    被路徑字樣意外命中的樣式，在全綠的報表上看起來與真正的防線完全一樣。

    本腳本反過來做：在產品程式碼裡刻意植入一個已知缺陷，跑一次驗收套件，檢查該紅
    的案號真的紅了。每個變異都宣告「必須紅的案號」（MustRed）與「連帶會紅的案號」
    （MayRed）；MustRed 少一個就是斷言失效，MustRed ∪ MayRed 之外多紅則是非預期
    的連鎖影響，兩者都會在對照表上標出來。

    安全性：
      * 植入與還原成對寫在 try/finally，任何路徑失敗都會還原。
      * 還原一律用植入前的原始位元組寫回，並以整份產品程式碼的雜湊確認逐位元組
        相同；不相同就以錯誤中止並指明受影響的檔案。
      * 植入期間在工作目錄留下 in-flight 標記（含原始位元組）。若上一次執行被強制
        中斷而留下被植入的程式碼，下一次啟動會先偵測到標記並自動還原。
      * 正式開跑前先跑一次未植入任何變異的對照組，要求全綠。對照組不綠時所有
        「植入後有紅」的否定性結論都不可信，因此直接中止。

.PARAMETER Mutation
    要執行的變異名稱，可多個；省略即全部執行。

.PARAMETER Tier
    傳給 verify.ps1 的層級。預設 Core（約一分鐘一輪），Full 較慢但涵蓋全部案例。

.PARAMETER List
    只列出有哪些變異、各自的說明與預期紅的案號，不執行任何動作。

.PARAMETER SkipControl
    略過對照組。只在剛剛才確認過套件全綠、要省時間時使用。

.EXAMPLE
    pwsh -File .\tests\mutate.ps1 -List
    pwsh -File .\tests\mutate.ps1
    pwsh -File .\tests\mutate.ps1 -Mutation M6 -Tier Full
#>
[CmdletBinding()]
param(
    # repo 根目錄（預設為本腳本的上一層）
    [string]$RepoRoot,

    # 工作目錄（預設 <本腳本目錄>\_mutwork）
    [string]$WorkRoot,

    [string[]]$Mutation,

    [ValidateSet('Core', 'Full')]
    [string]$Tier = 'Core',

    [switch]$List,

    [switch]$SkipControl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$script:TestsDir = Split-Path -Parent $PSCommandPath
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $script:TestsDir }
$script:RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $WorkRoot) { $WorkRoot = Join-Path $script:TestsDir '_mutwork' }
$script:Verify = Join-Path $script:TestsDir 'verify.ps1'

# 守護檔一律放在 repo 內的固定位置，不跟著 -WorkRoot 走：它們要能被「拿到這份
# repo 的人」看見，而不是被藏在某個自訂工作目錄裡。
#   RUNNING    執行期間存在，宣告本 repo 正處於「可能已植入缺陷」的中間狀態
#   .inflight  植入期間保存目標檔案的原始位元組，供被中斷後由下一次執行自動還原
$script:GuardDir = Join-Path $script:TestsDir '_mutwork'
$script:LockFile = Join-Path $script:GuardDir 'RUNNING'
$script:InflightDir = Join-Path $script:GuardDir '.inflight'

if (-not (Test-Path -LiteralPath $script:Verify)) { throw "找不到驗收套件：$script:Verify" }

# ==============================================================================
# 變異目錄
#
# 每一項：
#   Desc     一句話說明植入了什麼缺陷
#   File     目標檔案（相對 repo 根目錄）
#   Old/New  要替換的原文與變異後內容，可為陣列（同一檔案多處）
#   MustRed  這個缺陷一定要讓這些案號變紅；少一個就是斷言失效
#   MayRed   連帶會紅的案號，允許但不強制
#   MustInfo 這些案號必須變成 INFO（用於「測試端偵測到異常但無法斷言對錯」的情形）
#   Tier     跑這一項所需的驗收層級，省略即 Core。MustRed 含 Full-only 案號的變異
#            必須填 Full，否則那些案號根本不會執行，「沒紅」就不是斷言失效的證據。
#            命令列的 -Tier Full 一律優先，會把所有變異都拉到 Full。
#   Note     需要額外說明時填寫，會印在對照表下方
# ==============================================================================

$script:Catalog = [ordered]@{

    M1 = @{
        Desc = '只停用 zip-slip 的反斜線檢查'
        File = 'RunePost\Private\Expand-RuneZip.ps1'
        Old = "if (`$entry.FullName -match '\\') {"
        New = "if (`$false) {   # MUTATION M1"
        MustRed = @()
        MayRed = @()
        Note = @'
本項預期「不紅」，收錄的目的是把這個結論明確記錄在變異目錄裡。
Expand-RuneZip 有兩道路徑檢查：(a) entry 名稱含反斜線一律拒絕；(b) 正規化後
要求仍在目的資料夾內。(b) 涵蓋 (a) 的全部輸入，所以只拿掉 (a) 之後外部行為
完全相同，只有錯誤措辭從 the entry name contains a backslash 變成
the entry escapes the destination folder。這在
黑箱上不可觀測，要讓它紅只能斷言「哪一道檢查開火」，那是對實作細節過度指定。
兩道檢查各自確實有被覆蓋，由 M1b 與 M1c 分別證明。
'@
    }

    M1b = @{
        Desc = '停用 zip-slip 的兩道路徑檢查'
        File = 'RunePost\Private\Expand-RuneZip.ps1'
        Old = @(
            "if (`$entry.FullName -match '\\') {"
            "if (-not `$fullResolved.StartsWith(`$destRootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {"
        )
        New = @(
            "if (`$false) {   # MUTATION M1b：反斜線檢查"
            "if (`$false) {   # MUTATION M1b：正規化包含性檢查"
        )
        MustRed = @('C37', 'C41', 'C46', 'C47')
        MayRed = @('C44', 'C88', 'C89')
        Note = @'
C44 / C88（中途失敗回滾）連帶變紅：不安全的 entry 不再被拒，整包解包直接成功。
C89（例外型別契約）同理：根本沒有例外可擲。
'@
    }

    M1c = @{
        Desc = '只停用 zip-slip 的正規化包含性檢查'
        File = 'RunePost\Private\Expand-RuneZip.ps1'
        Old = "if (-not `$fullResolved.StartsWith(`$destRootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {"
        New = "if (`$false) {   # MUTATION M1c"
        MustRed = @('C37', 'C47')
        MayRed = @('C44', 'C88', 'C89')
        Note = 'C41 / C46 必須維持綠色：反斜線分支仍由另一道檢查擋下，這正是兩案各自覆蓋不同檢查的證據。'
    }

    M2 = @{
        Desc = 'HKDF info 不含 contentType（型別位元不再綁進金鑰派生）'
        File = 'RunePost\Private\Get-RuneHkdfInfo.ps1'
        Old = "`$info[`$magicBytes.Length + 1] = `$ContentType"
        New = "`$info[`$magicBytes.Length + 1] = 0   # MUTATION M2"
        MustRed = @('C52', 'C08')
        MayRed = @('C09', 'C10', 'C19', 'C37', 'C41', 'C44', 'C46', 'C47', 'C54', 'C88', 'C89')
        Note = @'
C52 變紅：contentType 被竄改後 tag 仍驗得過，錯誤退化成「由較新版本產生」。
C08 變紅：以 DESIGN §4.2 的規格參數派生出來的金鑰通不過 GCM 驗證 —— 這就是「實作
的 KDF 參數與規格不符」的直接證據，不是「窮舉沒命中」這種模糊結論。獨立解密鏈與
偽造容器兩組案例都靠同一份素材，因此由 fixture 的負向記憶統一指回 C08。
'@
    }

    M3 = @{
        Desc = '固定 nonce（移除隨機來源）'
        File = 'RunePost\Public\Invoke-RuneSeal.ps1'
        Old = "        [System.Security.Cryptography.RandomNumberGenerator]::Fill(`$nonce)"
        New = "        # MUTATION M3：不填隨機值，nonce 固定為全零"
        MustRed = @('C06')
        MayRed = @()
        Note = @'
只有 C06（一次性金鑰）該紅。偽造容器那一組（C54 / C37 / C41 / C46 / C47）維持綠色
的理由：偽造一律以 DESIGN §4.2 的規格參數派生，nonce 是不是隨機的與參數選擇無關。
C08 的證據欄此時會多列出「salt=null」「salt=空位元組陣列」兩個等價別名 —— nonce
全為零時 HMAC 的零填充讓它們與 salt=nonce 導出同一把金鑰。這是附加資訊，不影響判定。
'@
    }

    M4 = @{
        Desc = '-GenerateKeys 把私鑰 PEM 全文印到畫面上'
        File = 'RunePost\Public\New-RuneKeyPair.ps1'
        Old = "        `$publicPem = `$ecdh.ExportSubjectPublicKeyInfoPem()"
        New = "        Write-Host (`$ecdh.ExportPkcs8PrivateKeyPem())   # MUTATION M4`n        `$publicPem = `$ecdh.ExportSubjectPublicKeyInfoPem()"
        MustRed = @('C35')
        MayRed = @('C81')
        Note = 'C81（保護方式須在成功輸出第一行）只在 Full 層執行，Core 層不會出現。'
    }

    M7 = @{
        Desc = '兩則路徑安全訊息退化成一般的封存格式錯誤'
        File = 'RunePost\Private\Expand-RuneZip.ps1'
        Old = @(
            '"Unsafe archive path detected (the entry name contains a backslash): $($entry.FullName)")'
            '"Unsafe archive path detected (the entry escapes the destination folder): $($entry.FullName)")'
        )
        New = @(
            '"Archive format error: $($entry.FullName)")   # MUTATION M7'
            '"Archive format error: $($entry.FullName)")   # MUTATION M7'
        )
        MustRed = @('C37', 'C41', 'C46', 'C47')
        MayRed = @()
        Note = @'
檢查本身完好，仍然拒絕、仍然不逸出，只有措辭退化。四案全紅代表訊息斷言確實有
咬合力——Unsafe archive path detected 是獨立語意，不可以用 Archive format error
搪塞過去，否則使用者會把攻擊誤讀成檔案壞掉。
'@
    }

    # ---- 「保留行為、只退化訊息」類別 ----
    #
    # M7 起的這一組都不動任何檢查：仍然拒絕、仍然不留下檔案、exit code 不變，只把
    # 錯誤訊息的措辭退化成一句泛泛的失敗。它們把「訊息斷言」單獨隔離出來驗 —— 有
    # 專屬語意要求的錯誤（曲線不符、非互動拒絕、空檔案、公鑰格式無效）若被一般錯誤
    # 搪塞過去，使用者就無從判斷下一步該做什麼，而黑箱行為完全看不出差別。

    M11 = @{
        Desc = '曲線不符的訊息退化成一般的公鑰載入失敗'
        File = 'RunePost\Private\Get-RunePublicKey.ps1'
        Old = 'throw "The recipient public key is not P-256: the curve OID is $curveOid. This tool supports P-256 ($($Script:P256CurveOid)) only."'
        New = 'throw "Cannot load the recipient public key: the OID is $curveOid."   # MUTATION M11'
        MustRed = @('C45')
        MayRed = @()
        Note = @'
公鑰仍然被拒、仍然不產生輸出檔，只是不再點名曲線（退化後的訊息裡沒有 curve、
也沒有 P-256，因此 stage.curve 這條樣式整條落空）。C45 變紅代表「須明確報曲線
不符」這條斷言真的咬得動：使用者拿到 P-384 公鑰時要能知道該換一把 P-256，
光說 Cannot load the recipient public key 會被誤讀成檔案壞掉。
'@
    }

    M12 = @{
        Desc = '三處「非互動環境」拒絕訊息退化成不提環境的一般錯誤'
        File = @(
            'RunePost\Private\Read-RunePassphrase.ps1'
            'RunePost\Public\Export-RunePrivateKey.ps1'
            'RunePost\Public\New-RuneKeyPair.ps1'
        )
        Old = @(
            'throw "No passphrase was supplied for the private key. This is a non-interactive session (standard input is redirected), so the passphrase prompt cannot be displayed.`nPass a SecureString with $ParameterName, for example $ParameterName (Read-Host -AsSecureString)."'
            'throw "Cannot export the private key: this is a non-interactive session (standard input is redirected), so the confirmation prompt cannot be displayed.`nSpecify -Confirm:`$false to skip the confirmation (with rune-open.ps1, specify -Force), or run the command again in an interactive session."'
            'throw "The private key already exists: $($Script:DefaultKeyFile)`nThis is a non-interactive session, so the confirmation prompt cannot be displayed. Specify -Force to create a new key pair (the existing key pair is renamed and kept, not deleted), or move the existing file aside and run the command again."'
        )
        New = @(
            'throw "No passphrase was supplied for the private key.`nPass a SecureString with $ParameterName, for example $ParameterName (Read-Host -AsSecureString)."   # MUTATION M12'
            'throw "Cannot export the private key.`nSpecify -Confirm:`$false to skip the confirmation (with rune-open.ps1, specify -Force), or run the command again in an interactive session."   # MUTATION M12'
            'throw "The private key already exists: $($Script:DefaultKeyFile)`nSpecify -Force to create a new key pair (the existing key pair is renamed and kept, not deleted), or move the existing file aside and run the command again."   # MUTATION M12'
        )
        MustRed = @('C73', 'C76', 'C79', 'C86', 'C87')
        MayRed = @()
        Tier = 'Full'
        Note = @'
三處都照樣拒絕、照樣不產生檔案、照樣不卡在提示，出路指引（-Passphrase / -Force /
-Confirm:$false）也原封不動，只有 This is a non-interactive session 這句話沒了。
Read-RunePassphrase 那一處讓 C73 與 C76 變紅（解密與匯出兩條要密碼的路徑各一次），
Export-RunePrivateKey 那一處讓 C79、C86 與 C87(b) 變紅（非互動、-Force 不代表略過
確認、呼叫端 ConfirmPreference=None 三種情境各一次）。
New-RuneKeyPair 那一處則沒有對應的紅：C34 與 C87(a) 要求的是「已存在」這個環節加上
-Force 這條出路，並未要求點名非互動——那是刻意的，因為同一個拒絕在互動環境下也
成立，措辭不該綁死在環境上。
'@
    }

    M13 = @{
        Desc = '空私鑰檔的訊息退化成 DPAPI 解保護失敗'
        File = 'RunePost\Private\Get-RunePrivateKey.ps1'
        Old = 'throw "Cannot read the private key: $KeyFilePath is an empty file (0 bytes) and holds no key material."'
        New = 'throw "Cannot read the private key: $KeyFilePath could not be unprotected with DPAPI."   # MUTATION M13'
        MustRed = @('C83')
        MayRed = @()
        Tier = 'Full'
        Note = @'
0 位元組的私鑰檔仍然被擋下、仍然不寫出任何檔案，只是原因被說成 DPAPI 解保護失敗。
這正是 C83 案名裡「不繞成 DPAPI 解保護失敗」要防的那件事：使用者會去查 DPAPI 與
使用者設定檔，而真正的問題只是檔案是空的。C83 同時要求點名空檔案且不得提及 DPAPI，
兩條斷言在這個變異下都會開火。
'@
    }

    M14 = @{
        Desc = '公鑰 PEM 格式無效的訊息退化成一般的載入失敗'
        File = 'RunePost\Private\Get-RunePublicKey.ps1'
        Old = 'throw "The recipient public key PEM is not valid and cannot be loaded: $($_.Exception.Message)"'
        New = 'throw "Cannot load the recipient public key: $($_.Exception.Message)"   # MUTATION M14'
        MustRed = @('C60', 'C62')
        MayRed = @()
        Tier = 'Full'
        Note = @'
兩條取得公鑰的路徑（~\.rune\public.pem 的內容、-PublicKey 收到的 PEM 字串）都照樣
被拒。C60 與 C62 同時變紅，證明 public key PEM is not valid 這句話在兩條路徑上
各被驗了一次。
C61（-PublicKey 指到不存在的路徑）維持綠色：那是另一個分支，本來就不該受影響。
'@
    }

    M15 = @{
        Desc = 'DPAPI 保護的內容由 PKCS#8 換成 SEC1 EC 私鑰（載入端一併相容，外部行為不變）'
        File = @(
            'RunePost\Public\New-RuneKeyPair.ps1'
            'RunePost\Private\Get-RunePrivateKey.ps1'
        )
        Old = @(
            '            $pkcs8Bytes = $ecdh.ExportPkcs8PrivateKey()'
            '                        $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead)'
        )
        New = @(
            '            $pkcs8Bytes = $ecdh.ExportECPrivateKey()   # MUTATION M15'
            '                        try { $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead) } catch { $ecdh.ImportECPrivateKey($pkcs8Bytes, [ref] $bytesRead) }   # MUTATION M15'
        )
        MustRed = @('C08')
        MayRed = @('C09', 'C10', 'C19', 'C37', 'C41', 'C44', 'C46', 'C47', 'C54', 'C88', 'C89')
        Note = @'
DESIGN §5.6 規定 Dpapi 這一種格式保護的是「PKCS#8 位元組」。本變異改成保護 SEC1
EC 私鑰位元組，並讓載入端兩種都吃 —— 於是黑箱上完全看不出差別：檔案照樣是二進位、
照樣解得開 DPAPI、roundtrip 照樣位元一致，連 C74（既有 PKCS#8 DPAPI 私鑰必須繼續
可用）都維持綠色，因為載入端仍然先試 PKCS#8。
C08 變紅是唯一的訊號：獨立解密鏈照 §5.6 讀私鑰，只接受規格寫的那一種內容。這正是
把「私鑰儲存格式的規格符合性」單獨隔離出來驗——C31 / C70 只查「是不是 DPAPI 二進位、
有沒有 PEM 字樣」，查不到裡面包的是哪一種 DER。
連帶紅的一組全部相依於同一份素材（獨立解出來的明文、或以它為前置的偽造容器），由
fixture 的負向記憶統一指回 C08。
'@
    }

    M5 = @{
        Desc = '拿掉私鑰檔的 ACL 收斂'
        File = 'RunePost\Private\Set-RunePrivateKeyAcl.ps1'
        Old = "        `$acl.SetAccessRuleProtection(`$true, `$false)"
        New = "        return   # MUTATION M5：不中斷繼承、不移除既有授權"
        MustRed = @('C80')
        MayRed = @()
    }

    M6 = @{
        Desc = '-Unpack 在 GCM tag 驗證失敗時仍繼續往下解包'
        File = 'RunePost\Public\Invoke-RuneOpen.ps1'
        Old = "        throw 'Content verification failed (the AES-GCM authentication tag does not match). The ciphertext may have been tampered with or corrupted in transit.'"
        New = "        Write-Warning 'MUTATION M6: tag mismatch ignored'"
        MustRed = @('C12')
        MayRed = @('C52')
        Note = @'
錯誤不會消失，而是退化成下游的 Brotli decompression failed. The data may be
corrupted.。C12 因此不能只要求訊息落在「內容損壞」這一類，必須點名遭竄改
（tampered 這條樣式只認 tamper 與 authentication tag），否則這個缺陷抓不到。
'@
    }

    M8 = @{
        Desc = 'seal 的相依閉包被拉進解密專屬函式'
        File = 'RunePost\Public\Invoke-RuneSeal.ps1'
        Old = '    $plan = Get-RunePackPlan -PackPath $PackPath'
        New = "    if (`$false) { `$null = Get-RunePrivateKey -KeyFilePath `$PackPath }   # MUTATION M8`n    `$plan = Get-RunePackPlan -PackPath `$PackPath"
        MustRed = @('C63')
        MayRed = @()
        Note = @'
植入的是「永遠不會執行到」的呼叫，因為 C63 守的是相依方向這個靜態性質，不是執行
結果。真實的退化就長這樣：有人為了少寫一段，在 seal 這條路徑上重用了解密端的私鑰
載入函式，程式跑起來一切正常，架構意圖卻已經破了。用死碼植入正好把「行為沒變但
相依方向變了」單獨隔離出來——C63 以外一案都不該紅。
'@
    }

    M9 = @{
        Desc = 'open 的相依閉包被拉進加密專屬函式'
        File = 'RunePost\Public\Invoke-RuneOpen.ps1'
        Old = '    $parsed = ConvertFrom-RuneContainer -Bytes $containerBytes'
        New = "    if (`$false) { `$null = Get-RunePublicKey -PublicKeyRef `$InFilePath }   # MUTATION M9`n    `$parsed = ConvertFrom-RuneContainer -Bytes `$containerBytes"
        MustRed = @('C64')
        MayRed = @()
        Note = 'C63 的反方向，理由同 M8：以不會執行到的呼叫證明 C64 咬的是相依方向而非行為。'
    }

    M10 = @{
        Desc = '覆蓋既有金鑰的確認改為沿用呼叫端繼承來的 $ConfirmPreference'
        File = 'RunePost\Public\New-RuneKeyPair.ps1'
        Old = "        `$ConfirmPreference = if (`$Force) { 'None' } else { 'High' }"
        New = "        if (`$Force) { `$ConfirmPreference = 'None' }   # MUTATION M10：不覆寫繼承來的偏好"
        MustRed = @('C87')
        MayRed = @()
        Note = @'
缺陷的形狀是：呼叫端 session 只要有 $ConfirmPreference = 'None'（自動化 profile
常見），ShouldProcess 與疊在它外面的非互動防呆會一起失效，已有金鑰又沒帶 -Force
也會靜默輪替並 exit 0。C34 對這個缺陷咬不動——它跑在 $ConfirmPreference 預設值
High 之下，看不出「偏好被繼承」這件事，因此必須另有 C87 專門走 None 這條路徑。
'@
    }
}

# ==============================================================================
# 產品程式碼雜湊
# ==============================================================================

# 把目錄裡的欄位一律轉成真正的陣列。兩個 PowerShell 陷阱要一起避開：
#   * 未設定的欄位是 $null，而 @($null) 的長度是 1，會讓「沒宣告」與「宣告了一個
#     空值」分不開。
#   * 函式回傳單元素陣列時 PowerShell 會把它攤平成純量，呼叫端 $x[0] 拿到的就變成
#     字串的第一個字元。回傳值前面的一元逗號就是用來擋這件事。
function ConvertTo-List {
    param($Value)
    if ($null -eq $Value) { return , @() }
    return , @($Value | Where-Object { $null -ne $_ })
}

function Get-ProductFiles {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'RunePost') -Recurse -File)
    foreach ($n in @('rune-seal.ps1', 'rune-open.ps1')) {
        $p = Join-Path $script:RepoRoot $n
        if (Test-Path -LiteralPath $p) { $files += Get-Item -LiteralPath $p }
    }
    return @($files | Sort-Object FullName)
}

function Get-ProductHash {
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in Get-ProductFiles) {
        [void]$sb.AppendLine((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash + '  ' + $f.FullName.Substring($script:RepoRoot.Length))
    }
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())))
}

# ==============================================================================
# 中間狀態的守護
#
# 執行期間 repo 裡的產品程式碼隨時可能是被植入缺陷的版本。RUNNING 這個 lock 檔
# 就是給人與工具看的旗標：看到它就代表現在讀到／複製到的程式碼不可信。
# 植入期間另外把目標檔案的原始位元組留在 .inflight，行程被強制中斷時，下一次啟動
# 會自動還原。
# ==============================================================================

function Set-RunLock {
    [void][System.IO.Directory]::CreateDirectory($script:GuardDir)
    [System.IO.File]::WriteAllText($script:LockFile,
        ("變異測試執行中，開始於 {0}（PID {1}）。`n本 repo 的產品程式碼可能正處於被植入缺陷的中間狀態，請勿讀取或複製。`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PID),
        [System.Text.UTF8Encoding]::new($false))
}

function Clear-RunLock {
    if (Test-Path -LiteralPath $script:LockFile) { Remove-Item -LiteralPath $script:LockFile -Force }
}

# $Targets 是 @{ Path; Bytes } 的清單：一項變異可以同時動好幾個檔案（例如同一類
# 錯誤訊息散在三支檔案裡），每個檔案的原始位元組都要各自留一份。
function Set-Inflight {
    param([object[]]$Targets, [string]$Name)
    [void][System.IO.Directory]::CreateDirectory($script:InflightDir)
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add($Name)
    for ($i = 0; $i -lt $Targets.Count; $i++) {
        [System.IO.File]::WriteAllBytes((Join-Path $script:InflightDir ("original_{0}.bin" -f $i)), $Targets[$i].Bytes)
        [void]$lines.Add($Targets[$i].Path)
    }
    [System.IO.File]::WriteAllText((Join-Path $script:InflightDir 'target.txt'), ($lines -join "`n"), [System.Text.UTF8Encoding]::new($false))
}

function Clear-Inflight {
    if (Test-Path -LiteralPath $script:InflightDir) {
        Remove-Item -LiteralPath $script:InflightDir -Recurse -Force
    }
}

# 啟動時先處理上一次執行被強制中斷所留下的殘骸。無論走哪條路徑都會清掉 lock 與
# .inflight，因此任何入口（含 -List）都可以、也應該先呼叫這個函式。
function Restore-InterruptedRun {
    $meta = Join-Path $script:InflightDir 'target.txt'
    $hasPending = (Test-Path -LiteralPath $meta) -and (Test-Path -LiteralPath (Join-Path $script:InflightDir 'original_0.bin'))
    $hasLock = Test-Path -LiteralPath $script:LockFile

    if ($hasPending) {
        $lines = @([System.IO.File]::ReadAllLines($meta))
        $name = $lines[0]
        Write-Host ''
        for ($i = 1; $i -lt $lines.Count; $i++) {
            $path = $lines[$i]
            $bin = Join-Path $script:InflightDir ("original_{0}.bin" -f ($i - 1))
            Write-Host "偵測到上一次執行未還原的變異 $name，正在還原：$path" -ForegroundColor Yellow
            [System.IO.File]::WriteAllBytes($path, [System.IO.File]::ReadAllBytes($bin))
        }
        Write-Host '已還原。' -ForegroundColor Yellow
    }
    elseif ($hasLock) {
        Write-Host ''
        Write-Host '偵測到上一次執行的標記但沒有待還原的檔案（中斷發生在植入之前或還原之後），清除標記。' -ForegroundColor Yellow
    }
    Clear-Inflight
    Clear-RunLock
}

# ==============================================================================
# 執行一輪驗收套件，回傳每個案號的結果
# ==============================================================================

function Invoke-Suite {
    param([string]$RunName, [string]$RunTier)
    $work = Join-Path $WorkRoot $RunName
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & pwsh -NoProfile -File $script:Verify -RepoRoot $script:RepoRoot -WorkRoot $work -Clean -Tier $RunTier *>&1 | Out-Null
    $sw.Stop()

    $report = Join-Path $work 'verify-report.txt'
    if (-not (Test-Path -LiteralPath $report)) { throw "驗收套件沒有產生報表：$report" }
    $res = [ordered]@{}
    $summary = ''
    foreach ($l in [System.IO.File]::ReadAllLines($report)) {
        if ($l -match '^(\S+)\s+\[(PASS|FAIL|SKIP|INFO)\]') { $res[$Matches[1]] = $Matches[2] }
        elseif ($l -match '^註冊 ') { $summary = $l.Trim() }
    }
    return [pscustomobject]@{
        Results = $res
        Summary = $summary
        Seconds = [int]$sw.Elapsed.TotalSeconds
        Red     = @($res.GetEnumerator() | Where-Object { $_.Value -eq 'FAIL' } | ForEach-Object Key)
        Skipped = @($res.GetEnumerator() | Where-Object { $_.Value -eq 'SKIP' } | ForEach-Object Key)
        Info    = @($res.GetEnumerator() | Where-Object { $_.Value -eq 'INFO' } | ForEach-Object Key)
        Tier    = $RunTier
    }
}

# 命令列的 -Tier Full 一律優先；否則看變異自己宣告的層級（省略即 Core）。
function Get-EffectiveTier {
    param($Mutation)
    if ($Tier -eq 'Full') { return 'Full' }
    if ($Mutation.Tier -eq 'Full') { return 'Full' }
    return $Tier
}

# ==============================================================================
# 殘骸回收（排在所有出口之前，含 -List：任何一次啟動都要有機會把上一次執行的中間
# 狀態收乾淨，不能因為這次只是查看清單就跳過）
# ==============================================================================

Restore-InterruptedRun

# ==============================================================================
# -List
# ==============================================================================

if ($List) {
    Write-Host ''
    Write-Host '可用的變異：' -ForegroundColor Cyan
    foreach ($name in $script:Catalog.Keys) {
        $m = $script:Catalog[$name]
        $must = if ((ConvertTo-List $m.MustRed).Count) { ((ConvertTo-List $m.MustRed) -join ', ') } else { '（預期不紅）' }
        Write-Host ''
        Write-Host ("  {0,-4} {1}" -f $name, $m.Desc) -ForegroundColor White
        Write-Host ("       目標檔案 : {0}" -f ((ConvertTo-List $m.File) -join '；'))
        Write-Host ("       所需層級 : {0}" -f $(if ($m.Tier) { $m.Tier } else { 'Core' }))
        Write-Host ("       必須紅   : {0}" -f $must) -ForegroundColor $(if ((ConvertTo-List $m.MustRed).Count) { 'Green' } else { 'DarkYellow' })
        if ((ConvertTo-List $m.MayRed).Count) { Write-Host ("       連帶可紅 : {0}" -f ((ConvertTo-List $m.MayRed) -join ', ')) }
        if ((ConvertTo-List $m.MustInfo).Count) { Write-Host ("       必須 INFO: {0}" -f ((ConvertTo-List $m.MustInfo) -join ', ')) }
        if ($m.Note) {
            foreach ($line in ($m.Note.TrimEnd() -split "`r?`n")) { Write-Host ("       說明     : " + $line) -ForegroundColor DarkGray }
        }
    }
    Write-Host ''
    Write-Host ('共 {0} 項。各項按自己宣告的層級執行（省略即 Core）；-Tier Full 會把全部拉到 Full。' -f $script:Catalog.Count) -ForegroundColor Cyan
    exit 0
}

# ==============================================================================
# 主流程
# ==============================================================================

# pwsh -File 會把 -Mutation M1,M2 當成單一字串傳進來（逗號不拆），所以自己再拆一次，
# 讓命令列與 session 內呼叫兩種用法都成立。
$names = if ($Mutation) {
    @($Mutation | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
else { @($script:Catalog.Keys) }
foreach ($n in $names) {
    if (-not $script:Catalog.Contains($n)) { throw "未知的變異名稱：$n（可用 -List 查看）" }
}

[void][System.IO.Directory]::CreateDirectory($WorkRoot)

Write-Host ''
Write-Host '========== runepost 驗收套件變異測試 ==========' -ForegroundColor Cyan
Write-Host ("repo：{0}" -f $script:RepoRoot)
$tiers = @($names | ForEach-Object { Get-EffectiveTier $script:Catalog[$_] })
# 對照組必須涵蓋所有變異會用到的案例，否則 Full-only 案例在對照組就紅了也看不見。
$ctrlTier = if ($tiers -contains 'Full') { 'Full' } else { 'Core' }
Write-Host ("層級：{0}（實際各項：{1}）；變異：{2}" -f $Tier,
    (($names | ForEach-Object { '{0}={1}' -f $_, (Get-EffectiveTier $script:Catalog[$_]) }) -join ' '), ($names -join ', '))
Write-Host ''
Write-Host '植入期間本 repo 的產品程式碼會處於被刻意植入缺陷的中間狀態：' -ForegroundColor Yellow
Write-Host '請勿在此期間讀取、複製、打包或建立這份 repo 的副本。' -ForegroundColor Yellow
Write-Host ("狀態旗標：{0}（存在即代表仍在執行；正常結束會自行移除）" -f $script:LockFile) -ForegroundColor Yellow

$baseHash = Get-ProductHash
Write-Host ("產品程式碼基線雜湊：{0}" -f $baseHash.Substring(0, 32) + '…')

# 對照組：未植入任何變異時套件必須全綠。不綠的話，「植入後有紅」就無從歸因，
# 所有否定性結論都不可信，因此直接中止。
if (-not $SkipControl) {
    Write-Host ''
    Write-Host ("-- 對照組（未植入任何變異，層級 {0}）--" -f $ctrlTier) -ForegroundColor Cyan
    $ctrl = Invoke-Suite -RunName 'control' -RunTier $ctrlTier
    Write-Host ("   {0}（{1}s）" -f $ctrl.Summary, $ctrl.Seconds)
    if ($ctrl.Red.Count -gt 0) {
        Write-Host ''
        Write-Host ('對照組不是全綠（紅：{0}）。所有變異測試的結論都不可信，中止。' -f ($ctrl.Red -join ',')) -ForegroundColor Red
        exit 2
    }
    Write-Host '   對照組全綠，可以開始植入。' -ForegroundColor Green
}

$rows = [System.Collections.Generic.List[object]]::new()
$notes = [System.Collections.Generic.List[string]]::new()

# 從這裡開始 repo 隨時可能是被植入的版本。旗標留到全部跑完才移除；若行程被強制
# 中斷而留下旗標，下一次啟動的 Restore-InterruptedRun 會連同 .inflight 一起收掉。
# 殘留的旗標是安全的一邊：它讓人不信任這份 repo，而不是誤以為它乾淨。
Set-RunLock

foreach ($name in $names) {
    $m = $script:Catalog[$name]

    $olds = (ConvertTo-List $m.Old)
    $news = (ConvertTo-List $m.New)
    if ($olds.Count -ne $news.Count) { throw "$name：Old 與 New 的數量不一致" }

    # File 可以是單一檔案（所有替換都在它裡面）或與 Old/New 等長的清單（同一項變異
    # 動好幾支檔案，例如同一類錯誤訊息散在三個地方）。
    $fileList = (ConvertTo-List $m.File)
    if ($fileList.Count -eq 1) { $fileList = @($olds | ForEach-Object { $fileList[0] }) }
    if ($fileList.Count -ne $olds.Count) { throw "$name：File 既不是單一檔案，數量也對不上 Old/New" }

    # 依檔案彙整替換，並先把原始位元組全部讀進來
    $targets = [ordered]@{}
    for ($i = 0; $i -lt $olds.Count; $i++) {
        $path = Join-Path $script:RepoRoot $fileList[$i]
        if (-not (Test-Path -LiteralPath $path)) { throw "$name：找不到目標檔案 $path" }
        if (-not $targets.Contains($path)) {
            $targets[$path] = [pscustomobject]@{
                Path  = $path
                # 還原一律寫回這一份原始位元組，因此連 BOM 在內的每一個位元組都會
                # 回到原狀，與植入時用什麼編碼寫出去無關。
                Bytes = [System.IO.File]::ReadAllBytes($path)
                Text  = [System.IO.File]::ReadAllText($path)
                Pairs = [System.Collections.Generic.List[object]]::new()
            }
        }
        if (-not $targets[$path].Text.Contains($olds[$i])) {
            throw "$name：目標檔案裡找不到要替換的片段（產品程式碼可能已改寫，請更新變異定義）：$($olds[$i])"
        }
        [void]$targets[$path].Pairs.Add(@{ Old = $olds[$i]; New = $news[$i] })
    }
    $targetList = @($targets.Values)
    $pathList = ($targetList | ForEach-Object { $_.Path }) -join '；'

    $runTier = Get-EffectiveTier $m
    Write-Host ''
    Write-Host ("-- {0}：{1}（層級 {2}）--" -f $name, $m.Desc, $runTier) -ForegroundColor Yellow

    $run = $null
    try {
        Set-Inflight -Targets $targetList -Name $name
        foreach ($t in $targetList) {
            $mut = $t.Text
            foreach ($p in $t.Pairs) { $mut = $mut.Replace($p.Old, $p.New) }
            # 產品程式碼一律是 UTF-8 with BOM（DESIGN §6.6），植入後照同一種編碼寫回。
            [System.IO.File]::WriteAllText($t.Path, $mut, [System.Text.UTF8Encoding]::new($true))
        }
        $run = Invoke-Suite -RunName ("run_" + $name) -RunTier $runTier
    }
    finally {
        # 還原一律用原始位元組寫回；失敗要吵到不可能被忽略。
        try {
            foreach ($t in $targetList) { [System.IO.File]::WriteAllBytes($t.Path, $t.Bytes) }
            Clear-Inflight
        }
        catch {
            Write-Host ''
            Write-Host ('嚴重：無法還原被植入變異的產品程式碼！受影響檔案：' + $pathList) -ForegroundColor Red
            Write-Host ('原始位元組保留在：' + $script:InflightDir) -ForegroundColor Red
            Write-Host ('請先手動還原該檔案再繼續使用本 repo。') -ForegroundColor Red
            throw
        }
    }

    $nowHash = Get-ProductHash
    $restored = ($nowHash -eq $baseHash)
    if (-not $restored) {
        Write-Host ''
        Write-Host ('嚴重：還原後產品程式碼雜湊與基線不符。受影響檔案：' + $pathList) -ForegroundColor Red
        Write-Host ('  基線 {0}' -f $baseHash) -ForegroundColor Red
        Write-Host ('  目前 {0}' -f $nowHash) -ForegroundColor Red
        Write-Host ('狀態旗標刻意保留：' + $script:LockFile) -ForegroundColor Red
        # 這條路徑上 repo 真的處於不可信狀態，旗標留著才對，不清。
        exit 2
    }

    $must = (ConvertTo-List $m.MustRed)
    $may = (ConvertTo-List $m.MayRed)
    $mustInfo = (ConvertTo-List $m.MustInfo)
    $executed = @($run.Results.Keys)

    # MustRed 的案號必須在本層級真的有跑到，否則「沒紅」是因為沒跑，不是因為咬不動
    $notRun = @($must | Where-Object { $executed -notcontains $_ })
    $missing = @($must | Where-Object { $run.Red -notcontains $_ -and $executed -contains $_ })
    $unexpected = @($run.Red | Where-Object { $must -notcontains $_ -and $may -notcontains $_ })
    $infoMissing = @($mustInfo | Where-Object { $run.Info -notcontains $_ -and $executed -contains $_ })

    $verdict = 'OK'
    if ($notRun.Count) { $verdict = '層級不含' }
    elseif ($missing.Count -or $infoMissing.Count) { $verdict = '斷言失效' }
    elseif ($unexpected.Count) { $verdict = '非預期連帶' }

    $rows.Add([pscustomobject]@{
            變異     = $name
            說明     = $m.Desc
            層級     = $runTier
            必須紅   = $(if ($must.Count) { $must -join ',' } else { '（無）' })
            實際紅   = $(if ($run.Red.Count) { $run.Red -join ',' } else { '（無）' })
            判定     = $verdict
            還原相符 = $restored
            秒       = $run.Seconds
        })

    $colour = switch ($verdict) { 'OK' { 'Green' } '層級不含' { 'DarkYellow' } default { 'Red' } }
    Write-Host ("   執行 {0} 案；紅 [{1}]；SKIP [{2}]；INFO [{3}]；{4}s" -f `
            $run.Results.Count, ($run.Red -join ','), ($run.Skipped -join ','), ($run.Info -join ','), $run.Seconds)
    Write-Host ("   判定：{0}" -f $verdict) -ForegroundColor $colour
    if ($missing.Count) { Write-Host ("   預期紅卻沒紅：{0} —— 這些案例對本缺陷咬不動，必須查明" -f ($missing -join ',')) -ForegroundColor Red }
    if ($infoMissing.Count) { Write-Host ("   預期轉 INFO 卻沒有：{0}" -f ($infoMissing -join ',')) -ForegroundColor Red }
    if ($unexpected.Count) { Write-Host ("   非預期連帶紅：{0} —— 若屬合理連鎖，請補進 MayRed" -f ($unexpected -join ',')) -ForegroundColor Red }
    if ($notRun.Count) { Write-Host ("   本層級未執行：{0}（該項變異應宣告 Tier = 'Full'）" -f ($notRun -join ',')) -ForegroundColor DarkYellow }
    if ($m.Note) { $notes.Add(($name + '：' + $m.Note.Trim())) }
}

Write-Host ''
Write-Host '================================ 變異測試對照表 ================================' -ForegroundColor Cyan
$rows | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host

if ($notes.Count) {
    Write-Host '說明：' -ForegroundColor Cyan
    foreach ($n in $notes) {
        foreach ($line in ($n -split "`r?`n")) { Write-Host ('  ' + $line) -ForegroundColor DarkGray }
        Write-Host ''
    }
}

$bad = @($rows | Where-Object { $_.判定 -ne 'OK' })
$finalHash = Get-ProductHash
# 全部還原完成，repo 回到可信狀態，旗標可以撤了。
if ($finalHash -eq $baseHash) { Clear-RunLock }
Write-Host ("產品程式碼還原確認：{0}（{1}）" -f $(if ($finalHash -eq $baseHash) { '與基線位元組相同' } else { '不符！' }), $finalHash.Substring(0, 32) + '…') `
    -ForegroundColor $(if ($finalHash -eq $baseHash) { 'Green' } else { 'Red' })
Write-Host ('工作目錄：{0}' -f $WorkRoot)
Write-Host ('{0} 項變異，{1} 項判定 OK，{2} 項需要處理。' -f $rows.Count, ($rows.Count - $bad.Count), $bad.Count) `
    -ForegroundColor $(if ($bad.Count) { 'Red' } else { 'Green' })

exit ([int](($bad.Count -gt 0) -or ($finalHash -ne $baseHash)))
