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
#   .inflight  植入期間保存目標檔案的原始位元組，供被中斷後的下一輪自動還原
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
本項預期「不紅」，收錄它是為了把這個結論留在版控裡。
Expand-RuneZip 有兩道路徑檢查：(a) entry 名稱含反斜線一律拒絕；(b) 正規化後
要求仍在目的資料夾內。(b) 涵蓋 (a) 的全部輸入，所以只拿掉 (a) 之後外部行為
完全相同，只有錯誤措辭從「entry 名稱含反斜線」變成「跳脫目的資料夾」。這在
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
        MayRed = @('C44')
        Note = 'C44（中途失敗回滾）連帶變紅：不安全的 entry 不再被拒，整包解包直接成功。'
    }

    M1c = @{
        Desc = '只停用 zip-slip 的正規化包含性檢查'
        File = 'RunePost\Private\Expand-RuneZip.ps1'
        Old = "if (-not `$fullResolved.StartsWith(`$destRootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {"
        New = "if (`$false) {   # MUTATION M1c"
        MustRed = @('C37', 'C47')
        MayRed = @('C44')
        Note = 'C41 / C46 必須維持綠色：反斜線分支仍由另一道檢查擋下，這正是兩案各自覆蓋不同檢查的證據。'
    }

    M2 = @{
        Desc = 'HKDF info 不含 contentType（型別位元不再綁進金鑰派生）'
        File = 'RunePost\Private\Get-RuneHkdfInfo.ps1'
        Old = "`$info[`$magicBytes.Length + 1] = `$ContentType"
        New = "`$info[`$magicBytes.Length + 1] = 0   # MUTATION M2"
        MustRed = @('C52')
        MayRed = @()
        MustInfo = @('C08')
        Note = @'
C52 變紅：contentType 被竄改後 tag 仍驗得過，錯誤退化成「由較新版本產生」。
C08 轉為 INFO：獨立解密鏈的候選窮舉再也對不上實作的 info，代表測試端確實偵測
到 KDF 參數不符。依賴 C08 還原結果偽造容器的案例會因此 SKIP，屬預期連鎖。
'@
    }

    M3 = @{
        Desc = '固定 nonce（移除隨機來源）'
        File = 'RunePost\Public\Invoke-RuneSeal.ps1'
        Old = "        [System.Security.Cryptography.RandomNumberGenerator]::Fill(`$nonce)"
        New = "        # MUTATION M3：不填隨機值，nonce 固定為全零"
        MustRed = @('C06')
        MayRed = @('C54', 'C37', 'C41', 'C46', 'C47')
        Note = @'
連帶紅的來源：nonce 同時是 HKDF 的 salt，全零時 HMAC 的零填充讓「salt = 12 個
零位元組」與「salt = null」導出同一把金鑰，C08 的窮舉會鎖定 salt=null 這個別名，
偽造容器機制隨之以錯誤的參數派生。
'@
    }

    M4 = @{
        Desc = '-GenerateKeys 把私鑰 PEM 全文印到畫面上'
        File = 'RunePost\Public\Invoke-RuneGenerateKeys.ps1'
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
            '"偵測到不安全的封存路徑（entry 名稱含反斜線）：$($entry.FullName)")'
            '"偵測到不安全的封存路徑（跳脫目的資料夾）：$($entry.FullName)")'
        )
        New = @(
            '"封存格式錯誤：$($entry.FullName)")   # MUTATION M7'
            '"封存格式錯誤：$($entry.FullName)")   # MUTATION M7'
        )
        MustRed = @('C37', 'C41', 'C46', 'C47')
        MayRed = @()
        Note = @'
檢查本身完好，仍然拒絕、仍然不逸出，只有措辭退化。四案全紅代表訊息斷言確實有
咬合力——「不安全的封存路徑」是獨立語意，不可以用「格式損壞」搪塞過去，否則
使用者會把攻擊誤讀成檔案壞掉。
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
        Old = "        throw '內容驗證失敗（GCM 認證標籤不符）：檔案在傳輸過程中可能被竄改或損壞'"
        New = "        Write-Warning 'MUTATION M6：忽略 tag 驗證失敗'"
        MustRed = @('C12')
        MayRed = @('C52')
        Note = @'
錯誤不會消失，而是退化成下游的「Brotli 解壓縮失敗：資料可能已損壞」。C12 因此
不能只要求訊息落在「內容損壞」這一類，必須點名遭竄改，否則這個缺陷抓不到。
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
# 植入期間另外把目標檔案的原始位元組留在 .inflight，行程被強制中斷時下一輪啟動
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

function Set-Inflight {
    param([string]$Path, [byte[]]$OriginalBytes, [string]$Name)
    [void][System.IO.Directory]::CreateDirectory($script:InflightDir)
    [System.IO.File]::WriteAllBytes((Join-Path $script:InflightDir 'original.bin'), $OriginalBytes)
    [System.IO.File]::WriteAllText((Join-Path $script:InflightDir 'target.txt'), ($Name + "`n" + $Path), [System.Text.UTF8Encoding]::new($false))
}

function Clear-Inflight {
    if (Test-Path -LiteralPath $script:InflightDir) {
        Remove-Item -LiteralPath $script:InflightDir -Recurse -Force
    }
}

# 啟動時先處理上一輪被強制中斷留下的殘骸。無論走哪條路徑都會清掉 lock 與
# .inflight，因此任何入口（含 -List）都可以、也應該先呼叫這個函式。
function Restore-InterruptedRun {
    $meta = Join-Path $script:InflightDir 'target.txt'
    $bin = Join-Path $script:InflightDir 'original.bin'
    $hasPending = (Test-Path -LiteralPath $meta) -and (Test-Path -LiteralPath $bin)
    $hasLock = Test-Path -LiteralPath $script:LockFile

    if ($hasPending) {
        $lines = @([System.IO.File]::ReadAllLines($meta))
        $name = $lines[0]
        $path = $lines[1]
        Write-Host ''
        Write-Host "偵測到上一輪未還原的變異 $name，正在還原：$path" -ForegroundColor Yellow
        [System.IO.File]::WriteAllBytes($path, [System.IO.File]::ReadAllBytes($bin))
        Write-Host '已還原。' -ForegroundColor Yellow
    }
    elseif ($hasLock) {
        Write-Host ''
        Write-Host '偵測到上一輪的執行標記但沒有待還原的檔案（中斷發生在植入之前或還原之後），清除標記。' -ForegroundColor Yellow
    }
    Clear-Inflight
    Clear-RunLock
}

# ==============================================================================
# 執行一輪驗收套件，回傳每個案號的結果
# ==============================================================================

function Invoke-Suite {
    param([string]$RunName)
    $work = Join-Path $WorkRoot $RunName
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & pwsh -NoProfile -File $script:Verify -RepoRoot $script:RepoRoot -WorkRoot $work -Clean -Tier $Tier *>&1 | Out-Null
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
    }
}

# ==============================================================================
# 殘骸回收（排在所有出口之前，含 -List：任何一次啟動都要有機會把上一輪的中間
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
        Write-Host ("       目標檔案 : {0}" -f $m.File)
        Write-Host ("       必須紅   : {0}" -f $must) -ForegroundColor $(if ((ConvertTo-List $m.MustRed).Count) { 'Green' } else { 'DarkYellow' })
        if ((ConvertTo-List $m.MayRed).Count) { Write-Host ("       連帶可紅 : {0}" -f ((ConvertTo-List $m.MayRed) -join ', ')) }
        if ((ConvertTo-List $m.MustInfo).Count) { Write-Host ("       必須 INFO: {0}" -f ((ConvertTo-List $m.MustInfo) -join ', ')) }
        if ($m.Note) {
            foreach ($line in ($m.Note.TrimEnd() -split "`r?`n")) { Write-Host ("       說明     : " + $line) -ForegroundColor DarkGray }
        }
    }
    Write-Host ''
    Write-Host ('共 {0} 項。預設層級 Core；-Tier Full 可跑全部案例。' -f $script:Catalog.Count) -ForegroundColor Cyan
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
Write-Host ("層級：{0}；變異：{1}" -f $Tier, ($names -join ', '))
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
    Write-Host '-- 對照組（未植入任何變異）--' -ForegroundColor Cyan
    $ctrl = Invoke-Suite -RunName 'control'
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
    $path = Join-Path $script:RepoRoot $m.File
    if (-not (Test-Path -LiteralPath $path)) { throw "$name：找不到目標檔案 $path" }

    $olds = (ConvertTo-List $m.Old)
    $news = (ConvertTo-List $m.New)
    if ($olds.Count -ne $news.Count) { throw "$name：Old 與 New 的數量不一致" }

    $origBytes = [System.IO.File]::ReadAllBytes($path)
    $hasBom = ($origBytes.Length -ge 3 -and $origBytes[0] -eq 0xEF -and $origBytes[1] -eq 0xBB -and $origBytes[2] -eq 0xBF)
    $origText = [System.IO.File]::ReadAllText($path)
    foreach ($o in $olds) {
        if (-not $origText.Contains($o)) { throw "$name：目標檔案裡找不到要替換的片段（產品程式碼可能已改寫，請更新變異定義）：$o" }
    }

    Write-Host ''
    Write-Host ("-- {0}：{1} --" -f $name, $m.Desc) -ForegroundColor Yellow

    $run = $null
    try {
        $mut = $origText
        for ($i = 0; $i -lt $olds.Count; $i++) { $mut = $mut.Replace($olds[$i], $news[$i]) }
        Set-Inflight -Path $path -OriginalBytes $origBytes -Name $name
        [System.IO.File]::WriteAllText($path, $mut, [System.Text.UTF8Encoding]::new($hasBom))
        $run = Invoke-Suite -RunName ("run_" + $name)
    }
    finally {
        # 還原一律用原始位元組寫回；失敗要吵到不可能被忽略。
        try {
            [System.IO.File]::WriteAllBytes($path, $origBytes)
            Clear-Inflight
        }
        catch {
            Write-Host ''
            Write-Host ('嚴重：無法還原被植入變異的產品程式碼！受影響檔案：' + $path) -ForegroundColor Red
            Write-Host ('原始位元組保留在：' + (Join-Path $script:InflightDir 'original.bin')) -ForegroundColor Red
            Write-Host ('請先手動還原該檔案再繼續使用本 repo。') -ForegroundColor Red
            throw
        }
    }

    $nowHash = Get-ProductHash
    $restored = ($nowHash -eq $baseHash)
    if (-not $restored) {
        Write-Host ''
        Write-Host ('嚴重：還原後產品程式碼雜湊與基線不符。受影響檔案：' + $path) -ForegroundColor Red
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
    if ($notRun.Count) { Write-Host ("   本層級未執行：{0}（改用 -Tier Full）" -f ($notRun -join ',')) -ForegroundColor DarkYellow }
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
