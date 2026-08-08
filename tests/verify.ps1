#Requires -Version 7.2
<#
.SYNOPSIS
    runepost 獨立驗收腳本（規格 v2 / 容器 version 0x02 / ECDH P-256 + HKDF-SHA256 + AES-256-GCM）

.DESCRIPTION
    對 repo 根目錄的 rune-seal.ps1（加密端）與 rune-open.ps1（解密端 + 金鑰管理）
    跑一套完整案例。兩支都是薄入口腳本，實作在 RunePost\ 模組內。

    結構上的四條規矩：

      1. 受測腳本只在 Invoke-Seal / Invoke-Open 兩個函式裡各出現一次。案例一律
         透過這兩個語意動詞呼叫受測物，不自己拼參數陣列。
      2. 「失敗案例必須同時成立」的紀律（不得逾時、必須真的失敗、不得留下輸出檔
         或殘留檔案、錯誤訊息只比對 StdErr）寫在 Expect-SealRefused /
         Expect-OpenRefused 內部，不做成呼叫端要記得加的開關。
      3. 措辭斷言集中在 $script:Msg 這張期望訊息表；案例本體只做行為斷言。
      4. 共用素材是惰性 fixture，案例以 -Needs 宣告相依，因此 -Filter / -Tier
         篩出的任意子集都能單獨執行。

.PARAMETER RepoRoot
    repo 根目錄（內含 rune-seal.ps1 / rune-open.ps1 與 RunePost\ 模組）。

.PARAMETER Tier
    Core 只跑安全性與前置案例（目標一分鐘內），Full 跑全部。

.EXAMPLE
    pwsh -File .\verify.ps1 -RepoRoot Z:\path\to\repo
    pwsh -File .\verify.ps1 -RepoRoot Z:\path\to\repo -Tier Core
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,

    # 工作目錄（預設 <本腳本目錄>\_work）
    [string]$WorkRoot,

    # 執行前清空工作目錄
    [switch]$Clean,

    # 只跑編號符合此 regex 的案例（例：'C0[1-9]'）
    [string]$Filter,

    # 執行層級：Core 為安全性子集，Full 為全部
    [ValidateSet('Core', 'Full')]
    [string]$Tier = 'Full',

    # 單次子行程逾時秒數
    [int]$TimeoutSec = 180
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ==============================================================================
# 0. 基礎設施
# ==============================================================================

$script:ReviewRoot = Split-Path -Parent $PSCommandPath
if (-not $WorkRoot) { $WorkRoot = Join-Path $script:ReviewRoot '_work' }
$script:Work = $WorkRoot
$script:RunTier = $Tier
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Registered = [System.Collections.Generic.List[object]]::new()
$script:LogLines = [System.Collections.Generic.List[string]]::new()
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:Utf8Bom = [System.Text.UTF8Encoding]::new($true)

$script:RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$script:ModuleRoot = Join-Path $script:RepoRoot 'RunePost'

# 受測腳本的絕對路徑與初始雜湊在任何案例執行前就固定下來：C40 拿它比對「受測物
# 自始至終未被改動」，而 Invoke-Seal / Invoke-Open 也需要在 P1a/P1b 之外就能用
# （否則 -Filter 篩掉前置案例時會拿到 $null）。
$script:SutSeal = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot 'rune-seal.ps1'))
$script:SutOpen = [System.IO.Path]::GetFullPath((Join-Path $script:RepoRoot 'rune-open.ps1'))

function Write-Log {
    param([string]$Text)
    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $Text
    $script:LogLines.Add($line)
    Write-Verbose $line
}

function Squash {
    param([string]$Text, [int]$Max = 120)
    if ($null -eq $Text) { return '' }
    $s = ($Text -replace '\s+', ' ').Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '…' }
    return $s
}

function Assert {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Skip-Case { param([string]$Message) throw "SKIP:$Message" }
function Info-Case { param([string]$Message) throw "INFO:$Message" }

# 案例執行器：Body 回傳字串 => PASS；throw 'SKIP:x' / 'INFO:x' => SKIP / INFO；其餘 throw => FAIL
function Invoke-Case {
    param([string]$Id, [string]$Name, [scriptblock]$Body)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'FAIL'
    $evidence = ''
    try {
        $out = & $Body
        if ($out -is [System.Array]) { $out = $out[-1] }
        $status = 'PASS'
        $evidence = [string]$out
    }
    catch {
        $m = $_.Exception.Message
        if ($m -like 'SKIP:*') { $status = 'SKIP'; $evidence = $m.Substring(5) }
        elseif ($m -like 'INFO:*') { $status = 'INFO'; $evidence = $m.Substring(5) }
        else { $status = 'FAIL'; $evidence = $m }
    }
    $sw.Stop()
    $script:Results.Add([pscustomobject]@{
            No       = $Id
            Case     = $Name
            Result   = $status
            Evidence = $evidence
            Ms       = [int]$sw.ElapsedMilliseconds
        })
    Write-Log ("{0} {1} [{2}] {3}" -f $Id, $Name, $status, (Squash $evidence 400))

    $color = switch ($status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'DarkYellow' } default { 'Cyan' } }
    Write-Host ('  {0,-14} {1,-5} {2}' -f $Id, $status, (Squash $Name 46)) -ForegroundColor $color
}

# 案例登記器。
#   -Tier   必填。新增案例的作者必須表態這一案屬於 Core 還是 Full；沒表態就整套
#           中止，不讓案例以「預設層級」悄悄溜進來。
#   -Needs  這一案需要的 fixture 名稱。取用發生在 Body 之前，因此案例之間沒有
#           執行順序上的耦合，任意子集都能單獨執行。
function Invoke-TCase {
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Id,
        [Parameter(Mandatory = $true, Position = 1)][string]$Name,
        [Parameter(Mandatory = $true, Position = 2)][scriptblock]$Body,
        [string]$Tier,
        [string[]]$Needs = @()
    )
    if ($Tier -ne 'Core' -and $Tier -ne 'Full') {
        throw "案例 $Id 未表態層級：Invoke-TCase 必須指定 -Tier Core 或 -Tier Full"
    }
    $script:Registered.Add([pscustomobject]@{ No = $Id; Tier = $Tier; Name = $Name })

    if ($script:RunTier -eq 'Core' -and $Tier -ne 'Core') { return }
    if ($Filter -and $Id -notmatch $Filter) { return }

    $wrapped = {
        foreach ($n in $Needs) { [void](Get-Fixture $n) }
        & $Body
    }.GetNewClosure()
    Invoke-Case -Id $Id -Name $Name -Body $wrapped
}

# ==============================================================================
# 1. 子行程執行（wrapper 統一 UTF-8 輸出、統一退出碼、永不卡在互動）
# ==============================================================================

$script:Pwsh = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (-not $script:Pwsh -or -not (Test-Path -LiteralPath $script:Pwsh)) {
    $script:Pwsh = (Get-Command pwsh -ErrorAction Stop).Source
}

$script:WrapperSource = @'
# verify.ps1 產生的執行外殼：固定 UTF-8、轉發參數、統一錯誤與退出碼
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
try { $OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
$ErrorActionPreference = 'Continue'
$target = $env:CTXT_TARGET
$global:LASTEXITCODE = 0
try {
    & $target @args
}
catch {
    [Console]::Error.WriteLine('WRAPPER-CAUGHT: ' + $_.Exception.GetType().Name + ': ' + $_.Exception.Message)
    exit 3
}
if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
exit 0
'@

function Invoke-Transfer {
    param(
        [string]$ScriptPath,
        [string[]]$Arguments = @(),
        [hashtable]$EnvVars,
        [string]$WorkDir,
        [string]$StdinText,
        [int]$Timeout = $script:TimeoutSec
    )
    if (-not $Timeout) { $Timeout = 180 }
    if (-not $WorkDir) { $WorkDir = $script:Work }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:Pwsh
    foreach ($a in @('-NoProfile', '-NoLogo', '-File', $script:WrapperPath)) { [void]$psi.ArgumentList.Add($a) }
    foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add([string]$a) }
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = $script:Utf8NoBom
    $psi.StandardErrorEncoding = $script:Utf8NoBom
    $psi.StandardInputEncoding = $script:Utf8NoBom
    # 沙箱化只能靠 ProcessStartInfo.Environment：$HOME 在 pwsh session 啟動時就
    # 定案，行程內再改 $env:HOME 不會影響 ~ 的解析，也就擋不住寫進真實家目錄。
    $psi.Environment['CTXT_TARGET'] = $ScriptPath
    $psi.Environment['POWERSHELL_TELEMETRY_OPTOUT'] = '1'
    if ($EnvVars) { foreach ($k in $EnvVars.Keys) { $psi.Environment[$k] = [string]$EnvVars[$k] } }

    $p = [System.Diagnostics.Process]::Start($psi)
    $tOut = $p.StandardOutput.ReadToEndAsync()
    $tErr = $p.StandardError.ReadToEndAsync()
    try {
        if ($StdinText) { $p.StandardInput.Write($StdinText) }
    } catch { }
    try { $p.StandardInput.Close() } catch { }

    $timedOut = $false
    if (-not $p.WaitForExit($Timeout * 1000)) {
        $timedOut = $true
        try { $p.Kill($true) } catch { }
        [void]$p.WaitForExit(5000)
    }
    $so = $tOut.GetAwaiter().GetResult()
    $se = $tErr.GetAwaiter().GetResult()
    $code = if ($timedOut) { -1 } else { $p.ExitCode }
    $p.Dispose()

    $res = [pscustomobject]@{
        ExitCode = $code
        StdOut   = $so
        StdErr   = $se
        All      = ($so + "`n" + $se)
        TimedOut = $timedOut
        Failed   = ($timedOut -or $code -ne 0 -or -not [string]::IsNullOrWhiteSpace($se))
        Args     = ($Arguments -join ' ')
        Escaped  = $null
    }
    Write-Log ("RUN {0} => exit={1} stderr={2}" -f $res.Args, $res.ExitCode, (Squash $se 200))
    return $res
}

# ==============================================================================
# 2. 期望訊息表
#
# 所有「措辭」斷言集中在這一張表，案例本體只留行為斷言（有沒有失敗、有沒有輸出
# 檔、exit code、檔案有沒有被改動）。使用者可見輸出換語系時只要改這張表。
#
# 值一律是正則；同一個鍵可以並列多語言的說法。stage.* 是「錯誤訊息必須指明哪個
# 環節」的分類，供 Expect-*Refused 的 -Category 使用；其餘是個別案例要求的具體
# 措辭。取用一律經 Get-MsgPattern，鍵名打錯會立刻拋錯，不會靜默退化成比對空樣式。
# ==============================================================================

$script:Msg = [ordered]@{
    # --- 錯誤環節分類 ---
    'stage.base64'  = 'base64|Base64|BASE64|編碼|解碼|encod|decod'
    'stage.format'  = 'magic|RUNE|格式|標頭|檔頭|header|不符|無法辨識|not a valid|不是|無效'
    'stage.version' = '版本|version|不支援|unsupported|0x0|格式|magic'
    'stage.key'     = '私鑰|金鑰|key|解鑰|DPAPI|解不開|讀不到|無法讀取|無法解密|not found|decrypt|unprotect'
    'stage.tag'     = '損壞|竄改|corrupt|tamper|驗證失敗|校驗|完整性|tag|GCM|authentication|內容'
    'stage.unzip'   = '解壓|解壓縮|decompress|Brotli|brotli|壓縮|zip|ZIP|解包|封存|archive|損壞'
    'stage.nopub'   = '公鑰|public key|public\.pem'
    'stage.exists'  = '已存在|存在|exists|Force|覆蓋|overwrite'
    'stage.nomatch' = '找不到|沒有|未符合|不符合|沒有符合|no file|match|符合|空'
    'stage.input'   = '找不到|不存在|not found|無效|invalid|路徑|path'
    'stage.param'   = 'Parameter set|參數|ParameterBinding|不能同時|互斥|cannot be resolved|Missing an argument|遺失|必要|Mandatory|ParameterArgumentValidation|cannot be found'
    # 「不安全的封存路徑」必須是獨立語意，不可只用「格式損壞」搪塞
    'stage.unsafe'  = '不安全|逸出|逃逸|穿越|越界|非法路徑|不合法的路徑|路徑不安全|traversal|unsafe|zip.?slip'
    # 靜態公鑰曲線不符：必須明講 P-256，不能只丟 .NET 原始訊息
    'stage.curve'   = 'P-?256|prime256|nistP256|曲線'

    # --- 出路指引：錯誤訊息要告訴使用者下一步能做什麼 ---
    'hint.force'         = '-Force'
    'hint.passphrase'    = '-Passphrase'
    'hint.publickeyopt'  = '-PublicKey'
    'hint.generatekeys'  = 'GenerateKeys'
    'hint.pubfile'       = 'public\.pem'
    'hint.keyfile'       = 'private\.key'

    # --- 具體措辭 ---
    'notfound'            = '找不到|不存在|not found'
    'noninteractive'      = '非互動'
    'passphrase'          = '密碼'
    'emptyfile'           = '空'
    'legacymagic'         = 'CTXT'
    'dpapi'               = 'DPAPI'
    'fingerprint'         = 'RUNE-KEY'
    'pubkey.badpem'       = '公鑰 PEM 格式無效，無法載入'
    'pubkey.explicitpath' = '-PublicKey 指定的路徑'
    # 反面用：-PublicKey 指到使用者自己給的路徑時，不該再叫他「複製到本機 <該路徑>」
    'pubkey.copyhint'     = '複製到本機'
    'plainkey.format'     = '未加密的 PKCS#8 PEM'
    'plainkey.warning'    = '任何能讀取此檔案的人'
    'contenttype'         = '型別|content.?type'
    'newerversion'        = '較新版本|新版|請更新|update|newer'
    'tampered'            = '竄改|tamper|認證標籤'
    # 反面用：contentType 被竄改時不得被說成「型別不支援 / 版本較新」
    'typeorversion'       = '型別|content.?type|較新版本|不支援'
    'wildcard.skipdir'    = 'WARNING|警告|略過|跳過|不遞迴|skip'
    # 私鑰／公鑰不得整份印到畫面上
    'pem.privateblock'    = '-----BEGIN[A-Z ]*PRIVATE KEY-----'
    'pem.publicblock'     = '-----BEGIN PUBLIC KEY-----'
}

# 指紋格式：RUNE-KEY + 8 組 ×4 個大寫 hex，以 '-' 連接（含前綴共 39 字元）
$script:FpRegex = 'RUNE-KEY\s+([0-9A-F]{4}(?:-[0-9A-F]{4}){7})'

function Get-MsgPattern {
    param([string]$Key)
    if (-not $script:Msg.Contains($Key)) { throw "期望訊息表沒有這個鍵：$Key" }
    return $script:Msg[$Key]
}

function Test-Msg {
    param([string]$Text, [string]$Key)
    return [bool]($Text -match (Get-MsgPattern $Key))
}

function Assert-Msg {
    param([string]$Text, [string[]]$Keys = @(), [string[]]$Forbid = @(), [string]$What)
    foreach ($k in $Keys) {
        Assert (Test-Msg $Text $k) ("{0}：訊息缺少期望措辭 [{1}] => {2}" -f $What, $k, (Squash $Text 200))
    }
    foreach ($k in $Forbid) {
        Assert (-not (Test-Msg $Text $k)) ("{0}：訊息出現不該有的措辭 [{1}] => {2}" -f $What, $k, (Squash $Text 200))
    }
}

function Get-Fingerprint {
    param([string]$Text)
    $m = [regex]::Match($Text, $script:FpRegex)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

# ==============================================================================
# 3. 結果斷言
#
# 「被拒絕」這件事有一組必須同時成立的條件，逐案手寫會漏。這裡一次上齊：
#
#   1. 不得逾時         —— 卡在互動提示等同於永遠不會被發現的失敗。
#   2. 必須真的失敗     —— exit code 非 0 或 stderr 非空。
#   3. 不得留下產物     —— 半成品密文／半成品解包比什麼都沒有更糟。
#   4. 指定的檔案不得被改動。
#   5. 訊息一律只比對 StdErr —— 受測物的成功輸出含有與錯誤分類重疊的字樣
#      （seal 每次都印「收件人公鑰指紋：RUNE-KEY …」，裡面就有「公鑰」「RUNE」
#      「key」），拿 stdout+stderr 合併比對，format / key / nopub 這幾類會無條件
#      命中。真正的錯誤訊息一律經頂層 catch 寫到 stderr，只比對 StdErr 才是在
#      比對「錯誤訊息本身」。
#
# 這幾條寫在函式內部、依參數自動生效，不做成呼叫端要記得加的開關。
# ==============================================================================

function Expect-Refused {
    param(
        $Res,
        [string[]]$Category = @(),
        [string]$What,
        [string[]]$NoFile = @(),      # 這些路徑不得存在
        [string[]]$EmptyDir = @(),    # 這些資料夾不得有任何檔案或子目錄
        [hashtable]$Unchanged = @{},  # 路徑 -> 應維持不變的 SHA-256
        [string[]]$Expect = @(),
        [string[]]$Forbid = @()
    )
    Assert (-not $Res.TimedOut) "$What：子行程逾時（可能卡在互動提示）"
    Assert ($Res.Failed) ("$What：應該失敗卻成功了（exit={0}，stderr 空）" -f $Res.ExitCode)

    foreach ($p in $NoFile) {
        if (-not $p) { continue }
        Assert (-not [System.IO.File]::Exists($p)) "$What：已拒絕卻仍產生了檔案 $p"
    }
    foreach ($d in $EmptyDir) {
        if (-not $d) { continue }
        $left = Get-TreeMap $d
        Assert ($left.Count -eq 0) ("$What：已拒絕卻仍寫出 {0} 個檔案：{1}" -f $left.Count, (($left.Keys | Select-Object -First 5) -join ','))
        if ([System.IO.Directory]::Exists($d)) {
            $dirs = @([System.IO.Directory]::EnumerateDirectories($d, '*', [System.IO.SearchOption]::AllDirectories))
            Assert ($dirs.Count -eq 0) ("$What：已拒絕卻殘留目錄（含暫存資料夾）：" + (($dirs | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
        }
    }
    foreach ($p in $Unchanged.Keys) {
        Assert ([System.IO.File]::Exists($p)) "$What：應該原封不動的檔案不見了 $p"
        Assert ((Get-Sha $p) -eq $Unchanged[$p]) "$What：應該原封不動的檔案被改了 $p"
    }

    $msg = $Res.StdErr
    if ($Category.Count -gt 0) {
        $hit = @($Category | Where-Object { Test-Msg $msg ("stage." + $_) })
        Assert ($hit.Count -gt 0) ("{0}：有失敗但訊息未指明環節[{1}] => {2}" -f $What, ($Category -join '|'), (Squash $msg 200))
    }
    Assert-Msg -Text $msg -Keys $Expect -Forbid $Forbid -What $What
    return ("exit={0}; msg={1}" -f $Res.ExitCode, (Squash $msg 90))
}

# 加密端被拒：預設要求「不得產生輸出檔」。
function Expect-SealRefused {
    param($Res, [string]$OutFile, [string[]]$Category = @(), [string]$What,
        [hashtable]$Unchanged = @{}, [string[]]$Expect = @(), [string[]]$Forbid = @())
    return Expect-Refused -Res $Res -Category $Category -What $What `
        -NoFile @($OutFile | Where-Object { $_ }) -Unchanged $Unchanged -Expect $Expect -Forbid $Forbid
}

# 解密端被拒：預設要求「Destination 完全乾淨」。
function Expect-OpenRefused {
    param($Res, [string]$Destination, [string[]]$NoFile = @(), [string[]]$Category = @(), [string]$What,
        [hashtable]$Unchanged = @{}, [string[]]$Expect = @(), [string[]]$Forbid = @())
    return Expect-Refused -Res $Res -Category $Category -What $What `
        -EmptyDir @($Destination | Where-Object { $_ }) -NoFile $NoFile -Unchanged $Unchanged `
        -Expect $Expect -Forbid $Forbid
}

function Expect-Success {
    param($Res, [string]$What)
    Assert (-not $Res.TimedOut) "$What：子行程逾時"
    Assert (-not $Res.Failed) ("$What：失敗 exit={0} => {1}" -f $Res.ExitCode, (Squash $Res.All 220))
    return $Res
}

# ==============================================================================
# 4. 檔案 / 目錄 / 雜湊工具（全部走 .NET，避開 PowerShell 萬用字元路徑陷阱）
# ==============================================================================

function New-Dir {
    param([string]$Path)
    [void][System.IO.Directory]::CreateDirectory($Path)
    return $Path
}

function New-TextFile {
    param([string]$Path, [string]$Text)
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
    return $Path
}

function New-BinFile {
    param([string]$Path, [int]$Size, [int]$Seed = 0)
    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    $b = [byte[]]::new($Size)
    if ($Size -gt 0) {
        $rnd = [System.Random]::new($Seed)
        $rnd.NextBytes($b)
    }
    [System.IO.File]::WriteAllBytes($Path, $b)
    return $Path
}

function Get-Sha {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# 目錄 -> @{ 相對路徑(以 / 分隔) = SHA256 }
function Get-TreeMap {
    param([string]$Root)
    $map = @{}
    $full = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not [System.IO.Directory]::Exists($full)) { return $map }
    foreach ($f in [System.IO.Directory]::EnumerateFiles($full, '*', [System.IO.SearchOption]::AllDirectories)) {
        $rel = $f.Substring($full.Length + 1).Replace('\', '/')
        $map[$rel] = (Get-Sha $f)
    }
    return $map
}

function Clear-Dir {
    param([string]$Path)
    [void](New-Dir $Path)
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    return $Path
}

function Compare-MapExact {
    param([hashtable]$Expected, [hashtable]$Actual)
    $missing = @($Expected.Keys | Where-Object { -not $Actual.ContainsKey($_) })
    $extra = @($Actual.Keys | Where-Object { -not $Expected.ContainsKey($_) })
    $bad = @($Expected.Keys | Where-Object { $Actual.ContainsKey($_) -and $Actual[$_] -ne $Expected[$_] })
    if ($missing.Count -eq 0 -and $extra.Count -eq 0 -and $bad.Count -eq 0) { return $null }
    $parts = @()
    if ($missing.Count) { $parts += '缺少:' + (($missing | Select-Object -First 4) -join ',') }
    if ($extra.Count) { $parts += '多出:' + (($extra | Select-Object -First 4) -join ',') }
    if ($bad.Count) { $parts += 'SHA不符:' + (($bad | Select-Object -First 4) -join ',') }
    return ($parts -join '; ')
}

# 允許實作把根資料夾名一併包進 zip（規格只要求「保留結構」，兩種慣例都接受）
function Compare-Tree {
    param([hashtable]$Expected, [hashtable]$Actual, [string]$AllowRootPrefix)
    $d = Compare-MapExact $Expected $Actual
    if ($null -eq $d) { return @{ Diff = $null; Convention = '無根目錄前綴' } }
    if ($AllowRootPrefix) {
        $keys = @($Actual.Keys)
        if ($keys.Count -gt 0 -and -not ($keys | Where-Object { $_ -notlike "$AllowRootPrefix/*" })) {
            $m = @{}
            foreach ($k in $keys) { $m[$k.Substring($AllowRootPrefix.Length + 1)] = $Actual[$k] }
            $d2 = Compare-MapExact $Expected $m
            if ($null -eq $d2) { return @{ Diff = $null; Convention = "含根目錄前綴 $AllowRootPrefix/" } }
        }
    }
    return @{ Diff = $d; Convention = '' }
}

# ==============================================================================
# 5. 容器解析 / 重建（規格 v2）
# ==============================================================================

function Read-Container {
    param([string]$TxtPath)
    Assert ([System.IO.File]::Exists($TxtPath)) "容器檔不存在：$TxtPath"
    $raw = [System.IO.File]::ReadAllText($TxtPath)
    $lines = @(($raw -split "`r?`n") | Where-Object { $_.Length -gt 0 })
    $b64 = ($lines -join '')
    $bytes = [Convert]::FromBase64String($b64)

    Assert ($bytes.Length -ge 8 + 12 + 16) "容器長度過短：$($bytes.Length)B"
    $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    $version = $bytes[4]
    $contentType = $bytes[5]
    $epkLen = [int]$bytes[6] -bor ([int]$bytes[7] -shl 8)
    $o = 8
    $epk = if ($epkLen -gt 0 -and ($o + $epkLen) -le $bytes.Length) { $bytes[$o..($o + $epkLen - 1)] } else { @() }
    $o += $epkLen
    $nonce = if (($o + 12) -le $bytes.Length) { $bytes[$o..($o + 11)] } else { @() }
    $o += 12
    $tag = if (($o + 16) -le $bytes.Length) { $bytes[$o..($o + 15)] } else { @() }
    $o += 16
    $ct = if ($o -lt $bytes.Length) { $bytes[$o..($bytes.Length - 1)] } else { [byte[]]@() }

    return [pscustomobject]@{
        Path        = $TxtPath
        Raw         = $raw
        Lines       = $lines
        Bytes       = $bytes
        Magic       = $magic
        Version     = $version
        ContentType = $contentType
        EpkLen      = $epkLen
        Epk         = [byte[]]$epk
        Nonce       = [byte[]]$nonce
        Tag         = [byte[]]$tag
        Cipher      = [byte[]]$ct
        HeaderSize  = 8 + $epkLen
    }
}

function Write-Container {
    param([byte[]]$Bytes, [string]$Path)
    $b64 = [Convert]::ToBase64String($Bytes)
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $b64.Length; $i += 76) {
        [void]$sb.AppendLine($b64.Substring($i, [Math]::Min(76, $b64.Length - $i)))
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $script:Utf8NoBom)
    return $Path
}

# 把既有容器複製一份、改掉指定位移的位元組，寫成新的容器檔
function New-TamperedContainer {
    param([string]$Source, [string]$Name, [hashtable]$SetByte)
    $c = Read-Container $Source
    $b = [byte[]]$c.Bytes.Clone()
    foreach ($k in $SetByte.Keys) { $b[[int]$k] = [byte]$SetByte[$k] }
    return (Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) $Name))
}

function New-AesGcm {
    param([byte[]]$Key)
    try { return [System.Security.Cryptography.AesGcm]::new($Key, 16) }
    catch { return [System.Security.Cryptography.AesGcm]::new($Key) }
}

# ==============================================================================
# 6. ZIP 中央目錄白盒解析（不靠 ZipArchive，直接看旗標與壓縮方法）
# ==============================================================================

function Get-ZipCentralDirectory {
    param([byte[]]$Zip)
    $eocd = -1
    for ($i = $Zip.Length - 22; $i -ge 0; $i--) {
        if ($Zip[$i] -eq 0x50 -and $Zip[$i + 1] -eq 0x4B -and $Zip[$i + 2] -eq 0x05 -and $Zip[$i + 3] -eq 0x06) { $eocd = $i; break }
    }
    Assert ($eocd -ge 0) '找不到 ZIP End Of Central Directory 簽章（不是有效 zip）'
    $count = [BitConverter]::ToUInt16($Zip, $eocd + 10)
    $cdOff = [int][BitConverter]::ToUInt32($Zip, $eocd + 16)
    $entries = @()
    $p = $cdOff
    for ($n = 0; $n -lt $count; $n++) {
        Assert ($Zip[$p] -eq 0x50 -and $Zip[$p + 1] -eq 0x4B -and $Zip[$p + 2] -eq 0x01 -and $Zip[$p + 3] -eq 0x02) "中央目錄第 $n 筆簽章錯誤"
        $flags = [BitConverter]::ToUInt16($Zip, $p + 8)
        $method = [BitConverter]::ToUInt16($Zip, $p + 10)
        $csize = [int][BitConverter]::ToUInt32($Zip, $p + 20)
        $usize = [int][BitConverter]::ToUInt32($Zip, $p + 24)
        $nLen = [BitConverter]::ToUInt16($Zip, $p + 28)
        $eLen = [BitConverter]::ToUInt16($Zip, $p + 30)
        $cLen = [BitConverter]::ToUInt16($Zip, $p + 32)
        $nameBytes = if ($nLen -gt 0) { $Zip[($p + 46)..($p + 46 + $nLen - 1)] } else { @() }
        $strict = [System.Text.UTF8Encoding]::new($false, $true)
        $isUtf8 = $true
        $name = ''
        try { $name = $strict.GetString([byte[]]$nameBytes) } catch { $isUtf8 = $false; $name = [System.Text.Encoding]::ASCII.GetString([byte[]]$nameBytes) }
        $entries += [pscustomobject]@{
            Name        = $name
            NameBytes   = [byte[]]$nameBytes
            NameIsUtf8  = $isUtf8
            NameIsAscii = -not ($nameBytes | Where-Object { $_ -gt 127 })
            Utf8Flag    = (($flags -band 0x800) -ne 0)
            Method      = $method
            CompSize    = $csize
            Size        = $usize
        }
        $p += 46 + $nLen + $eLen + $cLen
    }
    return $entries
}

# 建一個只含指定 entry 名稱的 ZIP（用來構造惡意封存）
function New-ZipWithEntry {
    param([string]$EntryName, [string]$Content = 'PWNED-BY-REVIEWER')
    $ms = [System.IO.MemoryStream]::new()
    $za = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, $script:Utf8NoBom)
    $e = $za.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
    $w = [System.IO.StreamWriter]::new($e.Open())
    $w.Write($Content); $w.Dispose(); $za.Dispose()
    return $ms.ToArray()
}

# 建一個只含「目錄 entry」（名稱帶尾隨分隔符、零長度）的 ZIP
function New-ZipWithDirEntry {
    param([string]$EntryName)
    $ms = [System.IO.MemoryStream]::new()
    $za = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, $script:Utf8NoBom)
    [void]$za.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
    $za.Dispose()
    return $ms.ToArray()
}

# 依序建立多筆 entry 的 ZIP（用來構造「前幾筆合法、最後一筆不安全」的封存）
function New-ZipWithEntries {
    param([string[]]$EntryNames)
    $ms = [System.IO.MemoryStream]::new()
    $za = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, $script:Utf8NoBom)
    foreach ($n in $EntryNames) {
        $e = $za.CreateEntry($n, [System.IO.Compression.CompressionLevel]::NoCompression)
        $w = [System.IO.StreamWriter]::new($e.Open()); $w.Write("payload-$n"); $w.Dispose()
    }
    $za.Dispose()
    return $ms.ToArray()
}

# ==============================================================================
# 7. 獨立解密鏈：私鑰 -> ECDH -> HKDF-SHA256 -> AES-GCM -> Brotli -> Zip
#    規格未定義 HKDF 的 salt/info，因此以窮舉候選還原；全數失敗僅記 INFO。
# ==============================================================================

function Import-PrivateKeyFromBlob {
    # 私鑰檔有三種儲存格式（未加密 PKCS#8 PEM／密碼保護 PKCS#8 PEM／DPAPI 位元組），
    # 共用同一個路徑、靠內容判別。此處只還原不需要密碼的兩種；密碼保護的一律回傳
    # $null，由呼叫端當成「無法獨立重建」處理。
    param([string]$BlobPath)
    $blob = [System.IO.File]::ReadAllBytes($BlobPath)
    $asText = [System.Text.Encoding]::UTF8.GetString($blob)
    if ($asText -match '-----BEGIN ENCRYPTED PRIVATE KEY-----') { return $null }
    if ($asText -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') {
        $pemKey = [System.Security.Cryptography.ECDiffieHellman]::Create()
        try { $pemKey.ImportFromPem($asText); return $pemKey } catch { return $null }
    }
    $payload = $null
    foreach ($scope in @('CurrentUser', 'LocalMachine')) {
        try {
            $payload = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [System.Security.Cryptography.DataProtectionScope]::$scope)
            break
        } catch { }
    }
    if ($null -eq $payload) { return $null }

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ok = $false
    foreach ($how in @('pkcs8', 'ec', 'pem')) {
        try {
            switch ($how) {
                'pkcs8' { $ecdh.ImportPkcs8PrivateKey($payload, [ref]([int]0)) }
                'ec' { $ecdh.ImportECPrivateKey($payload, [ref]([int]0)) }
                'pem' { $ecdh.ImportFromPem([System.Text.Encoding]::UTF8.GetString($payload)) }
            }
            $ok = $true; break
        } catch { }
    }
    if (-not $ok) { return $null }
    return $ecdh
}

function Get-KdfCandidates {
    param($Container, [byte[]]$RecipientSpki)
    $u = [System.Text.Encoding]::UTF8
    $salts = [ordered]@{
        'null'   = $null
        'empty'  = [byte[]]@()
        'nonce'  = $Container.Nonce
        'epk'    = $Container.Epk
        'magic'  = $u.GetBytes('RUNE')
        'header' = [byte[]]($Container.Bytes[0..($Container.HeaderSize - 1)])
    }
    $infos = [ordered]@{
        'null'    = $null
        'empty'   = [byte[]]@()
        'RUNE'    = $u.GetBytes('RUNE')
        'RUNEv2'  = $u.GetBytes('RUNEv2')
        'RUNE-v2' = $u.GetBytes('RUNE-v2')
        'lowerrune' = $u.GetBytes('rune')
        'aesgcm'  = $u.GetBytes('AES-256-GCM')
        'key'     = $u.GetBytes('key')
        'magicver' = [byte[]]($Container.Bytes[0..4])
        'epk'     = $Container.Epk
        'epk+rpk' = [byte[]](@($Container.Epk) + @($RecipientSpki))
        'magicver+epk' = [byte[]](@($Container.Bytes[0..4]) + @($Container.Epk))
        'magicver+ctype' = [byte[]]($Container.Bytes[0..5])
        'magicver+ctype+epk' = [byte[]](@($Container.Bytes[0..5]) + @($Container.Epk))
        'magic+epk' = [byte[]](@($Container.Bytes[0..3]) + @($Container.Epk))
        'transfer' = $u.GetBytes('transfer.ps1')
    }
    return @{ Salts = $salts; Infos = $infos }
}

# 回傳 @{ Key; Salt; Info; Aad; Mode } 或 $null
function Resolve-ContentKey {
    param($Container, $Ecdh, [byte[]]$RecipientSpki)

    $peer = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $peer.ImportSubjectPublicKeyInfo([byte[]]$Container.Epk, [ref]([int]0))
    $z = $Ecdh.DeriveRawSecretAgreement($peer.PublicKey)

    $aads = [ordered]@{
        'none'   = $null
        'header' = [byte[]]($Container.Bytes[0..($Container.HeaderSize - 1)])
        'magic'  = [byte[]]($Container.Bytes[0..4])
    }

    $cands = Get-KdfCandidates -Container $Container -RecipientSpki $RecipientSpki
    $trials = [System.Collections.Generic.List[object]]::new()
    foreach ($sk in $cands.Salts.Keys) {
        foreach ($ik in $cands.Infos.Keys) {
            $trials.Add([pscustomobject]@{
                    Mode = 'HKDF'; Label = "HKDF(salt=$sk,info=$ik)"
                    Key  = [System.Security.Cryptography.HKDF]::DeriveKey(
                        [System.Security.Cryptography.HashAlgorithmName]::SHA256, $z, 32, $cands.Salts[$sk], $cands.Infos[$ik])
                })
        }
    }
    # 非 HKDF 的常見替代做法（若命中即代表未依規格使用 HKDF）
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $trials.Add([pscustomobject]@{ Mode = 'SHA256(z)'; Label = 'SHA256(z) 直接雜湊'; Key = $sha.ComputeHash($z) })
    $trials.Add([pscustomobject]@{ Mode = 'raw-z'; Label = '直接使用共享秘密'; Key = $z })

    foreach ($t in $trials) {
        foreach ($ak in $aads.Keys) {
            try {
                $gcm = New-AesGcm -Key ([byte[]]$t.Key)
                $plain = [byte[]]::new($Container.Cipher.Length)
                if ($null -eq $aads[$ak]) { $gcm.Decrypt($Container.Nonce, $Container.Cipher, $Container.Tag, $plain) }
                else { $gcm.Decrypt($Container.Nonce, $Container.Cipher, $Container.Tag, $plain, [byte[]]$aads[$ak]) }
                $gcm.Dispose()
                return @{ Key = [byte[]]$t.Key; Label = $t.Label; Mode = $t.Mode; Aad = $ak; Plain = $plain }
            } catch { }
        }
    }
    return $null
}

function Expand-Brotli {
    param([byte[]]$Data)
    $in = [System.IO.MemoryStream]::new($Data)
    $bs = [System.IO.Compression.BrotliStream]::new($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = [System.IO.MemoryStream]::new()
    $bs.CopyTo($out)
    $bs.Dispose(); $in.Dispose()
    return $out.ToArray()
}

function Compress-Brotli {
    param([byte[]]$Data)
    $out = [System.IO.MemoryStream]::new()
    $bs = [System.IO.Compression.BrotliStream]::new($out, [System.IO.Compression.CompressionLevel]::SmallestSize)
    $bs.Write($Data, 0, $Data.Length)
    $bs.Dispose()
    return $out.ToArray()
}

# 以受測物的收件人公鑰 + C08 還原出的 KDF 參數，偽造一個「密碼學上完全合法」的容器
function New-ForgedRune {
    param([byte[]]$ZipBytes, [string]$Path, [byte]$ContentType = 1)
    $kdf = Get-Fixture 'KdfInfo'
    Assert ($null -ne $kdf) '需先還原 KDF 參數（見 C08）'
    $spki = (Get-Fixture 'KeyA').PubSpki
    $plain = Compress-Brotli -Data $ZipBytes

    $eph = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $rec = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $rec.ImportSubjectPublicKeyInfo($spki, [ref]([int]0))
    $z = $eph.DeriveRawSecretAgreement($rec.PublicKey)
    $epk = $eph.ExportSubjectPublicKeyInfo()
    $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

    $hdr = [System.Collections.Generic.List[byte]]::new()
    $hdr.AddRange([System.Text.Encoding]::ASCII.GetBytes('RUNE'))
    $hdr.Add(2)
    $hdr.Add($ContentType)     # contentType（0x01 = 檔案樹）
    $hdr.Add([byte]($epk.Length -band 0xFF)); $hdr.Add([byte](($epk.Length -shr 8) -band 0xFF))
    $hdr.AddRange($epk)

    $m = [regex]::Match($kdf.Label, 'salt=([^,]+),info=([^)]+)')
    Assert ($m.Success) '無法沿用還原出的 KDF 參數'
    $fake = [pscustomobject]@{ Nonce = $nonce; Epk = $epk; Bytes = $hdr.ToArray(); HeaderSize = $hdr.Count }
    $cand = Get-KdfCandidates -Container $fake -RecipientSpki $spki
    $key = [System.Security.Cryptography.HKDF]::DeriveKey(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, $z, 32,
        $cand.Salts[$m.Groups[1].Value], $cand.Infos[$m.Groups[2].Value])

    $ct = [byte[]]::new($plain.Length); $tag = [byte[]]::new(16)
    $gcm = New-AesGcm -Key $key
    switch ($kdf.Aad) {
        'none' { $gcm.Encrypt($nonce, $plain, $ct, $tag) }
        'header' { $gcm.Encrypt($nonce, $plain, $ct, $tag, $hdr.ToArray()) }
        default { $gcm.Encrypt($nonce, $plain, $ct, $tag, [byte[]]($hdr.ToArray()[0..4])) }
    }
    $gcm.Dispose()

    $all = [System.Collections.Generic.List[byte]]::new()
    $all.AddRange($hdr); $all.AddRange($nonce); $all.AddRange($tag); $all.AddRange($ct)
    return (Write-Container -Bytes $all.ToArray() -Path $Path)
}

# ==============================================================================
# 8. 受測腳本靜態檢查工具
# ==============================================================================

function Find-PublicKeyAssignment {
    param([string]$Text)
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$t, [ref]$e)
    # 同時支援 $PublicKeyPem = '' 與 [string]$PublicKeyPem = ''（後者 Left 是 ConvertExpressionAst）
    $hits = $ast.FindAll({
            param($n)
            if ($n -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { return $false }
            $left = $n.Left
            if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
            ($left -is [System.Management.Automation.Language.VariableExpressionAst]) -and
            ($left.VariablePath.UserPath -match '(^|:)PublicKeyPem$')
        }, $true)
    return @{ Ast = $ast; Errors = $e; Hit = ($hits | Select-Object -First 1) }
}

function ConvertTo-Pem {
    param([byte[]]$Der, [string]$Label)
    $b64 = [Convert]::ToBase64String($Der)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("-----BEGIN $Label-----`n")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        [void]$sb.Append($b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) + "`n")
    }
    [void]$sb.Append("-----END $Label-----")
    return $sb.ToString()
}

function Get-PemBlock {
    param([string]$Text, [string]$Label = 'PUBLIC KEY')
    $m = [regex]::Match($Text, "-----BEGIN $Label-----[\s\S]*?-----END $Label-----")
    if ($m.Success) { return $m.Value }
    return $null
}

# 探針輸出的 KEY=VALUE 行 -> hashtable
function ConvertFrom-ProbeOutput {
    param([string]$Text)
    $kv = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^([A-Z0-9_]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
    }
    return $kv
}

# ==============================================================================
# 9. 家目錄沙箱
# ==============================================================================

function New-HomeSandbox {
    param([string]$Name)
    # 沙箱一律從空的開始：一個「已經有 private.key」的沙箱會讓 -GenerateKeys 走到
    # 「私鑰已存在」分支，既可能製造假紅也可能讓某些案例假綠。沙箱是否乾淨是每個
    # 金鑰案例的前提，不能靠呼叫端記得先清。
    $dir = Join-Path $script:Work "home_$Name"
    if ([System.IO.Directory]::Exists($dir)) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
    [void](New-Dir $dir)
    return @{
        Path = $dir
        Env  = @{
            USERPROFILE = $dir
            HOME        = $dir
            HOMEDRIVE   = $dir.Substring(0, 2)
            HOMEPATH    = $dir.Substring(2)
            APPDATA     = (New-Dir (Join-Path $dir 'AppData\Roaming'))
            LOCALAPPDATA = (New-Dir (Join-Path $dir 'AppData\Local'))
        }
        KeyPath = (Join-Path $dir '.rune\private.key')
        PubPath = (Join-Path $dir '.rune\public.pem')
    }
}

# 使用者真實家目錄的保護：偵測沙箱逃逸。每一次呼叫受測物之後都會自動執行，
# 不靠個別案例記得檢查。
$script:RealRuneDir = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.rune'
$script:RealKeyPath = Join-Path $script:RealRuneDir 'private.key'
$script:RealKeyExisted = [System.IO.File]::Exists($script:RealKeyPath)
$script:RealKeyHash = if ($script:RealKeyExisted) { Get-Sha $script:RealKeyPath } else { $null }
$script:EscapeNotes = @()

function Assert-NoHomeEscape {
    param([string]$When)
    if ($script:RealKeyExisted) {
        $h = if ([System.IO.File]::Exists($script:RealKeyPath)) { Get-Sha $script:RealKeyPath } else { '<deleted>' }
        if ($h -ne $script:RealKeyHash) {
            throw "嚴重：受測腳本改動了使用者真實私鑰 $script:RealKeyPath（$When），驗證中止"
        }
    }
    elseif ([System.IO.File]::Exists($script:RealKeyPath)) {
        # 我們造成的：搬回沙箱並還原原狀
        $stash = Join-Path $script:Work ('escaped_private_{0}.key' -f ([guid]::NewGuid().ToString('N').Substring(0, 6)))
        [System.IO.File]::Copy($script:RealKeyPath, $stash, $true)
        [System.IO.File]::Delete($script:RealKeyPath)
        $script:EscapeNotes += "$When 時 -GenerateKeys 寫到真實家目錄（未受 USERPROFILE 影響），已刪除並還原；副本 $stash"
        Write-Log $script:EscapeNotes[-1]
        return $stash
    }
    return $null
}

# ==============================================================================
# 10. 呼叫點：受測腳本只在這裡出現
#
# 所有案例一律經由 Invoke-Seal / Invoke-Open 呼叫受測物，不自己拼參數陣列、不自己
# 記得帶沙箱環境變數。預設環境是主測試金鑰 A 的沙箱、預設工作目錄是本套件的工作根。
#
# 密碼相關的路徑不在這裡：SecureString 無法從命令列傳給入口腳本，那些案例一律走
# Invoke-RuneProbe 以模組身分呼叫。
# ==============================================================================

function Resolve-SutEnv {
    param([hashtable]$Env, [bool]$Explicit)
    if ($Explicit) { return $Env }
    return (Get-Fixture 'KeyA').Sandbox.Env
}

function Invoke-Sut {
    param([string]$ScriptPath, [string[]]$Arguments, [hashtable]$Env, [string]$Cwd, [int]$Timeout, [string]$What)
    $res = Invoke-Transfer -ScriptPath $ScriptPath -Arguments $Arguments -EnvVars $Env -WorkDir $Cwd -Timeout $Timeout
    # 每一次呼叫受測物之後都檢查真實家目錄，不靠個別案例記得。
    $res.Escaped = Assert-NoHomeEscape -When $What
    return $res
}

function Invoke-Seal {
    <#
        對 rune-seal.ps1 執行一次。-Unpack / -Destination 是給「加密端必須拒絕解密端
        參數」那一案用的（C29），一般案例不會用到。
    #>
    param(
        [string]$Pack,
        [string]$OutFile,
        [string]$PublicKey,
        [switch]$Force,
        [string]$Unpack,
        [string]$Destination,
        [hashtable]$Env,
        [string]$Cwd,
        [int]$Timeout = 0
    )
    $a = @()
    if ($PSBoundParameters.ContainsKey('Pack')) { $a += @('-Pack', $Pack) }
    if ($PSBoundParameters.ContainsKey('Unpack')) { $a += @('-Unpack', $Unpack) }
    if ($PSBoundParameters.ContainsKey('Destination')) { $a += @('-Destination', $Destination) }
    if ($PSBoundParameters.ContainsKey('OutFile')) { $a += @('-OutFile', $OutFile) }
    if ($PSBoundParameters.ContainsKey('PublicKey')) { $a += @('-PublicKey', $PublicKey) }
    if ($Force) { $a += '-Force' }
    $e = Resolve-SutEnv -Env $Env -Explicit $PSBoundParameters.ContainsKey('Env')
    return Invoke-Sut -ScriptPath $script:SutSeal -Arguments $a -Env $e -Cwd $Cwd -Timeout $Timeout -What ('seal ' + ($a -join ' '))
}

function Invoke-Open {
    <#
        對 rune-open.ps1 執行一次。-Pack 是給「解密端必須拒絕加密端參數」那一案用的
        （C29），一般案例不會用到。
    #>
    param(
        [string]$Unpack,
        [string]$Destination,
        [string]$KeyFile,
        [switch]$GenerateKeys,
        [switch]$ExportPublicKey,
        [switch]$ExportPrivateKey,
        [string]$OutFile,
        [string]$Protect,
        [switch]$Force,
        [string]$Pack,
        [hashtable]$Env,
        [string]$Cwd,
        [int]$Timeout = 0
    )
    $a = @()
    if ($GenerateKeys) { $a += '-GenerateKeys' }
    if ($ExportPublicKey) { $a += '-ExportPublicKey' }
    if ($ExportPrivateKey) { $a += '-ExportPrivateKey' }
    if ($PSBoundParameters.ContainsKey('Unpack')) { $a += @('-Unpack', $Unpack) }
    if ($PSBoundParameters.ContainsKey('Destination')) { $a += @('-Destination', $Destination) }
    if ($PSBoundParameters.ContainsKey('Pack')) { $a += @('-Pack', $Pack) }
    if ($PSBoundParameters.ContainsKey('OutFile')) { $a += @('-OutFile', $OutFile) }
    if ($PSBoundParameters.ContainsKey('KeyFile')) { $a += @('-KeyFile', $KeyFile) }
    if ($PSBoundParameters.ContainsKey('Protect')) { $a += @('-Protect', $Protect) }
    if ($Force) { $a += '-Force' }
    $e = Resolve-SutEnv -Env $Env -Explicit $PSBoundParameters.ContainsKey('Env')
    return Invoke-Sut -ScriptPath $script:SutOpen -Arguments $a -Env $e -Cwd $Cwd -Timeout $Timeout -What ('open ' + ($a -join ' '))
}

# 以模組身分執行一段探針腳本。SecureString 無法從命令列傳給入口腳本，因此凡是需要
# 密碼的案例都走這條路徑：在子行程內建構 SecureString 並直接呼叫模組匯出的函式。
function Invoke-RuneProbe {
    param([string]$Name, [string]$Body, [hashtable]$EnvVars, [int]$Timeout = 180)
    $probe = Join-Path $script:Work "probe_$Name.ps1"
    [System.IO.File]::WriteAllText($probe, $Body, $script:Utf8Bom)
    $ev = @{ RUNE_MODULE = $script:ModuleRoot }
    if ($EnvVars) { foreach ($k in $EnvVars.Keys) { $ev[$k] = [string]$EnvVars[$k] } }
    $res = Invoke-Transfer -ScriptPath $probe -EnvVars $ev -Timeout $Timeout
    $res.Escaped = Assert-NoHomeEscape -When "probe($Name)"
    return $res
}

# 解包到 $Work\unpack\<DestName>（先清空），回傳子行程結果
function Invoke-UnpackOnly {
    param([string]$Txt, [string]$KeyFile, [string]$DestName, [int]$Timeout = 0)
    $dest = Clear-Dir (Join-Path $script:Work "unpack\$DestName")
    if ($KeyFile) { return Invoke-Open -Unpack $Txt -Destination $dest -KeyFile $KeyFile -Timeout $Timeout }
    return Invoke-Open -Unpack $Txt -Destination $dest -Timeout $Timeout
}

function Get-UnpackDest {
    param([string]$DestName)
    return (Join-Path $script:Work "unpack\$DestName")
}


# ==============================================================================
# 11. 惰性 fixture
#
# 共用素材（測試金鑰、密文容器、匯出的私鑰檔…）一律登記成 producer，第一次被需要
# 時才產生，之後重複取用同一份。案例以 -Needs 宣告相依，因此 -Filter / -Tier 篩出
# 的任意子集都能安全地單獨執行——案例之間沒有「誰先跑」的隱性耦合。
#
# producer 的職責只有「把素材做出來、順帶記錄產生過程的輸出」；斷言一律留在案例
# 裡，這樣「素材壞了」與「行為不符」在報表上分得開。
# ==============================================================================

$script:FixtureProducer = [ordered]@{}
$script:FixtureValue = @{}
$script:FixtureBuilding = @{}

function Register-Fixture {
    param([string]$Name, [scriptblock]$Producer)
    $script:FixtureProducer[$Name] = $Producer
}

function Get-Fixture {
    param([string]$Name)
    if ($script:FixtureValue.ContainsKey($Name)) { return $script:FixtureValue[$Name] }
    if (-not $script:FixtureProducer.Contains($Name)) { throw "未登記的 fixture：$Name" }
    if ($script:FixtureBuilding.ContainsKey($Name)) { throw "fixture 相依成環：$Name" }
    $script:FixtureBuilding[$Name] = $true
    try {
        Write-Log "FIXTURE build $Name"
        # producer 必須「恰好回傳一個物件」。回傳陣列（例如 byte[]）時要用
        # 一元逗號 return ,$bytes 包起來，否則 PowerShell 會把它攤平成多個輸出。
        $script:FixtureValue[$Name] = & $script:FixtureProducer[$Name]
    }
    finally { [void]$script:FixtureBuilding.Remove($Name) }
    return $script:FixtureValue[$Name]
}

# ---- 素材樹 ----
Register-Fixture 'Fx' {
    $f = Join-Path $script:Work 'fixtures'
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Recurse -Force }
    [void](New-Dir $f)

    # 單檔（二進位）
    [void](New-BinFile (Join-Path $f 'single\payload.bin') 262144 20260807)
    # wildcard 目錄：3 個 .txt（含中文檔名）+ 1 個非匹配 + 子目錄內的 .txt（不得被遞迴收入）
    [void](New-TextFile (Join-Path $f 'wild\alpha.txt') 'alpha')
    [void](New-TextFile (Join-Path $f 'wild\中文檔名測試.txt') "中文內容 `u{4F60}`u{597D}")
    [void](New-TextFile (Join-Path $f 'wild\第二個 檔案.txt') 'second file with space')
    [void](New-TextFile (Join-Path $f 'wild\skip-me.md') 'should not be packed')
    [void](New-TextFile (Join-Path $f 'wild\sub\nested.txt') 'must NOT be packed (no recursion)')
    # 資料夾：中文子目錄 + 深層 + 同名不同層 + 0 byte + 特殊字元
    [void](New-TextFile (Join-Path $f 'tree\readme.txt') 'root readme')
    [void](New-TextFile (Join-Path $f 'tree\中文目錄\說明.txt') '中文子目錄內容')
    [void](New-TextFile (Join-Path $f 'tree\中文目錄\更深\第三層\deep.txt') 'deep file')
    [void](New-TextFile (Join-Path $f 'tree\a\same.txt') 'A version')
    [void](New-TextFile (Join-Path $f 'tree\b\same.txt') 'B version')
    [void](New-BinFile (Join-Path $f 'tree\empty.bin') 0)
    [void](New-TextFile (Join-Path $f "tree\odd names\a b&c#d(e)[f]'g+h^i.txt") 'odd name content')
    [void](New-BinFile (Join-Path $f 'tree\bin\random.dat') 65536 99)
    # 高冗餘壓縮素材
    $rep = ([string]('CTXT-COMPRESSION-TEST-' * 40) + "`n")
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt 2000; $i++) { [void]$sb.Append($rep) }
    [void](New-TextFile (Join-Path $f 'redundant\big.txt') $sb.ToString())
    # 預設檔名推導素材
    [void](New-TextFile (Join-Path $f 'naming\report.docx') 'pretend docx')
    [void](New-TextFile (Join-Path $f 'naming\project\x.txt') 'proj file')
    [void](New-TextFile (Join-Path $f 'naming\wcdir\one.txt') 'one')
    [void](New-TextFile (Join-Path $f 'naming\wcdir\two.txt') 'two')
    [void](New-Dir (Join-Path $f 'emptywild'))
    $script:Fx = $f
    return $f
}

function Get-FxPath { param([string]$Relative) return (Join-Path (Get-Fixture 'Fx') $Relative) }

# fixtures\wild 的預期還原內容（CtWild 這份密文的明文側）
function Get-WildExpectedMap {
    $dir = Get-FxPath 'wild'
    $m = @{}
    foreach ($n in @('alpha.txt', '中文檔名測試.txt', '第二個 檔案.txt')) { $m[$n] = Get-Sha (Join-Path $dir $n) }
    return $m
}

# ---- 測試金鑰 ----

# -Protect 省略時走受測物的預設值（None）；指定時原樣轉發給 -GenerateKeys。
function New-TestKeyPair {
    param([string]$Name, [string]$Protect)
    $sb = New-HomeSandbox -Name $Name
    $res = if ($Protect) { Invoke-Open -GenerateKeys -Protect $Protect -Env $sb.Env -Cwd $sb.Path }
    else { Invoke-Open -GenerateKeys -Env $sb.Env -Cwd $sb.Path }
    $keyPath = $sb.KeyPath
    if (-not [System.IO.File]::Exists($keyPath)) {
        # 可能寫在沙箱其他位置，掃描沙箱
        $found = @([System.IO.Directory]::EnumerateFiles($sb.Path, 'private.key', [System.IO.SearchOption]::AllDirectories))
        if ($found.Count -gt 0) { $keyPath = $found[0] }
        elseif ($res.Escaped) { $keyPath = $res.Escaped }
    }
    # 公鑰 PEM 一律從落地的 ~\.rune\public.pem 讀取：-GenerateKeys 的成功輸出只印
    # 路徑與指紋，不印 PEM 全文。
    $pem = $null
    $spki = $null
    if ([System.IO.File]::Exists($sb.PubPath)) {
        $pem = Get-PemBlock -Text ([System.IO.File]::ReadAllText($sb.PubPath))
        if ($pem) {
            $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
            try { $ec.ImportFromPem($pem); $spki = $ec.ExportSubjectPublicKeyInfo() } catch { }
        }
    }
    return [pscustomobject]@{
        Name      = $Name
        Sandbox   = $sb
        Result    = $res
        KeyPath   = $keyPath
        HasKey    = [System.IO.File]::Exists($keyPath)
        PublicPem = $pem
        PubSpki   = $spki
        Escaped   = [bool]$res.Escaped
    }
}

# 主測試金鑰 A 與備用金鑰 B 固定以 -Protect Dpapi 產生。其後絕大多數案例都用金鑰 A
# 解密，因此整套案例同時就是「DPAPI 私鑰仍然可用」的回歸保護。
Register-Fixture 'KeyA' { return (New-TestKeyPair -Name 'A' -Protect 'Dpapi') }
Register-Fixture 'KeyB' { return (New-TestKeyPair -Name 'B' -Protect 'Dpapi') }

# 三種私鑰儲存格式各一把，供格式與權限案例使用
Register-Fixture 'KeyProtNone' { return (New-TestKeyPair -Name 'pnone') }
Register-Fixture 'KeyProtDpapi' { return (New-TestKeyPair -Name 'pdpapi' -Protect 'Dpapi') }

# 密碼保護案例共用的密碼。含空白、非 ASCII 與符號，順帶涵蓋 SecureString 經環境
# 變數傳入子行程後仍逐字相符（密碼錯一個字元就解不開，等於同時是編碼測試）。
$script:PassphraseText = 'rune 通行碼 #42 ok'

# 密碼保護的金鑰：產生、加密、解密在同一個探針行程內完成（SecureString 過不了命令列）
Register-Fixture 'KeyPass' {
    $sb = New-HomeSandbox -Name 'ppass'
    $src = Get-FxPath 'tree'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'ppass.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\ppass')

    $body = @'
Import-Module $env:RUNE_MODULE -Force
$pw = ConvertTo-SecureString $env:RUNE_PW -AsPlainText -Force
Invoke-RuneGenerateKeys -Protect Passphrase -Passphrase $pw
'HOMEOK=' + ($HOME -eq $env:USERPROFILE)
'KEYHEAD=' + (Get-Content -LiteralPath (Join-Path $env:USERPROFILE '.rune\private.key') -TotalCount 1)
Invoke-RuneSeal -PackPath $env:RUNE_SRC -OutFilePath $env:RUNE_OUT -PublicKeyRef (Join-Path $env:USERPROFILE '.rune\public.pem')
Invoke-RuneOpen -InFilePath $env:RUNE_OUT -DestinationPath $env:RUNE_DEST -Passphrase $pw
'DONE=1'
'@
    $r = Invoke-RuneProbe -Name 'ppass' -Body $body -EnvVars ($sb.Env + @{
            RUNE_PW = $script:PassphraseText; RUNE_SRC = $src; RUNE_OUT = $out; RUNE_DEST = $dest
        })
    return [pscustomobject]@{ Sandbox = $sb; Result = $r; Src = $src; Out = $out; Dest = $dest }
}

# ---- 密文容器 ----

function New-Container {
    param([string]$Name, [string]$Source)
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) "$Name.txt"
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $p = Invoke-Seal -Pack $Source -OutFile $out
    [void](Expect-Success $p "Pack($Name)")
    Assert ([System.IO.File]::Exists($out)) "Pack($Name) 未產生輸出檔 $out"
    return [pscustomobject]@{ Name = $Name; Source = $Source; Out = $out; Pack = $p }
}

Register-Fixture 'CtSingle' { return (New-Container -Name 'single' -Source (Get-FxPath 'single\payload.bin')) }
Register-Fixture 'CtWild' { return (New-Container -Name 'wild' -Source (Get-FxPath 'wild\*.txt')) }
Register-Fixture 'CtTree' { return (New-Container -Name 'tree' -Source (Get-FxPath 'tree')) }

# ---- 獨立解密鏈的還原結果 ----

# 規格未定義 HKDF 的 salt/info，因此以窮舉候選還原。還原不成一律回 $null，由案例
# 決定要記 INFO（C08 本案）還是 SKIP（依賴它偽造容器的案例）。
Register-Fixture 'PrivateKeyA' { return (Import-PrivateKeyFromBlob -BlobPath (Get-Fixture 'KeyA').KeyPath) }

Register-Fixture 'KdfInfo' {
    $ecdh = Get-Fixture 'PrivateKeyA'
    if ($null -eq $ecdh) { return $null }
    $c = Read-Container (Get-Fixture 'CtTree').Out
    return (Resolve-ContentKey -Container $c -Ecdh $ecdh -RecipientSpki (Get-Fixture 'KeyA').PubSpki)
}

Register-Fixture 'ZipTree' {
    $k = Get-Fixture 'KdfInfo'
    if ($null -eq $k) { return $null }
    $bytes = Expand-Brotli -Data $k.Plain
    return , $bytes
}

# 依賴偽造容器的案例統一用這個前置檢查，措辭一致
function Assert-KdfAvailable {
    if ($null -eq (Get-Fixture 'KdfInfo')) { Skip-Case '需先還原 KDF 參數（見 C08）才能構造密碼學上合法的容器' }
}

# ---- 金鑰輪替（-GenerateKeys -Force）----

Register-Fixture 'KeyRotate' {
    $kf = New-TestKeyPair -Name 'force'
    $runeDir = Join-Path $kf.Sandbox.Path '.rune'

    # 先用第一把金鑰加密一份密文，供「備份私鑰仍解得開舊密文」驗證
    $src = Get-FxPath 'single\payload.bin'
    $old = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'beforerotate.txt'
    if ([System.IO.File]::Exists($old)) { [System.IO.File]::Delete($old) }
    $packOld = $null
    if ($kf.HasKey -and $kf.PublicPem) {
        $packOld = Invoke-Seal -Pack $src -OutFile $old -PublicKey $kf.Sandbox.PubPath -Env $kf.Sandbox.Env
    }

    $oldKeyBytes = if ($kf.HasKey) { [System.IO.File]::ReadAllBytes($kf.KeyPath) } else { $null }
    $oldKeySha = if ($kf.HasKey) { Get-Sha $kf.KeyPath } else { $null }
    $oldPubText = if ([System.IO.File]::Exists($kf.Sandbox.PubPath)) { [System.IO.File]::ReadAllText($kf.Sandbox.PubPath) } else { $null }

    $r = Invoke-Open -GenerateKeys -Force -Env $kf.Sandbox.Env -Cwd $kf.Sandbox.Path

    return [pscustomobject]@{
        Key         = $kf
        RuneDir     = $runeDir
        PackOld     = $packOld
        CtOld       = $old
        SrcSha      = (Get-Sha $src)
        OldKeyBytes = $oldKeyBytes
        OldKeySha   = $oldKeySha
        OldPubText  = $oldPubText
        Result      = $r
    }
}

# ---- 私鑰匯出 ----

Register-Fixture 'ExportedPlainKey' {
    $outKey = Join-Path (New-Dir (Join-Path $script:Work 'keybackup')) 'from-dpapi.pem'
    if ([System.IO.File]::Exists($outKey)) { [System.IO.File]::Delete($outKey) }
    $r = Invoke-Open -ExportPrivateKey -OutFile $outKey -KeyFile (Get-Fixture 'KeyA').KeyPath -Force
    return [pscustomobject]@{ Path = $outKey; Result = $r }
}

Register-Fixture 'ExportedEncKey' {
    $outKey = Join-Path (New-Dir (Join-Path $script:Work 'keybackup')) 'from-dpapi-enc.pem'
    if ([System.IO.File]::Exists($outKey)) { [System.IO.File]::Delete($outKey) }
    $destBad = Clear-Dir (Join-Path $script:Work 'unpack\exported_enc_nopw')
    $destOk = Clear-Dir (Join-Path $script:Work 'unpack\exported_enc_ok')

    $body = @'
Import-Module $env:RUNE_MODULE -Force
$pw = ConvertTo-SecureString $env:RUNE_PW -AsPlainText -Force
Invoke-RuneExportPrivateKey -OutFilePath $env:RUNE_OUTKEY -KeyFilePath $env:RUNE_SRCKEY -Protect Passphrase -OutPassphrase $pw -Force
'HEAD=' + (Get-Content -LiteralPath $env:RUNE_OUTKEY -TotalCount 1)
try {
    Invoke-RuneOpen -InFilePath $env:RUNE_CT -DestinationPath $env:RUNE_DESTBAD -KeyFilePath $env:RUNE_OUTKEY
    'NOPW=NO-THROW'
}
catch {
    'NOPW=THROWN'
    'NOPWMSG=' + ($_.Exception.Message -replace '\s+', ' ')
}
Invoke-RuneOpen -InFilePath $env:RUNE_CT -DestinationPath $env:RUNE_DESTOK -KeyFilePath $env:RUNE_OUTKEY -Passphrase $pw
'DONE=1'
'@
    $r = Invoke-RuneProbe -Name 'exportenc' -Body $body -EnvVars ((Get-Fixture 'KeyA').Sandbox.Env + @{
            RUNE_PW = $script:PassphraseText; RUNE_OUTKEY = $outKey; RUNE_SRCKEY = (Get-Fixture 'KeyA').KeyPath
            RUNE_CT = (Get-Fixture 'CtWild').Out; RUNE_DESTBAD = $destBad; RUNE_DESTOK = $destOk
        })
    return [pscustomobject]@{ Path = $outKey; Result = $r; DestBad = $destBad; DestOk = $destOk }
}

# ==============================================================================
# 12. roundtrip 共用流程
# ==============================================================================

# 用金鑰 A 打包 + 解包
function Invoke-Roundtrip {
    param([string]$Name, [string]$Source)
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) "$Name.txt"
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $dest = Clear-Dir (Join-Path $script:Work "unpack\$Name")

    $p = Invoke-Seal -Pack $Source -OutFile $out
    [void](Expect-Success $p "Pack($Name)")
    Assert ([System.IO.File]::Exists($out)) "Pack($Name) 未產生輸出檔 $out"

    $u = Invoke-Open -Unpack $out -Destination $dest -KeyFile (Get-Fixture 'KeyA').KeyPath
    [void](Expect-Success $u "Unpack($Name)")
    return [pscustomobject]@{ Out = $out; Dest = $dest; Pack = $p; Unpack = $u }
}

# 指定金鑰對的 roundtrip：公鑰與私鑰都取自該金鑰對自己的沙箱，供「同一種私鑰儲存
# 格式從產生到解密走完整條路」的案例使用。
function Invoke-KeyRoundtrip {
    param($Key, [string]$Name, [string]$Source)
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) "$Name.txt"
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $dest = Clear-Dir (Join-Path $script:Work "unpack\$Name")

    $p = Invoke-Seal -Pack $Source -OutFile $out -PublicKey $Key.Sandbox.PubPath -Env $Key.Sandbox.Env
    [void](Expect-Success $p "Pack($Name)")
    $u = Invoke-Open -Unpack $out -Destination $dest -KeyFile $Key.KeyPath -Env $Key.Sandbox.Env
    [void](Expect-Success $u "Unpack($Name)")
    return [pscustomobject]@{ Out = $out; Dest = $dest; Pack = $p; Unpack = $u }
}

# 解包一份既有密文並與預期樹逐檔比對 SHA-256
function Assert-UnpackMatches {
    param([string]$Txt, [string]$KeyFile, [string]$DestName, [hashtable]$Expected, [string]$AllowRootPrefix, [string]$What)
    $dest = Clear-Dir (Join-Path $script:Work "unpack\$DestName")
    $u = Invoke-Open -Unpack $Txt -Destination $dest -KeyFile $KeyFile
    [void](Expect-Success $u $What)
    $c = Compare-Tree -Expected $Expected -Actual (Get-TreeMap $dest) -AllowRootPrefix $AllowRootPrefix
    Assert ($null -eq $c.Diff) ("$What：" + $c.Diff)
    return $c
}

# ==============================================================================
# 13. wrapper 落地
# ==============================================================================

Write-Host ''
Write-Host '========== runepost 獨立驗收（規格 v2 / container 0x02 / rune-seal + rune-open）==========' -ForegroundColor Cyan
Write-Host ('層級：{0}{1}' -f $script:RunTier, $(if ($Filter) { "；Filter=$Filter" } else { '' })) -ForegroundColor Cyan

if ($Clean -and (Test-Path -LiteralPath $script:Work)) {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}
[void](New-Dir $script:Work)
$script:WrapperPath = Join-Path $script:Work 'wrapper.ps1'
[System.IO.File]::WriteAllText($script:WrapperPath, $script:WrapperSource, $script:Utf8Bom)

# 受測腳本的初始雜湊：C40 拿它比對「自始至終未被改動」
$script:OrigHashSeal = if ([System.IO.File]::Exists($script:SutSeal)) { Get-Sha $script:SutSeal } else { $null }
$script:OrigHashOpen = if ([System.IO.File]::Exists($script:SutOpen)) { Get-Sha $script:SutOpen } else { $null }


# ==============================================================================
# 14. 案例
# ==============================================================================

Write-Host ''
Write-Host '-- 前置 --' -ForegroundColor Cyan

Invoke-TCase 'P0' '模組結構自洽：可載入、manifest 匯出清單與 Public\ 檔名一致' -Tier Core {
    <#
        psd1 的 FunctionsToExport 是明確清單而非 '*'（萬用字元會讓模組自動載入器為
        命令探索解析整個模組，有實測效能代價）。代價是新增／改名對外函式時必須手動
        同步這份清單，忘了同步的後果是「函式存在但呼叫不到」或「清單列了不存在的
        函式」。這一案守的就是這個漂移風險，排在最前面：沒過就不必往下測。

        順帶斷言「一檔一函式、檔名 = 函式名」——那是模組載入器
        （Export-ModuleMember -Function $Public.BaseName）正確運作的前提。
    #>
    Assert ([System.IO.Directory]::Exists($script:ModuleRoot)) "找不到模組資料夾：$script:ModuleRoot"
    $psd1 = Join-Path $script:ModuleRoot 'RunePost.psd1'
    Assert ([System.IO.File]::Exists($psd1)) "找不到 manifest：$psd1"

    $probe = Join-Path $script:Work 'modprobe.ps1'
    [System.IO.File]::WriteAllText($probe, @'
$ErrorActionPreference = 'Stop'
Import-Module $env:RUNE_MODULE -Force
$m = Get-Module RunePost
'EXPORTED=' + (($m.ExportedFunctions.Keys | Sort-Object) -join ',')
'CMDLETS=' + $m.ExportedCmdlets.Count
'ALIASES=' + $m.ExportedAliases.Count
'VARIABLES=' + $m.ExportedVariables.Count
'VERSION=' + $m.Version
$mf = Test-ModuleManifest $env:RUNE_MANIFEST
'MANIFEST=' + (($mf.ExportedFunctions.Keys | Sort-Object) -join ',')
'PSVERSION=' + $mf.PowerShellVersion
'@, $script:Utf8Bom)
    $r = Invoke-Transfer -ScriptPath $probe -EnvVars @{ RUNE_MODULE = $script:ModuleRoot; RUNE_MANIFEST = $psd1 }
    Assert (-not $r.TimedOut) '模組載入探針逾時'
    Assert ($r.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($r.StdErr)) `
    ('Import-Module 失敗：' + (Squash $r.All 300))

    $kv = @{}
    foreach ($line in ($r.StdOut -split "`r?`n")) {
        if ($line -match '^([A-Z]+)=(.*)$') { $kv[$Matches[1]] = $Matches[2] }
    }
    $onDisk = @(Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File |
            ForEach-Object { $_.BaseName } | Sort-Object) -join ','
    Assert ($kv['EXPORTED'] -eq $onDisk) `
    ('實際匯出的函式與 Public\ 檔名不一致：匯出 [{0}]，Public\ [{1}]' -f $kv['EXPORTED'], $onDisk)
    Assert ($kv['MANIFEST'] -eq $onDisk) `
    ('manifest 的 FunctionsToExport 與 Public\ 檔名不同步：manifest [{0}]，Public\ [{1}]' -f $kv['MANIFEST'], $onDisk)
    Assert ($kv['MANIFEST'] -notmatch '\*') "FunctionsToExport 不得使用萬用字元"
    foreach ($k in @('CMDLETS', 'ALIASES', 'VARIABLES')) {
        Assert ($kv[$k] -eq '0') ("模組不該匯出任何 $k，實際 $($kv[$k]) 個")
    }
    Assert ($kv['PSVERSION'] -eq '7.4') ('manifest PowerShellVersion 不是 7.4：' + $kv['PSVERSION'])

    $bad = @()
    foreach ($f in Get-ChildItem -LiteralPath $script:ModuleRoot -Recurse -Filter '*.ps1' -File) {
        $t = $null; $e = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
        if ($e.Count -gt 0) { $bad += "$($f.Name)：解析錯誤 $($e[0].Message)"; continue }
        $fn = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false))
        if ($fn.Count -ne 1) { $bad += "$($f.Name)：含 $($fn.Count) 個函式（應恰好 1 個）"; continue }
        if ($fn[0].Name -ne $f.BaseName) { $bad += "$($f.Name)：函式名 $($fn[0].Name) 與檔名不符" }
    }
    Assert ($bad.Count -eq 0) ('模組檔案結構違規：' + ($bad -join '; '))

    $pubCount = @(Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Public') -Filter '*.ps1' -File).Count
    $privCount = @(Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Private') -Filter '*.ps1' -File).Count
    return ('模組 v{0} 載入成功；匯出 {1} 個函式（{2}）且與 manifest／Public\ 三方一致；Public {3} 檔 / Private {4} 檔，全部一檔一函式且檔名相符' -f `
            $kv['VERSION'], @($onDisk -split ',').Count, $onDisk, $pubCount, $privCount)
}

Invoke-TCase 'P1a' '受測腳本存在且語法可解析（seal）' -Tier Core {
    Assert ([System.IO.File]::Exists($script:SutSeal)) "找不到受測腳本（seal）：$script:SutSeal"
    $text = [System.IO.File]::ReadAllText($script:SutSeal)
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
    Assert ($e.Count -eq 0) ('解析錯誤 {0} 個：{1}' -f $e.Count, (Squash ($e[0].Message) 120))
    return ('{0}；{1} 位元組；語法 OK' -f (Split-Path -Leaf $script:SutSeal), (Get-Item -LiteralPath $script:SutSeal).Length)
}

Invoke-TCase 'P1b' '受測腳本存在且語法可解析（open）' -Tier Core {
    Assert ([System.IO.File]::Exists($script:SutOpen)) "找不到受測腳本（open）：$script:SutOpen"
    $text = [System.IO.File]::ReadAllText($script:SutOpen)
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
    Assert ($e.Count -eq 0) ('解析錯誤 {0} 個：{1}' -f $e.Count, (Squash ($e[0].Message) 120))
    return ('{0}；{1} 位元組；語法 OK' -f (Split-Path -Leaf $script:SutOpen), (Get-Item -LiteralPath $script:SutOpen).Length)
}

Invoke-TCase 'P2' '不存在任何 $PublicKeyPem 賦值（公鑰已徹底外部化；入口腳本 + 模組全檔皆須檢查）' -Tier Core {
    # 掃描範圍必須含整個 RunePost\：實作在模組內，只掃兩支薄入口腳本會讓這個斷言
    # 變成必然通過——內嵌公鑰真的長回來也掃不到。
    $targets = @(
        @{ N = 'seal'; P = $script:SutSeal }
        @{ N = 'open'; P = $script:SutOpen }
    )
    foreach ($f in Get-ChildItem -LiteralPath $script:ModuleRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File) {
        $targets += @{ N = "RunePost\$($f.Name)"; P = $f.FullName }
    }
    foreach ($pair in $targets) {
        $text = [System.IO.File]::ReadAllText($pair.P)
        $f = Find-PublicKeyAssignment -Text $text
        $where = if ($null -ne $f.Hit) { $f.Hit.Extent.StartLineNumber } else { 0 }
        Assert ($null -eq $f.Hit) ('{0} 仍保留 $PublicKeyPem 賦值（行 {1}）：內嵌公鑰未徹底移除' -f $pair.N, $where)
        Assert (-not ($text -match 'PublicKeyPem')) ('{0} 仍出現 PublicKeyPem 字樣，內嵌公鑰的路徑未清乾淨' -f $pair.N)
    }
    return ('掃過 {0} 個檔案（2 支入口腳本 + 整個 RunePost\），皆無 $PublicKeyPem 賦值、無 PublicKeyPem 字樣；公鑰改為執行期讀取' -f $targets.Count)
}

Invoke-TCase 'P3' '家目錄沙箱可用（不污染真實 ~\.rune）' -Tier Core {
    $sb = New-HomeSandbox -Name 'probe'
    $probe = Join-Path $script:Work 'homeprobe.ps1'
    [System.IO.File]::WriteAllText($probe, '"H=$HOME"; "T=" + (Resolve-Path ~).ProviderPath; "U=$env:USERPROFILE"', $script:Utf8Bom)
    $r = Invoke-Transfer -ScriptPath $probe -EnvVars $sb.Env -WorkDir $sb.Path
    $ok = ($r.StdOut -split "`r?`n" | Where-Object { $_ -match '^[HTU]=' } | ForEach-Object { $_.Substring(2) } | Where-Object { $_ -notlike "$($sb.Path)*" })
    Assert (-not $ok) ('沙箱未完全生效：' + (Squash $r.StdOut 120))
    return ('~ / $HOME / $env:USERPROFILE 皆指向沙箱；真實私鑰存在={0}' -f $script:RealKeyExisted)
}

Invoke-TCase 'P4' '受測物 -GenerateKeys -Protect Dpapi 產生測試金鑰 A（open）' -Tier Core -Needs @('KeyA') {
    $k = Get-Fixture 'KeyA'
    Assert ($k.HasKey) ('未在 ~\.rune\private.key 產生私鑰；輸出=' + (Squash $k.Result.All 160))
    Assert ($null -ne $k.PublicPem) ('-GenerateKeys 未在 ~\.rune\public.pem 寫出合法的 PUBLIC KEY PEM；輸出=' + (Squash $k.Result.All 160))
    Assert ($null -ne $k.PubSpki) '公鑰 PEM 無法以 ImportFromPem 載入'
    $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ec.ImportFromPem($k.PublicPem)
    $curve = $ec.ExportParameters($false).Curve
    $isP256 = ($curve.Oid.Value -eq '1.2.840.10045.3.1.7') -or ($curve.Oid.FriendlyName -match 'nistP256|P-256|prime256')
    Assert $isP256 ('公鑰不是 P-256：' + $curve.Oid.Value + '/' + $curve.Oid.FriendlyName)
    $note = if ($k.Escaped) { '（注意：寫入未受沙箱控制的位置，已還原）' } else { '' }
    return ('私鑰 {0} 位元組；公鑰 P-256 SPKI {1}B{2}' -f (Get-Item -LiteralPath $k.KeyPath).Length, $k.PubSpki.Length, $note)
}

Invoke-TCase 'P5' '產生第二組測試金鑰 B（供錯誤私鑰案例）' -Tier Core -Needs @('KeyA', 'KeyB') {
    $a = Get-Fixture 'KeyA'; $b = Get-Fixture 'KeyB'
    Assert ($b.HasKey) '第二組私鑰未產生'
    Assert ((Get-Sha $b.KeyPath) -ne (Get-Sha $a.KeyPath)) '兩次 -GenerateKeys 產生相同的私鑰 blob（金鑰未隨機）'
    return ('金鑰 B 就緒；與 A 的 blob 不同')
}

Invoke-TCase 'P6' '沙箱家目錄已備妥 public.pem，且與 -GenerateKeys 印出的指紋對得起來' -Tier Core -Needs @('KeyA') {
    # -GenerateKeys 不印 PEM 全文，因此以「印出的指紋 == 獨立重算
    # SHA-256(落地 public.pem 的 SPKI DER)[0..15]」驗證兩者是同一把。
    $k = Get-Fixture 'KeyA'
    $pub = $k.Sandbox.PubPath
    Assert ([System.IO.File]::Exists($pub)) "-GenerateKeys 未在沙箱家目錄寫出 public.pem：$pub"
    $onDisk = Get-PemBlock -Text ([System.IO.File]::ReadAllText($pub))
    Assert ($null -ne $onDisk) 'public.pem 內容不是合法的 PUBLIC KEY PEM 區塊'
    $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ec.ImportFromPem($onDisk)
    Assert ([Convert]::ToHexString($ec.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($k.PubSpki)) `
        'public.pem 內的公鑰與 P4 取得的公鑰不是同一把'
    $fp = Get-Fingerprint -Text $k.Result.All
    Assert ($null -ne $fp) ('-GenerateKeys 未印出 RUNE-KEY 指紋：' + (Squash $k.Result.All 200))
    $digest = [System.Security.Cryptography.SHA256]::HashData($k.PubSpki)
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $expect = ((0..7) | ForEach-Object { $hex.Substring($_ * 4, 4) }) -join '-'
    Assert ($fp -eq $expect) ('印出的指紋與落地 public.pem 對不起來：印出 {0}，重算 {1}' -f $fp, $expect)
    return ('沙箱 ~\.rune\public.pem 就緒，指紋 RUNE-KEY {0} 與印出值逐字相符；seal / open 皆直接對原檔執行，全程未製作任何腳本副本' -f $expect)
}

Write-Host ''
Write-Host '-- Roundtrip --' -ForegroundColor Cyan

Invoke-TCase 'C01' '單檔 roundtrip（256KB 二進位，SHA-256 逐檔比對）' -Tier Core -Needs @('CtSingle') {
    $ct = Get-Fixture 'CtSingle'
    $src = $ct.Source
    [void](Assert-UnpackMatches -Txt $ct.Out -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'single' `
            -Expected @{ 'payload.bin' = (Get-Sha $src) } -What 'Unpack(single)')
    return ('1 檔位元完全一致；SHA={0}…；容器 {1}B' -f (Get-Sha $src).Substring(0, 12), (Get-Item -LiteralPath $ct.Out).Length)
}

Invoke-TCase 'C02' 'wildcard（含中文檔名）roundtrip 且不遞迴' -Tier Core -Needs @('CtWild') {
    $ct = Get-Fixture 'CtWild'
    $c = Assert-UnpackMatches -Txt $ct.Out -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'wild' `
        -Expected (Get-WildExpectedMap) -AllowRootPrefix 'wild' -What 'Unpack(wild)'
    $act = Get-TreeMap (Get-UnpackDest 'wild')
    Assert (-not ($act.Keys | Where-Object { $_ -match 'nested\.txt' })) '違反不遞迴：子目錄檔案被打包'
    Assert (-not ($act.Keys | Where-Object { $_ -match 'skip-me\.md' })) 'wildcard 匹配錯誤：非 .txt 被打包'
    return ('3 檔（含中文/空白檔名）一致；子目錄與非匹配副檔名皆未收入；{0}' -f $c.Convention)
}

Invoke-TCase 'C03' '資料夾遞迴 roundtrip（中文子目錄、深層、同名不同層）' -Tier Core -Needs @('CtTree') {
    $ct = Get-Fixture 'CtTree'
    $exp = Get-TreeMap $ct.Source
    $c = Assert-UnpackMatches -Txt $ct.Out -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'tree' `
        -Expected $exp -AllowRootPrefix 'tree' -What 'Unpack(tree)'
    return ('{0} 檔全部 SHA-256 一致（含 中文目錄/更深/第三層、a|b 同名、0 byte、特殊字元檔名）；{1}' -f $exp.Count, $c.Convention)
}

Write-Host ''
Write-Host '-- 格式白盒 --' -ForegroundColor Cyan

Invoke-TCase 'C04' '容器結構：magic/version=0x02/ephPubKeyLen/各段偏移自洽' -Tier Core -Needs @('CtTree') {
    $c = Read-Container (Get-Fixture 'CtTree').Out
    Assert ($c.Magic -eq 'RUNE') ("magic 不是 RUNE：'{0}'" -f $c.Magic)
    Assert ($c.Version -eq 2) ('version 不是 0x02：0x{0:X2}' -f $c.Version)
    Assert ($c.EpkLen -ge 80 -and $c.EpkLen -le 120) ('ephPubKeyLen 不在 80~120：{0}' -f $c.EpkLen)
    Assert ($c.Epk[0] -eq 0x30) ('ephemeral 公鑰非 DER SEQUENCE 開頭：0x{0:X2}' -f $c.Epk[0])
    Assert ($c.Nonce.Length -eq 12) 'nonce 長度不是 12'
    Assert ($c.Tag.Length -eq 16) 'tag 長度不是 16'
    Assert ($c.Cipher.Length -gt 0) 'ciphertext 為空'
    $expLen = 8 + $c.EpkLen + 12 + 16 + $c.Cipher.Length
    Assert ($expLen -eq $c.Bytes.Length) "長度不自洽：$expLen vs $($c.Bytes.Length)"
    return ('magic=RUNE ver=0x02 epkLen={0}(uint16 LE) der=0x30 nonce@{1} tag@{2} ct={3}B 總長自洽' -f `
            $c.EpkLen, (8 + $c.EpkLen), (8 + $c.EpkLen + 12), $c.Cipher.Length)
}

Invoke-TCase 'C51' 'contentType 欄位：byte[5] = 0x01（檔案樹），header 最小長度 8' -Tier Core -Needs @('CtTree', 'CtSingle') {
    $c = Read-Container (Get-Fixture 'CtTree').Out
    Assert ($c.ContentType -eq 1) ('資料夾容器的 contentType 不是 0x01：0x{0:X2}' -f $c.ContentType)
    $s = Read-Container (Get-Fixture 'CtSingle').Out
    Assert ($s.ContentType -eq 1) ('單檔容器的 contentType 不是 0x01：0x{0:X2}' -f $s.ContentType)
    Assert ($c.EpkLen -ge 80 -and $c.EpkLen -le 120) ('位移 +1 後 ephPubKeyLen 讀出異常：{0}' -f $c.EpkLen)
    Assert ($c.Epk[0] -eq 0x30) ('位移 +1 後 ephPubKey 非 DER SEQUENCE 開頭：0x{0:X2}' -f $c.Epk[0])
    return ('資料夾與單檔容器 byte[5] 皆為 0x01；ephPubKeyLen@6 讀出 {0}、ephPubKey@8 為 0x30' -f $c.EpkLen)
}

Invoke-TCase 'C05' 'base64 文字編碼：每 76 字元換行、字元集合法' -Tier Core -Needs @('CtTree') {
    $c = Read-Container (Get-Fixture 'CtTree').Out
    Assert ($c.Lines.Count -ge 2) '輸出行數過少，無法判斷換行'
    $bad = @($c.Lines[0..($c.Lines.Count - 2)] | Where-Object { $_.Length -ne 76 })
    Assert ($bad.Count -eq 0) ('有 {0} 行長度不是 76（首個長度 {1}）' -f $bad.Count, $bad[0].Length)
    Assert ($c.Lines[-1].Length -le 76) '最後一行超過 76'
    Assert (($c.Lines -join '') -match '^[A-Za-z0-9+/]+={0,2}$') 'base64 字元集不合法'
    Assert (-not ($c.Raw -match '[^\x00-\x7F]')) '輸出含非 ASCII 字元'
    return ('{0} 行，前 {1} 行皆 76 字元，末行 {2}；純 ASCII' -f $c.Lines.Count, ($c.Lines.Count - 1), $c.Lines[-1].Length)
}

Invoke-TCase 'C06' '一次性金鑰：同輸入 Pack 兩次，ephPub/nonce/密文皆不同' -Tier Core -Needs @('Fx', 'KeyA') {
    $src = Get-FxPath 'single\payload.bin'
    $o1 = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'once1.txt'
    $o2 = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'once2.txt'
    foreach ($o in @($o1, $o2)) { if ([System.IO.File]::Exists($o)) { [System.IO.File]::Delete($o) } }
    [void](Expect-Success (Invoke-Seal -Pack $src -OutFile $o1) 'Pack#1')
    [void](Expect-Success (Invoke-Seal -Pack $src -OutFile $o2) 'Pack#2')
    $a = Read-Container $o1; $b = Read-Container $o2
    $hex = { param($x) [Convert]::ToHexString([byte[]]$x) }
    Assert ((& $hex $a.Epk) -ne (& $hex $b.Epk)) 'ephemeral 公鑰重複（金鑰非一次性）'
    Assert ((& $hex $a.Nonce) -ne (& $hex $b.Nonce)) 'nonce 重複'
    Assert ((& $hex $a.Cipher) -ne (& $hex $b.Cipher)) '密文完全相同'
    Assert ((& $hex $a.Tag) -ne (& $hex $b.Tag)) 'tag 重複'
    return ('epk/nonce/ct/tag 四者皆不同；nonce1={0} nonce2={1}' -f (& $hex $a.Nonce), (& $hex $b.Nonce))
}

Invoke-TCase 'C07' 'ephemeral 公鑰確為可匯入的 P-256 SubjectPublicKeyInfo' -Tier Core -Needs @('CtTree') {
    $c = Read-Container (Get-Fixture 'CtTree').Out
    $e = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $read = 0
    $e.ImportSubjectPublicKeyInfo([byte[]]$c.Epk, [ref]$read)
    $p = $e.ExportParameters($false)
    $isP256 = ($p.Curve.Oid.Value -eq '1.2.840.10045.3.1.7') -or ($p.Curve.Oid.FriendlyName -match 'nistP256|P-256|prime256')
    Assert $isP256 ('曲線不是 P-256：{0}/{1}' -f $p.Curve.Oid.Value, $p.Curve.Oid.FriendlyName)
    Assert ($read -eq $c.EpkLen) "SPKI 實際長度 $read 與宣告 $($c.EpkLen) 不符"
    $rpk = [Convert]::ToHexString((Get-Fixture 'KeyA').PubSpki)
    Assert ([Convert]::ToHexString([byte[]]$c.Epk) -ne $rpk) 'ephemeral 公鑰等於收件人公鑰（未使用臨時金鑰）'
    return ('P-256 SPKI 解析成功，consumed={0}B，且不等於收件人公鑰' -f $read)
}

Invoke-TCase 'C08' '獨立解密鏈：私鑰→ECDH→HKDF-SHA256→AES-GCM→Brotli→Zip' -Tier Core -Needs @('CtTree') {
    if ($null -eq (Get-Fixture 'PrivateKeyA')) {
        Info-Case '私鑰 blob 無法以 DPAPI(null entropy)+PKCS8/EC/PEM 還原，無法獨立重建金鑰（規格未定義 blob 內部格式）'
    }
    $k = Get-Fixture 'KdfInfo'
    if ($null -eq $k) {
        Info-Case '窮舉 HKDF salt/info 候選未命中（規格未定義 salt/info），無法獨立重建內容金鑰；roundtrip 由 C01-C03 保證'
    }
    Assert ($k.Mode -eq 'HKDF') ('內容金鑰不是以 HKDF 導出，而是 {0}（違反規格「HKDF-SHA256」）' -f $k.Label)
    $zip = Get-Fixture 'ZipTree'
    Assert ($zip.Length -gt 0) 'Brotli 解壓結果為空'
    Assert ($zip[0] -eq 0x50 -and $zip[1] -eq 0x4B) 'Brotli 解壓後不是 ZIP（PK 簽章缺失）'
    $entries = Get-ZipCentralDirectory -Zip $zip
    $c = Read-Container (Get-Fixture 'CtTree').Out
    return ('金鑰導出={0}, AAD={1}；密文 {2}B → Brotli 解出 zip {3}B / {4} 筆項目' -f $k.Label, $k.Aad, $c.Cipher.Length, $zip.Length, $entries.Count)
}

Invoke-TCase 'C09' 'ZIP 為純 store（NoCompression）且單檔也打包' -Tier Core -Needs @('ZipTree', 'CtSingle') {
    $zip = Get-Fixture 'ZipTree'
    if ($null -eq $zip) { Skip-Case '需 C08 成功取得明文' }
    $e = Get-ZipCentralDirectory -Zip $zip
    $bad = @($e | Where-Object { $_.Method -ne 0 })
    Assert ($bad.Count -eq 0) ('有 {0} 筆非 store（method={1}）' -f $bad.Count, ($bad[0].Method))
    $mism = @($e | Where-Object { $_.CompSize -ne $_.Size })
    Assert ($mism.Count -eq 0) 'store 模式下 compressed != uncompressed'
    # 單檔輸入也必須是 zip 容器
    $c1 = Read-Container (Get-Fixture 'CtSingle').Out
    $k1 = Resolve-ContentKey -Container $c1 -Ecdh (Get-Fixture 'PrivateKeyA') -RecipientSpki (Get-Fixture 'KeyA').PubSpki
    Assert ($null -ne $k1) '單檔容器無法解出'
    $z1 = Expand-Brotli -Data $k1.Plain
    $e1 = Get-ZipCentralDirectory -Zip $z1
    Assert ($e1.Count -ge 1) '單檔輸入未被打包成 zip'
    return ('資料夾 {0} 筆全為 method=0；單檔輸入亦為 zip（{1} 筆：{2}）' -f $e.Count, $e1.Count, $e1[0].Name)
}

Invoke-TCase 'C10' 'ZIP 檔名 UTF-8（非 ASCII 項目須設 bit 11 且位元組為 UTF-8）' -Tier Core -Needs @('ZipTree') {
    $zip = Get-Fixture 'ZipTree'
    if ($null -eq $zip) { Skip-Case '需 C08 成功取得明文' }
    $e = Get-ZipCentralDirectory -Zip $zip
    $nonAscii = @($e | Where-Object { -not $_.NameIsAscii })
    Assert ($nonAscii.Count -gt 0) '素材中的中文路徑未出現在 zip 項目名（可能被轉碼或遺失）'
    $noFlag = @($nonAscii | Where-Object { -not $_.Utf8Flag })
    Assert ($noFlag.Count -eq 0) ('有 {0} 筆非 ASCII 檔名未設 UTF-8 旗標(bit 11)：{1}' -f $noFlag.Count, $noFlag[0].Name)
    $badEnc = @($nonAscii | Where-Object { -not $_.NameIsUtf8 })
    Assert ($badEnc.Count -eq 0) '檔名位元組不是合法 UTF-8'
    Assert (($e.Name -join '|') -match '中文目錄') 'zip 中找不到中文目錄名'
    return ('{0} 筆非 ASCII 項目全部 bit11=1 且為 UTF-8，例：{1}' -f $nonAscii.Count, $nonAscii[0].Name)
}

Invoke-TCase 'C11' '壓縮有效性：高冗餘輸入輸出遠小於原檔' -Tier Full -Needs @('Fx', 'KeyA') {
    $src = Get-FxPath 'redundant\big.txt'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'redundant.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    [void](Expect-Success (Invoke-Seal -Pack $src -OutFile $out -Timeout 300) 'Pack(redundant)')
    $inLen = (Get-Item -LiteralPath $src).Length
    $outLen = (Get-Item -LiteralPath $out).Length
    $limit = [Math]::Max(8192, $inLen * 0.02)
    Assert ($outLen -lt $limit) ('輸出 {0}B 未顯著小於輸入 {1}B（門檻 {2}B）' -f $outLen, $inLen, [int]$limit)
    return ('輸入 {0}B → 輸出 {1}B（{2:P3}，含 base64 膨脹與 {3}B 標頭）' -f $inLen, $outLen, ($outLen / $inLen), (8 + 91 + 28))
}


Write-Host ''
Write-Host '-- 錯誤路徑 --' -ForegroundColor Cyan

Invoke-TCase 'C12' '竄改 base64 一字元 → 報內容損壞（tag 驗證）' -Tier Core -Needs @('CtTree', 'KeyA') {
    $t = Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'tamper_b64.txt'
    [System.IO.File]::Copy((Get-Fixture 'CtTree').Out, $t, $true)
    $txt = [System.IO.File]::ReadAllText($t)
    $lines = @(($txt -split "`r?`n") | Where-Object { $_.Length -gt 0 })
    $li = [int]($lines.Count * 0.8)
    $line = $lines[$li]
    $ci = 10
    $old = $line[$ci]
    $new = if ($old -eq 'A') { 'B' } else { 'A' }
    $lines[$li] = $line.Substring(0, $ci) + $new + $line.Substring($ci + 1)
    [System.IO.File]::WriteAllText($t, (($lines -join "`r`n") + "`r`n"), $script:Utf8NoBom)
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'tamper_b64'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'tamper_b64') -Category 'tag' -What '竄改密文'
    return ("第 $li 行第 $ci 字元 '$old'→'$new'；$ev")
}

Invoke-TCase 'C13' '竄改 magic → 報格式不符' -Tier Full -Needs @('CtTree', 'KeyA') {
    $t = New-TamperedContainer -Source (Get-Fixture 'CtTree').Out -Name 'tamper_magic.txt' -SetByte @{ 0 = [byte][char]'X' }
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'tamper_magic'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'tamper_magic') -Category 'format' -What '竄改 magic'
    return ("magic 'RUNE'→'XUNE'；$ev")
}

Invoke-TCase 'C14' '竄改 version(0x02→0x09) → 報版本不符' -Tier Full -Needs @('CtTree', 'KeyA') {
    $t = New-TamperedContainer -Source (Get-Fixture 'CtTree').Out -Name 'tamper_ver.txt' -SetByte @{ 4 = 0x09 }
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'tamper_ver'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'tamper_ver') -Category 'version' -What '竄改 version'
    return ("version 0x02→0x09；$ev")
}

Invoke-TCase 'C50' '新舊格式互斥：舊 CTXT 容器須以 magic 不符被拒' -Tier Full -Needs @('KeyA') {
    # 舊工具的 CTXT v2 與本工具的 RUNE v2 沿用同一個 version 編號，兩者只靠 magic 互斥。
    # magic 檢查排在 version 檢查與所有金鑰操作之前，因此本案不需要能解開該容器的私鑰，
    # 直接以硬編碼的舊格式 header 樣板構造即可（可在任何機器重現）。
    $epkLen = 91
    $b = [System.Collections.Generic.List[byte]]::new()
    $b.AddRange([System.Text.Encoding]::ASCII.GetBytes('CTXT'))
    $b.Add(2)
    $b.Add([byte]($epkLen -band 0xFF)); $b.Add([byte](($epkLen -shr 8) -band 0xFF))
    $body = [byte[]]::new($epkLen + 12 + 16 + 64)   # ephPubKey + nonce + tag + ciphertext
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($body)
    $body[0] = 0x30                                  # 讓 ephPubKey 至少像 DER SEQUENCE
    $b.AddRange($body)
    $t = Write-Container -Bytes $b.ToArray() -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'legacy_ctxt.txt')

    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'legacy_ctxt'
    Assert ($r.ExitCode -eq 1) ('舊 CTXT 容器應以 exit 1 被拒絕，實際 exit={0}：{1}' -f $r.ExitCode, (Squash $r.All 160))
    # 訊息必須回報實際讀到的 magic，使用者才知道自己餵了哪一種檔案
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'legacy_ctxt') -Category 'format' `
        -What '舊 CTXT 容器' -Expect @('legacymagic')
    return ("舊 CTXT v2 容器遭 magic 檢查拒絕、Destination 乾淨；$ev")
}

# contentType 已綁進 HKDF info，因此翻掉它必然表現為 GCM 認證失敗（＝被竄改），
# 而不是「不支援的內容型別」。後者只能出現在「tag 驗過但型別未知」的合法容器上。
Invoke-TCase 'C52' 'contentType 竄改 0x01→0x02 → 須報「被竄改」（證明已綁進 HKDF info）' -Tier Core -Needs @('CtTree', 'KeyA') {
    $t = New-TamperedContainer -Source (Get-Fixture 'CtTree').Out -Name 'ctype_02.txt' -SetByte @{ 5 = 2 }
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'ctype_02'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'ctype_02') -Category 'tag' `
        -What 'contentType 翻成 0x02' -Forbid @('typeorversion')
    return ('0x01→0x02 報竄改而非型別問題（型別位元確實進了 HKDF info）；' + $ev)
}

Invoke-TCase 'C54' '合法的 contentType 0x03 容器 → 須報「由較新版本產生」' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Assert-KdfAvailable
    # 以 contentType = 0x03 完整走一次派生與加密：tag 必然驗得過，
    # 此時型別仍未知，正確的結論是「本程式版本落後」，不是「資料被竄改」。
    $t = New-ForgedRune -ZipBytes (New-ZipWithEntry -EntryName 'future.txt' -Content 'FROM-THE-FUTURE') `
        -ContentType 3 -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'ctype03.txt')
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'ctype03'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'ctype03') -What '未知的內容型別 0x03' `
        -Expect @('contenttype', 'newerversion') -Forbid @('tampered')
    return ('0x03 遭拒且訊息指向版本落後；' + $ev)
}

Invoke-TCase 'C15' '錯誤私鑰（另一組 P-256 blob）→ 報解鑰失敗' -Tier Core -Needs @('CtTree', 'KeyB') {
    $r = Invoke-UnpackOnly -Txt (Get-Fixture 'CtTree').Out -KeyFile (Get-Fixture 'KeyB').KeyPath -DestName 'wrongkey'
    # ECDH 混合式下，不匹配的私鑰在數學上仍能完成 ECDH，必然要到 GCM 才失敗；
    # 因此接受「解鑰失敗」或「內容損壞」，但訊息必須讓使用者判斷得出是金鑰或內容問題。
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'wrongkey') -Category @('key', 'tag') `
        -What '不匹配的私鑰'
    $stage = if (Test-Msg $r.StdErr 'stage.key') { '解鑰失敗' } else { '內容損壞（ECDH 下之必然表現）' }
    return ("環節={0}；{1}；未寫出任何檔案" -f $stage, $ev)
}

Invoke-TCase 'C16' '私鑰檔不存在 / 讀不到 → 報私鑰讀取失敗' -Tier Full -Needs @('CtTree') {
    $r = Invoke-UnpackOnly -Txt (Get-Fixture 'CtTree').Out -KeyFile (Join-Path $script:Work 'no_such_dir\private.key') -DestName 'nokey'
    return (Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'nokey') -Category 'key' -What '私鑰路徑不存在')
}

Invoke-TCase 'C17' '截斷容器（只留一半 base64）→ 指明環節' -Tier Full -Needs @('CtTree', 'KeyA') {
    $c = Read-Container (Get-Fixture 'CtTree').Out
    $half = [int]($c.Bytes.Length / 2)
    $b = [byte[]]$c.Bytes[0..($half - 1)]
    $t = Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'truncated.txt')
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'truncated'
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'truncated') -Category @('tag', 'format', 'base64') -What '截斷容器'
    return ('截半 {0}B→{1}B；{2}' -f $c.Bytes.Length, $half, $ev)
}

Invoke-TCase 'C18' '非 base64 內容 → 報 base64/編碼環節錯誤' -Tier Full -Needs @('KeyA') {
    $t = Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'notb64.txt'
    [System.IO.File]::WriteAllText($t, "這不是 base64 !!! @@@@`r`n###`r`n", $script:Utf8NoBom)
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'notb64'
    return (Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'notb64') -Category @('base64', 'format') -What '非 base64 內容')
}

Invoke-TCase 'C19' '偽造容器（tag 合法但明文非 Brotli）→ 報解壓失敗' -Tier Full -Needs @('KdfInfo', 'CtSingle', 'KeyA') {
    Assert-KdfAvailable
    # 用受測物自己的容器換掉密文：以相同金鑰重新加密一段非 Brotli 明文
    $c = Read-Container (Get-Fixture 'CtSingle').Out
    $k = Resolve-ContentKey -Container $c -Ecdh (Get-Fixture 'PrivateKeyA') -RecipientSpki (Get-Fixture 'KeyA').PubSpki
    Assert ($null -ne $k) '無法解出單檔容器'
    $junk = [System.Text.Encoding]::ASCII.GetBytes(('NOT-BROTLI-DATA-' * 32))
    $ct = [byte[]]::new($junk.Length)
    $tag = [byte[]]::new(16)
    $gcm = New-AesGcm -Key $k.Key
    if ($k.Aad -eq 'none') { $gcm.Encrypt($c.Nonce, $junk, $ct, $tag) }
    else {
        $aad = if ($k.Aad -eq 'header') { [byte[]]($c.Bytes[0..($c.HeaderSize - 1)]) } else { [byte[]]($c.Bytes[0..4]) }
        $gcm.Encrypt($c.Nonce, $junk, $ct, $tag, $aad)
    }
    $gcm.Dispose()
    $b = [System.Collections.Generic.List[byte]]::new()
    $b.AddRange([byte[]]($c.Bytes[0..($c.HeaderSize - 1)]))
    $b.AddRange([byte[]]$c.Nonce); $b.AddRange($tag); $b.AddRange($ct)
    $t = Write-Container -Bytes $b.ToArray() -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'notbrotli.txt')
    $r = Invoke-UnpackOnly -Txt $t -KeyFile (Get-Fixture 'KeyA').KeyPath -DestName 'notbrotli'
    return (Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'notbrotli') -Category 'unzip' -What 'tag 正確但明文非 Brotli')
}

Invoke-TCase 'C20' 'OutFile 已存在且未加 -Force → 報錯且不覆蓋' -Tier Full -Needs @('Fx', 'KeyA') {
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'exists.txt'
    [System.IO.File]::WriteAllText($out, 'SENTINEL-DO-NOT-OVERWRITE', $script:Utf8NoBom)
    $before = Get-Sha $out
    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out
    $ev = Expect-SealRefused -Res $r -Category 'exists' -What '輸出檔已存在' -Unchanged @{ $out = $before }
    return ("$ev；原檔內容未變")
}

Invoke-TCase 'C21' '-Force 可覆蓋既有 OutFile' -Tier Full -Needs @('Fx', 'KeyA') {
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'exists.txt'
    if (-not [System.IO.File]::Exists($out)) {
        [System.IO.File]::WriteAllText($out, 'SENTINEL-DO-NOT-OVERWRITE', $script:Utf8NoBom)
    }
    $before = Get-Sha $out
    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -Force
    [void](Expect-Success $r 'Pack -Force')
    Assert ((Get-Sha $out) -ne $before) '-Force 未覆蓋'
    $c = Read-Container $out
    Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2) '覆蓋後不是合法容器'
    return ('已覆蓋並產生合法容器 {0}B' -f $c.Bytes.Length)
}

Invoke-TCase 'C22' 'wildcard 空匹配 → 報錯' -Tier Full -Needs @('Fx', 'KeyA') {
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'empty.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $r = Invoke-Seal -Pack (Get-FxPath 'emptywild\*.txt') -OutFile $out
    $ev = Expect-SealRefused -Res $r -OutFile $out -Category 'nomatch' -What 'wildcard 無匹配'
    return ("$ev；未產生輸出")
}

Invoke-TCase 'C23' '~\.rune\public.pem 不存在 → 報找不到公鑰且不產生輸出檔' -Tier Full -Needs @('Fx') {
    # 訊息不只要說「找不到」，還要告訴使用者怎麼取得公鑰：到解密端跑 -GenerateKeys、
    # 檔案叫 public.pem、也可以用 -PublicKey 指定其他位置。
    $sb = New-HomeSandbox -Name 'nopub'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'nopub.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -Env $sb.Env
    return (Expect-SealRefused -Res $r -OutFile $out -Category 'nopub' -What '家目錄沒有 public.pem' `
            -Expect @('notfound', 'hint.generatekeys', 'hint.pubfile', 'hint.publickeyopt'))
}

Invoke-TCase 'C24' '輸入路徑不存在 → 報錯' -Tier Full -Needs @('Fx', 'KeyA') {
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'nosrc.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $r = Invoke-Seal -Pack (Get-FxPath 'no_such_file.bin') -OutFile $out
    return (Expect-SealRefused -Res $r -OutFile $out -Category 'input' -What '輸入不存在')
}

Write-Host ''
Write-Host '-- CLI / 預設檔名 --' -ForegroundColor Cyan

function Test-DefaultName {
    param([string]$InputPath, [string]$Expected, [string]$Tag)
    $cwd = Clear-Dir (Join-Path $script:Work "cwd_$Tag")
    $inDir = [System.IO.Path]::GetDirectoryName($InputPath.TrimEnd('\'))
    $inParent = [System.IO.Path]::GetDirectoryName($inDir)
    foreach ($d in @($cwd, $inDir, $inParent)) {
        $p = Join-Path $d $Expected
        if ([System.IO.File]::Exists($p)) { [System.IO.File]::Delete($p) }
    }
    $r = Invoke-Seal -Pack $InputPath -Cwd $cwd
    [void](Expect-Success $r "Pack(預設檔名 $Tag)")
    $found = $null
    foreach ($d in @($cwd, $inDir, $inParent)) {
        $p = Join-Path $d $Expected
        if ([System.IO.File]::Exists($p)) { $found = $p; break }
    }
    Assert ($null -ne $found) ("找不到預設輸出 '$Expected'（已找 cwd / 輸入所在目錄 / 其上層）；stdout=" + (Squash $r.StdOut 120))
    $c = Read-Container $found
    Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2) '預設輸出不是合法容器'
    $where = if ($found.StartsWith($cwd)) { '目前目錄' } else { '輸入所在位置' }
    return ("產生 $Expected（$where），{0}B" -f $c.Bytes.Length)
}

Invoke-TCase 'C25' '預設檔名：單檔 report.docx → report.docx.txt' -Tier Full -Needs @('Fx', 'KeyA') {
    Test-DefaultName -InputPath (Get-FxPath 'naming\report.docx') -Expected 'report.docx.txt' -Tag 'file'
}

Invoke-TCase 'C26' '預設檔名：資料夾 project → project.txt' -Tier Full -Needs @('Fx', 'KeyA') {
    Test-DefaultName -InputPath (Get-FxPath 'naming\project') -Expected 'project.txt' -Tag 'dir'
}

Invoke-TCase 'C27' '預設檔名：wildcard → 父資料夾名.txt' -Tier Full -Needs @('Fx', 'KeyA') {
    Test-DefaultName -InputPath (Get-FxPath 'naming\wcdir\*.txt') -Expected 'wcdir.txt' -Tag 'wild'
}

Invoke-TCase 'C29' '各產物拒絕對方參數：rune-seal 拒絕 -Unpack、rune-open 拒絕 -Pack' -Tier Full -Needs @('CtTree', 'Fx', 'KeyA') {
    $r1 = Invoke-Seal -Unpack (Get-Fixture 'CtTree').Out -Destination (New-Dir (Join-Path $script:Work 'unpack\mix1'))
    $ev1 = Expect-SealRefused -Res $r1 -Category 'param' -What 'rune-seal.ps1 收到 -Unpack'
    $r2 = Invoke-Open -Pack (Get-FxPath 'single\payload.bin')
    $ev2 = Expect-OpenRefused -Res $r2 -Category 'param' -What 'rune-open.ps1 收到 -Pack'
    return ("seal 拒絕 -Unpack（$ev1）；open 拒絕 -Pack（$ev2）")
}

Invoke-TCase 'C30' '-Unpack 缺 -Destination → 報錯（不得卡在互動）' -Tier Full -Needs @('CtTree', 'KeyA') {
    $r = Invoke-Open -Unpack (Get-Fixture 'CtTree').Out -KeyFile (Get-Fixture 'KeyA').KeyPath -Timeout 45
    return (Expect-OpenRefused -Res $r -Category 'param' -What '缺 -Destination')
}


Write-Host ''
Write-Host '-- 金鑰儲存 / GenerateKeys --' -ForegroundColor Cyan

Invoke-TCase 'C31' '-Protect Dpapi 的私鑰檔為 DPAPI blob（非明文 PEM）' -Tier Core -Needs @('KeyA') {
    $b = [System.IO.File]::ReadAllBytes((Get-Fixture 'KeyA').KeyPath)
    $ascii = [System.Text.Encoding]::ASCII.GetString($b)
    Assert ($ascii -notmatch 'PRIVATE KEY') '私鑰檔含 "PRIVATE KEY" 明文字樣（未加密儲存）'
    Assert ($ascii -notmatch '-----BEGIN') '私鑰檔含 PEM 標頭'
    $printable = @($b | Where-Object { ($_ -ge 32 -and $_ -lt 127) -or $_ -eq 10 -or $_ -eq 13 }).Count
    Assert (($printable / $b.Length) -lt 0.9) '私鑰檔幾乎全為可列印字元，疑似明文'
    $prot = $false
    try {
        [void][System.Security.Cryptography.ProtectedData]::Unprotect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        $prot = $true
    } catch { }
    $note = if ($prot) { '且可用 DPAPI(CurrentUser, 無 entropy) 解開' } else { '（DPAPI 解開需額外 entropy，未驗證）' }
    return ('{0}B 二進位，無 PEM 字樣，可列印比 {1:P0}；{2}' -f $b.Length, ($printable / $b.Length), $note)
}

Invoke-TCase 'C33' '-KeyFile 預設值 ~\.rune\private.key（不給 -KeyFile 也能解）' -Tier Full -Needs @('CtWild', 'KeyA') {
    $k = Get-Fixture 'KeyA'
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\defaultkey')
    $expected = Join-Path $k.Sandbox.Path '.rune\private.key'
    if (-not [System.IO.File]::Exists($expected)) {
        [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($expected))
        [System.IO.File]::Copy($k.KeyPath, $expected, $true)
    }
    $r = Invoke-Open -Unpack (Get-Fixture 'CtWild').Out -Destination $dest
    [void](Expect-Success $r 'Unpack(預設 KeyFile)')
    Assert ((Get-TreeMap $dest).Count -eq 3) '解出檔案數不符'
    return ('未指定 -KeyFile，從 ~\.rune\private.key 讀取成功')
}

# -GenerateKeys 對「私鑰已存在」的處置（見 rune-open.ps1 的 .DESCRIPTION）：
#   互動環境 → 印出現有指紋後詢問（預設不繼續）；
#   非互動環境（stdin 被重導向）且無 -Force → 直接拒絕，不卡在提示；
#   帶 -Force → 略過提示，先把舊的 private.key / public.pem 改名為
#               <原檔名>.bak-<時間戳>（是改名不是刪除），才寫入新金鑰對。
# 本套件的子行程一律關閉 stdin，因此 C34 測到的是「非互動 + 無 -Force」那條路徑；
# C65 / C66 涵蓋 -Force 這條路徑的落地行為與救援路徑。

Invoke-TCase 'C34' '-GenerateKeys 私鑰已存在 + 非互動且無 -Force → 拒絕，且完全不動既有檔案' -Tier Core -Needs @('KeyA') {
    $k = Get-Fixture 'KeyA'
    $runeDir = Join-Path $k.Sandbox.Path '.rune'
    $before = Get-Sha $k.KeyPath
    $bakBefore = @([System.IO.Directory]::EnumerateFiles($runeDir, '*.bak-*')).Count
    $r = Invoke-Open -GenerateKeys -Env $k.Sandbox.Env -Cwd $k.Sandbox.Path
    # 訊息必須指出 -Force 這條出路，否則使用者在非互動環境下無路可走
    $ev = Expect-OpenRefused -Res $r -Category 'exists' -What '私鑰已存在' `
        -Unchanged @{ $k.KeyPath = $before } -Expect @('hint.force')
    # 拒絕就是拒絕：不得留下任何備份檔（那代表已經動手改名了才失敗）
    $bakAfter = @([System.IO.Directory]::EnumerateFiles($runeDir, '*.bak-*')).Count
    Assert ($bakAfter -eq $bakBefore) ('被拒絕卻仍產生了備份檔（{0} → {1}）' -f $bakBefore, $bakAfter)
    return ("$ev；既有私鑰 SHA 未變、無備份檔產生、訊息有指引 -Force")
}

Invoke-TCase 'C65' '-GenerateKeys -Force：產生新金鑰，舊私鑰改名保留為 private.key.bak-* 且位元組不變' -Tier Full -Needs @('KeyRotate') {
    $rt = Get-Fixture 'KeyRotate'
    $kf = $rt.Key
    Assert ($kf.HasKey) '前置：force 沙箱未產生第一把私鑰'
    Assert ($null -ne $kf.PublicPem) '前置：force 沙箱未寫出 public.pem'
    Assert ($null -ne $rt.PackOld -and -not $rt.PackOld.Failed) ('前置：以輪替前的公鑰加密失敗 => ' + (Squash $rt.PackOld.All 160))
    [void](Expect-Success $rt.Result '-GenerateKeys -Force')

    # 新金鑰確實產生且與舊的不同
    Assert ([System.IO.File]::Exists($kf.KeyPath)) '-Force 後 private.key 不存在'
    Assert ((Get-Sha $kf.KeyPath) -ne $rt.OldKeySha) '-Force 後 private.key 內容未改變（沒有真的換新金鑰）'

    # 舊私鑰是「改名保留」而不是刪除
    $keyBaks = @([System.IO.Directory]::EnumerateFiles($rt.RuneDir, 'private.key.bak-*'))
    Assert ($keyBaks.Count -eq 1) ('private.key.bak-* 應恰好 1 個，實得 {0}：{1}' -f $keyBaks.Count, (($keyBaks | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
    $bakName = Split-Path -Leaf $keyBaks[0]
    Assert ($bakName -match '^private\.key\.bak-\d{8}-\d{6}') ("備份檔名不是 private.key.bak-<時間戳> 格式：$bakName")

    # 備份檔與舊私鑰逐位元組相同
    $bakBytes = [System.IO.File]::ReadAllBytes($keyBaks[0])
    Assert ($bakBytes.Length -eq $rt.OldKeyBytes.Length) ('備份長度 {0} 與舊私鑰 {1} 不符' -f $bakBytes.Length, $rt.OldKeyBytes.Length)
    $same = $true
    for ($i = 0; $i -lt $bakBytes.Length; $i++) { if ($bakBytes[$i] -ne $rt.OldKeyBytes[$i]) { $same = $false; break } }
    Assert $same '備份檔內容與舊私鑰不是逐位元組相同'
    Assert ((Get-Sha $keyBaks[0]) -eq $rt.OldKeySha) '備份檔 SHA-256 與舊私鑰不符'

    # public.pem 同樣改名保留，且內容是舊的那把
    $pubBaks = @([System.IO.Directory]::EnumerateFiles($rt.RuneDir, 'public.pem.bak-*'))
    Assert ($pubBaks.Count -eq 1) ('public.pem.bak-* 應恰好 1 個，實得 {0}' -f $pubBaks.Count)
    Assert ([System.IO.File]::ReadAllText($pubBaks[0]) -eq $rt.OldPubText) '公鑰備份內容與舊 public.pem 不同'
    Assert ((Split-Path -Leaf $pubBaks[0]) -eq ($bakName -replace '^private\.key', 'public.pem')) `
    ('私鑰／公鑰備份未共用同一個時間戳：{0} vs {1}' -f $bakName, (Split-Path -Leaf $pubBaks[0]))

    # 新的 public.pem 已重寫成新金鑰的，指紋也跟著變
    $newPub = Get-PemBlock -Text ([System.IO.File]::ReadAllText($kf.Sandbox.PubPath))
    Assert ($null -ne $newPub) '-Force 後 public.pem 不是合法 PEM'
    Assert ($newPub -ne (Get-PemBlock -Text $rt.OldPubText)) '-Force 後 public.pem 仍是舊公鑰'
    Assert-Msg -Text $rt.Result.All -Keys @('fingerprint') -What '-Force 後的輸出'
    Assert ($rt.Result.All -match [regex]::Escape($bakName)) `
    ('輸出未告知備份檔位置（使用者無從得知舊金鑰去哪了）：' + (Squash $rt.Result.All 200))
    return ("舊私鑰改名為 $bakName（逐位元組相同）、public.pem 同時間戳備份、新金鑰已寫入且指紋改變")
}

Invoke-TCase 'C66' '輪替後仍可用 -KeyFile 指向 private.key.bak-* 解開舊密文' -Tier Full -Needs @('KeyRotate') {
    $rt = Get-Fixture 'KeyRotate'
    $baks = @([System.IO.Directory]::EnumerateFiles($rt.RuneDir, 'private.key.bak-*'))
    Assert ($baks.Count -eq 1) '前置 C65 未產生備份私鑰'
    $backup = $baks[0]

    # 先確認新金鑰確實解不開舊密文（證明金鑰真的換了，備份不是多餘的）
    $destNew = Clear-Dir (Join-Path $script:Work 'unpack\rotated_newkey')
    $rn = Invoke-Open -Unpack $rt.CtOld -Destination $destNew -KeyFile $rt.Key.KeyPath -Env $rt.Key.Sandbox.Env
    [void](Expect-OpenRefused -Res $rn -Destination $destNew -What '輪替後的新私鑰解舊密文')

    # 備份私鑰解得開，且內容位元一致
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\rotated_backup')
    $rb = Invoke-Open -Unpack $rt.CtOld -Destination $dest -KeyFile $backup -Env $rt.Key.Sandbox.Env
    [void](Expect-Success $rb 'Unpack(-KeyFile 指向備份私鑰)')
    $d = Compare-MapExact @{ 'payload.bin' = $rt.SrcSha } (Get-TreeMap $dest)
    Assert ($null -eq $d) $d
    return ('新私鑰解不開舊密文；改用 -KeyFile ' + (Split-Path -Leaf $backup) + ' 則位元一致還原，救援路徑成立')
}

Invoke-TCase 'C35' '-GenerateKeys 只印路徑與指紋，不印任何 PEM 全文' -Tier Core -Needs @('KeyA') {
    # 成功輸出是「私鑰路徑 / 公鑰路徑 / 指紋」，PEM 全文不印——路徑已經給了，要看
    # 內容用 Get-Content。私鑰 PEM 更是絕對不能出現在畫面上：終端機捲軸、CI log、
    # 螢幕錄影都會把它帶走。這裡連「不得印出」都一併釘死。
    $o = (Get-Fixture 'KeyA').Result.All
    Assert-Msg -Text $o -Keys @('hint.pubfile', 'hint.keyfile', 'fingerprint') `
        -Forbid @('pem.publicblock', 'pem.privateblock') -What '-GenerateKeys 成功輸出'
    return (Squash (($o -split "`r?`n" | Where-Object { $_ -match 'public\.pem|RUNE-KEY' } | Select-Object -First 1)) 110)
}

Invoke-TCase 'C55' '-PublicKey 收 PEM 字串本體：家目錄無 public.pem 也能加密' -Tier Full -Needs @('Fx', 'KeyA') {
    $sb = New-HomeSandbox -Name 'pkstr'      # 這個沙箱刻意「沒有」public.pem
    $k = Get-Fixture 'KeyA'
    $src = Get-FxPath 'single\payload.bin'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'pkstring.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $r = Invoke-Seal -Pack $src -OutFile $out -PublicKey $k.PublicPem -Env $sb.Env
    [void](Expect-Success $r 'Pack(-PublicKey 收 PEM 字串)')
    $c = Read-Container $out
    Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2 -and $c.ContentType -eq 1) '產物不是合法的 RUNE v2 容器'

    [void](Assert-UnpackMatches -Txt $out -KeyFile $k.KeyPath -DestName 'pkstring' `
            -Expected @{ 'payload.bin' = (Get-Sha $src) } -What 'Unpack(-PublicKey 收 PEM 字串)')
    return ('家目錄無 public.pem，僅靠 -PublicKey 的 PEM 字串完成加密，且以金鑰 A 位元一致還原')
}

Invoke-TCase 'C56' '-PublicKey 收檔案路徑：可用非預設位置的公鑰檔' -Tier Full -Needs @('Fx', 'KeyA') {
    $sb = New-HomeSandbox -Name 'pkpath'     # 同樣沒有 public.pem
    $k = Get-Fixture 'KeyA'
    $pemFile = New-TextFile (Join-Path $script:Work 'keys\alice.pem') $k.PublicPem
    $src = Get-FxPath 'single\payload.bin'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'pkpath.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $r = Invoke-Seal -Pack $src -OutFile $out -PublicKey $pemFile -Env $sb.Env
    [void](Expect-Success $r 'Pack(-PublicKey 收檔案路徑)')
    [void](Assert-UnpackMatches -Txt $out -KeyFile $k.KeyPath -DestName 'pkpath' `
            -Expected @{ 'payload.bin' = (Get-Sha $src) } -What 'Unpack(-PublicKey 收檔案路徑)')
    return ('以 -PublicKey <路徑> 讀取非預設位置的公鑰檔，roundtrip 位元一致')
}

Invoke-TCase 'C57' '公鑰指紋：格式穩定、seal 與 -GenerateKeys 逐字一致且可獨立重算' -Tier Core -Needs @('Fx', 'KeyA') {
    $k = Get-Fixture 'KeyA'
    $genFp = Get-Fingerprint -Text $k.Result.All
    Assert ($null -ne $genFp) ('-GenerateKeys 未印出 RUNE-KEY 指紋（8 組 ×4 大寫 hex）：' + (Squash $k.Result.All 200))

    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'fp.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $p = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out
    [void](Expect-Success $p 'Pack(指紋)')
    $sealFp = Get-Fingerprint -Text $p.StdOut
    Assert ($null -ne $sealFp) ('-Pack 未印出 RUNE-KEY 指紋：' + (Squash $p.StdOut 200))
    Assert ($sealFp.Length -eq 39) ('指紋長度不是 39 個字元：{0}' -f $sealFp.Length)
    Assert ($sealFp -eq $genFp) ('加解密兩端的指紋不一致：seal={0} / generate={1}' -f $sealFp, $genFp)

    # 獨立重算：SHA-256( SPKI DER ) 前 16 bytes，大寫 hex 每 4 字元一組
    $digest = [System.Security.Cryptography.SHA256]::HashData($k.PubSpki)
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $expect = ((0..7) | ForEach-Object { $hex.Substring($_ * 4, 4) }) -join '-'
    Assert ($sealFp -eq $expect) ('指紋與 SHA-256(SPKI DER) 前 16 bytes 不符：實得 {0}，應為 {1}' -f $sealFp, $expect)
    return ('RUNE-KEY {0}；兩端逐字一致且等於 SHA-256(SPKI DER)[0..15]' -f $expect)
}

Invoke-TCase 'C58' '-ExportPublicKey 可從既有私鑰重建 public.pem，指紋不變' -Tier Full -Needs @('KeyA') {
    $k = Get-Fixture 'KeyA'
    $pub = $k.Sandbox.PubPath
    Assert ([System.IO.File]::Exists($pub)) '前置 P6 未通過（沙箱沒有 public.pem）'
    $backup = [System.IO.File]::ReadAllText($pub)
    [System.IO.File]::Delete($pub)
    try {
        $r = Invoke-Open -ExportPublicKey -Env $k.Sandbox.Env -Cwd $k.Sandbox.Path
        [void](Expect-Success $r '-ExportPublicKey')
        Assert ([System.IO.File]::Exists($pub)) '-ExportPublicKey 未重建 public.pem'
        $onDisk = Get-PemBlock -Text ([System.IO.File]::ReadAllText($pub))
        Assert ($null -ne $onDisk) '重建的 public.pem 不是合法 PEM'
        $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
        $ec.ImportFromPem($onDisk)
        Assert ([Convert]::ToHexString($ec.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($k.PubSpki)) `
            '重建出來的公鑰不是原來那把'
        $fp = Get-Fingerprint -Text $r.All
        Assert ($null -ne $fp) '-ExportPublicKey 未以相同格式印出指紋'
        Assert ($fp -eq (Get-Fingerprint -Text $k.Result.All)) '重新導出後指紋改變了'
        return ('public.pem 刪除後由私鑰完整重建，公鑰與指紋 RUNE-KEY {0} 皆不變' -f $fp)
    }
    finally {
        # 後續案例仍依賴這個沙箱的 public.pem，萬一重建失敗要還原
        if (-not [System.IO.File]::Exists($pub)) {
            [System.IO.File]::WriteAllText($pub, $backup, $script:Utf8NoBom)
        }
    }
}

Invoke-TCase 'C59' 'public.pem 被換成另一把金鑰 → 指紋必須改變（防掉包防線有效）' -Tier Core -Needs @('Fx', 'KeyA', 'KeyB') {
    $a = Get-Fixture 'KeyA'; $b = Get-Fixture 'KeyB'
    Assert ($null -ne $b.PublicPem) '前置 P5 未取得金鑰 B 的公鑰'
    $sb = New-HomeSandbox -Name 'swap'
    [void](New-TextFile $sb.PubPath $b.PublicPem)
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'swapped.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -Env $sb.Env
    [void](Expect-Success $r 'Pack(掉包後的 public.pem)')
    $fpB = Get-Fingerprint -Text $r.StdOut
    $fpA = Get-Fingerprint -Text $a.Result.All
    Assert ($null -ne $fpB) '換過公鑰後未印出指紋，使用者根本無從察覺'
    Assert ($fpB -ne $fpA) ('公鑰被換掉指紋卻沒變（防線失效）：{0}' -f $fpB)

    # 且產物確實是加密給 B：用 A 的私鑰解不開
    $u = Invoke-UnpackOnly -Txt $out -KeyFile $a.KeyPath -DestName 'swapped'
    [void](Expect-OpenRefused -Res $u -Destination (Get-UnpackDest 'swapped') -What '以 A 的私鑰解加密給 B 的密文')
    return ('A={0} → B={1}，指紋確實改變，且 A 的私鑰解不開' -f $fpA, $fpB)
}

# DESIGN.md §1.7.3 定義了三種公鑰錯誤路徑：找不到（C23）、曲線不符（C45）、
# 檔案存在但非合法 PEM（C60）。C61 / C62 再補上 -PublicKey 走「檔案路徑」與
# 「PEM 字串」兩種解析分支各自的找不到／格式錯誤情境。

Invoke-TCase 'C60' '~\.rune\public.pem 存在但非合法 PEM → 報公鑰格式無效' -Tier Full -Needs @('Fx') {
    $sb = New-HomeSandbox -Name 'badpem'
    [void](New-TextFile $sb.PubPath "這不是 PEM，只是隨便打的文字`n-----BEGIN GARBAGE-----`n")
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'badpem.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -Env $sb.Env
    return (Expect-SealRefused -Res $r -OutFile $out -What 'public.pem 非合法 PEM' -Expect @('pubkey.badpem'))
}

Invoke-TCase 'C61' '-PublicKey 指到不存在的路徑 → 報找不到，且措辭不繞' -Tier Full -Needs @('Fx') {
    # 訊息要回報使用者實際給的那個路徑、標明這是 -PublicKey 指定的（而非預設路徑），
    # 而且不可再叫他「把 public.pem 複製到 <他自己指定的那個路徑>」——語意繞圈。
    $badPath = Join-Path $script:Work 'no_such_dir\alice.pem'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'nopath.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $sb = New-HomeSandbox -Name 'pkbadpath'   # 沙箱刻意沒有 public.pem，逼真正生效的是 -PublicKey 那個分支
    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -PublicKey $badPath -Env $sb.Env
    $ev = Expect-SealRefused -Res $r -OutFile $out -What '-PublicKey 指到不存在的路徑' `
        -Expect @('pubkey.explicitpath') -Forbid @('pubkey.copyhint')
    Assert ($r.StdErr -match [regex]::Escape($badPath)) ('訊息未回報實際指定的路徑：' + (Squash $r.StdErr 200))
    return $ev
}

Invoke-TCase 'C62' '-PublicKey 收到格式錯誤的 PEM 字串 → 報公鑰格式無效' -Tier Full -Needs @('Fx') {
    $badPem = "-----BEGIN PUBLIC KEY-----`n這不是合法的 base64 內容`n-----END PUBLIC KEY-----"
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'badpemstring.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $sb = New-HomeSandbox -Name 'pkbadstring'
    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -PublicKey $badPem -Env $sb.Env
    return (Expect-SealRefused -Res $r -OutFile $out -What '-PublicKey 收到格式錯誤的 PEM 字串' -Expect @('pubkey.badpem'))
}

# 負面符號掃描（加密端不含解密端專屬符號，反之亦然）建立在「單檔部署、seal 與
# open 是兩份互不重疊的產物」之上。模組架構下加密端是複製整個 RunePost\，解密端
# 的程式碼本來就會一起過去，這個屬性不成立：只掃兩支薄入口腳本會變成必然通過，
# 掃模組則必然失敗。兩案因此以 INFO 記錄事實，而不是靜悄悄刪掉讓它從報表消失。
# 若「最小部署」仍是目標，可改成斷言 Public\Invoke-RuneSeal.ps1 的相依閉包不含
# 任何私鑰／解包函式——那守的是相依方向而非檔案內容，在模組架構下才成立。

Invoke-TCase 'C63' '負面符號掃描：加密端不含解密端專屬符號（模組架構下不成立）' -Tier Full {
    Info-Case ('加密端是複製整個 RunePost\ 資料夾，模組同時含 seal 與 open 兩側程式碼，' +
        '「加密端不含解密程式碼」不成立；只掃薄入口腳本則形同必然通過。以 INFO 記錄。')
}

Invoke-TCase 'C64' '負面符號掃描：解密端不含加密端專屬符號（模組架構下不成立）' -Tier Full {
    Info-Case '同 C63：此斷言的前提（兩份互不重疊的單檔產物）不存在。以 INFO 記錄。'
}


Write-Host ''
Write-Host '-- 隱藏案例（由規格不變量推導）--' -ForegroundColor Cyan

Invoke-TCase 'C36' '0 byte 檔單獨打包 roundtrip' -Tier Full -Needs @('Fx', 'KeyA') {
    $src = New-BinFile (Join-Path $script:Work 'fixtures\zero\empty.dat') 0
    $r = Invoke-Roundtrip -Name 'zero' -Source $src
    $c = Compare-Tree -Expected @{ 'empty.dat' = (Get-Sha $src) } -Actual (Get-TreeMap $r.Dest)
    Assert ($null -eq $c.Diff) $c.Diff
    return ('0 byte 檔還原成功（SHA e3b0c442…）')
}

# zip-slip：惡意封存的 entry 名稱不得讓檔案或目錄落在 Destination 之外。
# 四個分支各自獨立：檔案 entry 的 ../ 與 ..\，目錄 entry 的 ..\ 與 ../。
# 反斜線走的是「entry 名稱含 \ 一律拒絕」那條檢查，正斜線走的是「正規化後
# 的包含性判斷」，兩條是不同的程式碼路徑，缺一不可。
function Test-ZipSlip {
    param([string]$EntryName, [string]$Tag, [string]$LeakName, [switch]$DirEntry, [switch]$RequireRefuse)
    Assert-KdfAvailable
    $root = New-Dir (Join-Path $script:Work "unpack\zipslip_$Tag")
    $dest = Clear-Dir (Join-Path $root 'inner')
    $outside = Join-Path $root $LeakName
    if ([System.IO.File]::Exists($outside)) { [System.IO.File]::Delete($outside) }
    if ([System.IO.Directory]::Exists($outside)) { [System.IO.Directory]::Delete($outside, $true) }

    $zip = if ($DirEntry) { New-ZipWithDirEntry -EntryName $EntryName } else { New-ZipWithEntry -EntryName $EntryName }
    $t = New-ForgedRune -ZipBytes $zip -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) "zipslip_$Tag.txt")
    $r = Invoke-Open -Unpack $t -Destination $dest -KeyFile (Get-Fixture 'KeyA').KeyPath

    $leakedFile = [System.IO.File]::Exists($outside)
    $leakedDir = [System.IO.Directory]::Exists($outside)
    $leakBody = if ($leakedFile) { [System.IO.File]::ReadAllText($outside) } else { '' }
    if ($leakedFile) { [System.IO.File]::Delete($outside) }
    if ($leakedDir) { [System.IO.Directory]::Delete($outside, $true) }
    Assert (-not ($leakedFile -or $leakedDir)) `
    ("嚴重：ZIP entry '{0}' 在 Destination 之外落地（exit={1}，{2}報錯；內容 '{3}'）" -f `
            $EntryName, $r.ExitCode, $(if ($r.Failed) { '有' } else { '未' }), (Squash $leakBody 24))

    if ($RequireRefuse) {
        # 未逸出還不夠：必須以「不安全的封存路徑」明確拒絕，不可只說格式損壞，
        # 也不可默默略過該筆 entry 當作成功。
        $ev = Expect-OpenRefused -Res $r -Destination $dest -Category 'unsafe' -What ("ZIP entry '$EntryName'")
        return ("entry '{0}' 遭拒且未逸出；{1}" -f $EntryName, $ev)
    }
    return ("entry '{0}' 未逸出（exit={1}）：{2}" -f $EntryName, $r.ExitCode, (Squash $r.All 70))
}

Invoke-TCase 'C37' '解包不得逸出 Destination（zip 路徑安全）' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Test-ZipSlip -EntryName '../escaped.txt' -Tag 'fwd' -LeakName 'escaped.txt'
}

Invoke-TCase 'C41' 'zip-slip 變體：entry 名用反斜線 ..\ 不得逸出 Destination' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Test-ZipSlip -EntryName '..\pwned.txt' -Tag 'back' -LeakName 'pwned.txt' -RequireRefuse
}

Invoke-TCase 'C46' '目錄 entry 也要走 zip-slip 檢查：..\evil\（反斜線分支）' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Test-ZipSlip -EntryName '..\evil\' -Tag 'dirback' -LeakName 'evil' -DirEntry -RequireRefuse
}

Invoke-TCase 'C47' '目錄 entry 也要走 zip-slip 檢查：../evil2/（包含性判斷分支）' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Test-ZipSlip -EntryName '../evil2/' -Tag 'dirfwd' -LeakName 'evil2' -DirEntry -RequireRefuse
}

Invoke-TCase 'C42' 'wildcard 命中子目錄：須出聲警告，且解包後不留空目錄' -Tier Full -Needs @('Fx', 'KeyA') {
    $dir = New-Dir (Get-FxPath 'wcdir_sub')
    [void](New-TextFile (Join-Path $dir 'top.txt') 'top level file')
    [void](New-TextFile (Join-Path $dir 'subfolder\inside.txt') 'INSIDE-MUST-NOT-VANISH-SILENTLY')
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'wcdir_sub.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $p = Invoke-Seal -Pack (Join-Path $dir '*') -OutFile $out
    Assert (-not $p.TimedOut) 'Pack 逾時'
    Assert ($p.ExitCode -eq 0) ('Pack 應成功（僅需警告）但 exit={0}：{1}' -f $p.ExitCode, (Squash $p.All 160))
    Assert ([System.IO.File]::Exists($out)) 'Pack 未產生輸出檔'
    Assert-Msg -Text $p.All -Keys @('wildcard.skipdir') -What 'wildcard 命中目錄（靜默丟資料是不可接受的）'

    $dest = Clear-Dir (Join-Path $script:Work 'unpack\wcdir_sub')
    [void](Expect-Success (Invoke-Open -Unpack $out -Destination $dest -KeyFile (Get-Fixture 'KeyA').KeyPath) 'Unpack(wcdir_sub)')

    $files = Get-TreeMap $dest
    $dirs = @([System.IO.Directory]::EnumerateDirectories($dest, '*', [System.IO.SearchOption]::AllDirectories))
    Assert (@($files.Keys | Where-Object { $_ -match '(^|/)top\.txt$' }).Count -eq 1) ('top.txt 未正確還原：' + (($files.Keys) -join ','))
    Assert (-not ($files.Keys | Where-Object { $_ -match 'inside\.txt' })) '違反不遞迴：子目錄內的檔案被打包了'
    Assert ($dirs.Count -eq 0) ('解包後留下空目錄（不遞迴就不該產生目錄項目）：' + (($dirs | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
    $warn = ($p.All -split "`r?`n" | Where-Object { $_ -match 'WARNING|警告|略過|跳過' } | Select-Object -First 1)
    return ('已警告且只還原 top.txt、無空目錄；warn=' + (Squash $warn 70))
}

Invoke-TCase 'C43' '資料夾模式須保留空子目錄（含巢狀空目錄）' -Tier Full -Needs @('Fx', 'KeyA') {
    $dir = New-Dir (Get-FxPath 'emptydirs')
    [void](New-TextFile (Join-Path $dir 'keep\file.txt') 'only real file')
    [void](New-Dir (Join-Path $dir '空目錄'))
    [void](New-Dir (Join-Path $dir '空目錄2\深層空'))
    $r = Invoke-Roundtrip -Name 'emptydirs' -Source $dir

    $files = Get-TreeMap $r.Dest
    $c = Compare-Tree -Expected (Get-TreeMap $dir) -Actual $files -AllowRootPrefix 'emptydirs'
    Assert ($null -eq $c.Diff) $c.Diff
    $dirs = @([System.IO.Directory]::EnumerateDirectories($r.Dest, '*', [System.IO.SearchOption]::AllDirectories) |
            ForEach-Object { $_.Substring($r.Dest.Length + 1).Replace('\', '/') })
    foreach ($want in @('空目錄', '空目錄2/深層空')) {
        $hit = @($dirs | Where-Object { $_ -eq $want -or $_ -eq "emptydirs/$want" }).Count
        Assert ($hit -eq 1) ("空子目錄 '$want' 未被保留；實際目錄：" + (($dirs | Select-Object -First 6) -join ','))
    }
    return ('空目錄 與 空目錄2/深層空 皆保留;檔案 {0} 筆 SHA 一致;{1}' -f $files.Count, $c.Convention)
}

Invoke-TCase 'C44' '解包中途失敗須回滾：Destination 無殘留、無暫存資料夾' -Tier Core -Needs @('KdfInfo', 'KeyA') {
    Assert-KdfAvailable
    # 前兩筆合法、第三筆不安全 -> 前兩筆會先落地，之後才拋錯，藉此驗回滾
    $zip = New-ZipWithEntries -EntryNames @('good1.txt', 'sub/good2.txt', '../evil.txt')
    $t = New-ForgedRune -ZipBytes $zip -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'partial.txt')

    $root = New-Dir (Join-Path $script:Work 'unpack\rollback')
    $dest = Clear-Dir (Join-Path $root 'dest')
    $r = Invoke-Open -Unpack $t -Destination $dest -KeyFile (Get-Fixture 'KeyA').KeyPath

    $outside = Join-Path $root 'evil.txt'
    $leaked = [System.IO.File]::Exists($outside)
    if ($leaked) { [System.IO.File]::Delete($outside) }
    Assert (-not $leaked) '嚴重：../evil.txt 逸出到 Destination 之外'
    # Destination 完全乾淨（無檔案、無殘留目錄含暫存資料夾）由 Expect-OpenRefused 統一把關
    $ev = Expect-OpenRefused -Res $r -Destination $dest -What '含不安全項目的封存'
    return ('前 2 筆合法 + 第 3 筆不安全 -> 失敗且 Destination 完全乾淨；' + $ev)
}

Invoke-TCase 'C45' 'public.pem 內容為 P-384 → 須明確報曲線不符' -Tier Core -Needs @('Fx') {
    $sb = New-HomeSandbox -Name 'p384'
    $p384 = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP384)
    $pem = ConvertTo-Pem -Der $p384.ExportSubjectPublicKeyInfo() -Label 'PUBLIC KEY'
    [void](New-TextFile $sb.PubPath $pem)
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'p384.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $r = Invoke-Seal -Pack (Get-FxPath 'single\payload.bin') -OutFile $out -Env $sb.Env
    # 只比對 StdErr 由 Expect-SealRefused 統一負責：stdout 的進度橫幅本來就含
    # 「ECDH P-256」，拿合併輸出比對 curve 這一類會無條件命中。
    $ev = Expect-SealRefused -Res $r -OutFile $out -Category 'curve' -What 'P-384 的 public.pem'
    return ('P-384 的 public.pem 遭拒且錯誤訊息點明曲線；' + $ev)
}

Invoke-TCase 'C48' '回滾搬移不得破壞 Destination 既有的無關內容' -Tier Core -Needs @('CtWild', 'KeyA') {
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\merge')
    [void](New-TextFile (Join-Path $dest 'alpha.txt') 'OLD-CONTENT-WILL-COLLIDE')
    [void](New-TextFile (Join-Path $dest 'unrelated.txt') 'KEEP-ME')
    [void](New-TextFile (Join-Path $dest 'existingdir\note.txt') 'KEEP-ME-TOO')

    $r = Invoke-Open -Unpack (Get-Fixture 'CtWild').Out -Destination $dest -KeyFile (Get-Fixture 'KeyA').KeyPath
    [void](Expect-Success $r 'Unpack(既有內容合併)')

    # 硬性要求：與封存無關的既有資料不得被刪或改
    Assert ([System.IO.File]::Exists((Join-Path $dest 'unrelated.txt'))) '既有的無關檔案 unrelated.txt 被刪除了'
    Assert ([System.IO.File]::ReadAllText((Join-Path $dest 'unrelated.txt')) -eq 'KEEP-ME') '既有的無關檔案內容被改動'
    Assert ([System.IO.File]::Exists((Join-Path $dest 'existingdir\note.txt'))) '既有的無關子目錄內容被刪除了'
    Assert ([System.IO.File]::ReadAllText((Join-Path $dest 'existingdir\note.txt')) -eq 'KEEP-ME-TOO') '既有子目錄內檔案被改動'
    # 暫存資料夾不得殘留
    $tmp = @([System.IO.Directory]::EnumerateDirectories($dest, '.rune-tmp-*'))
    Assert ($tmp.Count -eq 0) ('殘留暫存資料夾：' + (($tmp | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
    # 同名檔案的處置（規格未定義，僅記錄實際語意）
    $alpha = [System.IO.File]::ReadAllText((Join-Path $dest 'alpha.txt'))
    $collide = if ($alpha -eq 'alpha') { '同名檔案被覆蓋' } elseif ($alpha -like 'OLD-*') { '同名檔案被保留' } else { "同名檔案內容=$alpha" }
    return ("無關檔案/子目錄完好、無暫存殘留；$collide")
}

Invoke-TCase 'C49' '深層長路徑 roundtrip（暫存資料夾前綴不得撐爆路徑長度）' -Tier Full -Needs @('Fx', 'KeyA') {
    $segs = @('層級目錄名稱abcdefghij') * 8
    $rel = ($segs -join '\')
    $srcRoot = Join-Path $script:Work 'fixtures\deeppath'
    $srcFile = Join-Path (Join-Path $srcRoot $rel) 'deep-payload.txt'
    try { [void](New-TextFile $srcFile 'deep content') }
    catch { Skip-Case ('本機無法建立該深度的來源路徑（' + $srcFile.Length + ' 字元），非受測物問題') }
    if (-not [System.IO.File]::Exists($srcFile)) { Skip-Case '來源深層路徑建立失敗' }

    $r = Invoke-Roundtrip -Name 'deeppath' -Source $srcRoot
    $c = Compare-Tree -Expected (Get-TreeMap $srcRoot) -Actual (Get-TreeMap $r.Dest) -AllowRootPrefix 'deeppath'
    Assert ($null -eq $c.Diff) $c.Diff
    $tmp = @([System.IO.Directory]::EnumerateDirectories($r.Dest, '.rune-tmp-*'))
    Assert ($tmp.Count -eq 0) '殘留暫存資料夾'
    return ('相對路徑 {0} 字元、來源全長 {1} 字元，含 .rune-tmp 前綴仍完整還原' -f $rel.Length, $srcFile.Length)
}

# 以「模組」身分使用受測物（不經入口腳本）。其餘案例全部經由 rune-seal.ps1 /
# rune-open.ps1，而那兩支自己會設 $ErrorActionPreference = 'Stop' 與 Set-StrictMode。
# 「使用者 Import-Module 之後直接呼叫函式」這條路徑因此零覆蓋，C67 / C68 補這個洞：
# 探針腳本刻意不設任何偏好（wrapper 給的是預設的 Continue、StrictMode 也是關的）。

Invoke-TCase 'C67' '以模組身分直接呼叫 Invoke-RuneSeal / Invoke-RuneOpen 完成 roundtrip（不經入口腳本）' -Tier Full -Needs @('Fx', 'KeyA') {
    $k = Get-Fixture 'KeyA'
    $src = Get-FxPath 'tree'
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'asmodule.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\asmodule')

    $probe = Join-Path $script:Work 'usemodule.ps1'
    # 刻意不寫 $ErrorActionPreference、不寫 Set-StrictMode：這一案要測的就是
    # 「呼叫端什麼都沒設」時模組自己站得住。
    [System.IO.File]::WriteAllText($probe, @'
Import-Module $env:RUNE_MODULE -Force
"CALLER-EAP=$ErrorActionPreference"
Invoke-RuneSeal -PackPath $env:RUNE_SRC -OutFilePath $env:RUNE_OUT -PublicKeyRef $env:RUNE_PUB
Invoke-RuneOpen -InFilePath $env:RUNE_OUT -DestinationPath $env:RUNE_DEST -KeyFilePath $env:RUNE_KEY
'DONE'
'@, $script:Utf8Bom)

    $r = Invoke-Transfer -ScriptPath $probe -EnvVars @{
        RUNE_MODULE = $script:ModuleRoot
        RUNE_SRC    = $src
        RUNE_OUT    = $out
        RUNE_DEST   = $dest
        RUNE_PUB    = $k.Sandbox.PubPath
        RUNE_KEY    = $k.KeyPath
    }
    [void](Expect-Success $r '以模組身分 roundtrip')
    Assert ($r.StdOut -match 'CALLER-EAP=Continue') `
    ('探針 session 的 EAP 不是預設的 Continue，這一案就失去意義：' + (Squash $r.StdOut 120))
    Assert ($r.StdOut -match 'DONE') '探針未跑完'
    Assert ([System.IO.File]::Exists($out)) '直接呼叫 Invoke-RuneSeal 未產生容器'

    $c = Read-Container $out
    Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2 -and $c.ContentType -eq 1) '產物不是合法的 RUNE v2 容器'
    $cmp = Compare-Tree -Expected (Get-TreeMap $src) -Actual (Get-TreeMap $dest) -AllowRootPrefix 'tree'
    Assert ($null -eq $cmp.Diff) $cmp.Diff
    return ('未經入口腳本、呼叫端偏好為預設（EAP=Continue、StrictMode 關）：{0} 檔位元一致還原；{1}' -f `
        (Get-TreeMap $src).Count, $cmp.Convention)
}

Invoke-TCase 'C68' '模組被直接呼叫時錯誤路徑仍終止（不會靜默往下跑）' -Tier Full -Needs @('Fx') {
    # 判準不是「有沒有印錯誤」，而是「失敗之後下一行有沒有被執行」——只印錯誤卻
    # 繼續跑才是最危險的靜默失敗。這一案守的是「模組被直接呼叫」這條路徑上的
    # 對外契約：失敗必須終止且不留半成品。
    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'modfail.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

    $probe = Join-Path $script:Work 'usemodule_fail.ps1'
    [System.IO.File]::WriteAllText($probe, @'
Import-Module $env:RUNE_MODULE -Force
Invoke-RuneSeal -PackPath $env:RUNE_SRC -OutFilePath $env:RUNE_OUT -PublicKeyRef $env:RUNE_PUB
'SENTINEL-NOT-TERMINATED'
'@, $script:Utf8Bom)

    $r = Invoke-Transfer -ScriptPath $probe -EnvVars @{
        RUNE_MODULE = $script:ModuleRoot
        RUNE_SRC    = (Get-FxPath 'single\payload.bin')
        RUNE_OUT    = $out
        RUNE_PUB    = (Join-Path $script:Work 'no_such_dir\nokey.pem')
    }
    Assert (-not $r.TimedOut) '子行程逾時'
    Assert ($r.Failed) '公鑰不存在卻沒有任何失敗跡象'
    Assert (-not ($r.All -match 'SENTINEL-NOT-TERMINATED')) `
    ('錯誤未終止：Invoke-RuneSeal 失敗後下一行仍被執行（靜默繼續）=> ' + (Squash $r.All 200))
    Assert (-not [System.IO.File]::Exists($out)) '公鑰不存在卻仍產生了輸出檔'
    Assert-Msg -Text $r.StdErr -Keys @('stage.nopub') -What '模組直接呼叫時的公鑰錯誤'
    return ('公鑰不存在 → 直接呼叫模組函式時仍為終止性錯誤，後續語句未執行、無輸出檔；' + (Squash $r.StdErr 80))
}


Write-Host ''
Write-Host '-- 私鑰儲存格式 / 私鑰匯出 --' -ForegroundColor Cyan

# 私鑰有三種儲存格式，共用 ~\.rune\private.key 這一個路徑，由內容自動判別。
# 需要密碼的案例一律以模組身分執行：SecureString 無法從命令列傳給入口腳本，
# 而本套件的子行程一律關閉標準輸入，不能靠互動提示輸入。

Invoke-TCase 'C69' '-Protect None（預設）：未加密 PKCS#8 PEM 落地、印出未加密警告、roundtrip 位元一致' -Tier Full -Needs @('Fx', 'KeyProtNone') {
    $kp = Get-Fixture 'KeyProtNone'
    Assert (-not $kp.Result.Failed) ('-GenerateKeys（預設 -Protect）失敗 => ' + (Squash $kp.Result.All 200))
    Assert ($kp.HasKey) '未產生 private.key'
    Assert ($null -ne $kp.PublicPem) '未寫出 public.pem'

    $text = [System.IO.File]::ReadAllText($kp.KeyPath)
    Assert ($text -match '^\s*-----BEGIN PRIVATE KEY-----') ('私鑰檔不是未加密 PKCS#8 PEM：' + (Squash $text 60))
    Assert ($text -notmatch 'ENCRYPTED') '未加密模式卻寫出 ENCRYPTED PRIVATE KEY'

    # 未加密警告：使用者必須被明白告知這個檔案沒有任何保護，以及後果是什麼
    Assert-Msg -Text $kp.Result.All -Keys @('plainkey.format', 'plainkey.warning') -What '-Protect None 的產生輸出'

    # 明文 PEM 可用標準 API 獨立載入，且與落地的 public.pem 是同一把
    $ind = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ind.ImportFromPem($text)
    Assert ([Convert]::ToHexString($ind.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($kp.PubSpki)) `
        '明文私鑰與同時寫出的 public.pem 不是同一把'

    $src = Get-FxPath 'tree'
    $r = Invoke-KeyRoundtrip -Key $kp -Name 'pnone' -Source $src
    $cmp = Compare-Tree -Expected (Get-TreeMap $src) -Actual (Get-TreeMap $r.Dest) -AllowRootPrefix 'tree'
    Assert ($null -eq $cmp.Diff) $cmp.Diff
    return ('標頭 -----BEGIN PRIVATE KEY-----、可獨立以 ImportFromPem 載入、與 public.pem 同一把；警告已印出；{0} 檔位元一致還原' -f (Get-TreeMap $src).Count)
}

Invoke-TCase 'C70' '-Protect Dpapi：DPAPI blob 落地、不印未加密警告、roundtrip 位元一致' -Tier Full -Needs @('Fx', 'KeyProtDpapi') {
    $kp = Get-Fixture 'KeyProtDpapi'
    Assert (-not $kp.Result.Failed) ('-GenerateKeys -Protect Dpapi 失敗 => ' + (Squash $kp.Result.All 200))
    Assert ($kp.HasKey) '未產生 private.key'

    $b = [System.IO.File]::ReadAllBytes($kp.KeyPath)
    $ascii = [System.Text.Encoding]::ASCII.GetString($b)
    Assert ($ascii -notmatch '-----BEGIN') 'DPAPI 模式的私鑰檔含 PEM 標頭'
    $unprotected = $null
    try {
        $unprotected = [System.Security.Cryptography.ProtectedData]::Unprotect($b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    } catch { }
    Assert ($null -ne $unprotected) 'DPAPI(CurrentUser, 無 entropy) 解不開這個私鑰檔'
    Assert-Msg -Text $kp.Result.All -Forbid @('plainkey.warning') -What '-Protect Dpapi 的產生輸出'

    $src = Get-FxPath 'tree'
    $r = Invoke-KeyRoundtrip -Key $kp -Name 'pdpapi' -Source $src
    $cmp = Compare-Tree -Expected (Get-TreeMap $src) -Actual (Get-TreeMap $r.Dest) -AllowRootPrefix 'tree'
    Assert ($null -eq $cmp.Diff) $cmp.Diff
    return ('{0}B 二進位、可用 DPAPI(CurrentUser) 解開、無 PEM 標頭、無未加密警告；{1} 檔位元一致還原' -f $b.Length, (Get-TreeMap $src).Count)
}

Invoke-TCase 'C71' '-Protect Passphrase：加密 PKCS#8 PEM 落地，密碼正確可完成 roundtrip' -Tier Full -Needs @('KeyPass') {
    $kp = Get-Fixture 'KeyPass'
    [void](Expect-Success $kp.Result '-Protect Passphrase roundtrip')
    $kv = ConvertFrom-ProbeOutput -Text $kp.Result.StdOut
    Assert ($kv['HOMEOK'] -eq 'True') '探針的家目錄未落在沙箱內'
    Assert ($kv['KEYHEAD'] -eq '-----BEGIN ENCRYPTED PRIVATE KEY-----') ('私鑰檔不是加密 PKCS#8 PEM：' + $kv['KEYHEAD'])
    Assert ($kv['DONE'] -eq '1') '探針未跑完'

    # 由測試端獨立確認：這個 PEM 沒有密碼就載不進來，有密碼才行
    $pem = [System.IO.File]::ReadAllText($kp.Sandbox.KeyPath)
    $noPw = $false
    try { ([System.Security.Cryptography.ECDiffieHellman]::Create()).ImportFromPem($pem) } catch { $noPw = $true }
    Assert $noPw '加密 PEM 竟可直接以 ImportFromPem 載入（內容未真的加密）'
    $withPw = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $withPw.ImportFromEncryptedPem($pem, $script:PassphraseText)
    Assert ($withPw.ExportParameters($false).Curve.Oid.Value -eq '1.2.840.10045.3.1.7') '加密 PEM 解出的不是 P-256'

    $cmp = Compare-Tree -Expected (Get-TreeMap $kp.Src) -Actual (Get-TreeMap $kp.Dest) -AllowRootPrefix 'tree'
    Assert ($null -eq $cmp.Diff) $cmp.Diff
    return ('標頭 -----BEGIN ENCRYPTED PRIVATE KEY-----、無密碼載不進來、有密碼解出 P-256；{0} 檔位元一致還原' -f (Get-TreeMap $kp.Src).Count)
}

Invoke-TCase 'C72' '加密 PKCS#8 PEM：密碼錯誤時明確報錯、不崩潰、不產生輸出' -Tier Full -Needs @('KeyPass') {
    $kp = Get-Fixture 'KeyPass'
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\ppass_wrong')

    $body = @'
Import-Module $env:RUNE_MODULE -Force
$pw = ConvertTo-SecureString $env:RUNE_PW -AsPlainText -Force
try {
    Invoke-RuneOpen -InFilePath $env:RUNE_CT -DestinationPath $env:RUNE_DEST -Passphrase $pw
    'RESULT=NO-THROW'
}
catch {
    'RESULT=THROWN'
    'MSG=' + ($_.Exception.Message -replace '\s+', ' ')
}
'@
    $r = Invoke-RuneProbe -Name 'ppass_wrong' -Body $body -EnvVars ($kp.Sandbox.Env + @{
            RUNE_PW = ($script:PassphraseText + '-wrong'); RUNE_CT = $kp.Out; RUNE_DEST = $dest
        })
    Assert (-not $r.TimedOut) '子行程逾時（可能卡在互動提示）'
    Assert (-not $r.Failed) ('密碼錯誤應是可捕捉的錯誤，不該讓行程崩潰：' + (Squash $r.All 200))
    $kv = ConvertFrom-ProbeOutput -Text $r.StdOut
    Assert ($kv['RESULT'] -eq 'THROWN') '密碼錯誤卻沒有報錯'
    Assert-Msg -Text $kv['MSG'] -Keys @('stage.key', 'passphrase') -What '密碼錯誤的訊息'
    Assert ((Get-TreeMap $dest).Count -eq 0) '密碼錯誤卻仍寫出檔案'
    return ('密碼錯誤 → 終止性錯誤且訊息指明密碼；目的資料夾無任何檔案；msg=' + (Squash $kv['MSG'] 90))
}

Invoke-TCase 'C73' '非互動且未提供密碼：兩條路徑都明確失敗且不卡住' -Tier Full -Needs @('KeyPass') {
    $kp = Get-Fixture 'KeyPass'

    # (a) 以密碼保護的私鑰解密，未給 -Passphrase
    $dest = Clear-Dir (Join-Path $script:Work 'unpack\ppass_nopw')
    $swA = [System.Diagnostics.Stopwatch]::StartNew()
    $ra = Invoke-Open -Unpack $kp.Out -Destination $dest -KeyFile $kp.Sandbox.KeyPath -Env $kp.Sandbox.Env -Timeout 45
    $swA.Stop()
    $evA = Expect-OpenRefused -Res $ra -Destination $dest -Category 'key' -What '非互動解密未提供密碼' `
        -Expect @('noninteractive', 'hint.passphrase')

    # (b) -GenerateKeys -Protect Passphrase，未給 -Passphrase
    $sb = New-HomeSandbox -Name 'nopw'
    $swB = [System.Diagnostics.Stopwatch]::StartNew()
    $rb = Invoke-Open -GenerateKeys -Protect 'Passphrase' -Env $sb.Env -Cwd $sb.Path -Timeout 45
    $swB.Stop()
    [void](Expect-OpenRefused -Res $rb -Category 'key' -What '非互動產生金鑰未提供密碼' `
            -NoFile @($sb.KeyPath, $sb.PubPath) -Expect @('noninteractive'))

    # 逾時上限 45s 只保證不會掛死整套；這裡再要求「很快就結束」，證明是主動拒絕而非等待輸入
    Assert ($swA.ElapsedMilliseconds -lt 30000 -and $swB.ElapsedMilliseconds -lt 30000) `
    ('結束太慢，疑似曾停在等待輸入：{0}ms / {1}ms' -f $swA.ElapsedMilliseconds, $swB.ElapsedMilliseconds)
    return ('-Unpack {0}ms、-GenerateKeys {1}ms 均主動拒絕（逾時上限 45s 未觸發），未留下任何檔案；{2}' -f `
            $swA.ElapsedMilliseconds, $swB.ElapsedMilliseconds, (Squash $evA 60))
}

Invoke-TCase 'C74' '既有 DPAPI 私鑰相容性：由測試獨立構造的 DPAPI blob 仍可解密' -Tier Full -Needs @('Fx', 'KeyA') {
    # 不經受測物產生金鑰：直接以 .NET 產生 P-256、輸出 PKCS#8、用
    # ProtectedData.Protect(CurrentUser, entropy=null) 保護後落地。這就是既有
    # ~\.rune\private.key 的位元組格式，本案要求它在改動後仍然讀得回來。
    $dir = New-Dir (Join-Path $script:Work 'legacykey')
    $keyPath = Join-Path $dir 'private.key'
    $pubPath = Join-Path $dir 'public.pem'
    $ec = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $pkcs8 = $ec.ExportPkcs8PrivateKey()
    $blob = [System.Security.Cryptography.ProtectedData]::Protect(
        $pkcs8, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($keyPath, $blob)
    [System.IO.File]::WriteAllText($pubPath, $ec.ExportSubjectPublicKeyInfoPem(), $script:Utf8NoBom)

    $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'legacy.txt'
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    [void](Expect-Success (Invoke-Seal -Pack (Get-FxPath 'wild\*.txt') -OutFile $out -PublicKey $pubPath) `
            'Pack(獨立構造的 DPAPI 金鑰)')
    [void](Assert-UnpackMatches -Txt $out -KeyFile $keyPath -DestName 'legacy' `
            -Expected (Get-WildExpectedMap) -AllowRootPrefix 'wild' -What 'Unpack(獨立構造的 DPAPI 金鑰)')

    # 同一把金鑰也要能導出公鑰（-ExportPublicKey 走的是同一條私鑰載入路徑）
    $rp = Invoke-Open -ExportPublicKey -KeyFile $keyPath
    [void](Expect-Success $rp 'ExportPublicKey(獨立構造的 DPAPI 金鑰)')
    $digest = [System.Security.Cryptography.SHA256]::HashData($ec.ExportSubjectPublicKeyInfo())
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $expectFp = ((0..7) | ForEach-Object { $hex.Substring($_ * 4, 4) }) -join '-'
    Assert ($rp.All -match [regex]::Escape($expectFp)) ('導出的指紋與獨立重算不符：' + (Squash $rp.All 200))
    return ('非受測物產生的 DPAPI blob（{0}B）可解密 3 檔且位元一致，指紋 RUNE-KEY {1} 與獨立重算相符' -f $blob.Length, $expectFp)
}

Invoke-TCase 'C75' '-ExportPrivateKey：從 DPAPI 私鑰匯出未加密 PKCS#8 PEM，可用來解開既有密文' -Tier Full -Needs @('CtWild', 'ExportedPlainKey') {
    $k = Get-Fixture 'KeyA'
    $ex = Get-Fixture 'ExportedPlainKey'
    [void](Expect-Success $ex.Result '-ExportPrivateKey(DPAPI → 明文 PEM)')
    Assert ([System.IO.File]::Exists($ex.Path)) '未產生匯出檔'
    $text = [System.IO.File]::ReadAllText($ex.Path)
    Assert ($text -match '^\s*-----BEGIN PRIVATE KEY-----') ('匯出檔不是未加密 PKCS#8 PEM：' + (Squash $text 60))
    Assert-Msg -Text $ex.Result.All -Keys @('plainkey.warning') -What '匯出未加密私鑰的輸出'

    # 匯出的是同一把金鑰：指紋必須與金鑰 A 的公鑰一致
    $digest = [System.Security.Cryptography.SHA256]::HashData($k.PubSpki)
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $expectFp = ((0..7) | ForEach-Object { $hex.Substring($_ * 4, 4) }) -join '-'
    Assert ($ex.Result.All -match [regex]::Escape($expectFp)) ('匯出時印出的指紋與金鑰 A 不符：' + (Squash $ex.Result.All 200))
    $ind = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ind.ImportFromPem($text)
    Assert ([Convert]::ToHexString($ind.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($k.PubSpki)) `
        '匯出檔的公鑰與金鑰 A 不是同一把'

    # 關鍵：用匯出檔解開「匯出之前就已經存在」的密文
    [void](Assert-UnpackMatches -Txt (Get-Fixture 'CtWild').Out -KeyFile $ex.Path -DestName 'exported_plain' `
            -Expected (Get-WildExpectedMap) -AllowRootPrefix 'wild' -What 'Unpack(匯出的明文 PEM)')
    return ('DPAPI 私鑰 → 未加密 PKCS#8 PEM（{0}B），指紋 RUNE-KEY {1} 不變，且可解開匯出前產生的密文（3 檔位元一致）' -f `
        (Get-Item -LiteralPath $ex.Path).Length, $expectFp)
}

Invoke-TCase 'C76' '-ExportPrivateKey -Protect Passphrase：匯出檔為加密 PKCS#8 PEM，需密碼才能使用' -Tier Full -Needs @('ExportedEncKey') {
    $ex = Get-Fixture 'ExportedEncKey'
    [void](Expect-Success $ex.Result '-ExportPrivateKey(DPAPI → 加密 PEM)')
    $kv = ConvertFrom-ProbeOutput -Text $ex.Result.StdOut
    Assert ($kv['HEAD'] -eq '-----BEGIN ENCRYPTED PRIVATE KEY-----') ('匯出檔不是加密 PKCS#8 PEM：' + $kv['HEAD'])
    Assert ($kv['NOPW'] -eq 'THROWN') '加密的匯出檔在未提供密碼時竟可直接使用'
    Assert-Msg -Text $kv['NOPWMSG'] -Keys @('noninteractive') -What '加密匯出檔未提供密碼的訊息'
    Assert ((Get-TreeMap $ex.DestBad).Count -eq 0) '未提供密碼卻仍寫出檔案'
    Assert ($kv['DONE'] -eq '1') '探針未跑完'
    $cmp = Compare-Tree -Expected (Get-WildExpectedMap) -Actual (Get-TreeMap $ex.DestOk) -AllowRootPrefix 'wild'
    Assert ($null -eq $cmp.Diff) $cmp.Diff
    return ('DPAPI 私鑰 → 加密 PKCS#8 PEM；無密碼被拒（無檔案產出），有密碼則 3 檔位元一致還原')
}

Invoke-TCase 'C77' '格式自動偵測：同一把私鑰的三種儲存格式對同一份密文結果相同' -Tier Full -Needs @('CtWild', 'ExportedPlainKey', 'ExportedEncKey') {
    $k = Get-Fixture 'KeyA'
    $plain = (Get-Fixture 'ExportedPlainKey').Path
    $enc = (Get-Fixture 'ExportedEncKey').Path
    # 三個檔案的內容格式必須真的不同，否則這一案等於測了三次同一件事
    foreach ($p in @(@{ N = 'Dpapi'; P = $k.KeyPath }, @{ N = 'PlainPem'; P = $plain }, @{ N = 'EncPem'; P = $enc })) {
        $head = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($p.P))
        $actual = if ($head -match '-----BEGIN ENCRYPTED PRIVATE KEY-----') { 'EncPem' }
        elseif ($head -match '-----BEGIN PRIVATE KEY-----') { 'PlainPem' } else { 'Dpapi' }
        Assert ($actual -eq $p.N) ('{0} 這一份的實際格式是 {1}' -f $p.N, $actual)
    }

    $expected = Get-WildExpectedMap
    foreach ($p in @(@{ N = 'dpapi'; P = $k.KeyPath }, @{ N = 'plain'; P = $plain })) {
        [void](Assert-UnpackMatches -Txt (Get-Fixture 'CtWild').Out -KeyFile $p.P -DestName ('detect_' + $p.N) `
                -Expected $expected -AllowRootPrefix 'wild' -What ('Unpack(' + $p.N + ')'))
    }

    $encDest = Clear-Dir (Join-Path $script:Work 'unpack\detect_enc')
    $body = @'
Import-Module $env:RUNE_MODULE -Force
$pw = ConvertTo-SecureString $env:RUNE_PW -AsPlainText -Force
Invoke-RuneOpen -InFilePath $env:RUNE_CT -DestinationPath $env:RUNE_DEST -KeyFilePath $env:RUNE_KEY -Passphrase $pw
'DONE=1'
'@
    $r = Invoke-RuneProbe -Name 'detectenc' -Body $body -EnvVars ($k.Sandbox.Env + @{
            RUNE_PW = $script:PassphraseText; RUNE_CT = (Get-Fixture 'CtWild').Out; RUNE_DEST = $encDest; RUNE_KEY = $enc
        })
    [void](Expect-Success $r 'Unpack(加密 PEM)')
    $c = Compare-Tree -Expected $expected -Actual (Get-TreeMap $encDest) -AllowRootPrefix 'wild'
    Assert ($null -eq $c.Diff) ('enc 格式的還原結果不符：' + $c.Diff)
    return ('同一份密文以 DPAPI／未加密 PEM／加密 PEM 三種私鑰檔解出的 3 檔內容完全相同；格式僅由檔案內容判別，皆未指定任何格式參數')
}

Invoke-TCase 'C78' '-ExportPrivateKey：-OutFile 已存在且未加 -Force → 拒絕，原檔一個位元都不變' -Tier Full -Needs @('ExportedPlainKey') {
    $ex = Get-Fixture 'ExportedPlainKey'
    $before = Get-Sha $ex.Path
    $lenBefore = (Get-Item -LiteralPath $ex.Path).Length
    $r = Invoke-Open -ExportPrivateKey -OutFile $ex.Path -KeyFile (Get-Fixture 'KeyA').KeyPath -Timeout 45
    $ev = Expect-OpenRefused -Res $r -Category 'exists' -What '-ExportPrivateKey 輸出檔已存在' `
        -Unchanged @{ $ex.Path = $before } -Expect @('hint.force')
    Assert ((Get-Item -LiteralPath $ex.Path).Length -eq $lenBefore) '既有的匯出檔長度改變了'
    return ("$ev；原檔 SHA-256 與長度皆未變")
}

Invoke-TCase 'C79' '-ExportPrivateKey：非互動環境未加 -Force → 拒絕確認，且不產生輸出檔' -Tier Full -Needs @('KeyA') {
    $outKey = Join-Path (New-Dir (Join-Path $script:Work 'keybackup')) 'noforce.pem'
    if ([System.IO.File]::Exists($outKey)) { [System.IO.File]::Delete($outKey) }
    $r = Invoke-Open -ExportPrivateKey -OutFile $outKey -KeyFile (Get-Fixture 'KeyA').KeyPath -Timeout 45
    $ev = Expect-OpenRefused -Res $r -Category 'key' -What '-ExportPrivateKey 非互動且無 -Force' `
        -NoFile @($outKey) -Expect @('noninteractive', 'hint.force')
    return ("$ev；未產生任何檔案")
}

Invoke-TCase 'C80' '私鑰檔權限：中斷繼承且只剩擁有者與 SYSTEM（三種格式與匯出檔皆然）' -Tier Core `
    -Needs @('KeyProtNone', 'KeyProtDpapi', 'KeyPass', 'ExportedPlainKey', 'ExportedEncKey') {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = @($me, 'S-1-5-18')
    $targets = @(
        @{ N = '-GenerateKeys None'; P = (Get-Fixture 'KeyProtNone').KeyPath }
        @{ N = '-GenerateKeys Dpapi'; P = (Get-Fixture 'KeyProtDpapi').KeyPath }
        @{ N = '-GenerateKeys Passphrase'; P = (Get-Fixture 'KeyPass').Sandbox.KeyPath }
        @{ N = '-ExportPrivateKey None'; P = (Get-Fixture 'ExportedPlainKey').Path }
        @{ N = '-ExportPrivateKey Passphrase'; P = (Get-Fixture 'ExportedEncKey').Path }
    )
    $seen = @()
    foreach ($t in $targets) {
        Assert ([System.IO.File]::Exists($t.P)) ('{0}：私鑰檔不存在 {1}' -f $t.N, $t.P)
        $acl = Get-Acl -LiteralPath $t.P
        Assert ($acl.AreAccessRulesProtected) ('{0}：權限仍繼承自父資料夾（未中斷繼承）' -f $t.N)
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $who = $rule.IdentityReference.Value
            Assert ($allowed -contains $sid) ('{0}：出現不該有的授權對象 {1}（{2}）' -f $t.N, $who, $sid)
            Assert (-not $rule.IsInherited) ('{0}：{1} 是繼承而來的項目' -f $t.N, $who)
            $seen += $who
        }
    }
    # 反面對照：公鑰不該被收斂（公鑰本來就是要交出去的），否則等於這條斷言測不出東西
    $pubAcl = Get-Acl -LiteralPath (Get-Fixture 'KeyProtNone').Sandbox.PubPath
    Assert (-not $pubAcl.AreAccessRulesProtected) 'public.pem 也被中斷繼承了，收斂範圍不該擴及公鑰'
    $pubHas = @($pubAcl.Access | Where-Object { $_.IdentityReference.Value -match 'Administrators|BUILTIN' }).Count
    return ('5 個私鑰檔皆中斷繼承、授權對象僅 {0}；同資料夾的 public.pem 仍為繼承（含 BUILTIN 項目 {1} 筆），證明收斂確有作用且未擴及公鑰' -f `
        (($seen | Sort-Object -Unique) -join ' / '), $pubHas)
}

Invoke-TCase 'C81' '私鑰保護方式標示在成功輸出的第一行，且走一般輸出串流' -Tier Full `
    -Needs @('KeyProtNone', 'KeyProtDpapi', 'ExportedPlainKey') {
    # 標示必須在 stdout：警告串流在輸出被重新導向時常被丟棄或另存，使用者不該
    # 因此不知道自己手上這把私鑰是不是明文。
    $checks = @(
        @{ N = '-GenerateKeys None'; O = (Get-Fixture 'KeyProtNone').Result.StdOut; K = 'plainkey.format' }
        @{ N = '-GenerateKeys Dpapi'; O = (Get-Fixture 'KeyProtDpapi').Result.StdOut; K = 'dpapi' }
        @{ N = '-ExportPrivateKey None'; O = (Get-Fixture 'ExportedPlainKey').Result.StdOut; K = 'plainkey.format' }
    )
    $lines = @()
    foreach ($c in $checks) {
        $first = @(($c.O -split "`r?`n") | Where-Object { $_.Trim().Length -gt 0 })[0]
        Assert ($null -ne $first) ('{0}：沒有任何輸出' -f $c.N)
        Assert ($first -notmatch '^\s*WARNING:') ('{0}：第一行是警告串流的內容，格式標示不該只靠警告：{1}' -f $c.N, (Squash $first 120))
        Assert-Msg -Text $first -Keys @($c.K) -What ($c.N + ' 的第一行')
        $lines += (Squash $first 60)
    }
    Assert ([string]::IsNullOrWhiteSpace((Get-Fixture 'KeyProtNone').Result.StdErr)) '成功路徑不該有 stderr 輸出'
    return ('三處成功輸出的第一行皆標示保護方式且非 WARNING 行：' + ($lines -join ' ｜ '))
}

Invoke-TCase 'C82' '-ExportPrivateKey 原子寫入：正常路徑不留 .tmp-* 殘留' -Tier Full -Needs @('KeyA') {
    $k = Get-Fixture 'KeyA'
    $dir = Clear-Dir (Join-Path $script:Work 'keybackup_atomic')
    $outKey = Join-Path $dir 'atomic.pem'

    # 連續匯出兩次（第二次走 -Force 覆蓋路徑），兩次都不得留下暫存檔
    foreach ($pass in @(1, 2)) {
        [void](Expect-Success (Invoke-Open -ExportPrivateKey -OutFile $outKey -KeyFile $k.KeyPath -Force) `
            ("-ExportPrivateKey 第 $pass 次"))
    }
    $files = @([System.IO.Directory]::EnumerateFiles($dir))
    $tmp = @($files | Where-Object { (Split-Path -Leaf $_) -like '*.tmp-*' })
    Assert ($tmp.Count -eq 0) ('留下暫存檔：' + (($tmp | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
    Assert ($files.Count -eq 1) ('輸出資料夾應只有 1 個檔案，實得 {0}：{1}' -f $files.Count, (($files | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
    $text = [System.IO.File]::ReadAllText($outKey)
    Assert ($text -match '-----BEGIN PRIVATE KEY-----' -and $text -match '-----END PRIVATE KEY-----') `
        '匯出檔不是完整的 PEM（頭尾標記不齊，疑似截斷）'
    $ind = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $ind.ImportFromPem($text)
    Assert ([Convert]::ToHexString($ind.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($k.PubSpki)) '匯出檔內容不是金鑰 A'
    return ('連續匯出 2 次（含 -Force 覆蓋），資料夾只剩 1 個完整可載入的 PEM，無 .tmp-* 殘留')
}

Invoke-TCase 'C83' '空的私鑰檔：直接報「空檔案」，不繞成 DPAPI 解保護失敗' -Tier Full -Needs @('CtWild', 'KeyA') {
    $emptyKey = Join-Path (New-Dir (Join-Path $script:Work 'emptykey')) 'private.key'
    [System.IO.File]::WriteAllBytes($emptyKey, [byte[]]@())
    Assert ((Get-Item -LiteralPath $emptyKey).Length -eq 0) '前置：測試檔不是 0 位元組'
    $r = Invoke-UnpackOnly -Txt (Get-Fixture 'CtWild').Out -KeyFile $emptyKey -DestName 'emptykey' -Timeout 45
    $ev = Expect-OpenRefused -Res $r -Destination (Get-UnpackDest 'emptykey') -Category 'key' -What '空的私鑰檔' `
        -Expect @('emptyfile') -Forbid @('dpapi')
    return ("$ev；訊息點名空檔案且未提及 DPAPI")
}

Invoke-TCase 'C40' '原始受測腳本（seal + open）自始至終未被修改' -Tier Core {
    $nowSeal = Get-Sha $script:SutSeal
    $nowOpen = Get-Sha $script:SutOpen
    Assert ($script:OrigHashSeal -eq $nowSeal) 'seal 產物在測試過程中被改動'
    Assert ($script:OrigHashOpen -eq $nowOpen) 'open 產物在測試過程中被改動'
    return ('seal SHA-256 {0}… / open SHA-256 {1}… 皆未變' -f $nowSeal.Substring(0, 16), $nowOpen.Substring(0, 16))
}

# ==============================================================================
# 15. 報表
# ==============================================================================

$pass = @($script:Results | Where-Object Result -EQ 'PASS').Count
$fail = @($script:Results | Where-Object Result -EQ 'FAIL').Count
$skip = @($script:Results | Where-Object Result -EQ 'SKIP').Count
$info = @($script:Results | Where-Object Result -EQ 'INFO').Count

$coreCount = @($script:Registered | Where-Object Tier -EQ 'Core').Count
$fullCount = $script:Registered.Count - $coreCount

$table = $script:Results | Select-Object `
@{N = '編號'; E = { $_.No } },
@{N = '案例'; E = { Squash $_.Case 44 } },
@{N = '結果'; E = { $_.Result } },
@{N = '證據摘要'; E = { Squash $_.Evidence 96 } }

Write-Host ''
Write-Host '================================ 驗收報表 ================================' -ForegroundColor Cyan
$table | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host

if ($script:EscapeNotes.Count) {
    Write-Host '沙箱逃逸警告：' -ForegroundColor Yellow
    $script:EscapeNotes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

# 註冊數與執行數分開報：只看 PASS/FAIL 無法分辨「全綠」與「其實只跑了幾案」。
$summary = ('註冊 {0} 案（Core {1} / Full-only {2}）；本次層級 {3}{4} 實際執行 {5} 案：PASS {6} / FAIL {7} / SKIP {8} / INFO {9}' -f `
        $script:Registered.Count, $coreCount, $fullCount, $script:RunTier,
    $(if ($Filter) { "、Filter=$Filter，" } else { '，' }),
    $script:Results.Count, $pass, $fail, $skip, $info)
Write-Host $summary -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
$expectedRun = if ($script:RunTier -eq 'Core') { $coreCount } else { $script:Registered.Count }
if (-not $Filter -and $script:Results.Count -ne $expectedRun) {
    Write-Host ('警告：本層級應執行 {0} 案，實際只執行 {1} 案' -f $expectedRun, $script:Results.Count) -ForegroundColor Red
}
Write-Host ('工作目錄：{0}' -f $script:Work)

# 報表／log 跟著 -WorkRoot 走，不寫死在本腳本所在目錄——受審物常是唯讀 checkout。
$reportPath = Join-Path $WorkRoot 'verify-report.txt'
$logPath = Join-Path $WorkRoot 'verify-log.txt'
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('runepost 驗收報表（規格 v2，rune-seal + rune-open）')
[void]$sb.AppendLine('RepoRoot：' + $script:RepoRoot)
[void]$sb.AppendLine('時間：' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
[void]$sb.AppendLine('')
[void]$sb.AppendLine(($table | Format-Table -AutoSize -Wrap | Out-String -Width 200))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('案例層級：')
foreach ($r in $script:Registered) { [void]$sb.AppendLine(('  {0,-6} {1}' -f $r.No, $r.Tier)) }
[void]$sb.AppendLine('')
[void]$sb.AppendLine('完整證據：')
foreach ($r in $script:Results) {
    [void]$sb.AppendLine(('{0} [{1}] {2}' -f $r.No, $r.Result, $r.Case))
    [void]$sb.AppendLine('     ' + $r.Evidence)
}
if ($script:EscapeNotes.Count) { [void]$sb.AppendLine('沙箱逃逸：' + ($script:EscapeNotes -join ' | ')) }
[void]$sb.AppendLine($summary)
[System.IO.File]::WriteAllText($reportPath, $sb.ToString(), $script:Utf8Bom)
[System.IO.File]::WriteAllLines($logPath, $script:LogLines, $script:Utf8Bom)
Write-Host ('報表：{0}' -f $reportPath)

exit ([int]($fail -gt 0))
