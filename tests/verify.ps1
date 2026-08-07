#Requires -Version 7.2
<#
.SYNOPSIS
    runepost 獨立驗收腳本（規格 v2 / 容器 version 0x02 / ECDH P-256 + HKDF-SHA256 + AES-256-GCM）

.DESCRIPTION
    本腳本只依據凍結規格撰寫，未讀取任何受測實作原始碼。
    對 dist\rune-seal.ps1（加密端）與 dist\rune-open.ps1（解密端 + 金鑰管理）
    兩個產物跑一套完整案例；-Pack 相關案例一律對 rune-seal.ps1 執行，
    -Unpack / -GenerateKeys / -ExportPublicKey 相關案例一律對 rune-open.ps1 執行。

.PARAMETER RepoRoot
    repo 根目錄（內含 dist\rune-seal.ps1 / dist\rune-open.ps1）。

.EXAMPLE
    pwsh -File .\verify.ps1 -RepoRoot Z:\path\to\repo
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
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:LogLines = [System.Collections.Generic.List[string]]::new()
$script:Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:Utf8Bom = [System.Text.UTF8Encoding]::new($true)

$script:RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$script:SealScript = Join-Path $script:RepoRoot 'dist\rune-seal.ps1'
$script:OpenScript = Join-Path $script:RepoRoot 'dist\rune-open.ps1'

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

    if ($Filter -and $Id -notmatch $Filter) { return }

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
    }
    Write-Log ("RUN {0} => exit={1} stderr={2}" -f $res.Args, $res.ExitCode, (Squash $se 200))
    return $res
}

# 錯誤訊息「指明環節」的關鍵字（中英雙語，避免語系造成偽陰性）
$script:ErrPatterns = @{
    base64  = 'base64|Base64|BASE64|編碼|解碼|encod|decod'
    format  = 'magic|RUNE|格式|標頭|檔頭|header|不符|無法辨識|not a valid|不是|無效'
    version = '版本|version|不支援|unsupported|0x0|格式|magic'
    key     = '私鑰|金鑰|key|解鑰|DPAPI|解不開|讀不到|無法讀取|無法解密|not found|decrypt|unprotect'
    tag     = '損壞|竄改|corrupt|tamper|驗證失敗|校驗|完整性|tag|GCM|authentication|內容'
    unzip   = '解壓|解壓縮|decompress|Brotli|brotli|壓縮|zip|ZIP|解包|封存|archive|損壞'
    nopub   = '公鑰|public key|public\.pem'
    exists  = '已存在|存在|exists|Force|覆蓋|overwrite'
    nomatch = '找不到|沒有|未符合|不符合|沒有符合|no file|match|符合|空'
    input   = '找不到|不存在|not found|無效|invalid|路徑|path'
    param   = 'Parameter set|參數|ParameterBinding|不能同時|互斥|cannot be resolved|Missing an argument|遺失|必要|Mandatory|ParameterArgumentValidation|cannot be found'
    # 「不安全的封存路徑」必須是獨立語意，不可只用「格式損壞」搪塞
    unsafe  = '不安全|逸出|逃逸|穿越|越界|非法路徑|不合法的路徑|路徑不安全|traversal|unsafe|zip.?slip'
    # 靜態公鑰曲線不符：必須明講 P-256，不能只丟 .NET 原始訊息
    curve   = 'P-?256|prime256|nistP256|曲線'
}

function Expect-Failure {
    <#
        -ErrOnly：只比對 $Res.StdErr，不含 $Res.StdOut。

        為什麼需要：rune-seal.ps1 只要成功載入公鑰，就會在「打包中」之前無條件印出
        「收件人公鑰指紋：RUNE-KEY …（請與解密端 …指紋逐字比對；不符代表公鑰可能已
        被掉包）」這段橫幅。這段橫幅本身就含 RUNE（→ format 類的 'RUNE'）、KEY（→
        key 類的 'key'，-match 預設不分大小寫）、公鑰（→ nopub 類的 '公鑰'），所以只
        要拿 $Res.All（stdout+stderr）比對 format / key / nopub 這三類，任何 seal 端
        失敗案例都會無條件命中——不管真正的錯誤訊息有沒有指明環節。
        真正的錯誤訊息一律經頂層 catch 用 [Console]::Error.WriteLine 印到 stderr（見
        flow/seal-main.ps1 / flow/open-main.ps1 的進入點），所以只比對 StdErr 才是
        比對「錯誤訊息本身」，而不是被成功路徑的進度輸出污染。
        seal 端斷言 format / key / nopub 這三類時必須加 -ErrOnly；其餘類別（exists /
        nomatch / input / param / tag / unsafe / curve / …）不受銀幕橫幅影響，可維持
        比對 $Res.All 不變。
    #>
    param($Res, [string]$Category, [string]$What, [switch]$ErrOnly)
    Assert (-not $Res.TimedOut) "$What：子行程逾時（可能卡在互動提示）"
    Assert ($Res.Failed) ("$What：應該失敗卻成功了 (exit={0}, stderr 空)" -f $Res.ExitCode)
    $msg = if ($ErrOnly) { $Res.StdErr } else { $Res.All }
    $pat = $script:ErrPatterns[$Category]
    Assert ($msg -match $pat) ("$What：有失敗但訊息未指明環節[$Category] => " + (Squash $msg 200))
    return ("exit={0}; msg={1}" -f $Res.ExitCode, (Squash $msg 90))
}

function Expect-Success {
    param($Res, [string]$What)
    Assert (-not $Res.TimedOut) "$What：子行程逾時"
    Assert (-not $Res.Failed) ("$What：失敗 exit={0} => {1}" -f $Res.ExitCode, (Squash $Res.All 220))
    return $Res
}

# ==============================================================================
# 2. 檔案 / 目錄 / 雜湊工具（全部走 .NET，避開 PowerShell 萬用字元路徑陷阱）
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
# 3. 容器解析 / 重建（規格 v2）
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
        Path       = $TxtPath
        Raw        = $raw
        Lines      = $lines
        Bytes      = $bytes
        Magic      = $magic
        Version    = $version
        ContentType = $contentType
        EpkLen     = $epkLen
        Epk        = [byte[]]$epk
        Nonce      = [byte[]]$nonce
        Tag        = [byte[]]$tag
        Cipher     = [byte[]]$ct
        HeaderSize = 8 + $epkLen
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

function New-AesGcm {
    param([byte[]]$Key)
    try { return [System.Security.Cryptography.AesGcm]::new($Key, 16) }
    catch { return [System.Security.Cryptography.AesGcm]::new($Key) }
}

# ==============================================================================
# 4. ZIP 中央目錄白盒解析（不靠 ZipArchive，直接看旗標與壓縮方法）
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

# ==============================================================================
# 5. 獨立解密鏈：DPAPI -> ECDH -> HKDF-SHA256 -> AES-GCM -> Brotli -> Zip
#    規格未定義 HKDF 的 salt/info，因此以窮舉候選還原；全數失敗僅記 INFO。
# ==============================================================================

function Import-PrivateKeyFromBlob {
    param([string]$BlobPath)
    $blob = [System.IO.File]::ReadAllBytes($BlobPath)
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

# ==============================================================================
# 6. 受測腳本解析
#    公鑰改為執行期讀檔後，測試不再製作任何腳本副本、不再注入任何內容，
#    一律直接對受測物原檔執行；此處只留下「內嵌是否已徹底移除」的偵測器。
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

# ==============================================================================
# 7. 沙箱家目錄 + 受測物 -GenerateKeys 取得測試金鑰
# ==============================================================================

function New-HomeSandbox {
    param([string]$Name)
    $dir = New-Dir (Join-Path $script:Work "home_$Name")
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

# 使用者真實家目錄的保護：偵測沙箱逃逸
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

function New-TestKeyPair {
    param([string]$Name, [string]$ScriptPath)
    $sb = New-HomeSandbox -Name $Name
    $res = Invoke-Transfer -ScriptPath $ScriptPath -Arguments @('-GenerateKeys') -EnvVars $sb.Env -WorkDir $sb.Path
    $escaped = Assert-NoHomeEscape -When "-GenerateKeys($Name)"
    $keyPath = $sb.KeyPath
    if (-not [System.IO.File]::Exists($keyPath)) {
        # 可能寫在沙箱其他位置，掃描沙箱
        $found = @([System.IO.Directory]::EnumerateFiles($sb.Path, 'private.key', [System.IO.SearchOption]::AllDirectories))
        if ($found.Count -gt 0) { $keyPath = $found[0] }
        elseif ($escaped) { $keyPath = $escaped }
    }
    $pem = Get-PemBlock -Text $res.All
    return [pscustomobject]@{
        Name     = $Name
        Sandbox  = $sb
        Result   = $res
        KeyPath  = $keyPath
        HasKey   = [System.IO.File]::Exists($keyPath)
        PublicPem = $pem
        Escaped  = [bool]$escaped
    }
}

# 打包 + 解包的共用流程：Pack 一律用當前軌的 $script:SutSeal，Unpack 一律用 $script:SutOpen。
# 兩者是 $script: 範圍變數，由 Invoke-VerifyTrack 在每一軌開始時設定，函式本身只定義一次。
function Invoke-Roundtrip {
    param([string]$Name, [string]$Source, [string]$OutTxt, [string[]]$ExtraPack = @())
    $out = if ($OutTxt) { $OutTxt } else { Join-Path $script:Work "out\$Name.txt" }
    [void](New-Dir ([System.IO.Path]::GetDirectoryName($out)))
    if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
    $dest = New-Dir (Join-Path $script:Work "unpack\$Name")
    Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $p = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments (@('-Pack', $Source, '-OutFile', $out) + $ExtraPack) -EnvVars $script:KeyA.Sandbox.Env
    [void](Expect-Success $p "Pack($Name)")
    Assert ([System.IO.File]::Exists($out)) "Pack($Name) 未產生輸出檔 $out"

    $u = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $out, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env
    [void](Expect-Success $u "Unpack($Name)")
    return [pscustomobject]@{ Out = $out; Dest = $dest; Pack = $p; Unpack = $u }
}

function Copy-Container {
    param([string]$Src, [string]$Name)
    $dst = Join-Path (New-Dir (Join-Path $script:Work 'tamper')) $Name
    [System.IO.File]::Copy($Src, $dst, $true)
    return $dst
}

function Invoke-UnpackOnly {
    param([string]$Txt, [string]$KeyFile, [string]$DestName, [string[]]$Extra = @())
    $dest = New-Dir (Join-Path $script:Work "unpack\$DestName")
    $a = @('-Unpack', $Txt, '-Destination', $dest)
    if ($KeyFile) { $a += @('-KeyFile', $KeyFile) }
    $a += $Extra
    return Invoke-Transfer -ScriptPath $script:SutOpen -Arguments $a -EnvVars $script:KeyA.Sandbox.Env
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

# 以受測物的收件人公鑰 + C08 還原出的 KDF 參數，偽造一個「密碼學上完全合法」的容器
function New-ForgedRune {
    param([byte[]]$ZipBytes, [string]$Path, [byte]$ContentType = 1)
    Assert ($null -ne $script:KdfInfo) '需 C08 還原 KDF 參數'
    $plain = Compress-Brotli -Data $ZipBytes

    $eph = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $rec = [System.Security.Cryptography.ECDiffieHellman]::Create()
    $rec.ImportSubjectPublicKeyInfo($script:PubSpkiA, [ref]([int]0))
    $z = $eph.DeriveRawSecretAgreement($rec.PublicKey)
    $epk = $eph.ExportSubjectPublicKeyInfo()
    $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

    $hdr = [System.Collections.Generic.List[byte]]::new()
    $hdr.AddRange([System.Text.Encoding]::ASCII.GetBytes('RUNE'))
    $hdr.Add(2)
    $hdr.Add($ContentType)     # contentType（預設 0x01 = 檔案樹）
    $hdr.Add([byte]($epk.Length -band 0xFF)); $hdr.Add([byte](($epk.Length -shr 8) -band 0xFF))
    $hdr.AddRange($epk)

    $m = [regex]::Match($script:KdfInfo.Label, 'salt=([^,]+),info=([^)]+)')
    Assert ($m.Success) '無法沿用 C08 還原出的 KDF 參數'
    $fake = [pscustomobject]@{ Nonce = $nonce; Epk = $epk; Bytes = $hdr.ToArray(); HeaderSize = $hdr.Count }
    $cand = Get-KdfCandidates -Container $fake -RecipientSpki $script:PubSpkiA
    $key = [System.Security.Cryptography.HKDF]::DeriveKey(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, $z, 32,
        $cand.Salts[$m.Groups[1].Value], $cand.Infos[$m.Groups[2].Value])

    $ct = [byte[]]::new($plain.Length); $tag = [byte[]]::new(16)
    $gcm = New-AesGcm -Key $key
    switch ($script:KdfInfo.Aad) {
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
# 8. wrapper 落地（兩軌共用，與受測腳本無關）
# ==============================================================================

Write-Host ''
Write-Host '========== runepost 獨立驗收（規格 v2 / container 0x02 / rune-seal + rune-open）==========' -ForegroundColor Cyan

if ($Clean -and (Test-Path -LiteralPath $script:Work)) {
    Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
}
[void](New-Dir $script:Work)
$script:WrapperPath = Join-Path $script:Work 'wrapper.ps1'
[System.IO.File]::WriteAllText($script:WrapperPath, $script:WrapperSource, $script:Utf8Bom)

# ==============================================================================
# 9. 驗證主體：對 (SealScript, OpenScript) = (rune-seal.ps1, rune-open.ps1) 跑完整套案例
# ==============================================================================

function Invoke-VerifyTrack {
    param(
        [string]$SealScript,
        [string]$OpenScript
    )

    $script:Work = $WorkRoot
    [void](New-Dir $script:Work)

    function Invoke-TCase {
        param([string]$Id, [string]$Name, [scriptblock]$Body)
        Invoke-Case -Id $Id -Name $Name -Body $Body
    }

    $script:SutSeal = $null
    $script:SutOpen = $null
    $script:OrigHashSeal = $null
    $script:OrigHashOpen = $null
    $script:KeyA = $null
    $script:KeyB = $null
    $script:PubPemA = $null
    $script:PubSpkiA = $null
    $script:EcdhA = $null
    $script:KdfInfo = $null

    Write-Host ''
    Write-Host '-- 前置 --' -ForegroundColor Cyan

    Invoke-TCase 'P1a' '受測腳本存在且語法可解析（seal）' {
        Assert ([System.IO.File]::Exists($SealScript)) "找不到受測腳本（seal）：$SealScript"
        $script:SutSeal = [System.IO.Path]::GetFullPath($SealScript)
        $script:OrigHashSeal = Get-Sha $script:SutSeal
        $text = [System.IO.File]::ReadAllText($script:SutSeal)
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
        Assert ($e.Count -eq 0) ('解析錯誤 {0} 個：{1}' -f $e.Count, (Squash ($e[0].Message) 120))
        return ('{0}；{1} 位元組；語法 OK' -f (Split-Path -Leaf $script:SutSeal), (Get-Item -LiteralPath $script:SutSeal).Length)
    }

    Invoke-TCase 'P1b' '受測腳本存在且語法可解析（open）' {
        Assert ([System.IO.File]::Exists($OpenScript)) "找不到受測腳本（open）：$OpenScript"
        $script:SutOpen = [System.IO.Path]::GetFullPath($OpenScript)
        $script:OrigHashOpen = Get-Sha $script:SutOpen
        $text = [System.IO.File]::ReadAllText($script:SutOpen)
        $t = $null; $e = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
        Assert ($e.Count -eq 0) ('解析錯誤 {0} 個：{1}' -f $e.Count, (Squash ($e[0].Message) 120))
        return ('{0}；{1} 位元組；語法 OK' -f (Split-Path -Leaf $script:SutOpen), (Get-Item -LiteralPath $script:SutOpen).Length)
    }

    Invoke-TCase 'P2' '產物中不存在任何 $PublicKeyPem 賦值（公鑰已徹底外部化；seal + open 皆須檢查）' {
        Assert ($null -ne $script:SutSeal -and $null -ne $script:SutOpen) '前置 P1a/P1b 未通過'
        foreach ($pair in @(@{ N = 'seal'; P = $script:SutSeal }, @{ N = 'open'; P = $script:SutOpen })) {
            $text = [System.IO.File]::ReadAllText($pair.P)
            $f = Find-PublicKeyAssignment -Text $text
            $where = if ($null -ne $f.Hit) { $f.Hit.Extent.StartLineNumber } else { 0 }
            Assert ($null -eq $f.Hit) ('{0} 產物仍保留 $PublicKeyPem 賦值（行 {1}）：內嵌公鑰未徹底移除' -f $pair.N, $where)
            Assert (-not ($text -match 'PublicKeyPem')) ('{0} 產物仍出現 PublicKeyPem 字樣，內嵌公鑰的路徑未清乾淨' -f $pair.N)
        }
        return ('seal + open 兩產物皆無 $PublicKeyPem 賦值、無 PublicKeyPem 字樣；公鑰改為執行期讀取')
    }

    Invoke-TCase 'P3' '家目錄沙箱可用（不污染真實 ~\.rune）' {
        $sb = New-HomeSandbox -Name 'probe'
        $probe = Join-Path $script:Work 'homeprobe.ps1'
        [System.IO.File]::WriteAllText($probe, '"H=$HOME"; "T=" + (Resolve-Path ~).ProviderPath; "U=$env:USERPROFILE"', $script:Utf8Bom)
        $r = Invoke-Transfer -ScriptPath $probe -EnvVars $sb.Env -WorkDir $sb.Path
        $ok = ($r.StdOut -split "`r?`n" | Where-Object { $_ -match '^[HTU]=' } | ForEach-Object { $_.Substring(2) } | Where-Object { $_ -notlike "$($sb.Path)*" })
        Assert (-not $ok) ('沙箱未完全生效：' + (Squash $r.StdOut 120))
        return ('~ / $HOME / $env:USERPROFILE 皆指向沙箱；真實私鑰存在={0}' -f $script:RealKeyExisted)
    }

    Invoke-TCase 'P4' '受測物 -GenerateKeys 產生測試金鑰 A（open）' {
        Assert ($null -ne $script:SutOpen) '前置 P1b 未通過'
        $script:KeyA = New-TestKeyPair -Name 'A' -ScriptPath $script:SutOpen
        Assert ($script:KeyA.HasKey) ('未在 ~\.rune\private.key 產生私鑰；輸出=' + (Squash $script:KeyA.Result.All 160))
        Assert ($null -ne $script:KeyA.PublicPem) ('-GenerateKeys 未印出 PUBLIC KEY PEM 區塊；輸出=' + (Squash $script:KeyA.Result.All 160))
        $script:PubPemA = $script:KeyA.PublicPem
        $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
        $ec.ImportFromPem($script:PubPemA)
        $script:PubSpkiA = $ec.ExportSubjectPublicKeyInfo()
        $curve = $ec.ExportParameters($false).Curve
        $isP256 = ($curve.Oid.Value -eq '1.2.840.10045.3.1.7') -or ($curve.Oid.FriendlyName -match 'nistP256|P-256|prime256')
        Assert $isP256 ('公鑰不是 P-256：' + $curve.Oid.Value + '/' + $curve.Oid.FriendlyName)
        $note = if ($script:KeyA.Escaped) { '（注意：寫入未受沙箱控制的位置，已還原）' } else { '' }
        return ('私鑰 {0} 位元組；公鑰 P-256 SPKI {1}B{2}' -f (Get-Item -LiteralPath $script:KeyA.KeyPath).Length, $script:PubSpkiA.Length, $note)
    }

    Invoke-TCase 'P5' '產生第二組測試金鑰 B（供錯誤私鑰案例）' {
        Assert ($null -ne $script:SutOpen) '前置 P1b 未通過'
        $script:KeyB = New-TestKeyPair -Name 'B' -ScriptPath $script:SutOpen
        Assert ($script:KeyB.HasKey) '第二組私鑰未產生'
        Assert ((Get-Sha $script:KeyB.KeyPath) -ne (Get-Sha $script:KeyA.KeyPath)) '兩次 -GenerateKeys 產生相同的私鑰 blob（金鑰未隨機）'
        return ('金鑰 B 就緒；與 A 的 blob 不同')
    }

    Invoke-TCase 'P6' '沙箱家目錄已備妥 public.pem（不再製作任何腳本副本）' {
        Assert ($null -ne $script:PubPemA) '前置 P4 未通過'
        $pub = $script:KeyA.Sandbox.PubPath
        Assert ([System.IO.File]::Exists($pub)) "-GenerateKeys 未在沙箱家目錄寫出 public.pem：$pub"
        $onDisk = Get-PemBlock -Text ([System.IO.File]::ReadAllText($pub))
        Assert ($null -ne $onDisk) 'public.pem 內容不是合法的 PUBLIC KEY PEM 區塊'
        $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
        $ec.ImportFromPem($onDisk)
        Assert ([Convert]::ToHexString($ec.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($script:PubSpkiA)) `
            'public.pem 內的公鑰與 -GenerateKeys 印出的 PEM 不是同一把'
        return ('沙箱 ~\.rune\public.pem 就緒且與印出的公鑰一致；seal / open 皆直接對原檔執行，全程未製作任何腳本副本')
    }

    # 前置未過就沒有意義往下跑（只看本軌新增的 P 系列結果，不受另一軌影響）
    $preFailCount = @($script:Results | Where-Object { $_.No -like 'P*' -and $_.Result -eq 'FAIL' }).Count
    $trackCanRun = ($preFailCount -eq 0)

    # ------- 共用測試素材 -------
    function Initialize-Fixtures {
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
        return $f
    }

    $script:Fx = $null
    if ($trackCanRun) { $script:Fx = Initialize-Fixtures }

    if (-not $trackCanRun) {
        Write-Host ''
        Write-Host '前置作業失敗，後續案例全部跳過。' -ForegroundColor Red
        return
    }

    Write-Host ''
    Write-Host '-- Roundtrip --' -ForegroundColor Cyan

    Invoke-TCase 'C01' '單檔 roundtrip（256KB 二進位，SHA-256 逐檔比對）' {
        $src = Join-Path $script:Fx 'single\payload.bin'
        $r = Invoke-Roundtrip -Name 'single' -Source $src
        $script:CtSingle = $r.Out
        $exp = @{ 'payload.bin' = (Get-Sha $src) }
        $act = Get-TreeMap $r.Dest
        $c = Compare-Tree -Expected $exp -Actual $act
        Assert ($null -eq $c.Diff) $c.Diff
        return ('1 檔位元完全一致；SHA={0}…；容器 {1}B' -f (Get-Sha $src).Substring(0, 12), (Get-Item -LiteralPath $r.Out).Length)
    }

    Invoke-TCase 'C02' 'wildcard（含中文檔名）roundtrip 且不遞迴' {
        $dir = Join-Path $script:Fx 'wild'
        $r = Invoke-Roundtrip -Name 'wild' -Source (Join-Path $dir '*.txt')
        $script:CtWild = $r.Out
        $exp = @{}
        foreach ($n in @('alpha.txt', '中文檔名測試.txt', '第二個 檔案.txt')) { $exp[$n] = Get-Sha (Join-Path $dir $n) }
        $act = Get-TreeMap $r.Dest
        $c = Compare-Tree -Expected $exp -Actual $act -AllowRootPrefix 'wild'
        Assert ($null -eq $c.Diff) $c.Diff
        Assert (-not ($act.Keys | Where-Object { $_ -match 'nested\.txt' })) '違反不遞迴：子目錄檔案被打包'
        Assert (-not ($act.Keys | Where-Object { $_ -match 'skip-me\.md' })) 'wildcard 匹配錯誤：非 .txt 被打包'
        return ('3 檔（含中文/空白檔名）一致；子目錄與非匹配副檔名皆未收入；{0}' -f $c.Convention)
    }

    Invoke-TCase 'C03' '資料夾遞迴 roundtrip（中文子目錄、深層、同名不同層）' {
        $dir = Join-Path $script:Fx 'tree'
        $r = Invoke-Roundtrip -Name 'tree' -Source $dir
        $script:CtTree = $r.Out
        $exp = Get-TreeMap $dir
        $act = Get-TreeMap $r.Dest
        $c = Compare-Tree -Expected $exp -Actual $act -AllowRootPrefix 'tree'
        Assert ($null -eq $c.Diff) $c.Diff
        return ('{0} 檔全部 SHA-256 一致（含 中文目錄/更深/第三層、a|b 同名、0 byte、特殊字元檔名）；{1}' -f $exp.Count, $c.Convention)
    }

    Write-Host ''
    Write-Host '-- 格式白盒 --' -ForegroundColor Cyan

    Invoke-TCase 'C04' '容器結構：magic/version=0x02/ephPubKeyLen/各段偏移自洽' {
        Assert ($null -ne $script:CtTree) 'C03 未產生容器'
        $c = Read-Container $script:CtTree
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

    Invoke-TCase 'C51' 'contentType 欄位：byte[5] = 0x01（檔案樹），header 最小長度 8' {
        Assert ($null -ne $script:CtTree) 'C03 未產生容器'
        $c = Read-Container $script:CtTree
        Assert ($c.ContentType -eq 1) ('資料夾容器的 contentType 不是 0x01：0x{0:X2}' -f $c.ContentType)
        $s = Read-Container $script:CtSingle
        Assert ($s.ContentType -eq 1) ('單檔容器的 contentType 不是 0x01：0x{0:X2}' -f $s.ContentType)
        Assert ($c.EpkLen -ge 80 -and $c.EpkLen -le 120) ('位移 +1 後 ephPubKeyLen 讀出異常：{0}' -f $c.EpkLen)
        Assert ($c.Epk[0] -eq 0x30) ('位移 +1 後 ephPubKey 非 DER SEQUENCE 開頭：0x{0:X2}' -f $c.Epk[0])
        return ('資料夾與單檔容器 byte[5] 皆為 0x01；ephPubKeyLen@6 讀出 {0}、ephPubKey@8 為 0x30' -f $c.EpkLen)
    }

    Invoke-TCase 'C05' 'base64 文字編碼：每 76 字元換行、字元集合法' {
        $c = Read-Container $script:CtTree
        Assert ($c.Lines.Count -ge 2) '輸出行數過少，無法判斷換行'
        $bad = @($c.Lines[0..($c.Lines.Count - 2)] | Where-Object { $_.Length -ne 76 })
        Assert ($bad.Count -eq 0) ('有 {0} 行長度不是 76（首個長度 {1}）' -f $bad.Count, $bad[0].Length)
        Assert ($c.Lines[-1].Length -le 76) '最後一行超過 76'
        Assert (($c.Lines -join '') -match '^[A-Za-z0-9+/]+={0,2}$') 'base64 字元集不合法'
        Assert (-not ($c.Raw -match '[^\x00-\x7F]')) '輸出含非 ASCII 字元'
        return ('{0} 行，前 {1} 行皆 76 字元，末行 {2}；純 ASCII' -f $c.Lines.Count, ($c.Lines.Count - 1), $c.Lines[-1].Length)
    }

    Invoke-TCase 'C06' '一次性金鑰：同輸入 Pack 兩次，ephPub/nonce/密文皆不同' {
        $src = Join-Path $script:Fx 'single\payload.bin'
        $o1 = Join-Path $script:Work 'out\once1.txt'
        $o2 = Join-Path $script:Work 'out\once2.txt'
        foreach ($o in @($o1, $o2)) { if ([System.IO.File]::Exists($o)) { [System.IO.File]::Delete($o) } }
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $o1) -EnvVars $script:KeyA.Sandbox.Env) 'Pack#1')
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $o2) -EnvVars $script:KeyA.Sandbox.Env) 'Pack#2')
        $a = Read-Container $o1; $b = Read-Container $o2
        $hex = { param($x) [Convert]::ToHexString([byte[]]$x) }
        Assert ((& $hex $a.Epk) -ne (& $hex $b.Epk)) 'ephemeral 公鑰重複（金鑰非一次性）'
        Assert ((& $hex $a.Nonce) -ne (& $hex $b.Nonce)) 'nonce 重複'
        Assert ((& $hex $a.Cipher) -ne (& $hex $b.Cipher)) '密文完全相同'
        Assert ((& $hex $a.Tag) -ne (& $hex $b.Tag)) 'tag 重複'
        return ('epk/nonce/ct/tag 四者皆不同；nonce1={0} nonce2={1}' -f (& $hex $a.Nonce), (& $hex $b.Nonce))
    }

    Invoke-TCase 'C07' 'ephemeral 公鑰確為可匯入的 P-256 SubjectPublicKeyInfo' {
        $c = Read-Container $script:CtTree
        $e = [System.Security.Cryptography.ECDiffieHellman]::Create()
        $read = 0
        $e.ImportSubjectPublicKeyInfo([byte[]]$c.Epk, [ref]$read)
        $p = $e.ExportParameters($false)
        $isP256 = ($p.Curve.Oid.Value -eq '1.2.840.10045.3.1.7') -or ($p.Curve.Oid.FriendlyName -match 'nistP256|P-256|prime256')
        Assert $isP256 ('曲線不是 P-256：{0}/{1}' -f $p.Curve.Oid.Value, $p.Curve.Oid.FriendlyName)
        Assert ($read -eq $c.EpkLen) "SPKI 實際長度 $read 與宣告 $($c.EpkLen) 不符"
        $rpk = [Convert]::ToHexString($script:PubSpkiA)
        Assert ([Convert]::ToHexString([byte[]]$c.Epk) -ne $rpk) 'ephemeral 公鑰等於收件人公鑰（未使用臨時金鑰）'
        return ('P-256 SPKI 解析成功，consumed={0}B，且不等於收件人公鑰' -f $read)
    }

    Invoke-TCase 'C08' '獨立解密鏈：DPAPI→ECDH→HKDF-SHA256→AES-GCM→Brotli→Zip' {
        $ecdh = Import-PrivateKeyFromBlob -BlobPath $script:KeyA.KeyPath
        if ($null -eq $ecdh) { Info-Case '私鑰 blob 無法以 DPAPI(null entropy)+PKCS8/EC/PEM 還原，無法獨立重建金鑰（規格未定義 blob 內部格式）' }
        $script:EcdhA = $ecdh
        $c = Read-Container $script:CtTree
        $k = Resolve-ContentKey -Container $c -Ecdh $ecdh -RecipientSpki $script:PubSpkiA
        if ($null -eq $k) { Info-Case '窮舉 HKDF salt/info 候選未命中（規格未定義 salt/info），無法獨立重建內容金鑰；roundtrip 由 C01-C03 保證' }
        $script:KdfInfo = $k
        Assert ($k.Mode -eq 'HKDF') ('內容金鑰不是以 HKDF 導出，而是 {0}（違反規格「HKDF-SHA256」）' -f $k.Label)
        $plain = $k.Plain
        $zip = Expand-Brotli -Data $plain
        Assert ($zip.Length -gt 0) 'Brotli 解壓結果為空'
        Assert ($zip[0] -eq 0x50 -and $zip[1] -eq 0x4B) 'Brotli 解壓後不是 ZIP（PK 簽章缺失）'
        $script:ZipTree = $zip
        $entries = Get-ZipCentralDirectory -Zip $zip
        return ('金鑰導出={0}, AAD={1}；密文 {2}B → Brotli 解出 zip {3}B / {4} 筆項目' -f $k.Label, $k.Aad, $c.Cipher.Length, $zip.Length, $entries.Count)
    }

    Invoke-TCase 'C09' 'ZIP 為純 store（NoCompression）且單檔也打包' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 成功取得明文' }
        $e = Get-ZipCentralDirectory -Zip $script:ZipTree
        $bad = @($e | Where-Object { $_.Method -ne 0 })
        Assert ($bad.Count -eq 0) ('有 {0} 筆非 store（method={1}）' -f $bad.Count, ($bad[0].Method))
        $mism = @($e | Where-Object { $_.CompSize -ne $_.Size })
        Assert ($mism.Count -eq 0) 'store 模式下 compressed != uncompressed'
        # 單檔輸入也必須是 zip 容器
        $c1 = Read-Container $script:CtSingle
        $k1 = Resolve-ContentKey -Container $c1 -Ecdh $script:EcdhA -RecipientSpki $script:PubSpkiA
        Assert ($null -ne $k1) '單檔容器無法解出'
        $z1 = Expand-Brotli -Data $k1.Plain
        $e1 = Get-ZipCentralDirectory -Zip $z1
        Assert ($e1.Count -ge 1) '單檔輸入未被打包成 zip'
        return ('資料夾 {0} 筆全為 method=0；單檔輸入亦為 zip（{1} 筆：{2}）' -f $e.Count, $e1.Count, $e1[0].Name)
    }

    Invoke-TCase 'C10' 'ZIP 檔名 UTF-8（非 ASCII 項目須設 bit 11 且位元組為 UTF-8）' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 成功取得明文' }
        $e = Get-ZipCentralDirectory -Zip $script:ZipTree
        $nonAscii = @($e | Where-Object { -not $_.NameIsAscii })
        Assert ($nonAscii.Count -gt 0) '素材中的中文路徑未出現在 zip 項目名（可能被轉碼或遺失）'
        $noFlag = @($nonAscii | Where-Object { -not $_.Utf8Flag })
        Assert ($noFlag.Count -eq 0) ('有 {0} 筆非 ASCII 檔名未設 UTF-8 旗標(bit 11)：{1}' -f $noFlag.Count, $noFlag[0].Name)
        $badEnc = @($nonAscii | Where-Object { -not $_.NameIsUtf8 })
        Assert ($badEnc.Count -eq 0) '檔名位元組不是合法 UTF-8'
        Assert (($e.Name -join '|') -match '中文目錄') 'zip 中找不到中文目錄名'
        return ('{0} 筆非 ASCII 項目全部 bit11=1 且為 UTF-8，例：{1}' -f $nonAscii.Count, $nonAscii[0].Name)
    }

    Invoke-TCase 'C11' '壓縮有效性：高冗餘輸入輸出遠小於原檔' {
        $src = Join-Path $script:Fx 'redundant\big.txt'
        $out = Join-Path $script:Work 'out\redundant.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $out) -EnvVars $script:KeyA.Sandbox.Env -Timeout 300) 'Pack(redundant)')
        $inLen = (Get-Item -LiteralPath $src).Length
        $outLen = (Get-Item -LiteralPath $out).Length
        $limit = [Math]::Max(8192, $inLen * 0.02)
        Assert ($outLen -lt $limit) ('輸出 {0}B 未顯著小於輸入 {1}B（門檻 {2}B）' -f $outLen, $inLen, [int]$limit)
        return ('輸入 {0}B → 輸出 {1}B（{2:P3}，含 base64 膨脹與 {3}B 標頭）' -f $inLen, $outLen, ($outLen / $inLen), (8 + 91 + 28))
    }

    Write-Host ''
    Write-Host '-- 錯誤路徑 --' -ForegroundColor Cyan

    Invoke-TCase 'C12' '竄改 base64 一字元 → 報內容損壞（tag 驗證）' {
        $t = Copy-Container $script:CtTree 'tamper_b64.txt'
        $txt = [System.IO.File]::ReadAllText($t)
        $lines = @(($txt -split "`r?`n") | Where-Object { $_.Length -gt 0 })
        $li = [int]($lines.Count * 0.8)
        $line = $lines[$li]
        $ci = 10
        $old = $line[$ci]
        $new = if ($old -eq 'A') { 'B' } else { 'A' }
        $lines[$li] = $line.Substring(0, $ci) + $new + $line.Substring($ci + 1)
        [System.IO.File]::WriteAllText($t, (($lines -join "`r`n") + "`r`n"), $script:Utf8NoBom)
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'tamper_b64'
        $ev = Expect-Failure $r 'tag' '竄改密文'
        return ("第 $li 行第 $ci 字元 '$old'→'$new'；$ev")
    }

    Invoke-TCase 'C13' '竄改 magic → 報格式不符' {
        $c = Read-Container $script:CtTree
        $b = [byte[]]$c.Bytes.Clone()
        $b[0] = [byte][char]'X'
        $t = Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'tamper_magic.txt')
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'tamper_magic'
        $ev = Expect-Failure $r 'format' '竄改 magic'
        return ("magic 'RUNE'→'XUNE'；$ev")
    }

    Invoke-TCase 'C14' '竄改 version(0x02→0x09) → 報版本不符' {
        $c = Read-Container $script:CtTree
        $b = [byte[]]$c.Bytes.Clone()
        $b[4] = 0x09
        $t = Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'tamper_ver.txt')
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'tamper_ver'
        $ev = Expect-Failure $r 'version' '竄改 version'
        return ("version 0x02→0x09；$ev")
    }

    Invoke-TCase 'C50' '新舊格式互斥：舊 CTXT 容器須以 magic 不符被拒' {
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

        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'legacy_ctxt'
        Assert (-not $r.TimedOut) '舊 CTXT 容器導致子行程卡住'
        Assert ($r.ExitCode -eq 1) ('舊 CTXT 容器應以 exit 1 被拒絕，實際 exit={0}：{1}' -f $r.ExitCode, (Squash $r.All 160))
        $ev = Expect-Failure $r 'format' '舊 CTXT 容器'
        Assert ($r.All -match 'CTXT') ('訊息未回報實際讀到的 magic（應含 CTXT）：' + (Squash $r.All 200))
        $dest = Join-Path $script:Work 'unpack\legacy_ctxt'
        Assert ((Get-TreeMap $dest).Count -eq 0) '舊格式被拒卻仍寫出了檔案'
        return ("舊 CTXT v2 容器遭 magic 檢查拒絕、Destination 乾淨；$ev")
    }

    # contentType 已綁進 HKDF info，因此翻掉它必然表現為 GCM 認證失敗（＝被竄改），
    # 而不是「不支援的內容型別」。後者只能出現在「tag 驗過但型別未知」的合法容器上。
    function Test-ContentTypeFlip {
        param([byte]$NewType, [string]$Tag)
        $c = Read-Container $script:CtTree
        $b = [byte[]]$c.Bytes.Clone()
        $b[5] = $NewType
        $t = Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) "ctype_$Tag.txt")
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName "ctype_$Tag"
        $ev = Expect-Failure $r 'tag' ('contentType 翻成 0x{0:X2}' -f $NewType)
        Assert (-not ($r.All -match '型別|content.?type|較新版本|不支援')) `
        ('contentType 被竄改卻報成「型別不支援」：代表該欄位沒進 HKDF info，或合法性檢查被放在解析階段 => ' + (Squash $r.All 200))
        $dest = Join-Path $script:Work "unpack\ctype_$Tag"
        Assert ((Get-TreeMap $dest).Count -eq 0) 'contentType 被竄改卻仍寫出了檔案'
        return ('0x01→0x{0:X2} 報竄改而非型別問題；{1}' -f $NewType, $ev)
    }

    Invoke-TCase 'C52' 'contentType 竄改 0x01→0x02 → 須報「被竄改」（證明已綁進 HKDF info）' {
        Test-ContentTypeFlip -NewType 2 -Tag '02'
    }

    Invoke-TCase 'C53' 'contentType 竄改 0x01→0xFF → 須報「被竄改」而非型別不支援' {
        Test-ContentTypeFlip -NewType 255 -Tag 'ff'
    }

    Invoke-TCase 'C54' '合法的 contentType 0x03 容器 → 須報「由較新版本產生」' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能偽造密碼學上合法的容器' }
        # 以 contentType = 0x03 完整走一次派生與加密：tag 必然驗得過，
        # 此時型別仍未知，正確的結論是「本程式版本落後」，不是「資料被竄改」。
        $t = New-ForgedRune -ZipBytes (New-ZipWithEntry -EntryName 'future.txt' -Content 'FROM-THE-FUTURE') `
            -ContentType 3 -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'ctype03.txt')
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'ctype03'
        Assert (-not $r.TimedOut) '子行程逾時'
        Assert ($r.Failed) '未知的內容型別 0x03 竟然解包成功'
        Assert ($r.All -match '型別|content.?type') ('訊息未指明是內容型別的問題：' + (Squash $r.All 200))
        Assert ($r.All -match '較新版本|新版|請更新|update|newer') ('訊息未指引使用者更新工具：' + (Squash $r.All 200))
        Assert (-not ($r.All -match '竄改|tamper|認證標籤')) ('合法容器的未知型別被誤報成竄改：' + (Squash $r.All 200))
        $dest = Join-Path $script:Work 'unpack\ctype03'
        Assert ((Get-TreeMap $dest).Count -eq 0) '未知型別被拒卻仍寫出了檔案'
        return ('0x03 遭拒且訊息指向版本落後：' + (Squash $r.All 90))
    }

    Invoke-TCase 'C15' '錯誤私鑰（另一組 P-256 blob）→ 報解鑰失敗' {
        $r = Invoke-UnpackOnly -Txt $script:CtTree -KeyFile $script:KeyB.KeyPath -DestName 'wrongkey'
        Assert (-not $r.TimedOut) '子行程逾時'
        Assert ($r.Failed) '用不匹配的私鑰竟然解包成功'
        # ECDH 混合式下，不匹配的私鑰在數學上仍能完成 ECDH，必然要到 GCM 才失敗；
        # 因此接受「解鑰失敗」或「內容損壞」，但訊息必須讓使用者判斷得出是金鑰問題或內容問題。
        $isKey = $r.All -match $script:ErrPatterns['key']
        $isTag = $r.All -match $script:ErrPatterns['tag']
        Assert ($isKey -or $isTag) ('訊息未指明解鑰/內容環節：' + (Squash $r.All 200))
        $stage = if ($isKey) { '解鑰失敗' } else { '內容損壞（ECDH 下之必然表現）' }
        $dest = Join-Path $script:Work 'unpack\wrongkey'
        Assert ((Get-TreeMap $dest).Count -eq 0) '解鑰失敗卻仍寫出了檔案'
        return ("環節={0}；msg={1}；未寫出任何檔案" -f $stage, (Squash $r.All 70))
    }

    Invoke-TCase 'C16' '私鑰檔不存在 / 讀不到 → 報私鑰讀取失敗' {
        $r = Invoke-UnpackOnly -Txt $script:CtTree -KeyFile (Join-Path $script:Work 'no_such_dir\private.key') -DestName 'nokey'
        return (Expect-Failure $r 'key' '私鑰路徑不存在')
    }

    Invoke-TCase 'C17' '截斷容器（只留一半 base64）→ 指明環節' {
        $c = Read-Container $script:CtTree
        $half = [int]($c.Bytes.Length / 2)
        $b = [byte[]]$c.Bytes[0..($half - 1)]
        $t = Write-Container -Bytes $b -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'truncated.txt')
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'truncated'
        Assert (-not $r.TimedOut) '截斷容器導致子行程卡住'
        Assert ($r.Failed) '截斷容器竟然解包成功'
        $ok = ($r.All -match ($script:ErrPatterns['tag'] + '|' + $script:ErrPatterns['format'] + '|' + $script:ErrPatterns['base64']))
        Assert $ok ('訊息未指明環節：' + (Squash $r.All 180))
        return ('截半 {0}B→{1}B；{2}' -f $c.Bytes.Length, $half, (Squash $r.All 90))
    }

    Invoke-TCase 'C18' '非 base64 內容 → 報 base64/編碼環節錯誤' {
        $t = Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'notb64.txt'
        [System.IO.File]::WriteAllText($t, "這不是 base64 !!! @@@@`r`n###`r`n", $script:Utf8NoBom)
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'notb64'
        Assert ($r.Failed) '非 base64 內容竟然解包成功'
        $ok = ($r.All -match ($script:ErrPatterns['base64'] + '|' + $script:ErrPatterns['format']))
        Assert $ok ('訊息未指明 base64/格式環節：' + (Squash $r.All 180))
        return (Squash $r.All 100)
    }

    Invoke-TCase 'C19' '偽造容器（tag 合法但明文非 Brotli）→ 報解壓失敗' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能偽造合法容器' }
        # 用受測物自己的容器換掉密文：以相同金鑰重新加密一段非 Brotli 明文
        $c = Read-Container $script:CtSingle
        $k = Resolve-ContentKey -Container $c -Ecdh $script:EcdhA -RecipientSpki $script:PubSpkiA
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
        $r = Invoke-UnpackOnly -Txt $t -KeyFile $script:KeyA.KeyPath -DestName 'notbrotli'
        return (Expect-Failure $r 'unzip' 'tag 正確但明文非 Brotli')
    }

    Invoke-TCase 'C20' 'OutFile 已存在且未加 -Force → 報錯且不覆蓋' {
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'exists.txt'
        [System.IO.File]::WriteAllText($out, 'SENTINEL-DO-NOT-OVERWRITE', $script:Utf8NoBom)
        $before = Get-Sha $out
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out) -EnvVars $script:KeyA.Sandbox.Env
        $ev = Expect-Failure $r 'exists' '輸出檔已存在'
        Assert ((Get-Sha $out) -eq $before) '未加 -Force 卻覆蓋了既有檔案'
        return ("$ev；原檔內容未變")
    }

    Invoke-TCase 'C21' '-Force 可覆蓋既有 OutFile' {
        $out = Join-Path $script:Work 'out\exists.txt'
        $before = Get-Sha $out
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out, '-Force') -EnvVars $script:KeyA.Sandbox.Env
        [void](Expect-Success $r 'Pack -Force')
        Assert ((Get-Sha $out) -ne $before) '-Force 未覆蓋'
        $c = Read-Container $out
        Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2) '覆蓋後不是合法容器'
        return ('已覆蓋並產生合法容器 {0}B' -f $c.Bytes.Length)
    }

    Invoke-TCase 'C22' 'wildcard 空匹配 → 報錯' {
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'emptywild\*.txt'), '-OutFile', (Join-Path $script:Work 'out\empty.txt')) -EnvVars $script:KeyA.Sandbox.Env
        $ev = Expect-Failure $r 'nomatch' 'wildcard 無匹配'
        Assert (-not [System.IO.File]::Exists((Join-Path $script:Work 'out\empty.txt'))) '空匹配卻仍產生輸出檔'
        return ("$ev；未產生輸出")
    }

    Invoke-TCase 'C23' '~\.rune\public.pem 不存在 → 報找不到公鑰且不產生輸出檔' {
        $sb = New-HomeSandbox -Name 'nopub'
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'nopub.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out) -EnvVars $sb.Env
        Assert (-not $r.TimedOut) '子行程逾時'
        Assert ($r.Failed) '家目錄沒有 public.pem 卻仍打包成功'
        Assert (-not [System.IO.File]::Exists($out)) '找不到公鑰卻仍產生了輸出檔'
        # 只比對 StdErr：seal 端一旦成功載入公鑰就會印出含「公鑰」「RUNE」「key」字樣的
        # 指紋橫幅到 stdout，若拿 $r.All 比對 nopub/format/key 這幾類會被該橫幅污染而
        # 無條件命中（本案是在載入公鑰失敗、橫幅根本沒印出的情況下觸發，但仍統一比對
        # StdErr，不依賴「這次剛好沒印」這個事實）。
        Assert ($r.StdErr -match $script:ErrPatterns['nopub']) ('訊息未指明公鑰環節：' + (Squash $r.StdErr 200))
        Assert ($r.StdErr -match '找不到|不存在|not found') ('訊息未說明公鑰檔不存在：' + (Squash $r.StdErr 200))
        # 訊息必須指引使用者「怎麼取得公鑰」，而不是只說找不到
        Assert ($r.StdErr -match 'GenerateKeys') ('訊息未指引到解密端執行 -GenerateKeys：' + (Squash $r.StdErr 200))
        Assert ($r.StdErr -match 'public\.pem') ('訊息未提到 public.pem：' + (Squash $r.StdErr 200))
        Assert ($r.StdErr -match '-PublicKey') ('訊息未提到可用 -PublicKey 指定路徑或 PEM 字串：' + (Squash $r.StdErr 200))
        return (Squash $r.StdErr 130)
    }

    Invoke-TCase 'C24' '輸入路徑不存在 → 報錯' {
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'no_such_file.bin'), '-OutFile', (Join-Path $script:Work 'out\nosrc.txt')) -EnvVars $script:KeyA.Sandbox.Env
        return (Expect-Failure $r 'input' '輸入不存在')
    }

    Write-Host ''
    Write-Host '-- CLI / 預設檔名 --' -ForegroundColor Cyan

    function Test-DefaultName {
        param([string]$InputPath, [string]$Expected, [string]$Tag)
        $cwd = New-Dir (Join-Path $script:Work "cwd_$Tag")
        Get-ChildItem -LiteralPath $cwd -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        $inDir = [System.IO.Path]::GetDirectoryName($InputPath.TrimEnd('\'))
        $inParent = [System.IO.Path]::GetDirectoryName($inDir)
        foreach ($d in @($cwd, $inDir, $inParent)) {
            $p = Join-Path $d $Expected
            if ([System.IO.File]::Exists($p)) { [System.IO.File]::Delete($p) }
        }
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $InputPath) -EnvVars $script:KeyA.Sandbox.Env -WorkDir $cwd
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

    Invoke-TCase 'C25' '預設檔名：單檔 report.docx → report.docx.txt' {
        Test-DefaultName -InputPath (Join-Path $script:Fx 'naming\report.docx') -Expected 'report.docx.txt' -Tag 'file'
    }

    Invoke-TCase 'C26' '預設檔名：資料夾 project → project.txt' {
        Test-DefaultName -InputPath (Join-Path $script:Fx 'naming\project') -Expected 'project.txt' -Tag 'dir'
    }

    Invoke-TCase 'C27' '預設檔名：wildcard → 父資料夾名.txt' {
        Test-DefaultName -InputPath (Join-Path $script:Fx 'naming\wcdir\*.txt') -Expected 'wcdir.txt' -Tag 'wild'
    }

    Invoke-TCase 'C28' 'Pack 完成印出輸出路徑與大小統計' {
        $src = Join-Path $script:Fx 'redundant\big.txt'
        $out = Join-Path $script:Work 'out\stats.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $out) -EnvVars $script:KeyA.Sandbox.Env -Timeout 300
        [void](Expect-Success $r 'Pack(stats)')
        $o = $r.StdOut
        Assert ($o -match [regex]::Escape('stats.txt')) ('輸出未提及輸出檔路徑：' + (Squash $o 150))
        $nums = [regex]::Matches($o, '[\d][\d,\.]*\s*(B|KB|MB|GB|bytes|位元組)?')
        Assert ($nums.Count -ge 2) ('輸出缺少大小統計數字：' + (Squash $o 150))
        return (Squash $o 110)
    }

    Invoke-TCase 'C29' '各產物拒絕對方參數：rune-seal 拒絕 -Unpack、rune-open 拒絕 -Pack' {
        $r1 = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Unpack', $script:CtTree, '-Destination', (New-Dir (Join-Path $script:Work 'unpack\mix1'))) -EnvVars $script:KeyA.Sandbox.Env
        $ev1 = Expect-Failure $r1 'param' 'rune-seal.ps1 收到 -Unpack'
        $r2 = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin')) -EnvVars $script:KeyA.Sandbox.Env
        $ev2 = Expect-Failure $r2 'param' 'rune-open.ps1 收到 -Pack'
        return ("seal 拒絕 -Unpack（$ev1）；open 拒絕 -Pack（$ev2）")
    }

    Invoke-TCase 'C30' '-Unpack 缺 -Destination → 報錯（不得卡在互動）' {
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtTree, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env -Timeout 45
        Assert (-not $r.TimedOut) '缺 -Destination 時卡住（Mandatory 提示無法在非互動下結束）'
        return (Expect-Failure $r 'param' '缺 -Destination')
    }

    Write-Host ''
    Write-Host '-- 金鑰儲存 / GenerateKeys --' -ForegroundColor Cyan

    Invoke-TCase 'C31' '私鑰檔為 DPAPI blob（非明文 PEM）' {
        $b = [System.IO.File]::ReadAllBytes($script:KeyA.KeyPath)
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

    Invoke-TCase 'C32' '同帳號以 DPAPI 私鑰 Unpack 成功（-KeyFile 指定）' {
        $dest = New-Dir (Join-Path $script:Work 'unpack\dpapi')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtWild, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env
        [void](Expect-Success $r 'Unpack(DPAPI)')
        Assert ((Get-TreeMap $dest).Count -eq 3) '解出檔案數不符'
        return ('DPAPI blob 解鑰成功，還原 3 檔')
    }

    Invoke-TCase 'C33' '-KeyFile 預設值 ~\.rune\private.key（不給 -KeyFile 也能解）' {
        $dest = New-Dir (Join-Path $script:Work 'unpack\defaultkey')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        $expected = Join-Path $script:KeyA.Sandbox.Path '.rune\private.key'
        if (-not [System.IO.File]::Exists($expected)) {
            [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($expected))
            [System.IO.File]::Copy($script:KeyA.KeyPath, $expected, $true)
        }
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtWild, '-Destination', $dest) -EnvVars $script:KeyA.Sandbox.Env
        [void](Expect-Success $r 'Unpack(預設 KeyFile)')
        Assert ((Get-TreeMap $dest).Count -eq 3) '解出檔案數不符'
        return ('未指定 -KeyFile，從 ~\.rune\private.key 讀取成功')
    }

    Invoke-TCase 'C34' '-GenerateKeys 私鑰已存在時拒絕覆蓋' {
        $before = Get-Sha $script:KeyA.KeyPath
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-GenerateKeys') -EnvVars $script:KeyA.Sandbox.Env -WorkDir $script:KeyA.Sandbox.Path
        [void](Assert-NoHomeEscape -When 'C34')
        $ev = Expect-Failure $r 'exists' '私鑰已存在'
        Assert ((Get-Sha $script:KeyA.KeyPath) -eq $before) '既有私鑰被覆蓋了'
        return ("$ev；既有私鑰 SHA 未變")
    }

    Invoke-TCase 'C35' '-GenerateKeys 印出公鑰 PEM、public.pem 路徑與指紋' {
        $o = $script:KeyA.Result.All
        Assert ($null -ne (Get-PemBlock -Text $o)) '未印出 PUBLIC KEY PEM'
        Assert ($o -match 'public\.pem') '未指引使用者把 public.pem 交給加密端'
        Assert ($o -match 'RUNE-KEY') '未印出公鑰指紋（RUNE-KEY ...），加密端無從比對'
        return (Squash (($o -split "`r?`n" | Where-Object { $_ -match 'public\.pem|RUNE-KEY' } | Select-Object -First 1)) 110)
    }

    # 指紋格式：RUNE-KEY + 8 組 ×4 個大寫 hex，以 '-' 連接（共 39 字元）
    $script:FpRegex = 'RUNE-KEY\s+([0-9A-F]{4}(?:-[0-9A-F]{4}){7})'

    function Get-Fingerprint {
        param([string]$Text)
        $m = [regex]::Match($Text, $script:FpRegex)
        if ($m.Success) { return $m.Groups[1].Value }
        return $null
    }

    Invoke-TCase 'C55' '-PublicKey 收 PEM 字串本體：家目錄無 public.pem 也能加密' {
        $sb = New-HomeSandbox -Name 'pkstr'      # 這個沙箱刻意「沒有」public.pem
        $src = Join-Path $script:Fx 'single\payload.bin'
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'pkstring.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $out, '-PublicKey', $script:PubPemA) -EnvVars $sb.Env
        [void](Expect-Success $r 'Pack(-PublicKey 收 PEM 字串)')
        $c = Read-Container $out
        Assert ($c.Magic -eq 'RUNE' -and $c.Version -eq 2 -and $c.ContentType -eq 1) '產物不是合法的 RUNE v2 容器'

        $dest = New-Dir (Join-Path $script:Work 'unpack\pkstring')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $out, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env) 'Unpack(-PublicKey 收 PEM 字串)')
        $d = Compare-MapExact @{ 'payload.bin' = (Get-Sha $src) } (Get-TreeMap $dest)
        Assert ($null -eq $d) $d
        return ('家目錄無 public.pem，僅靠 -PublicKey 的 PEM 字串完成加密，且以金鑰 A 位元一致還原')
    }

    Invoke-TCase 'C56' '-PublicKey 收檔案路徑：可用非預設位置的公鑰檔' {
        $sb = New-HomeSandbox -Name 'pkpath'     # 同樣沒有 public.pem
        $pemFile = New-TextFile (Join-Path $script:Work 'keys\alice.pem') $script:PubPemA
        $src = Join-Path $script:Fx 'single\payload.bin'
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'pkpath.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', $src, '-OutFile', $out, '-PublicKey', $pemFile) -EnvVars $sb.Env
        [void](Expect-Success $r 'Pack(-PublicKey 收檔案路徑)')

        $dest = New-Dir (Join-Path $script:Work 'unpack\pkpath')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $out, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env) 'Unpack(-PublicKey 收檔案路徑)')
        $d = Compare-MapExact @{ 'payload.bin' = (Get-Sha $src) } (Get-TreeMap $dest)
        Assert ($null -eq $d) $d
        return ('以 -PublicKey <路徑> 讀取非預設位置的公鑰檔，roundtrip 位元一致')
    }

    Invoke-TCase 'C57' '公鑰指紋：格式穩定、seal 與 -GenerateKeys 逐字一致且可獨立重算' {
        $genFp = Get-Fingerprint -Text $script:KeyA.Result.All
        Assert ($null -ne $genFp) ('-GenerateKeys 未印出 RUNE-KEY 指紋（8 組 ×4 大寫 hex）：' + (Squash $script:KeyA.Result.All 200))

        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'fp.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }
        $p = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out) -EnvVars $script:KeyA.Sandbox.Env
        [void](Expect-Success $p 'Pack(指紋)')
        $sealFp = Get-Fingerprint -Text $p.StdOut
        Assert ($null -ne $sealFp) ('-Pack 未印出 RUNE-KEY 指紋：' + (Squash $p.StdOut 200))
        Assert ($sealFp.Length -eq 39) ('指紋長度不是 39 個字元：{0}' -f $sealFp.Length)
        Assert ($sealFp -eq $genFp) ('加解密兩端的指紋不一致：seal={0} / generate={1}' -f $sealFp, $genFp)

        # 獨立重算：SHA-256( SPKI DER ) 前 16 bytes，大寫 hex 每 4 字元一組
        $digest = [System.Security.Cryptography.SHA256]::HashData($script:PubSpkiA)
        $hex = [Convert]::ToHexString($digest, 0, 16)
        $expect = ((0..7) | ForEach-Object { $hex.Substring($_ * 4, 4) }) -join '-'
        Assert ($sealFp -eq $expect) ('指紋與 SHA-256(SPKI DER) 前 16 bytes 不符：實得 {0}，應為 {1}' -f $sealFp, $expect)
        return ('RUNE-KEY {0}；兩端逐字一致且等於 SHA-256(SPKI DER)[0..15]' -f $expect)
    }

    Invoke-TCase 'C58' '-ExportPublicKey 可從既有私鑰重建 public.pem，指紋不變' {
        $pub = $script:KeyA.Sandbox.PubPath
        Assert ([System.IO.File]::Exists($pub)) '前置 P6 未通過（沙箱沒有 public.pem）'
        $backup = [System.IO.File]::ReadAllText($pub)
        [System.IO.File]::Delete($pub)
        try {
            $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-ExportPublicKey') -EnvVars $script:KeyA.Sandbox.Env -WorkDir $script:KeyA.Sandbox.Path
            [void](Assert-NoHomeEscape -When 'C58')
            [void](Expect-Success $r '-ExportPublicKey')
            Assert ([System.IO.File]::Exists($pub)) '-ExportPublicKey 未重建 public.pem'
            $onDisk = Get-PemBlock -Text ([System.IO.File]::ReadAllText($pub))
            Assert ($null -ne $onDisk) '重建的 public.pem 不是合法 PEM'
            $ec = [System.Security.Cryptography.ECDiffieHellman]::Create()
            $ec.ImportFromPem($onDisk)
            Assert ([Convert]::ToHexString($ec.ExportSubjectPublicKeyInfo()) -eq [Convert]::ToHexString($script:PubSpkiA)) `
                '重建出來的公鑰不是原來那把'
            $fp = Get-Fingerprint -Text $r.All
            Assert ($null -ne $fp) '-ExportPublicKey 未以相同格式印出指紋'
            Assert ($fp -eq (Get-Fingerprint -Text $script:KeyA.Result.All)) '重新導出後指紋改變了'
            return ('public.pem 刪除後由私鑰完整重建，公鑰與指紋 RUNE-KEY {0} 皆不變' -f $fp)
        }
        finally {
            # 後續案例仍依賴這個沙箱的 public.pem，萬一重建失敗要還原
            if (-not [System.IO.File]::Exists($pub)) {
                [System.IO.File]::WriteAllText($pub, $backup, $script:Utf8NoBom)
            }
        }
    }

    Invoke-TCase 'C59' 'public.pem 被換成另一把金鑰 → 指紋必須改變（防掉包防線有效）' {
        Assert ($null -ne $script:KeyB.PublicPem) '前置 P5 未取得金鑰 B 的公鑰'
        $sb = New-HomeSandbox -Name 'swap'
        [void](New-TextFile $sb.PubPath $script:KeyB.PublicPem)
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'swapped.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out) -EnvVars $sb.Env
        [void](Expect-Success $r 'Pack(掉包後的 public.pem)')
        $fpB = Get-Fingerprint -Text $r.StdOut
        $fpA = Get-Fingerprint -Text $script:KeyA.Result.All
        Assert ($null -ne $fpB) '換過公鑰後未印出指紋，使用者根本無從察覺'
        Assert ($fpB -ne $fpA) ('公鑰被換掉指紋卻沒變（防線失效）：{0}' -f $fpB)

        # 且產物確實是加密給 B：用 A 的私鑰解不開
        $u = Invoke-UnpackOnly -Txt $out -KeyFile $script:KeyA.KeyPath -DestName 'swapped'
        Assert ($u.Failed) '公鑰換成 B 之後，A 的私鑰竟然解得開'
        Assert ((Get-TreeMap (Join-Path $script:Work 'unpack\swapped')).Count -eq 0) '解不開卻仍寫出檔案'
        return ('A={0} → B={1}，指紋確實改變，且 A 的私鑰解不開' -f $fpA, $fpB)
    }

    Write-Host ''
    Write-Host '-- 隱藏案例（由規格不變量推導）--' -ForegroundColor Cyan

    Invoke-TCase 'C36' '0 byte 檔單獨打包 roundtrip' {
        $src = New-BinFile (Join-Path $script:Work 'fixtures\zero\empty.dat') 0
        $r = Invoke-Roundtrip -Name 'zero' -Source $src
        $act = Get-TreeMap $r.Dest
        $c = Compare-Tree -Expected @{ 'empty.dat' = (Get-Sha $src) } -Actual $act
        Assert ($null -eq $c.Diff) $c.Diff
        return ('0 byte 檔還原成功（SHA e3b0c442…）')
    }

    Invoke-TCase 'C37' '解包不得逸出 Destination（zip 路徑安全）' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能構造惡意 zip' }
        # 自製含 ../ 項目的 zip -> Brotli -> 用受測物公鑰做 ECDH 加密
        $ms = [System.IO.MemoryStream]::new()
        $za = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, $script:Utf8NoBom)
        $e = $za.CreateEntry('../escaped.txt', [System.IO.Compression.CompressionLevel]::NoCompression)
        $w = [System.IO.StreamWriter]::new($e.Open())
        $w.Write('ESCAPED'); $w.Dispose(); $za.Dispose()
        $zipBytes = $ms.ToArray()
        $plain = Compress-Brotli -Data $zipBytes

        $eph = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $rec = [System.Security.Cryptography.ECDiffieHellman]::Create()
        $rec.ImportSubjectPublicKeyInfo($script:PubSpkiA, [ref]([int]0))
        $z = $eph.DeriveRawSecretAgreement($rec.PublicKey)
        $epk = $eph.ExportSubjectPublicKeyInfo()
        $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

        $hdr = [System.Collections.Generic.List[byte]]::new()
        $hdr.AddRange([System.Text.Encoding]::ASCII.GetBytes('RUNE'))
        $hdr.Add(2)
        $hdr.Add(1)     # contentType 0x01 = 檔案樹
        $hdr.Add([byte]($epk.Length -band 0xFF)); $hdr.Add([byte](($epk.Length -shr 8) -band 0xFF))
        $hdr.AddRange($epk)

        # 沿用 C08 還原出的 KDF 參數
        $lbl = $script:KdfInfo.Label
        $m = [regex]::Match($lbl, 'salt=([^,]+),info=([^)]+)')
        Assert ($m.Success) '無法沿用 KDF 參數'
        $fake = [pscustomobject]@{ Nonce = $nonce; Epk = $epk; Bytes = $hdr.ToArray(); HeaderSize = $hdr.Count }
        $cand = Get-KdfCandidates -Container $fake -RecipientSpki $script:PubSpkiA
        $key = [System.Security.Cryptography.HKDF]::DeriveKey(
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, $z, 32,
            $cand.Salts[$m.Groups[1].Value], $cand.Infos[$m.Groups[2].Value])
        $ct = [byte[]]::new($plain.Length); $tag = [byte[]]::new(16)
        $gcm = New-AesGcm -Key $key
        if ($script:KdfInfo.Aad -eq 'none') { $gcm.Encrypt($nonce, $plain, $ct, $tag) }
        elseif ($script:KdfInfo.Aad -eq 'header') { $gcm.Encrypt($nonce, $plain, $ct, $tag, $hdr.ToArray()) }
        else { $gcm.Encrypt($nonce, $plain, $ct, $tag, [byte[]]($hdr.ToArray()[0..4])) }
        $gcm.Dispose()
        $all = [System.Collections.Generic.List[byte]]::new()
        $all.AddRange($hdr); $all.AddRange($nonce); $all.AddRange($tag); $all.AddRange($ct)
        $t = Write-Container -Bytes $all.ToArray() -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'zipslip.txt')

        $dest = New-Dir (Join-Path $script:Work 'unpack\zipslip\inner')
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $t, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env
        $outside = Join-Path $script:Work 'unpack\zipslip\escaped.txt'
        $leaked = [System.IO.File]::Exists($outside)
        if ($leaked) { [System.IO.File]::Delete($outside) }
        Assert (-not $leaked) '嚴重：zip 內 ../ 路徑被寫到 Destination 之外（zip slip）'
        return ('../escaped.txt 未逸出（exit={0}）：{1}' -f $r.ExitCode, (Squash $r.All 70))
    }

    Invoke-TCase 'C38' 'Destination 不存在時的行為（規格未定義，僅記錄）' {
        $dest = Join-Path $script:Work 'unpack\nonexistent_dest'
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtWild, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env
        if (-not $r.Failed) {
            Assert ((Get-TreeMap $dest).Count -eq 3) '宣稱成功但檔案不齊'
            Info-Case '自動建立不存在的 Destination 並解出 3 檔'
        }
        Info-Case ('明確報錯而不自動建立：' + (Squash $r.All 80))
    }

    Invoke-TCase 'C39' '同一容器重複解包兩次結果一致（冪等）' {
        $d1 = New-Dir (Join-Path $script:Work 'unpack\idem1')
        $d2 = New-Dir (Join-Path $script:Work 'unpack\idem2')
        foreach ($d in @($d1, $d2)) { Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force }
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtTree, '-Destination', $d1, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env) 'Unpack#1')
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtTree, '-Destination', $d2, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env) 'Unpack#2')
        $c = Compare-MapExact (Get-TreeMap $d1) (Get-TreeMap $d2)
        Assert ($null -eq $c) $c
        return ('兩次解包內容完全相同（{0} 檔）' -f (Get-TreeMap $d1).Count)
    }

    Invoke-TCase 'C41' 'zip-slip 變體：entry 名用反斜線 ..\ 不得逸出 Destination' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能構造惡意 zip' }
        $root = New-Dir (Join-Path $script:Work 'unpack\zipslip_back')
        $dest = New-Dir (Join-Path $root 'inner')
        $outside = Join-Path $root 'pwned.txt'
        if ([System.IO.File]::Exists($outside)) { [System.IO.File]::Delete($outside) }

        $t = New-ForgedRune -ZipBytes (New-ZipWithEntry -EntryName '..\pwned.txt') `
            -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'zipslip_backslash.txt')
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $t, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env

        $leaked = [System.IO.File]::Exists($outside)
        $leakBody = if ($leaked) { [System.IO.File]::ReadAllText($outside) } else { '' }
        if ($leaked) { [System.IO.File]::Delete($outside) }
        Assert (-not $leaked) ("嚴重：ZIP entry '..\pwned.txt' 被寫到 Destination 之外（exit={0}，{1}報錯；內容 '{2}'）" -f `
                $r.ExitCode, $(if ($r.Failed) { '有' } else { '未' }), (Squash $leakBody 24))
        Assert ($r.Failed) '未逸出，但也沒報錯：應以錯誤明確拒絕不安全的封存路徑'
        Assert ($r.All -match $script:ErrPatterns['unsafe']) `
        ('已拒絕但訊息未指明「不安全的封存路徑」（不可只說格式損壞）：' + (Squash $r.All 200))
        return ("反斜線 ..\pwned.txt 遭拒且未逸出，exit={0}；{1}" -f $r.ExitCode, (Squash $r.All 70))
    }

    Invoke-TCase 'C42' 'wildcard 命中子目錄：須出聲警告，且解包後不留空目錄' {
        $dir = New-Dir (Join-Path $script:Fx 'wcdir_sub')
        [void](New-TextFile (Join-Path $dir 'top.txt') 'top level file')
        [void](New-TextFile (Join-Path $dir 'subfolder\inside.txt') 'INSIDE-MUST-NOT-VANISH-SILENTLY')
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'wcdir_sub.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

        $p = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $dir '*'), '-OutFile', $out) -EnvVars $script:KeyA.Sandbox.Env
        Assert (-not $p.TimedOut) 'Pack 逾時'
        Assert ($p.ExitCode -eq 0) ('Pack 應成功（僅需警告）但 exit={0}：{1}' -f $p.ExitCode, (Squash $p.All 160))
        Assert ([System.IO.File]::Exists($out)) 'Pack 未產生輸出檔'
        Assert ($p.All -match 'WARNING|警告|略過|跳過|不遞迴|skip') `
        ('wildcard 命中目錄卻無任何警告（靜默丟資料）：' + (Squash $p.All 200))

        $dest = New-Dir (Join-Path $script:Work 'unpack\wcdir_sub')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        [void](Expect-Success (Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $out, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env) 'Unpack(wcdir_sub)')

        $files = Get-TreeMap $dest
        $dirs = @([System.IO.Directory]::EnumerateDirectories($dest, '*', [System.IO.SearchOption]::AllDirectories))
        Assert (@($files.Keys | Where-Object { $_ -match '(^|/)top\.txt$' }).Count -eq 1) ('top.txt 未正確還原：' + (($files.Keys) -join ','))
        Assert (-not ($files.Keys | Where-Object { $_ -match 'inside\.txt' })) '違反不遞迴：子目錄內的檔案被打包了'
        Assert ($dirs.Count -eq 0) ('解包後留下空目錄（不遞迴就不該產生目錄項目）：' + (($dirs | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
        $warn = ($p.All -split "`r?`n" | Where-Object { $_ -match 'WARNING|警告|略過|跳過' } | Select-Object -First 1)
        return ('已警告且只還原 top.txt、無空目錄；warn=' + (Squash $warn 70))
    }

    Invoke-TCase 'C43' '資料夾模式須保留空子目錄（含巢狀空目錄）' {
        $dir = New-Dir (Join-Path $script:Fx 'emptydirs')
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

    Invoke-TCase 'C44' '解包中途失敗須回滾：Destination 無殘留、無暫存資料夾' {
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能構造中途失敗的封存' }
        # 前兩筆合法、第三筆不安全 -> 前兩筆會先落地，之後才拋錯，藉此驗回滾
        $ms = [System.IO.MemoryStream]::new()
        $za = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, $script:Utf8NoBom)
        foreach ($n in @('good1.txt', 'sub/good2.txt', '../evil.txt')) {
            $e = $za.CreateEntry($n, [System.IO.Compression.CompressionLevel]::NoCompression)
            $w = [System.IO.StreamWriter]::new($e.Open()); $w.Write("payload-$n"); $w.Dispose()
        }
        $za.Dispose()
        $t = New-ForgedRune -ZipBytes $ms.ToArray() -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) 'partial.txt')

        $root = New-Dir (Join-Path $script:Work 'unpack\rollback')
        $dest = New-Dir (Join-Path $root 'dest')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $t, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env

        $outside = Join-Path $root 'evil.txt'
        $leaked = [System.IO.File]::Exists($outside)
        if ($leaked) { [System.IO.File]::Delete($outside) }
        Assert (-not $leaked) '嚴重：../evil.txt 逸出到 Destination 之外'
        Assert ($r.Failed) '含不安全項目的封存竟然解包成功'
        $left = Get-TreeMap $dest
        Assert ($left.Count -eq 0) ('解包失敗卻在 Destination 留下 {0} 個殘留檔案：{1}' -f $left.Count, (($left.Keys | Select-Object -First 5) -join ','))
        $leftDirs = @([System.IO.Directory]::EnumerateDirectories($dest, '*', [System.IO.SearchOption]::AllDirectories))
        Assert ($leftDirs.Count -eq 0) ('解包失敗後殘留目錄（含暫存資料夾）：' + (($leftDirs | ForEach-Object { Split-Path -Leaf $_ }) -join ','))
        return ('前 2 筆合法 + 第 3 筆不安全 -> 失敗且 Destination 完全乾淨；' + (Squash $r.All 70))
    }

    Invoke-TCase 'C45' 'public.pem 內容為 P-384 → 須明確報曲線不符' {
        $sb = New-HomeSandbox -Name 'p384'
        $p384 = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP384)
        $pem = ConvertTo-Pem -Der $p384.ExportSubjectPublicKeyInfo() -Label 'PUBLIC KEY'
        [void](New-TextFile $sb.PubPath $pem)
        $out = Join-Path (New-Dir (Join-Path $script:Work 'out')) 'p384.txt'
        if ([System.IO.File]::Exists($out)) { [System.IO.File]::Delete($out) }

        $r = Invoke-Transfer -ScriptPath $script:SutSeal -Arguments @('-Pack', (Join-Path $script:Fx 'single\payload.bin'), '-OutFile', $out) -EnvVars $sb.Env
        Assert (-not $r.TimedOut) '逾時'
        Assert ($r.Failed) 'P-384 公鑰竟然被接受並完成打包'
        Assert (-not [System.IO.File]::Exists($out)) '曲線不符卻仍產生了輸出檔'
        # 只比對錯誤輸出：stdout 的進度橫幅本來就含 "ECDH P-256"，拿 All 比對會誤判成通過
        $errText = if (-not [string]::IsNullOrWhiteSpace($r.StdErr)) { $r.StdErr } else { $r.StdOut }
        Assert ($errText -match $script:ErrPatterns['curve']) `
        ('有拒絕但錯誤訊息未點明 P-256 曲線需求（丟出 .NET 原始訊息不算）：' + (Squash $errText 200))
        return ('P-384 的 public.pem 遭拒且錯誤訊息點明曲線：' + (Squash $errText 80))
    }

    # ---- 針對 v1.1 新增邏輯的加強驗證（空目錄 entry / 回滾搬移 / 長路徑）----

    function Test-DirEntrySlip {
        param([string]$EntryName, [string]$Tag, [string]$LeakName)
        if ($null -eq $script:KdfInfo) { Skip-Case '需 C08 還原 KDF 參數才能構造惡意 zip' }
        $root = New-Dir (Join-Path $script:Work "unpack\dirslip_$Tag")
        $dest = New-Dir (Join-Path $root 'inner')
        $outside = Join-Path $root $LeakName
        if ([System.IO.Directory]::Exists($outside)) { [System.IO.Directory]::Delete($outside, $true) }

        $t = New-ForgedRune -ZipBytes (New-ZipWithDirEntry -EntryName $EntryName) `
            -Path (Join-Path (New-Dir (Join-Path $script:Work 'tamper')) "dirslip_$Tag.txt")
        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $t, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env

        $leaked = [System.IO.Directory]::Exists($outside)
        if ($leaked) { [System.IO.Directory]::Delete($outside, $true) }
        Assert (-not $leaked) ("嚴重：目錄 entry '$EntryName' 在 Destination 之外建出了目錄（exit={0}）" -f $r.ExitCode)
        Assert ($r.Failed) "目錄 entry '$EntryName' 未被拒絕（安全檢查被目錄分支繞過）"
        Assert ($r.All -match $script:ErrPatterns['unsafe']) `
        ("目錄 entry 遭拒但訊息未指明不安全路徑：" + (Squash $r.All 200))
        return ("目錄 entry '$EntryName' 遭拒且未建出目錄，exit={0}；{1}" -f $r.ExitCode, (Squash $r.All 70))
    }

    Invoke-TCase 'C46' '目錄 entry 也要走 zip-slip 檢查：..\evil\（反斜線分支）' {
        Test-DirEntrySlip -EntryName '..\evil\' -Tag 'back' -LeakName 'evil'
    }

    Invoke-TCase 'C47' '目錄 entry 也要走 zip-slip 檢查：../evil2/（包含性判斷分支）' {
        Test-DirEntrySlip -EntryName '../evil2/' -Tag 'fwd' -LeakName 'evil2'
    }

    Invoke-TCase 'C48' '回滾搬移不得破壞 Destination 既有的無關內容' {
        $dest = New-Dir (Join-Path $script:Work 'unpack\merge')
        Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        [void](New-TextFile (Join-Path $dest 'alpha.txt') 'OLD-CONTENT-WILL-COLLIDE')
        [void](New-TextFile (Join-Path $dest 'unrelated.txt') 'KEEP-ME')
        [void](New-TextFile (Join-Path $dest 'existingdir\note.txt') 'KEEP-ME-TOO')

        $r = Invoke-Transfer -ScriptPath $script:SutOpen -Arguments @('-Unpack', $script:CtWild, '-Destination', $dest, '-KeyFile', $script:KeyA.KeyPath) -EnvVars $script:KeyA.Sandbox.Env
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

    Invoke-TCase 'C49' '深層長路徑 roundtrip（暫存資料夾前綴不得撐爆路徑長度）' {
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

    Invoke-TCase 'C40' '原始受測腳本（seal + open）自始至終未被修改' {
        $nowSeal = Get-Sha $script:SutSeal
        $nowOpen = Get-Sha $script:SutOpen
        Assert ($script:OrigHashSeal -eq $nowSeal) 'seal 產物在測試過程中被改動'
        Assert ($script:OrigHashOpen -eq $nowOpen) 'open 產物在測試過程中被改動'
        return ('seal SHA-256 {0}… / open SHA-256 {1}… 皆未變' -f $nowSeal.Substring(0, 16), $nowOpen.Substring(0, 16))
    }
}

# ==============================================================================
# 10. 驅動
# ==============================================================================

Invoke-VerifyTrack -SealScript $script:SealScript -OpenScript $script:OpenScript

# ==============================================================================
# 11. 報表
# ==============================================================================

$pass = @($script:Results | Where-Object Result -EQ 'PASS').Count
$fail = @($script:Results | Where-Object Result -EQ 'FAIL').Count
$skip = @($script:Results | Where-Object Result -EQ 'SKIP').Count
$info = @($script:Results | Where-Object Result -EQ 'INFO').Count

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

Write-Host ('總計 {0} 案：PASS {1} / FAIL {2} / SKIP {3} / INFO {4}' -f $script:Results.Count, $pass, $fail, $skip, $info) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
Write-Host ('工作目錄：{0}' -f $script:Work)

$reportPath = Join-Path $script:ReviewRoot 'verify-report.txt'
$logPath = Join-Path $script:ReviewRoot 'verify-log.txt'
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('runepost 驗收報表（規格 v2，rune-seal + rune-open）')
[void]$sb.AppendLine('RepoRoot：' + $script:RepoRoot)
[void]$sb.AppendLine('時間：' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
[void]$sb.AppendLine('')
[void]$sb.AppendLine(($table | Format-Table -AutoSize -Wrap | Out-String -Width 200))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('完整證據：')
foreach ($r in $script:Results) {
    [void]$sb.AppendLine(('{0} [{1}] {2}' -f $r.No, $r.Result, $r.Case))
    [void]$sb.AppendLine('     ' + $r.Evidence)
}
if ($script:EscapeNotes.Count) { [void]$sb.AppendLine('沙箱逃逸：' + ($script:EscapeNotes -join ' | ')) }
[void]$sb.AppendLine(('總計 {0}：PASS {1} / FAIL {2} / SKIP {3} / INFO {4}' -f $script:Results.Count, $pass, $fail, $skip, $info))
[System.IO.File]::WriteAllText($reportPath, $sb.ToString(), $script:Utf8Bom)
[System.IO.File]::WriteAllLines($logPath, $script:LogLines, $script:Utf8Bom)
Write-Host ('報表：{0}' -f $reportPath)

exit ([int]($fail -gt 0))
