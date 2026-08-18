#Requires -Version 7.4
<#
.SYNOPSIS
    Assembles a self-contained single-file distribution of runepost from the RunePost module and one entry script.

.DESCRIPTION
    runepost is normally distributed as the RunePost\ module folder plus the two thin entry
    scripts (rune-seal.ps1 / rune-open.ps1). This builder produces an additional form: one
    self-contained .ps1 per entry script that inlines every module function, so the file runs
    on any machine without the RunePost\ folder beside it.

    The output layout, in order:
        <comment-based help>              from the entry script, first so Get-Help works
        #Requires -Version 7.4            after the help block; the order must not be swapped
        [CmdletBinding()] param(...)      from the entry script; param stays the first statement
        Set-StrictMode / $ErrorActionPreference
        <module-level $Script: constants> from RunePost.psm1
        <all Private functions>
        <all Public functions>
        <entry dispatch body>             the Import-Module line is dropped; functions are inlined

    No public key is baked in. The public build is a key-independent general tool; each user
    brings their own public.pem, exactly as with the module form.

.PARAMETER Product
    Which single-file product to build: rune-seal, rune-open, or all (the default).

.PARAMETER RepoRoot
    Repository root that holds RunePost\ and the two entry scripts. Defaults to the parent of
    this script's folder.

.PARAMETER OutDir
    Output directory for the assembled files. Defaults to <RepoRoot>\dist.

.PARAMETER Check
    Do not write. Assemble in memory and compare byte for byte against the file already on disk
    in OutDir. Any mismatch (or a missing file) reports the difference and exits 1. Used by CI to
    catch a hand-edited or stale artifact, and to assert the builder is deterministic.
#>
[CmdletBinding()]
param(
    [ValidateSet('rune-seal', 'rune-open', 'all')]
    [string] $Product = 'all',

    [string] $RepoRoot,

    [string] $OutDir,

    [switch] $Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 路徑
# ==========================================================================

if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ModuleRoot = Join-Path $RepoRoot 'RunePost'
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot 'dist' }

# 產物一律 UTF-8 with BOM、LF：與專案其餘原始碼一致（DESIGN §6.6）。BOM 讓非 PS7 的
# host 也能正確解碼註解裡的中文；LF 由 .gitattributes 對 *.ps1 強制，這裡自己也保證。
$Utf8Bom = [System.Text.UTF8Encoding]::new($true)

# ==========================================================================
# 讀檔工具：一律以 UTF-8 讀進、去掉 BOM、換行正規化為 LF
#
# 逐檔內聯時若混入 CRLF 或殘留 BOM，會讓不同機器上的組裝結果不一致，-Check 也就失去
# 意義。因此所有輸入都先過這一關，組裝全程只有 LF。
# ==========================================================================

function Read-SourceText {
    param([string] $Path)
    $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    return ($text -replace "`r`n", "`n") -replace "`r", "`n"
}

# ==========================================================================
# 入口腳本切分
#
# 以 AST 求切點，不靠行號：
#   Head = 檔頭到「$ErrorActionPreference = 'Stop'」為止（含 CBH、#Requires、
#          屬性、param、Set-StrictMode、$ErrorActionPreference）。
#   Body = 其後全部（進入點 try/catch，rune-open 另有兩個呈現層函式）。
# 兩段的邊界正是 EndBlock 的第 2 個語句（$ErrorActionPreference 指派）結束處。
# ==========================================================================

function Split-EntryScript {
    param([string] $Path)
    $text = Read-SourceText $Path
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { throw "入口腳本解析失敗：$Path — $($e[0].Message)" }

    $stmts = $ast.EndBlock.Statements
    if ($stmts.Count -lt 2) { throw "入口腳本結構異常（param 之後語句不足）：$Path" }
    # 前兩個語句必須是 Set-StrictMode 與 $ErrorActionPreference 指派，否則切點無效。
    $s0 = $stmts[0].Extent.Text
    if ($s0 -notmatch 'Set-StrictMode') { throw "入口腳本第 1 個語句不是 Set-StrictMode：$Path" }
    $assign = $stmts[1]
    if ($assign -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or
        $assign.Left.Extent.Text -ne '$ErrorActionPreference') {
        throw "入口腳本第 2 個語句不是 `$ErrorActionPreference 指派：$Path"
    }

    $split = $assign.Extent.EndOffset
    return [pscustomobject]@{
        Head = $text.Substring(0, $split)
        Body = $text.Substring($split)
    }
}

# 內聯後移除 Body 裡的 Import-Module 那一行，以及緊貼其上、專講該行的註解區塊
# （模組已內聯，那段解釋不再描述當前狀態）。找不到就報錯：入口腳本一定有這一行。
function Remove-ImportModule {
    param([string] $Body)
    $lines = [System.Collections.Generic.List[string]]@($Body -split "`n")
    $idx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*Import-Module\b') { $idx = $i; break }
    }
    if ($idx -lt 0) { throw '入口腳本的進入點找不到 Import-Module；bundler 假設不成立' }
    $lines.RemoveAt($idx)
    # 往上收掉緊貼的註解行（中間不得有空行才算「緊貼」）。
    while ($idx -gt 0 -and $lines[$idx - 1] -match '^\s*#') {
        $lines.RemoveAt($idx - 1); $idx--
    }
    return ($lines -join "`n")
}

# ==========================================================================
# 模組層級 $Script: 常數：從 .psm1 抽出「第一個到最後一個 $Script: 指派」之間的整段
# （中間夾帶的說明註解一併保留），載入器與 Set-StrictMode/$ErrorActionPreference 都不取。
# ==========================================================================

function Get-ModuleConstants {
    param([string] $Psm1Path)
    $text = Read-SourceText $Psm1Path
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { throw "psm1 解析失敗：$Psm1Path — $($e[0].Message)" }

    $consts = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $_.Left.Extent.Text -like '$Script:*'
        })
    if ($consts.Count -eq 0) { throw "psm1 找不到任何 `$Script: 常數：$Psm1Path" }
    $start = [int]::MaxValue; $end = 0
    foreach ($c in $consts) {
        if ($c.Extent.StartOffset -lt $start) { $start = $c.Extent.StartOffset }
        if ($c.Extent.EndOffset -gt $end) { $end = $c.Extent.EndOffset }
    }
    return $text.Substring($start, $end - $start)
}

# ==========================================================================
# 來源溯源雜湊：對「所有進 bundle 的來源檔」做一個確定性的 SHA-256，取前 12 碼。
# 不用 git commit hash——那會讓檔案無法自我一致。序列化採「相對路徑 + 各檔 SHA-256」
# 依路徑排序，因此同一份來源永遠得到同一個值，-Check 才站得住。
# ==========================================================================

function Get-SourceProvenance {
    param([string[]] $Files)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($f in ($Files | Sort-Object)) {
        $rel = $f.Substring($RepoRoot.Length).TrimStart('\', '/').Replace('\', '/')
        $h = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($f)))
        [void]$sb.Append($rel).Append('  ').Append($h).Append("`n")
    }
    $digest = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($sb.ToString()))
    return [Convert]::ToHexString($digest).Substring(0, 12)
}

# ==========================================================================
# 組裝一支自足單檔
# ==========================================================================

function Build-One {
    param([string] $EntryName)

    $entryPath = Join-Path $RepoRoot "$EntryName.ps1"
    if (-not (Test-Path -LiteralPath $entryPath)) { throw "找不到入口腳本：$entryPath" }

    $private = @(Get-ChildItem -LiteralPath (Join-Path $ModuleRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name)
    $public = @(Get-ChildItem -LiteralPath (Join-Path $ModuleRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name)
    $psm1 = Join-Path $ModuleRoot 'RunePost.psm1'

    $sourceFiles = @($entryPath, $psm1) + $private.FullName + $public.FullName
    $prov = Get-SourceProvenance -Files $sourceFiles

    $split = Split-EntryScript $entryPath
    $constants = Get-ModuleConstants $psm1
    $body = Remove-ImportModule $split.Body

    $nl = "`n"
    # 溯源註解插在 CBH 之後、#Requires 之前：CBH 必須是檔案第一個語彙元素，Get-Help
    # 才讀得到（實測顯示緊貼在 CBH 上方的註解會讓 Get-Help 退回自動語法列）。切在
    # 第一個 CBH 結束符 '#>' 那一行之後。
    $headLines = [System.Collections.Generic.List[string]]@($split.Head -split "`n")
    $cbhEnd = -1
    for ($i = 0; $i -lt $headLines.Count; $i++) {
        if ($headLines[$i].Trim() -eq '#>') { $cbhEnd = $i; break }
    }
    if ($cbhEnd -lt 0) { throw "入口腳本開頭找不到 comment-based help 結束符 '#>'：$EntryName" }
    $headLines.Insert($cbhEnd + 1, "# 要修改請改動來源後重新執行 bundler。來源內容 SHA-256 前 12 碼：$prov")
    $headLines.Insert($cbhEnd + 1, '# 本檔由 tools\Build-Bundle.ps1 自 RunePost 模組與入口腳本組裝產生，請勿直接編輯。')
    $headWithProv = $headLines -join $nl

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append($headWithProv)
    [void]$sb.Append($nl).Append($nl)
    [void]$sb.Append('# ==========================================================================').Append($nl)
    [void]$sb.Append('# 模組層級常數（取自 RunePost.psm1）').Append($nl)
    [void]$sb.Append('# ==========================================================================').Append($nl)
    [void]$sb.Append($constants).Append($nl).Append($nl)
    [void]$sb.Append('# ==========================================================================').Append($nl)
    [void]$sb.Append('# 內部函式（取自 RunePost\Private，逐字內聯）').Append($nl)
    [void]$sb.Append('# ==========================================================================').Append($nl)
    foreach ($f in $private) { [void]$sb.Append((Read-SourceText $f.FullName).TrimEnd("`n")).Append($nl).Append($nl) }
    [void]$sb.Append('# ==========================================================================').Append($nl)
    [void]$sb.Append('# 對外函式（取自 RunePost\Public，逐字內聯）').Append($nl)
    [void]$sb.Append('# ==========================================================================').Append($nl)
    foreach ($f in $public) { [void]$sb.Append((Read-SourceText $f.FullName).TrimEnd("`n")).Append($nl).Append($nl) }
    [void]$sb.Append($body.TrimStart("`n"))

    # 收尾：確保單一結尾換行、全程 LF。
    $content = ($sb.ToString() -replace "`r`n", "`n") -replace "`r", "`n"
    $content = $content.TrimEnd("`n") + $nl
    return $content
}

# ==========================================================================
# 主流程
# ==========================================================================

$products = if ($Product -eq 'all') { @('rune-seal', 'rune-open') } else { @($Product) }

$failed = $false
foreach ($p in $products) {
    $content = Build-One $p
    $bytes = $Utf8Bom.GetPreamble() + $Utf8Bom.GetBytes($content)
    $outPath = Join-Path $OutDir "$p.ps1"

    if ($Check) {
        if (-not (Test-Path -LiteralPath $outPath)) {
            Write-Host "CHECK FAIL: $outPath is missing; run the builder without -Check first." -ForegroundColor Red
            $failed = $true
            continue
        }
        $onDisk = [System.IO.File]::ReadAllBytes($outPath)
        if ($onDisk.Length -ne $bytes.Length -or [Convert]::ToHexString($onDisk) -ne [Convert]::ToHexString($bytes)) {
            Write-Host "CHECK FAIL: $outPath differs from a fresh build (on disk $($onDisk.Length) bytes, rebuilt $($bytes.Length) bytes)." -ForegroundColor Red
            $failed = $true
        }
        else {
            Write-Host "CHECK OK: $outPath matches source ($($bytes.Length) bytes)."
        }
    }
    else {
        [void][System.IO.Directory]::CreateDirectory($OutDir)
        [System.IO.File]::WriteAllBytes($outPath, $bytes)
        Write-Host "Built $outPath ($($bytes.Length) bytes)."
    }
}

if ($failed) { exit 1 }
exit 0
