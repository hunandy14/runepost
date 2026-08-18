#Requires -Version 7.4
<#
.SYNOPSIS
    Proves each dist bundle inlines the RunePost module functions verbatim, character for character.

.DESCRIPTION
    Complements the behavioural equivalence check (tests\verify.ps1 run against the bundles). This
    one is textual: it parses each bundle with the PowerShell AST, pulls out every top-level
    function definition, and compares its source text against the same-named function in
    RunePost\Public or RunePost\Private. A single changed character fails the run.

    Both bundles inline the full module, so every module function must appear identically in both.
    The check also fails if a module function is missing from a bundle, or if a bundle defines a
    module-named function whose text differs.

.PARAMETER RepoRoot
    Repository root that holds RunePost\ and dist\. Defaults to the parent of this script's folder.

.PARAMETER DistDir
    Directory holding the built bundles. Defaults to <RepoRoot>\dist.
#>
[CmdletBinding()]
param(
    [string] $RepoRoot,
    [string] $DistDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath) }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ModuleRoot = Join-Path $RepoRoot 'RunePost'
if (-not $DistDir) { $DistDir = Join-Path $RepoRoot 'dist' }

function Get-FunctionMap {
    param([string] $Path)
    $t = $null; $e = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { throw "解析失敗：$Path — $($e[0].Message)" }
    $map = [ordered]@{}
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        $map[$fn.Name] = $fn.Extent.Text
    }
    return $map
}

# 模組同名函式的原始碼（一檔一函式）。
$moduleFns = [ordered]@{}
foreach ($dir in @('Private', 'Public')) {
    foreach ($f in Get-ChildItem -LiteralPath (Join-Path $ModuleRoot $dir) -Filter '*.ps1' -File | Sort-Object Name) {
        $m = Get-FunctionMap $f.FullName
        if ($m.Count -ne 1) { throw "$($f.Name)：不是恰好一個函式（$($m.Count) 個）" }
        foreach ($k in $m.Keys) { $moduleFns[$k] = $m[$k] }
    }
}

$problems = [System.Collections.Generic.List[string]]::new()
$checked = 0

foreach ($product in @('rune-seal', 'rune-open')) {
    $bundlePath = Join-Path $DistDir "$product.ps1"
    if (-not (Test-Path -LiteralPath $bundlePath)) { throw "找不到 bundle：$bundlePath（請先執行 Build-Bundle.ps1）" }
    $bundleFns = Get-FunctionMap $bundlePath

    foreach ($name in $moduleFns.Keys) {
        if (-not $bundleFns.Contains($name)) {
            $problems.Add("$product：缺少模組函式 $name")
            continue
        }
        if ($bundleFns[$name] -cne $moduleFns[$name]) {
            $problems.Add("$product：函式 $name 的內聯文字與模組不符（逐字元比對）")
        }
        else {
            $checked++
        }
    }
}

if ($problems.Count -gt 0) {
    Write-Host '函式文字等價檢查：不通過' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host ("函式文字等價檢查：通過。{0} 個模組函式在兩支 bundle 內皆逐字元一致（每支各 {1} 個）。" -f `
    ($checked), ($moduleFns.Count)) -ForegroundColor Green
exit 0
