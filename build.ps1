#Requires -Version 7.4
<#
.SYNOPSIS
    從 src/ fragment 組裝 dist/ 產物（runepost）。

.DESCRIPTION
    只依 manifest 明列的 fragment 相對路徑組裝，絕不 glob src/。
    每個 fragment 讀入後：解碼 UTF-8、剝除前導 BOM、CRLF/CR 正規化為 LF、
    確保恰好以一個 \n 結尾，再依 manifest 順序附加。
    組裝完成後以 [Parser]::ParseInput 對整份產物做語法檢查，錯誤行號會被映回
    「來源 fragment + fragment 內行號」再報出。
    src/ 底下每個 .ps1 必須至少被一個產物引用，否則視為孤兒，組裝失敗。

.PARAMETER Product
    要建的產物（對應 manifest 的 key）；預設建全部。

.PARAMETER OutDir
    輸出目錄，預設 <repoRoot>\dist。

.PARAMETER Check
    只驗不寫：記憶體組裝結果與磁碟上既有產物逐位元組比對，不符則 exit 1
    並印出產物名與第一個相異的行號。

.EXAMPLE
    .\build.ps1
    建出 manifest 內所有產物到 dist\。

.EXAMPLE
    .\build.ps1 -Product rune-seal -Check
    只驗證 rune-seal 是否與 src/ 目前內容一致，不寫檔。
#>
[CmdletBinding()]
param(
    [string[]] $Product,
    [string] $OutDir,
    [switch] $Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 0. 路徑
# ==========================================================================
$Script:RepoRoot = Split-Path -Parent $PSCommandPath
$Script:SrcRoot = Join-Path $Script:RepoRoot 'src'
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Script:RepoRoot 'dist'
}

# ==========================================================================
# 1. manifest —— 唯一的產物組成清單，build.ps1 絕不 glob src/
#    key = 產物基底名（dist\<key>.ps1）；value = 依序組裝的 fragment 相對路徑陣列
#
#    兩個產物：rune-seal（加密端）、rune-open（解密端 + 金鑰管理）。
#    雙軌期的合體版 rune-all 已在 verify.ps1 證明與兩者等價後移除（見 git log）。
# ==========================================================================
$Script:Manifest = [ordered]@{
    'rune-seal' = @(
        # --- shell：rune-seal 專屬 help / param / entry ---
        'shell/seal-help.ps1'
        'shell/seal-param.ps1'
        # --- keystore：金鑰路徑說明與常數（seal / open 共用）---
        'keystore/paths-doc.ps1'
        # --- container：容器格式常數 ---
        'container/format-spec.ps1'
        'keystore/paths.ps1'
        # --- filemode：打包 / ZIP 寫入 ---
        'filemode/pack-plan.ps1'
        'filemode/zip-write.ps1'
        # --- codec：Brotli 壓縮方向 ---
        'codec/brotli-compress.ps1'
        # --- crypto / keystore：金鑰交換與派生 ---
        'crypto/ecdh-keygen.ps1'
        'keystore/fingerprint.ps1'
        'keystore/public-key.ps1'
        'crypto/kdf.ps1'
        'crypto/aes-seal.ps1'
        # --- container：容器組裝 ---
        'container/write.ps1'
        # --- flow：-Pack 主流程 ---
        'flow/seal-main.ps1'
        # --- shell：進入點 ---
        'shell/seal-entry.ps1'
    )
    'rune-open' = @(
        # --- shell：rune-open 專屬 help / param / entry ---
        'shell/open-help.ps1'
        'shell/open-param.ps1'
        # --- keystore：金鑰路徑說明與常數（seal / open 共用）---
        'keystore/paths-doc.ps1'
        # --- container：容器格式常數 ---
        'container/format-spec.ps1'
        'keystore/paths.ps1'
        # --- keystore：私鑰路徑常數（open 專用，見該檔註解：不與 seal 共用是為了
        #     負面符號掃描——DefaultKeyFile 不該出現在 dist/rune-seal.ps1 裡）---
        'keystore/private-paths.ps1'
        # --- container：位元組工具 ---
        'container/byte-range.ps1'
        # --- crypto / keystore：金鑰交換與派生（-GenerateKeys 用得到 ecdh-keygen）---
        'crypto/ecdh-keygen.ps1'
        'keystore/fingerprint.ps1'
        'crypto/kdf.ps1'
        # --- codec / crypto：Brotli 解壓、ECDH 協議 ---
        'codec/brotli-expand.ps1'
        'crypto/ecdh-agree.ps1'
        # --- container：容器解析 ---
        'container/read.ps1'
        # --- filemode：ZIP 解包 ---
        'filemode/zip-read.ps1'
        # --- keystore：私鑰載入 ---
        'keystore/private-key.ps1'
        # --- flow：-Unpack 主流程 ---
        'flow/open-main.ps1'
        # --- keystore：-GenerateKeys / -ExportPublicKey ---
        'keystore/public-key-block.ps1'
        'keystore/generate-keys.ps1'
        'keystore/export-public-key.ps1'
        # --- shell：進入點 ---
        'shell/open-entry.ps1'
    )
}

# ==========================================================================
# 2. fragment 讀取 / 正規化
# ==========================================================================

function Read-NormalizedFragment {
    <#
        讀入單一 fragment：UTF-8 解碼、剝除前導 BOM、CRLF/CR -> LF、
        確保恰好以一個 \n 結尾。回傳正規化後的文字（不含結尾以外的額外空行）。
    #>
    param([string] $Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $bom = [System.Text.Encoding]::UTF8.GetPreamble()
    if ($bytes.Length -ge $bom.Length) {
        $hasBom = $true
        for ($i = 0; $i -lt $bom.Length; $i++) {
            if ($bytes[$i] -ne $bom[$i]) { $hasBom = $false; break }
        }
        if ($hasBom) { $bytes = $bytes[$bom.Length..($bytes.Length - 1)] }
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $text = $text -replace "`r`n", "`n" -replace "`r", "`n"
    $text = $text.TrimEnd("`n") + "`n"
    return $text
}

function Get-AssembledProduct {
    <#
        依 manifest 內某產物的 fragment 清單組裝，回傳
        @{ Text = <組裝後全文（不含檔頭）>; LineMap = <int[]，assembled 行號(1-based, 不含檔頭)
           -> 索引對應 LineMapInfo>；LineMapInfo = @(@{Fragment=;Line=}, ...) }
    #>
    param([string[]] $FragmentRelPaths)

    $sb = [System.Text.StringBuilder]::new()
    $lineMapInfo = [System.Collections.Generic.List[object]]::new()

    foreach ($rel in $FragmentRelPaths) {
        $full = Join-Path $Script:SrcRoot ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "缺漏的 fragment（manifest 內列出但檔案不存在）：src/$rel"
        }
        $norm = Read-NormalizedFragment -Path $full
        $fragLines = $norm.TrimEnd("`n") -split "`n"
        for ($i = 0; $i -lt $fragLines.Count; $i++) {
            $lineMapInfo.Add([pscustomobject]@{ Fragment = $rel; Line = ($i + 1) })
        }
        [void]$sb.Append($norm)
    }

    return [pscustomobject]@{
        Text        = $sb.ToString()
        LineMapInfo = $lineMapInfo
    }
}

# ==========================================================================
# 3. 產生檔檔頭
# ==========================================================================

function Get-SourceDigest {
    <# 所有來源 fragment（依 manifest 順序、正規化後）串接後的 SHA-256 前 12 碼（小寫 hex）。#>
    param([string] $AssembledText)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($AssembledText)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([Convert]::ToHexString($hash).ToLowerInvariant()).Substring(0, 12)
}

function New-ProductHeader {
    param([string] $ProductName, [string] $Digest, [int] $FragmentCount)
    $lines = @(
        '# 本檔由 build.ps1 自 src/ 組裝產生，請勿直接編輯 —— 請改 src/ 後重跑 build.ps1'
        "# source-digest: $Digest"
        '# format: RUNE v2'
        "# product: $ProductName"
        "# fragments: $FragmentCount"
    )
    return (($lines -join "`n") + "`n")
}

# ==========================================================================
# 4. 組裝後語法檢查（行號映回來源 fragment）
# ==========================================================================

function Test-AssembledSyntax {
    param([string] $HeaderText, [string] $BodyText, [object[]] $LineMapInfo, [string] $ProductName)

    $full = $HeaderText + $BodyText
    $headerLineCount = ([regex]::Matches($HeaderText, "`n")).Count

    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($full, [ref]$tokens, [ref]$errors)

    if ($errors -and $errors.Count -gt 0) {
        $msgs = foreach ($e in $errors) {
            $assembledLine = $e.Extent.StartLineNumber
            $bodyLine = $assembledLine - $headerLineCount
            if ($bodyLine -ge 1 -and $bodyLine -le $LineMapInfo.Count) {
                $src = $LineMapInfo[$bodyLine - 1]
                "$($ProductName): $($e.Message)（來源 src/$($src.Fragment):$($src.Line)，組裝後第 $assembledLine 行）"
            }
            else {
                "$($ProductName): $($e.Message)（組裝後第 $assembledLine 行，位於產生檔檔頭區）"
            }
        }
        throw ($msgs -join "`n")
    }
}

# ==========================================================================
# 5. 孤兒檢查：src/ 底下每個 .ps1 都必須至少被一個產物引用
# ==========================================================================

function Test-NoOrphanFragments {
    param([hashtable] $Manifest)

    $referenced = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($key in $Manifest.Keys) {
        foreach ($rel in $Manifest[$key]) { [void]$referenced.Add($rel) }
    }

    $onDisk = @(Get-ChildItem -LiteralPath $Script:SrcRoot -Recurse -Filter '*.ps1' -File |
            ForEach-Object { $_.FullName.Substring($Script:SrcRoot.Length + 1) -replace '\\', '/' })

    $orphans = @($onDisk | Where-Object { -not $referenced.Contains($_) })
    if ($orphans.Count -gt 0) {
        throw ('src/ 底下有 {0} 個孤兒 fragment（存在但未被任何產物的 manifest 引用）：{1}' -f `
                $orphans.Count, ($orphans -join ', '))
    }
}

# ==========================================================================
# 6. 主流程
# ==========================================================================

try {
    if (-not (Test-Path -LiteralPath $Script:SrcRoot -PathType Container)) {
        throw "找不到 src/ 目錄：$Script:SrcRoot"
    }

    $allProducts = @($Script:Manifest.Keys)
    if (-not $Product -or $Product.Count -eq 0) {
        $Product = $allProducts
    }
    else {
        foreach ($p in $Product) {
            if ($allProducts -notcontains $p) {
                throw "未知的產物：'$p'。可用產物：$($allProducts -join ', ')"
            }
        }
    }

    # 孤兒檢查一律針對「全部」manifest 內容執行，不受 -Product 篩選影響——
    # 否則 `-Product rune-seal` 會讓 rune-open 專屬的 fragment 被誤判為孤兒。
    Test-NoOrphanFragments -Manifest $Script:Manifest

    # 全部組裝並通過語法檢查後才開始寫檔／比對，避免留下半套 dist/
    $built = [ordered]@{}
    foreach ($p in $Product) {
        $asm = Get-AssembledProduct -FragmentRelPaths $Script:Manifest[$p]
        $digest = Get-SourceDigest -AssembledText $asm.Text
        $header = New-ProductHeader -ProductName $p -Digest $digest -FragmentCount $Script:Manifest[$p].Count
        Test-AssembledSyntax -HeaderText $header -BodyText $asm.Text -LineMapInfo $asm.LineMapInfo -ProductName $p
        $built[$p] = [pscustomobject]@{
            Header = $header
            Body   = $asm.Text
            Full   = $header + $asm.Text
        }
    }

    $utf8Bom = [System.Text.UTF8Encoding]::new($true)

    if ($Check) {
        $mismatches = @()
        foreach ($p in $Product) {
            $outPath = Join-Path $OutDir "$p.ps1"
            if (-not (Test-Path -LiteralPath $outPath -PathType Leaf)) {
                $mismatches += "$p：磁碟上不存在 $outPath"
                continue
            }
            $onDiskBytes = [System.IO.File]::ReadAllBytes($outPath)
            $onDiskText = $utf8Bom.GetString($onDiskBytes)
            # 去除 BOM 字元（GetString 對含 BOM 的位元組陣列不會自動吃掉 U+FEFF）
            if ($onDiskText.Length -gt 0 -and [int]$onDiskText[0] -eq 0xFEFF) {
                $onDiskText = $onDiskText.Substring(1)
            }
            $expected = $built[$p].Full
            if ($onDiskText -ne $expected) {
                $expLines = $expected -split "`n"
                $actLines = $onDiskText -split "`n"
                $firstDiff = 0
                $maxLen = [Math]::Max($expLines.Count, $actLines.Count)
                for ($i = 0; $i -lt $maxLen; $i++) {
                    $e = if ($i -lt $expLines.Count) { $expLines[$i] } else { $null }
                    $a = if ($i -lt $actLines.Count) { $actLines[$i] } else { $null }
                    if ($e -ne $a) { $firstDiff = $i + 1; break }
                }
                $mismatches += "$p：磁碟上的 $outPath 與 src/ 現況組裝結果不同，第 $firstDiff 行起相異"
            }
        }
        if ($mismatches.Count -gt 0) {
            throw ($mismatches -join "`n")
        }
        Write-Host ('-Check 通過：{0} 個產物與 src/ 現況一致' -f $Product.Count)
    }
    else {
        if (-not (Test-Path -LiteralPath $OutDir -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $OutDir -Force)
        }
        foreach ($p in $Product) {
            $outPath = Join-Path $OutDir "$p.ps1"
            [System.IO.File]::WriteAllText($outPath, $built[$p].Full, $utf8Bom)
            Write-Host ('已寫出：{0}' -f $outPath)
        }
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
