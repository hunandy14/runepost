#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具（加密端）— 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：打包（ZIP/store）→ 壓縮（Brotli）→ 加密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→ 文字編碼（Base64）。
    純 .NET 內建類別實作，零外部依賴，全程記憶體操作，不經 PowerShell 管道。

    公鑰不內嵌在腳本裡，執行時才從 ~\.rune\public.pem 讀取（或以 -PublicKey 指定）。
    因此本腳本是與金鑰無關的通用工具，任何人取得後配上自己的 public.pem 即可使用。
    金鑰的產生與管理請在解密端使用 rune-open.ps1。

    加密端只使用收件人公鑰，與解密端私鑰的儲存格式（rune-open.ps1 -GenerateKeys
    -Protect 的 None／Passphrase／Dpapi）無關，本腳本的用法不因該選擇而改變。
    密文張貼到公開管道後即為永久存在，而收件人私鑰是唯一的還原手段；請確認收件人
    已備妥私鑰備份（rune-open.ps1 -ExportPrivateKey），再開始傳送密文。

.EXAMPLE
    .\rune-seal.ps1 C:\data\report.docx
    把收件人的 public.pem 放到本機 ~\.rune\public.pem 後，將單一檔案打包、壓縮、加密
    並輸出成 report.docx.txt。每次執行都會先印出所用公鑰的指紋，請與解密端核對。

.EXAMPLE
    .\rune-seal.ps1 C:\data\report.docx -PublicKey D:\keys\alice.pem
    用指定路徑的公鑰檔加密。-PublicKey 也接受 PEM 字串本體（字串含 -----BEGIN 即視為
    內容而非路徑）；多行 PEM 請用變數或 here-string 帶入，不要直接打在命令列上。
#>
[CmdletBinding()]
# 本腳本是 CLI 入口，職責就是把模組回傳的結果印給使用者看。Write-Host 在這裡是
# 正確的工具：訊息要無條件出現在畫面上，又不能混進任何回傳值。模組側一律回傳
# 物件、不印字，這條規則只在這一層例外。
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'CLI 入口腳本的呈現層：輸出是給人看的終端訊息，不是回傳值。')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Pack,

    [string] $OutFile,

    [switch] $Force,

    # 收件人公鑰：字串含 -----BEGIN 視為 PEM 內容本體，否則視為檔案路徑。
    # 不指定時讀預設路徑 ~\.rune\public.pem。
    [string] $PublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 進入點
# ==========================================================================

try {
    # Import-Module 放在 try 內：模組資料夾遺失／損壞也走同一個乾淨的錯誤出口，
    # 而不是噴出 PowerShell 原生的多行錯誤記錄。
    #
    # -Force 保證跑到的一定是磁碟上的版本：不帶 -Force 時，Import-Module 對同一
    # session 內已載入的同路徑模組是 no-op，會靜默沿用舊程式碼。本腳本的常態用法
    # 是全新 pwsh 行程，此時沒有東西可重載，-Force 不構成成本。
    Import-Module (Join-Path $PSScriptRoot 'RunePost') -Force

    # -InformationAction Continue：模組把「收件人公鑰指紋」與逐步進度寫到資訊
    # 串流，預設是靜音的。指紋每次執行都要出現在畫面上（那是察覺 public.pem
    # 被掉包的唯一機會），進度也要邊做邊出現而不是事後補印，所以在這裡打開。
    $result = Invoke-RuneSeal -PackPath $Pack -OutFilePath $OutFile -PublicKeyRef $PublicKey `
        -ForceOverwrite:$Force -InformationAction Continue

    Write-Host ''
    Write-Host "完成：$($result.OutFile)"
    Write-Host ('原始（打包後、壓縮前）: {0:N0} bytes' -f $result.OriginalSize)
    Write-Host ('壓縮後（Brotli）       : {0:N0} bytes' -f $result.CompressedSize)
    Write-Host ('Base64 後（輸出檔）    : {0:N0} bytes' -f $result.Base64Size)
}
catch {
    # 用 [Console]::Error.WriteLine 直接印一行錯誤訊息，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的一行錯誤說明。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
