#Requires -Version 7.4
<#
.SYNOPSIS
    runepost encrypting side. Sends files one way between two Windows machines you own, over a public plain-text channel such as a forum post or a pastebin.

.DESCRIPTION
    The pipeline is pack (ZIP, store) -> compress (Brotli) -> encrypt (AES-256-GCM with a key derived from ephemeral ECDH P-256 and HKDF-SHA256) -> encode (Base64).
    Everything is built on the .NET base class library, with no external dependencies. All work happens in memory and never touches the PowerShell pipeline.

    The recipient public key is not embedded in this script. It is read at run time from
    ~\.rune\public.pem, or from the location given by -PublicKey. This script is therefore
    a key-independent general tool: anyone can use it with their own public.pem.
    Create and manage key pairs on the decrypting machine with rune-open.ps1.

    The encrypting side uses the recipient public key only. It is unaffected by the
    protection mode of the recipient private key (None, Passphrase, or Dpapi, chosen with
    rune-open.ps1 -GenerateKeys -Protect).
    Ciphertext posted to a public channel is permanent, and the recipient private key is
    the only way to recover it. Confirm that the recipient holds a private key backup
    (rune-open.ps1 -ExportPrivateKey) before sending any ciphertext.

.EXAMPLE
    .\rune-seal.ps1 C:\data\report.docx
    Packs, compresses, and encrypts a single file into report.docx.txt, using the
    recipient public key at ~\.rune\public.pem. Every run first prints the fingerprint of
    the public key in use. Compare it with the fingerprint on the decrypting machine.

.EXAMPLE
    .\rune-seal.ps1 C:\data\report.docx -PublicKey D:\keys\alice.pem
    Encrypts with the public key file at the given path. -PublicKey also accepts the PEM
    content itself: a string containing -----BEGIN is treated as content rather than as a
    path. Pass a multi-line PEM through a variable or a here-string rather than typing it
    on the command line.
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
    Write-Host "Done: $($result.OutFile)"
    Write-Host ('Packed, before compression : {0:N0} bytes' -f $result.OriginalSize)
    Write-Host ('Compressed with Brotli     : {0:N0} bytes' -f $result.CompressedSize)
    Write-Host ('Base64 output file         : {0:N0} bytes' -f $result.Base64Size)
}
catch {
    # 用 [Console]::Error.WriteLine 直接印例外訊息本身，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的錯誤說明。WriteLine 只呼叫一次，但訊息本身可以內嵌換行。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
