#Requires -Version 7.2
<#
.SYNOPSIS
    密文傳輸工具 — 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：打包（ZIP/store）→ 壓縮（Brotli）→ 加密（AES-256-GCM，金鑰以 RSA-4096-OAEP 包裹）→ 文字編碼（Base64）。
    純 .NET 內建類別實作，零外部依賴，全程 .NET stream / 記憶體操作，不讓二進位資料經過 PowerShell 管道。

.EXAMPLE
    .\transfer.ps1 -GenerateKeys
    產生 RSA-4096 金鑰對，私鑰存到 ~\.ctxt\private.pem，並在畫面印出公鑰 PEM。

.EXAMPLE
    .\transfer.ps1 -Pack C:\data\report.docx
    將公鑰貼入 $PublicKeyPem 後，把單一檔案打包、壓縮、加密並輸出成 report.docx.txt。

.EXAMPLE
    .\transfer.ps1 -Unpack report.docx.txt -Destination C:\out
    在持有私鑰的機器上解密還原檔案。
#>

[CmdletBinding(DefaultParameterSetName = 'Pack')]
param(
    [Parameter(ParameterSetName = 'Pack', Mandatory = $true, Position = 0)]
    [string] $Pack,

    [Parameter(ParameterSetName = 'Pack')]
    [string] $OutFile,

    [Parameter(ParameterSetName = 'Pack')]
    [switch] $Force,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Unpack,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Destination,

    [Parameter(ParameterSetName = 'Unpack')]
    [string] $KeyFile,

    [Parameter(ParameterSetName = 'GenerateKeys', Mandatory = $true)]
    [switch] $GenerateKeys
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 公鑰設定區
#
# 使用方式：
#   1. 先在「解密端」（保管私鑰的那台機器）執行：
#        pwsh .\transfer.ps1 -GenerateKeys
#      私鑰會寫到 ~\.ctxt\private.pem，畫面會印出對應的公鑰 PEM。
#   2. 把印出的 "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"
#      完整貼到下面 $PublicKeyPem 這個 here-string 裡（保留左右單引號 @' / '@）。
#   3. 把貼好公鑰的這份腳本複製/分發到「加密端」機器即可執行 -Pack。
#
# 交付版此處必須保持空字串，-Pack 執行時偵測到空值會直接報錯，
# 提醒使用者尚未完成設定，避免誤以為可以直接使用。
# ==========================================================================
$PublicKeyPem = ''

# ==========================================================================
# 容器二進位格式（加密前於記憶體組好，再整體 Base64）：
#   magic "CTXT"(4B ASCII) | version 0x01(1B) | wrappedKeyLen(uint16 LE)
#   | RSA 包裹的 AES 金鑰 | nonce(12B) | tag(16B) | ciphertext
#   明文側被加密的內容 = Brotli( Zip( 輸入 ) )
# ==========================================================================
$Script:CtxtMagic = 'CTXT'
$Script:CtxtVersion = [byte] 1
$Script:NonceLength = 12
$Script:TagLength = 16
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.ctxt'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.pem'

# ==========================================================================
# 區塊：位元組工具
# ==========================================================================

function Get-ByteRange {
    <# 從位元組陣列擷取子區段，避免 PowerShell range index (..)  在空長度時的邊界問題 #>
    param(
        [byte[]] $Source,
        [int] $Offset,
        [int] $Length
    )
    $dest = [byte[]]::new($Length)
    if ($Length -gt 0) {
        [System.Buffer]::BlockCopy($Source, $Offset, $dest, 0, $Length)
    }
    return , $dest
}

# ==========================================================================
# 區塊：-Pack 主流程（骨架，待下一個里程碑實作）
# ==========================================================================

function Invoke-CtxtPack {
    param(
        [string] $PackPath,
        [string] $OutFilePath,
        [switch] $ForceOverwrite
    )
    throw '尚未實作：-Pack'
}

# ==========================================================================
# 區塊：-Unpack 主流程（骨架，待下一個里程碑實作）
# ==========================================================================

function Invoke-CtxtUnpack {
    param(
        [string] $InFilePath,
        [string] $DestinationPath,
        [string] $KeyFilePath
    )
    throw '尚未實作：-Unpack'
}

# ==========================================================================
# 區塊：-GenerateKeys 主流程（骨架，待下一個里程碑實作）
# ==========================================================================

function Invoke-CtxtGenerateKeys {
    throw '尚未實作：-GenerateKeys'
}

# ==========================================================================
# 進入點
# ==========================================================================

try {
    switch ($PSCmdlet.ParameterSetName) {
        'GenerateKeys' {
            Invoke-CtxtGenerateKeys
        }
        'Pack' {
            Invoke-CtxtPack -PackPath $Pack -OutFilePath $OutFile -ForceOverwrite:$Force
        }
        'Unpack' {
            Invoke-CtxtUnpack -InFilePath $Unpack -DestinationPath $Destination -KeyFilePath $KeyFile
        }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
