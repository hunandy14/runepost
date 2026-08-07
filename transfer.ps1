#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具 — 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：打包（ZIP/store）→ 壓縮（Brotli）→ 加密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→ 文字編碼（Base64）。
    純 .NET 內建類別實作，零外部依賴，全程 .NET stream / 記憶體操作，不讓二進位資料經過 PowerShell 管道。

.EXAMPLE
    .\transfer.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對，私鑰以 DPAPI 保護後存到 ~\.ctxt\private.key，並在畫面印出公鑰 PEM。

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
#      私鑰（ECDH P-256）會以 DPAPI（CurrentUser）保護後寫到 ~\.ctxt\private.key，
#      畫面會印出對應的公鑰 PEM。私鑰檔只有「同一台機器、同一個 Windows 帳號」
#      能用 DPAPI 解回來，換機器或換帳號一律讀不開，因此不再需要另外設密碼。
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
#   magic "CTXT"(4B ASCII) | version 0x02(1B) | ephPubKeyLen(uint16 LE)
#   | ephemeral ECDH P-256 公鑰（SubjectPublicKeyInfo DER）| nonce(12B) | tag(16B) | ciphertext
#   明文側被加密的內容 = Brotli( Zip( 輸入 ) )
#
#   金鑰交換／派生（version 2）：
#     每次 -Pack 產生一次性 ephemeral ECDH P-256 金鑰對，與腳本內嵌的靜態
#     公鑰做 ECDH（DeriveRawSecretAgreement）得共享祕密；再以
#     HKDF-SHA256(ikm = 共享祕密, salt = nonce, info = magic+version+ephemeral公鑰DER)
#     派生 32 bytes 的 AES-256-GCM 金鑰。salt 選用 nonce（而非空）是為了讓每次
#     Pack 產生的金鑰額外與該次的 nonce 綁定；info 內含 magic/version/ephemeral
#     公鑰，確保派生結果與容器內容一一對應、不可跨欄位替換。
# ==========================================================================
$Script:CtxtMagic = 'CTXT'
$Script:CtxtVersion = [byte] 2
$Script:NonceLength = 12
$Script:TagLength = 16
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.ctxt'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'

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
# 區塊：打包（ZIP / store，UTF-8 檔名）
# ==========================================================================

function Get-CtxtPackPlan {
    <#
        依 -Pack 參數判斷輸入型態（單檔 / wildcard / 資料夾），
        回傳要打包的項目清單，以及推導輸出檔名用的基底名稱。
    #>
    param([string] $PackPath)

    if ($PackPath -match '[*?]') {
        # --- wildcard：Get-Item 展開，僅當層不遞迴 ---
        $items = @(Get-Item -Path $PackPath -ErrorAction SilentlyContinue)
        if ($items.Count -eq 0) {
            throw "找不到符合萬用字元的項目：$PackPath"
        }
        $parent = Split-Path -Path $PackPath -Parent
        if ([string]::IsNullOrEmpty($parent)) {
            $parent = (Get-Location).Path
        }
        else {
            $parent = (Resolve-Path -LiteralPath $parent).Path
        }
        $entries = foreach ($item in $items) {
            [pscustomobject]@{
                EntryName   = $item.Name
                SourcePath  = $item.FullName
                IsDirectory = $item.PSIsContainer
            }
        }
        return [pscustomobject]@{
            Entries         = @($entries)
            DefaultBaseName = (Split-Path -Path $parent -Leaf)
        }
    }
    elseif (Test-Path -LiteralPath $PackPath -PathType Container) {
        # --- 資料夾：遞迴整包，保留子目錄結構 ---
        $root = (Get-Item -LiteralPath $PackPath).FullName.TrimEnd('\', '/')
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)
        if ($files.Count -eq 0) {
            throw "資料夾內沒有可打包的檔案：$PackPath"
        }
        $entries = foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
            [pscustomobject]@{
                EntryName   = $rel
                SourcePath  = $f.FullName
                IsDirectory = $false
            }
        }
        return [pscustomobject]@{
            Entries         = @($entries)
            DefaultBaseName = (Split-Path -Path $root -Leaf)
        }
    }
    elseif (Test-Path -LiteralPath $PackPath -PathType Leaf) {
        # --- 單檔 ---
        $file = Get-Item -LiteralPath $PackPath
        return [pscustomobject]@{
            Entries         = @([pscustomobject]@{
                EntryName   = $file.Name
                SourcePath  = $file.FullName
                IsDirectory = $false
            })
            DefaultBaseName = $file.Name
        }
    }
    else {
        throw "找不到指定的路徑：$PackPath"
    }
}

function New-CtxtZipBytes {
    <# 依項目清單建立 ZIP（store，UTF-8 檔名），回傳位元組陣列 #>
    param([object[]] $Entries)

    $ms = [System.IO.MemoryStream]::new()
    $zip = [System.IO.Compression.ZipArchive]::new(
        $ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, [System.Text.Encoding]::UTF8)
    try {
        foreach ($e in $Entries) {
            if ($e.IsDirectory) {
                $dirName = ($e.EntryName -replace '\\', '/').TrimEnd('/') + '/'
                [void]$zip.CreateEntry($dirName, [System.IO.Compression.CompressionLevel]::NoCompression)
                continue
            }
            $entry = $zip.CreateEntry($e.EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
            $entryStream = $entry.Open()
            try {
                $fileStream = [System.IO.File]::OpenRead($e.SourcePath)
                try {
                    $fileStream.CopyTo($entryStream)
                }
                finally {
                    $fileStream.Dispose()
                }
            }
            finally {
                $entryStream.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }
    return , $ms.ToArray()
}

# ==========================================================================
# 區塊：壓縮（Brotli）— 壓縮方向
# ==========================================================================

function Compress-CtxtBrotli {
    param([byte[]] $InputBytes)
    $outMs = [System.IO.MemoryStream]::new()
    $brotli = [System.IO.Compression.BrotliStream]::new(
        $outMs, [System.IO.Compression.CompressionLevel]::SmallestSize, $true)
    try {
        $brotli.Write($InputBytes, 0, $InputBytes.Length)
    }
    finally {
        $brotli.Dispose()
    }
    return , $outMs.ToArray()
}

# ==========================================================================
# 區塊：金鑰交換與派生（ECDH P-256 + HKDF-SHA256，加解密共用）
# ==========================================================================

function New-CtxtEcdhKeyPair {
    <# 產生一個新的 ECDH P-256 金鑰對（同時持有公私鑰） #>
    return [System.Security.Cryptography.ECDiffieHellman]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
}

function Get-CtxtStaticPublicKey {
    <# 從腳本內嵌的 $PublicKeyPem 載入靜態 ECDH 公鑰（只含公鑰） #>
    param([string] $PublicKeyPemText)
    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $ecdh.ImportFromPem($PublicKeyPemText)
    }
    catch {
        throw "公鑰 PEM 格式無效，無法載入：$($_.Exception.Message)"
    }
    return $ecdh
}

function Get-CtxtHkdfInfo {
    <# HKDF 的 info：magic + version + ephemeral 公鑰 DER 位元組 #>
    param([byte[]] $EphPubKeyDer)
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:CtxtMagic)
    $info = [byte[]]::new($magicBytes.Length + 1 + $EphPubKeyDer.Length)
    [System.Buffer]::BlockCopy($magicBytes, 0, $info, 0, $magicBytes.Length)
    $info[$magicBytes.Length] = $Script:CtxtVersion
    [System.Buffer]::BlockCopy($EphPubKeyDer, 0, $info, $magicBytes.Length + 1, $EphPubKeyDer.Length)
    return , $info
}

function Get-CtxtDerivedAesKey {
    <# HKDF-SHA256(ikm=共享祕密, salt=nonce, info=magic+version+ephemeral公鑰) -> 32B AES 金鑰 #>
    param(
        [byte[]] $SharedSecret,
        [byte[]] $Nonce,
        [byte[]] $InfoBytes
    )
    return [System.Security.Cryptography.HKDF]::DeriveKey(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, $SharedSecret, 32, $Nonce, $InfoBytes)
}

function Protect-CtxtAesGcm {
    <# 用外部提供的 AES 金鑰／nonce 做 GCM 加密，回傳 Tag/Ciphertext #>
    param(
        [byte[]] $PlainBytes,
        [byte[]] $AesKey,
        [byte[]] $Nonce
    )

    $tag = [byte[]]::new($Script:TagLength)
    $cipherBytes = [byte[]]::new($PlainBytes.Length)

    $aesGcm = [System.Security.Cryptography.AesGcm]::new($AesKey, $Script:TagLength)
    try {
        $aesGcm.Encrypt($Nonce, $PlainBytes, $cipherBytes, $tag)
    }
    finally {
        $aesGcm.Dispose()
    }

    return [pscustomobject]@{
        Tag        = $tag
        Ciphertext = $cipherBytes
    }
}

# ==========================================================================
# 區塊：容器二進位格式組裝
# ==========================================================================

function New-CtxtContainer {
    param(
        [byte[]] $EphPubKey,
        [byte[]] $Nonce,
        [byte[]] $Tag,
        [byte[]] $Ciphertext
    )
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:CtxtMagic)
    $lenBytes = [BitConverter]::GetBytes([uint16] $EphPubKey.Length)

    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($magicBytes, 0, $magicBytes.Length)
    $ms.WriteByte($Script:CtxtVersion)
    $ms.Write($lenBytes, 0, 2)
    $ms.Write($EphPubKey, 0, $EphPubKey.Length)
    $ms.Write($Nonce, 0, $Nonce.Length)
    $ms.Write($Tag, 0, $Tag.Length)
    $ms.Write($Ciphertext, 0, $Ciphertext.Length)
    return , $ms.ToArray()
}

# ==========================================================================
# 區塊：-Pack 主流程
# ==========================================================================

function Invoke-CtxtPack {
    param(
        [string] $PackPath,
        [string] $OutFilePath,
        [switch] $ForceOverwrite
    )

    if ([string]::IsNullOrWhiteSpace($PublicKeyPem)) {
        throw '尚未設定公鑰：請先在解密端執行 -GenerateKeys 產生金鑰對，並將印出的公鑰 PEM 貼入本腳本頂部的 $PublicKeyPem 變數後再重新執行 -Pack。'
    }

    $plan = Get-CtxtPackPlan -PackPath $PackPath
    if (-not $plan.Entries -or $plan.Entries.Count -eq 0) {
        throw "沒有可打包的項目（路徑或萬用字元未匹配到任何檔案）：$PackPath"
    }

    if ([string]::IsNullOrWhiteSpace($OutFilePath)) {
        $OutFilePath = Join-Path -Path (Get-Location).Path -ChildPath ($plan.DefaultBaseName + '.txt')
    }
    else {
        $OutFilePath = [System.IO.Path]::GetFullPath($OutFilePath)
    }

    if ((Test-Path -LiteralPath $OutFilePath) -and -not $ForceOverwrite) {
        throw "輸出檔案已存在：$OutFilePath（如需覆蓋請加上 -Force）"
    }

    Write-Host "打包中：共 $($plan.Entries.Count) 個項目..."
    $zipBytes = New-CtxtZipBytes -Entries $plan.Entries
    $originalSize = $zipBytes.Length

    Write-Host '壓縮中（Brotli, SmallestSize）...'
    $compressed = Compress-CtxtBrotli -InputBytes $zipBytes
    $compressedSize = $compressed.Length

    Write-Host '加密中（ECDH P-256 + HKDF-SHA256 + AES-256-GCM）...'
    $ephemeral = New-CtxtEcdhKeyPair
    $staticPub = Get-CtxtStaticPublicKey -PublicKeyPemText $PublicKeyPem
    try {
        $sharedSecret = $ephemeral.DeriveRawSecretAgreement($staticPub.PublicKey)
        $ephPubKeyDer = $ephemeral.ExportSubjectPublicKeyInfo()

        $nonce = [byte[]]::new($Script:NonceLength)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

        $infoBytes = Get-CtxtHkdfInfo -EphPubKeyDer $ephPubKeyDer
        $aesKey = Get-CtxtDerivedAesKey -SharedSecret $sharedSecret -Nonce $nonce -InfoBytes $infoBytes
        [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)

        $aes = Protect-CtxtAesGcm -PlainBytes $compressed -AesKey $aesKey -Nonce $nonce
        [Array]::Clear($aesKey, 0, $aesKey.Length)
    }
    finally {
        $ephemeral.Dispose()
        $staticPub.Dispose()
    }

    $container = New-CtxtContainer -EphPubKey $ephPubKeyDer -Nonce $nonce -Tag $aes.Tag -Ciphertext $aes.Ciphertext

    $b64Text = [Convert]::ToBase64String($container, [System.Base64FormattingOptions]::InsertLineBreaks)
    [System.IO.File]::WriteAllText($OutFilePath, $b64Text, [System.Text.Encoding]::ASCII)
    $b64Size = (Get-Item -LiteralPath $OutFilePath).Length

    Write-Host ''
    Write-Host "完成：$OutFilePath"
    Write-Host ('原始（打包後、壓縮前）: {0:N0} bytes' -f $originalSize)
    Write-Host ('壓縮後（Brotli）       : {0:N0} bytes' -f $compressedSize)
    Write-Host ('Base64 後（輸出檔）    : {0:N0} bytes' -f $b64Size)
}

# ==========================================================================
# 區塊：解壓（Brotli）— 解壓方向
# ==========================================================================

function Expand-CtxtBrotli {
    param([byte[]] $InputBytes)
    $inMs = [System.IO.MemoryStream]::new($InputBytes)
    $outMs = [System.IO.MemoryStream]::new()
    $brotli = [System.IO.Compression.BrotliStream]::new(
        $inMs, [System.IO.Compression.CompressionMode]::Decompress, $false)
    try {
        $brotli.CopyTo($outMs)
    }
    finally {
        $brotli.Dispose()
    }
    return , $outMs.ToArray()
}

# ==========================================================================
# 區塊：解密 — 解密方向
# ==========================================================================

function Get-CtxtSharedSecretForDecrypt {
    <# 用自己的 ECDH 私鑰與容器內的 ephemeral 公鑰做 ECDH，得共享祕密 #>
    param(
        [byte[]] $EphPubKeyDer,
        [System.Security.Cryptography.ECDiffieHellman] $OwnPrivateKey
    )
    $ephPub = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $bytesRead = 0
        try {
            $ephPub.ImportSubjectPublicKeyInfo($EphPubKeyDer, [ref] $bytesRead)
        }
        catch {
            throw "容器內的 ephemeral 公鑰格式無效：$($_.Exception.Message)"
        }
        try {
            return $OwnPrivateKey.DeriveRawSecretAgreement($ephPub.PublicKey)
        }
        catch {
            throw "ECDH 金鑰交換失敗：私鑰與加密所用的公鑰不匹配，或私鑰檔案已損壞（$($_.Exception.Message)）"
        }
    }
    finally {
        $ephPub.Dispose()
    }
}

# ==========================================================================
# 區塊：容器二進位格式解析
# ==========================================================================

function ConvertFrom-CtxtContainer {
    param([byte[]] $Bytes)

    $headerMin = 4 + 1 + 2
    if ($Bytes.Length -lt $headerMin) {
        throw '容器格式錯誤：檔頭長度不足，檔案可能已損壞或被截斷'
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
    if ($magic -ne $Script:CtxtMagic) {
        throw "容器格式錯誤：檔頭 magic 不符（讀到 '$magic'），此檔案可能不是本工具產生的密文"
    }

    $version = $Bytes[4]
    if ($version -ne $Script:CtxtVersion) {
        throw "版本不符：檔案版本為 $version，本程式僅支援版本 $($Script:CtxtVersion)"
    }

    $ephPubKeyLen = [BitConverter]::ToUInt16($Bytes, 5)
    $offset = 7
    $minTotal = $offset + $ephPubKeyLen + $Script:NonceLength + $Script:TagLength
    if ($Bytes.Length -lt $minTotal) {
        throw '容器格式錯誤：長度不足以包含完整的 ephemeral 公鑰／nonce／tag，檔案可能已損壞或被截斷'
    }

    $ephPubKey = Get-ByteRange -Source $Bytes -Offset $offset -Length $ephPubKeyLen
    $offset += $ephPubKeyLen
    $nonce = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:NonceLength
    $offset += $Script:NonceLength
    $tag = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:TagLength
    $offset += $Script:TagLength
    $ciphertextLen = $Bytes.Length - $offset
    $ciphertext = Get-ByteRange -Source $Bytes -Offset $offset -Length $ciphertextLen

    return [pscustomobject]@{
        EphPubKey  = $ephPubKey
        Nonce      = $nonce
        Tag        = $tag
        Ciphertext = $ciphertext
    }
}

# ==========================================================================
# 區塊：ZIP 解包
# ==========================================================================

function Expand-CtxtZip {
    <# 將 ZIP 位元組解開到目的資料夾（手動走 stream，防 zip-slip） #>
    param(
        [byte[]] $ZipBytes,
        [string] $Destination
    )

    $ms = [System.IO.MemoryStream]::new($ZipBytes)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new(
            $ms, [System.IO.Compression.ZipArchiveMode]::Read, $false, [System.Text.Encoding]::UTF8)
        try {
            $destRoot = (New-Item -ItemType Directory -Path $Destination -Force).FullName
            $destRootWithSep = $destRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

            foreach ($entry in $zip.Entries) {
                # (a) 本工具自家產物一律用 '/' 當目錄分隔符（打包端 Get-CtxtPackPlan 已把
                #     '\' 轉成 '/'，見該函式內的 -replace '\\', '/'）。因此 entry 名稱只要
                #     含反斜線，就一定不是自家封裝，直接拒絕，不嘗試解讀成相對路徑。
                if ($entry.FullName -match '\\') {
                    throw [System.Security.SecurityException]::new(
                        "偵測到不安全的封存路徑（entry 名稱含反斜線）：$($entry.FullName)")
                }

                $relPath = $entry.FullName -replace '/', [System.IO.Path]::DirectorySeparatorChar
                $destPath = Join-Path -Path $destRoot -ChildPath $relPath

                # (b) 防禦性檢查：不用字串樣式（只擋 "../"）比對，改用正規化後的
                #     包含性判斷——把 destPath 解析成絕對路徑，要求其開頭必須是
                #     「$destRoot + 目錄分隔符」，否則一律視為跳脫目的資料夾。
                $fullResolved = [System.IO.Path]::GetFullPath($destPath)
                if (-not $fullResolved.StartsWith($destRootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw [System.Security.SecurityException]::new(
                        "偵測到不安全的封存路徑（跳脫目的資料夾）：$($entry.FullName)")
                }

                if ($entry.FullName.EndsWith('/')) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    continue
                }

                $destDir = Split-Path -Path $destPath -Parent
                if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }

                $entryStream = $entry.Open()
                try {
                    $outStream = [System.IO.File]::Create($destPath)
                    try {
                        $entryStream.CopyTo($outStream)
                    }
                    finally {
                        $outStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $ms.Dispose()
    }
}

# ==========================================================================
# 區塊：私鑰載入（-Unpack 用；DPAPI CurrentUser 保護的 Pkcs8 私鑰 blob）
# ==========================================================================

function Get-CtxtPrivateKey {
    <#
        讀取 ~\.ctxt\private.key（或 -KeyFile 指定路徑），該檔內容是用
        DPAPI（CurrentUser scope）保護過的 ECDH P-256 Pkcs8 私鑰位元組。
        只有「同一台機器、同一個 Windows 帳號」才解得開；否則視為
        「私鑰讀不到／DPAPI 解保護失敗」。
    #>
    param([string] $KeyFilePath)

    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) {
        $KeyFilePath = $Script:DefaultKeyFile
    }

    if (-not (Test-Path -LiteralPath $KeyFilePath -PathType Leaf)) {
        throw "私鑰檔案讀取失敗：找不到 $KeyFilePath（請確認路徑，或先以 -GenerateKeys 產生金鑰）"
    }

    $protectedBytes = [System.IO.File]::ReadAllBytes($KeyFilePath)

    $pkcs8Bytes = $null
    try {
        $pkcs8Bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    catch {
        throw "私鑰讀不到／DPAPI 解保護失敗（是否為非本機、非本 Windows 帳號產生的私鑰檔，或檔案已損壞？）：$($_.Exception.Message)"
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $bytesRead = 0
        try {
            $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead)
        }
        catch {
            throw "私鑰讀不到／DPAPI 解保護失敗：DPAPI 解密後的私鑰內容格式無效（$($_.Exception.Message)）"
        }
    }
    catch {
        $ecdh.Dispose()
        throw
    }
    finally {
        if ($pkcs8Bytes) {
            [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
        }
    }

    return $ecdh
}

# ==========================================================================
# 區塊：-Unpack 主流程
# ==========================================================================

function Invoke-CtxtUnpack {
    param(
        [string] $InFilePath,
        [string] $DestinationPath,
        [string] $KeyFilePath
    )

    if (-not (Test-Path -LiteralPath $InFilePath -PathType Leaf)) {
        throw "找不到輸入檔案：$InFilePath"
    }

    $rawText = [System.IO.File]::ReadAllText($InFilePath)
    $cleaned = ($rawText -replace '\s', '')
    if ([string]::IsNullOrEmpty($cleaned)) {
        throw '輸入檔案內容為空，無法解析'
    }

    try {
        $containerBytes = [Convert]::FromBase64String($cleaned)
    }
    catch {
        throw "Base64 解碼失敗：檔案內容可能已損壞或被截斷（$($_.Exception.Message)）"
    }

    $parsed = ConvertFrom-CtxtContainer -Bytes $containerBytes

    $ecdh = Get-CtxtPrivateKey -KeyFilePath $KeyFilePath
    try {
        $sharedSecret = Get-CtxtSharedSecretForDecrypt -EphPubKeyDer $parsed.EphPubKey -OwnPrivateKey $ecdh
    }
    finally {
        $ecdh.Dispose()
    }
    $infoBytes = Get-CtxtHkdfInfo -EphPubKeyDer $parsed.EphPubKey
    $aesKey = Get-CtxtDerivedAesKey -SharedSecret $sharedSecret -Nonce $parsed.Nonce -InfoBytes $infoBytes
    [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)

    try {
        $plain = [byte[]]::new($parsed.Ciphertext.Length)
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($aesKey, $Script:TagLength)
        try {
            $aesGcm.Decrypt($parsed.Nonce, $parsed.Ciphertext, $parsed.Tag, $plain)
        }
        finally {
            $aesGcm.Dispose()
            [Array]::Clear($aesKey, 0, $aesKey.Length)
        }
    }
    catch [System.Security.Cryptography.AuthenticationTagMismatchException] {
        throw '內容驗證失敗（GCM 認證標籤不符）：檔案在傳輸過程中可能被竄改或損壞'
    }
    catch {
        throw "GCM 解密失敗：內容可能已損壞（$($_.Exception.Message)）"
    }

    try {
        $zipBytes = Expand-CtxtBrotli -InputBytes $plain
    }
    catch {
        throw "Brotli 解壓縮失敗：資料可能已損壞（$($_.Exception.Message)）"
    }

    try {
        Expand-CtxtZip -ZipBytes $zipBytes -Destination $DestinationPath
    }
    catch [System.Security.SecurityException] {
        # 路徑安全例外（zip-slip 等）要原樣往上拋，不可被包成「封裝格式錯誤或已損壞」，
        # 以免使用者誤以為只是資料損毀而忽略了實際的安全性問題。
        throw
    }
    catch {
        throw "ZIP 解包失敗：封裝格式錯誤或已損壞（$($_.Exception.Message)）"
    }

    Write-Host "解密完成，檔案已還原至：$((Get-Item -LiteralPath $DestinationPath).FullName)"
}

# ==========================================================================
# 區塊：-GenerateKeys 主流程
# ==========================================================================

function Invoke-CtxtGenerateKeys {
    if (Test-Path -LiteralPath $Script:DefaultKeyFile) {
        throw "私鑰檔案已存在，為避免覆蓋既有金鑰（可能導致已加密的舊檔案永久無法解密），已拒絕操作：$($Script:DefaultKeyFile)`n如確定要產生新金鑰，請先手動備份／移除該檔案後再重新執行。"
    }

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }

    Write-Host '產生 ECDH P-256 金鑰對中，請稍候...'
    $ecdh = New-CtxtEcdhKeyPair
    $pkcs8Bytes = $null
    try {
        $pkcs8Bytes = $ecdh.ExportPkcs8PrivateKey()
        $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $pkcs8Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

        [System.IO.File]::WriteAllBytes($Script:DefaultKeyFile, $protectedBytes)

        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
    }
    finally {
        if ($pkcs8Bytes) {
            [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
        }
        $ecdh.Dispose()
    }

    Write-Host ''
    Write-Host "私鑰已寫入（DPAPI CurrentUser 保護）：$($Script:DefaultKeyFile)"
    Write-Host '此檔案只有在這台機器、這個 Windows 帳號下才解得開；請自行備份，'
    Write-Host '遺失或搬到別的機器／帳號，將無法解密任何已用對應公鑰加密的檔案。'
    Write-Host ''
    Write-Host '===== 請將以下公鑰 PEM 完整貼入 transfer.ps1 頂部的 $PublicKeyPem 變數（加密端使用）====='
    Write-Host $publicPem
    Write-Host '=========================================================================='
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
