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
# 區塊：加密 — 加密方向（AES-256-GCM + RSA-4096-OAEP-SHA256 包裹金鑰）
# ==========================================================================

function Protect-CtxtAesGcm {
    <# 產生一次性 AES-256 金鑰與 12B nonce，GCM 加密，回傳 Key/Nonce/Tag/Ciphertext #>
    param([byte[]] $PlainBytes)

    $key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
    $nonce = [byte[]]::new($Script:NonceLength)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $tag = [byte[]]::new($Script:TagLength)
    $cipherBytes = [byte[]]::new($PlainBytes.Length)

    $aesGcm = [System.Security.Cryptography.AesGcm]::new($key, $Script:TagLength)
    try {
        $aesGcm.Encrypt($nonce, $PlainBytes, $cipherBytes, $tag)
    }
    finally {
        $aesGcm.Dispose()
    }

    return [pscustomobject]@{
        Key        = $key
        Nonce      = $nonce
        Tag        = $tag
        Ciphertext = $cipherBytes
    }
}

function Protect-CtxtAesKey {
    <# 用 RSA 公鑰（OAEP-SHA256）包裹 AES 金鑰 #>
    param(
        [byte[]] $AesKey,
        [string] $PublicKeyPemText
    )
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        try {
            $rsa.ImportFromPem($PublicKeyPemText)
        }
        catch {
            throw "公鑰 PEM 格式無效，無法載入：$($_.Exception.Message)"
        }
        return $rsa.Encrypt($AesKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    finally {
        $rsa.Dispose()
    }
}

# ==========================================================================
# 區塊：容器二進位格式組裝
# ==========================================================================

function New-CtxtContainer {
    param(
        [byte[]] $WrappedKey,
        [byte[]] $Nonce,
        [byte[]] $Tag,
        [byte[]] $Ciphertext
    )
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:CtxtMagic)
    $lenBytes = [BitConverter]::GetBytes([uint16] $WrappedKey.Length)

    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($magicBytes, 0, $magicBytes.Length)
    $ms.WriteByte($Script:CtxtVersion)
    $ms.Write($lenBytes, 0, 2)
    $ms.Write($WrappedKey, 0, $WrappedKey.Length)
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

    Write-Host '加密中（AES-256-GCM + RSA-4096-OAEP-SHA256）...'
    $aes = Protect-CtxtAesGcm -PlainBytes $compressed
    $wrappedKey = Protect-CtxtAesKey -AesKey $aes.Key -PublicKeyPemText $PublicKeyPem
    [Array]::Clear($aes.Key, 0, $aes.Key.Length)

    $container = New-CtxtContainer -WrappedKey $wrappedKey -Nonce $aes.Nonce -Tag $aes.Tag -Ciphertext $aes.Ciphertext

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

function Unprotect-CtxtAesKey {
    <# 用 RSA 私鑰解開 AES 金鑰包裹 #>
    param(
        [byte[]] $WrappedKey,
        [System.Security.Cryptography.RSA] $Rsa
    )
    try {
        return $Rsa.Decrypt($WrappedKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    catch {
        throw "AES 金鑰解密失敗：私鑰與加密所用的公鑰不匹配，或私鑰檔案已損壞（$($_.Exception.Message)）"
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

    $wrappedKeyLen = [BitConverter]::ToUInt16($Bytes, 5)
    $offset = 7
    $minTotal = $offset + $wrappedKeyLen + $Script:NonceLength + $Script:TagLength
    if ($Bytes.Length -lt $minTotal) {
        throw '容器格式錯誤：長度不足以包含完整的金鑰／nonce／tag，檔案可能已損壞或被截斷'
    }

    $wrappedKey = Get-ByteRange -Source $Bytes -Offset $offset -Length $wrappedKeyLen
    $offset += $wrappedKeyLen
    $nonce = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:NonceLength
    $offset += $Script:NonceLength
    $tag = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:TagLength
    $offset += $Script:TagLength
    $ciphertextLen = $Bytes.Length - $offset
    $ciphertext = Get-ByteRange -Source $Bytes -Offset $offset -Length $ciphertextLen

    return [pscustomobject]@{
        WrappedKey = $wrappedKey
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
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName -match '(^|/)\.\.(/|$)' -or [System.IO.Path]::IsPathRooted($entry.FullName)) {
                    throw "ZIP 內含不安全的路徑項目：$($entry.FullName)"
                }
                $relPath = $entry.FullName -replace '/', [System.IO.Path]::DirectorySeparatorChar
                $destPath = Join-Path -Path $destRoot -ChildPath $relPath

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
# 區塊：私鑰載入（-Unpack 用；-GenerateKeys 的產生流程於下一個里程碑實作）
# ==========================================================================

function Get-CtxtPrivateKey {
    <# 載入私鑰 PEM；若為加密 PEM 則互動詢問密碼（Read-Host -AsSecureString） #>
    param([string] $KeyFilePath)

    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) {
        $KeyFilePath = $Script:DefaultKeyFile
    }

    if (-not (Test-Path -LiteralPath $KeyFilePath -PathType Leaf)) {
        throw "私鑰檔案讀取失敗：找不到 $KeyFilePath（請確認路徑，或先以 -GenerateKeys 產生金鑰）"
    }

    $pemText = [System.IO.File]::ReadAllText($KeyFilePath)

    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        if ($pemText -match 'ENCRYPTED PRIVATE KEY') {
            $securePwd = Read-Host -Prompt '私鑰已加密，請輸入密碼' -AsSecureString
            $plainPwd = [System.Net.NetworkCredential]::new('', $securePwd).Password
            try {
                $rsa.ImportFromEncryptedPem($pemText, $plainPwd)
            }
            catch {
                throw "私鑰解密失敗：密碼錯誤，或私鑰檔案已損壞（$($_.Exception.Message)）"
            }
            finally {
                $plainPwd = $null
            }
        }
        else {
            try {
                $rsa.ImportFromPem($pemText)
            }
            catch {
                throw "私鑰讀不到或解不開：PEM 格式無效或檔案已損壞（$($_.Exception.Message)）"
            }
        }
    }
    catch {
        $rsa.Dispose()
        throw
    }

    return $rsa
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

    $rsa = Get-CtxtPrivateKey -KeyFilePath $KeyFilePath
    try {
        $aesKey = Unprotect-CtxtAesKey -WrappedKey $parsed.WrappedKey -Rsa $rsa
    }
    finally {
        $rsa.Dispose()
    }

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

    Write-Host '產生 RSA-4096 金鑰對中，請稍候...'
    $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $securePwd = Read-Host -Prompt '設定私鑰保護密碼（可留空，直接按 Enter 略過＝不加密私鑰）' -AsSecureString
        $plainPwd = [System.Net.NetworkCredential]::new('', $securePwd).Password

        if ([string]::IsNullOrEmpty($plainPwd)) {
            $privatePem = $rsa.ExportPkcs8PrivateKeyPem()
        }
        else {
            $pbeParams = [System.Security.Cryptography.PbeParameters]::new(
                [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                600000)
            $privatePem = $rsa.ExportEncryptedPkcs8PrivateKeyPem($plainPwd, $pbeParams)
        }
        $plainPwd = $null

        [System.IO.File]::WriteAllText($Script:DefaultKeyFile, $privatePem)

        $publicPem = $rsa.ExportSubjectPublicKeyInfoPem()
    }
    finally {
        $rsa.Dispose()
    }

    Write-Host ''
    Write-Host "私鑰已寫入：$($Script:DefaultKeyFile)"
    Write-Host '請妥善保管此檔案並自行備份，遺失將無法解密任何已用對應公鑰加密的檔案。'
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
