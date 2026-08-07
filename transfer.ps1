#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具 — 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：打包（ZIP/store）→ 壓縮（Brotli）→ 加密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→ 文字編碼（Base64）。
    純 .NET 內建類別實作，零外部依賴，全程記憶體操作，不經 PowerShell 管道。

.EXAMPLE
    .\transfer.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對，私鑰以 DPAPI 保護後存到 ~\.rune\private.key，並在畫面印出公鑰 PEM。

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
#      私鑰（ECDH P-256）會以 DPAPI（CurrentUser）保護後寫到 ~\.rune\private.key，
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
#   magic "RUNE"(4B ASCII) | version 0x02(1B) | contentType(1B) | ephPubKeyLen(uint16 LE)
#   | ephemeral ECDH P-256 公鑰（SubjectPublicKeyInfo DER）| nonce(12B) | tag(16B) | ciphertext
#
#   欄位位移：magic@0 version@4 contentType@5 ephPubKeyLen@6 ephPubKey@8
#            nonce@8+n tag@20+n ciphertext@36+n（n = ephPubKeyLen），header 最小長度 8。
#
#   contentType（1 byte，明文）：
#     0x01 = 檔案樹，明文側被加密的內容 = Brotli( Zip( 輸入 ) )
#     0x02 = UTF-8 純文字，明文側 = Brotli( UTF8( 文字 ) )，無 ZIP 層【保留，本版尚未實作】
#   放在 version 之後，是為了讓 magic+version（byte 0–4）成為所有版本共通、永遠可解析的
#   前綴；未來版本可自 byte 5 起重新定義而不失去「這是 Rune 檔、版本是 N」的判讀能力。
#   以明文存放的代價只是洩漏「這是檔案還是文字」，而負載大小早就洩漏了同一件事。
#
#   金鑰交換／派生（version 2）：
#     每次 -Pack 產生一次性 ephemeral ECDH P-256 金鑰對，與腳本內嵌的靜態
#     公鑰做 ECDH（DeriveRawSecretAgreement）得共享祕密；再以
#     HKDF-SHA256(ikm = 共享祕密, salt = nonce,
#                 info = magic + version + contentType + ephemeral公鑰DER)
#     派生 32 bytes 的 AES-256-GCM 金鑰。salt 選用 nonce（而非空）是為了讓每次
#     Pack 產生的金鑰額外與該次的 nonce 綁定；info 內含 magic/version/contentType/
#     ephemeral 公鑰，確保派生結果與容器內容一一對應、不可跨欄位替換。
#
#   【contentType 必須進 HKDF info】本工具的 AES-GCM 未使用 AAD，tag 只涵蓋 ciphertext，
#   涵蓋不到 header 任何一個 byte。若 contentType 不進 info，攻擊者把 0x01 翻成 0x02
#   後 tag 仍會驗過，解密端就會把一串 ZIP 位元組當成 UTF-8 文字處理——這是 content-type
#   confusion。綁進 info 之後，翻位元 → 派生金鑰不同 → tag 不符，直接走既有的認證失敗路徑。
#   也因此「型別是否支援」的檢查必須放在 GCM 解密成功之後（見 Invoke-RuneOpen）：
#   tag 驗過就等於這個 byte 是真品，此時值仍未知才能斷定是版本落後而非資料被竄改。
#
#   【新舊互斥】RUNE v2 與舊工具的 CTXT v2 無血緣關係，version 編號重用純屬巧合，
#   兩者靠 magic 互斥：magic 檢查排在 version 檢查之前（見 ConvertFrom-RuneContainer），
#   舊 CTXT 密文餵進來一定先被 magic 擋掉，永遠到不了 version 比對；反向亦然。
#   縱深防禦：magic 亦在 HKDF info 內，即使強行跳過檢查，派生金鑰也不同 → tag 不符。
# ==========================================================================
$Script:RuneMagic = 'RUNE'
$Script:RuneVersion = [byte] 2
# 內容型別列舉：0x01 檔案樹（本版唯一會產生也唯一支援的型別）、0x02 UTF-8 純文字（保留）
$Script:ContentTypeFileTree = [byte] 1
$Script:ContentTypeText = [byte] 2
$Script:NonceLength = 12
$Script:TagLength = 16
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'

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

function Get-RunePackPlan {
    <#
        依 -Pack 參數判斷輸入型態（單檔 / wildcard / 資料夾），
        回傳要打包的項目清單，以及推導輸出檔名用的基底名稱。
    #>
    param([string] $PackPath)

    if ($PackPath -match '[*?]') {
        # --- wildcard：Get-Item 展開，僅當層不遞迴。wildcard 命中的子目錄一律
        #     略過並警告（不遞迴打包目錄），不再靜默把目錄當空 entry 塞進封存包。
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
        $fileItems = @(foreach ($item in $items) {
            if ($item.PSIsContainer) {
                Write-Warning "wildcard 不遞迴，已略過目錄：$($item.Name)"
                continue
            }
            $item
        })
        if ($fileItems.Count -eq 0) {
            throw "找不到符合萬用字元的項目：$PackPath（僅匹配到目錄，wildcard 不遞迴打包目錄）"
        }
        $entries = foreach ($item in $fileItems) {
            [pscustomobject]@{
                EntryName   = $item.Name
                SourcePath  = $item.FullName
                IsDirectory = $false
            }
        }
        return [pscustomobject]@{
            Entries         = @($entries)
            DefaultBaseName = (Split-Path -Path $parent -Leaf)
        }
    }
    elseif (Test-Path -LiteralPath $PackPath -PathType Container) {
        # --- 資料夾：遞迴整包，保留子目錄結構（含空子目錄） ---
        $root = (Get-Item -LiteralPath $PackPath).FullName.TrimEnd('\', '/')
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)
        $allDirs = @(Get-ChildItem -LiteralPath $root -Recurse -Directory -Force)
        if ($files.Count -eq 0 -and $allDirs.Count -eq 0) {
            throw "資料夾內沒有可打包的檔案：$PackPath"
        }
        $fileEntries = foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
            [pscustomobject]@{
                EntryName   = $rel
                SourcePath  = $f.FullName
                IsDirectory = $false
            }
        }
        # 空子目錄（本身及遞迴子孫都不含任何檔案）額外列舉成目錄 entry，
        # 讓 -Unpack 端可以還原出空的目錄結構，而不是被靜默丟棄。
        $emptyDirEntries = foreach ($d in $allDirs) {
            $hasAnyFile = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Force).Count -gt 0
            if (-not $hasAnyFile) {
                $rel = $d.FullName.Substring($root.Length + 1) -replace '\\', '/'
                [pscustomobject]@{
                    EntryName   = $rel
                    SourcePath  = $null
                    IsDirectory = $true
                }
            }
        }
        return [pscustomobject]@{
            Entries         = @($fileEntries) + @($emptyDirEntries)
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

function New-RuneZipBytes {
    <# 依項目清單建立 ZIP（store，UTF-8 檔名），回傳位元組陣列。含資料夾模式列舉的空目錄 entry。 #>
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

function Compress-RuneBrotli {
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

function New-RuneEcdhKeyPair {
    <# 產生一個新的 ECDH P-256 金鑰對（同時持有公私鑰） #>
    return [System.Security.Cryptography.ECDiffieHellman]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
}

function Get-RuneStaticPublicKey {
    <# 從腳本內嵌的 $PublicKeyPem 載入靜態 ECDH 公鑰（只含公鑰），並驗證曲線為 P-256 #>
    param([string] $PublicKeyPemText)
    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $ecdh.ImportFromPem($PublicKeyPemText)
    }
    catch {
        $ecdh.Dispose()
        throw "公鑰 PEM 格式無效，無法載入：$($_.Exception.Message)"
    }

    $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
    if ($curveOid -ne $Script:P256CurveOid) {
        $ecdh.Dispose()
        throw "公鑰不是 P-256：曲線 OID 為 $curveOid，本工具僅支援 P-256（$($Script:P256CurveOid)）"
    }

    return $ecdh
}

function Get-RuneHkdfInfo {
    <#
        HKDF 的 info：magic + version + contentType + ephemeral 公鑰 DER 位元組。
        contentType 必須在其中——GCM 未使用 AAD，header 不受 tag 保護，
        只有綁進金鑰派生才能讓型別位元被竄改時直接表現為認證失敗。
    #>
    param(
        [byte] $ContentType,
        [byte[]] $EphPubKeyDer
    )
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:RuneMagic)
    $info = [byte[]]::new($magicBytes.Length + 1 + 1 + $EphPubKeyDer.Length)
    [System.Buffer]::BlockCopy($magicBytes, 0, $info, 0, $magicBytes.Length)
    $info[$magicBytes.Length] = $Script:RuneVersion
    $info[$magicBytes.Length + 1] = $ContentType
    [System.Buffer]::BlockCopy($EphPubKeyDer, 0, $info, $magicBytes.Length + 2, $EphPubKeyDer.Length)
    return , $info
}

function Get-RuneDerivedAesKey {
    <# HKDF-SHA256(ikm=共享祕密, salt=nonce, info=magic+version+contentType+ephemeral公鑰) -> 32B AES 金鑰 #>
    param(
        [byte[]] $SharedSecret,
        [byte[]] $Nonce,
        [byte[]] $InfoBytes
    )
    return [System.Security.Cryptography.HKDF]::DeriveKey(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, $SharedSecret, 32, $Nonce, $InfoBytes)
}

function Protect-RuneAesGcm {
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

function New-RuneContainer {
    param(
        [byte] $ContentType,
        [byte[]] $EphPubKey,
        [byte[]] $Nonce,
        [byte[]] $Tag,
        [byte[]] $Ciphertext
    )
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:RuneMagic)
    # 明確指定小端序寫入，不依賴 BitConverter 隨執行平台而定的位元組順序
    # （Windows 上兩者結果相同，但明確指定較不易出錯，也符合容器格式的
    # 「uint16 LE」宣告）。
    $lenBytes = [byte[]]::new(2)
    [System.Buffers.Binary.BinaryPrimitives]::WriteUInt16LittleEndian($lenBytes, [uint16] $EphPubKey.Length)

    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($magicBytes, 0, $magicBytes.Length)
    $ms.WriteByte($Script:RuneVersion)
    $ms.WriteByte($ContentType)
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

function Invoke-RuneSeal {
    param(
        [string] $PackPath,
        [string] $OutFilePath,
        [switch] $ForceOverwrite
    )

    if ([string]::IsNullOrWhiteSpace($PublicKeyPem)) {
        throw '尚未設定公鑰：請先在解密端執行 -GenerateKeys 產生金鑰對，並將印出的公鑰 PEM 貼入本腳本頂部的 $PublicKeyPem 變數後再重新執行 -Pack。'
    }

    $plan = Get-RunePackPlan -PackPath $PackPath
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
    $zipBytes = New-RuneZipBytes -Entries $plan.Entries
    $originalSize = $zipBytes.Length

    Write-Host '壓縮中（Brotli, SmallestSize）...'
    $compressed = Compress-RuneBrotli -InputBytes $zipBytes
    $compressedSize = $compressed.Length

    Write-Host '加密中（ECDH P-256 + HKDF-SHA256 + AES-256-GCM）...'
    $ephemeral = New-RuneEcdhKeyPair
    $staticPub = Get-RuneStaticPublicKey -PublicKeyPemText $PublicKeyPem
    $aesKey = $null
    try {
        $sharedSecret = $ephemeral.DeriveRawSecretAgreement($staticPub.PublicKey)
        $ephPubKeyDer = $ephemeral.ExportSubjectPublicKeyInfo()

        $nonce = [byte[]]::new($Script:NonceLength)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

        $infoBytes = Get-RuneHkdfInfo -ContentType $Script:ContentTypeFileTree -EphPubKeyDer $ephPubKeyDer
        $aesKey = Get-RuneDerivedAesKey -SharedSecret $sharedSecret -Nonce $nonce -InfoBytes $infoBytes
        [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)

        $aes = Protect-RuneAesGcm -PlainBytes $compressed -AesKey $aesKey -Nonce $nonce
    }
    finally {
        # 與解密端一致：無論成功或中途拋錯，aesKey 一律在 finally 清零，
        # 不因 Protect-RuneAesGcm 拋例外而讓金鑰殘留在記憶體中未被清除。
        if ($aesKey) {
            [Array]::Clear($aesKey, 0, $aesKey.Length)
        }
        $ephemeral.Dispose()
        $staticPub.Dispose()
    }

    # 本版的 -Pack 一律產生檔案樹型別（0x01）；0x02 純文字保留給後續版本。
    $container = New-RuneContainer -ContentType $Script:ContentTypeFileTree -EphPubKey $ephPubKeyDer `
        -Nonce $nonce -Tag $aes.Tag -Ciphertext $aes.Ciphertext

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

function Expand-RuneBrotli {
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

function Get-RuneSharedSecretForDecrypt {
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

function ConvertFrom-RuneContainer {
    <#
        只擷取欄位，不做內容型別的合法性驗證：contentType 的 0x00–0xFF 任何值都照原樣
        回傳。型別是否支援必須等 GCM 認證通過之後才能判定，否則「位元被竄改」會被誤報成
        「不支援的內容型別」（詳見 Invoke-RuneOpen）。
    #>
    param([byte[]] $Bytes)

    $headerMin = 4 + 1 + 1 + 2
    if ($Bytes.Length -lt $headerMin) {
        throw '容器格式錯誤：檔頭長度不足，檔案可能已損壞或被截斷'
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
    if ($magic -ne $Script:RuneMagic) {
        throw "容器格式錯誤：檔頭 magic 不符（讀到 '$magic'），此檔案可能不是本工具產生的密文"
    }

    $version = $Bytes[4]
    if ($version -ne $Script:RuneVersion) {
        throw "版本不符：檔案版本為 $version，本程式僅支援版本 $($Script:RuneVersion)"
    }

    $contentType = $Bytes[5]

    # 明確指定小端序讀取，對應寫入端 New-RuneContainer 的 WriteUInt16LittleEndian
    $ephPubKeyLenBytes = Get-ByteRange -Source $Bytes -Offset 6 -Length 2
    $ephPubKeyLen = [System.Buffers.Binary.BinaryPrimitives]::ReadUInt16LittleEndian($ephPubKeyLenBytes)
    $offset = 8
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
        ContentType = $contentType
        EphPubKey   = $ephPubKey
        Nonce       = $nonce
        Tag         = $tag
        Ciphertext  = $ciphertext
    }
}

# ==========================================================================
# 區塊：ZIP 解包
# ==========================================================================

function Expand-RuneZip {
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
                # (a) 本工具自家產物一律用 '/' 當目錄分隔符（打包端 Get-RunePackPlan 已把
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

function Move-RuneExtractedTree {
    <#
        把 $SourceDir 底下的內容遞迴搬到 $DestDir（同名目錄就合併、同名檔案就覆蓋），
        用於 -Unpack 的「先解到暫存資料夾，全部成功後才搬到正式 Destination」流程。
    #>
    param(
        [string] $SourceDir,
        [string] $DestDir
    )

    if (-not (Test-Path -LiteralPath $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }

    foreach ($child in Get-ChildItem -LiteralPath $SourceDir -Force) {
        $targetPath = Join-Path -Path $DestDir -ChildPath $child.Name
        if ($child.PSIsContainer) {
            if (Test-Path -LiteralPath $targetPath -PathType Container) {
                Move-RuneExtractedTree -SourceDir $child.FullName -DestDir $targetPath
            }
            else {
                Move-Item -LiteralPath $child.FullName -Destination $targetPath -Force
            }
        }
        else {
            Move-Item -LiteralPath $child.FullName -Destination $targetPath -Force
        }
    }
}

# ==========================================================================
# 區塊：私鑰載入（-Unpack 用；DPAPI CurrentUser 保護的 Pkcs8 私鑰 blob）
# ==========================================================================

function Get-RunePrivateKey {
    <#
        讀取 ~\.rune\private.key（或 -KeyFile 指定路徑），該檔內容是用
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

        $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
        if ($curveOid -ne $Script:P256CurveOid) {
            throw "私鑰不是 P-256：曲線 OID 為 $curveOid，本工具僅支援 P-256（$($Script:P256CurveOid)）"
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

function Invoke-RuneOpen {
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

    $parsed = ConvertFrom-RuneContainer -Bytes $containerBytes

    $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath
    try {
        $sharedSecret = Get-RuneSharedSecretForDecrypt -EphPubKeyDer $parsed.EphPubKey -OwnPrivateKey $ecdh
    }
    finally {
        $ecdh.Dispose()
    }
    $infoBytes = Get-RuneHkdfInfo -ContentType $parsed.ContentType -EphPubKeyDer $parsed.EphPubKey
    $aesKey = Get-RuneDerivedAesKey -SharedSecret $sharedSecret -Nonce $parsed.Nonce -InfoBytes $infoBytes
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

    # 內容型別的合法性檢查必須在此——GCM 認證通過之後、解壓之前。
    # contentType 已綁進 HKDF info，tag 驗過就等於這個 byte 是真品；此時值仍未知，
    # 才能斷定是本程式版本落後，而不是資料被竄改。若把這個檢查提前到解析階段，
    # 「位元被翻掉」會被誤報成「不支援的內容型別」，使用者就抓不到真正的問題。
    if ($parsed.ContentType -ne $Script:ContentTypeFileTree) {
        throw ('本容器的內容型別 0x{0:X2} 由較新版本的 Rune 產生，請更新 rune-open.ps1' -f $parsed.ContentType)
    }

    try {
        $zipBytes = Expand-RuneBrotli -InputBytes $plain
    }
    catch {
        throw "Brotli 解壓縮失敗：資料可能已損壞（$($_.Exception.Message)）"
    }

    # 先解到 Destination 底下的暫存資料夾，全部成功後才搬到正式位置；
    # 任何一步失敗都清掉暫存資料夾並報錯，Destination 不留半成品。
    $tmpDir = Join-Path -Path $DestinationPath -ChildPath (".rune-tmp-" + [Guid]::NewGuid().ToString('N'))
    try {
        try {
            Expand-RuneZip -ZipBytes $zipBytes -Destination $tmpDir
        }
        catch [System.Security.SecurityException] {
            # 路徑安全例外（zip-slip 等）要原樣往上拋，不可被包成「封裝格式錯誤或已損壞」，
            # 以免使用者誤以為只是資料損毀而忽略了實際的安全性問題。
            throw
        }
        catch {
            throw "ZIP 解包失敗：封裝格式錯誤或已損壞（$($_.Exception.Message)）"
        }

        try {
            Move-RuneExtractedTree -SourceDir $tmpDir -DestDir $DestinationPath
        }
        catch {
            throw "解包結果搬移失敗：無法將暫存資料夾內容搬到 $DestinationPath（$($_.Exception.Message)）"
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmpDir) {
            Remove-Item -LiteralPath $tmpDir -Recurse -Force
        }
    }

    Write-Host "解密完成，檔案已還原至：$((Get-Item -LiteralPath $DestinationPath).FullName)"
}

# ==========================================================================
# 區塊：-GenerateKeys 主流程
# ==========================================================================

function Invoke-RuneGenerateKeys {
    if (Test-Path -LiteralPath $Script:DefaultKeyFile) {
        throw "私鑰檔案已存在，為避免覆蓋既有金鑰（可能導致已加密的舊檔案永久無法解密），已拒絕操作：$($Script:DefaultKeyFile)`n如確定要產生新金鑰，請先手動備份／移除該檔案後再重新執行。"
    }

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }

    Write-Host '產生 ECDH P-256 金鑰對中，請稍候...'
    $ecdh = New-RuneEcdhKeyPair
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
            Invoke-RuneGenerateKeys
        }
        'Pack' {
            Invoke-RuneSeal -PackPath $Pack -OutFilePath $OutFile -ForceOverwrite:$Force
        }
        'Unpack' {
            Invoke-RuneOpen -InFilePath $Unpack -DestinationPath $Destination -KeyFilePath $KeyFile
        }
    }
}
catch {
    # 用 [Console]::Error.WriteLine 直接印一行錯誤訊息，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的一行錯誤說明。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
