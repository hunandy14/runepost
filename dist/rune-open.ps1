# 本檔由 build.ps1 自 src/ 組裝產生，請勿直接編輯 —— 請改 src/ 後重跑 build.ps1
# source-digest: bbc9c01226b9
# format: RUNE v2
# product: rune-open
# fragments: 20
#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具（解密端 + 金鑰管理）— 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：文字解碼（Base64）→ 解密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→
    解壓（Brotli）→ 解包（ZIP/store）。純 .NET 內建類別實作，零外部依賴，全程記憶體操作。

    私鑰以 DPAPI（CurrentUser）保護後存於 ~\.rune\private.key，只有「同一台機器、
    同一個 Windows 帳號」解得開。公鑰同時寫到 ~\.rune\public.pem，交給加密端
    （rune-seal.ps1）使用。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對：私鑰以 DPAPI 保護後存到 ~\.rune\private.key，公鑰同時寫到
    ~\.rune\public.pem，並在畫面印出公鑰 PEM 與公鑰指紋。

.EXAMPLE
    .\rune-open.ps1 -ExportPublicKey
    從既有的 ~\.rune\private.key 重新導出公鑰，覆寫 ~\.rune\public.pem 並印出指紋。
    public.pem 遺失時用這個補回來，也可以拿來隨時再看一次自己的指紋。

.EXAMPLE
    .\rune-open.ps1 -Unpack report.docx.txt -Destination C:\out
    在持有私鑰的機器上解密還原檔案。
#>
[CmdletBinding(DefaultParameterSetName = 'Unpack')]
param(
    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Unpack,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Destination,

    [Parameter(ParameterSetName = 'Unpack')]
    [Parameter(ParameterSetName = 'ExportPublicKey')]
    [string] $KeyFile,

    [Parameter(ParameterSetName = 'GenerateKeys', Mandatory = $true)]
    [switch] $GenerateKeys,

    [Parameter(ParameterSetName = 'ExportPublicKey', Mandatory = $true)]
    [switch] $ExportPublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 金鑰的取得與擺放（公鑰不內嵌在腳本裡）
#
#   1. 在「解密端」（保管私鑰的那台機器）執行：
#        pwsh .\transfer.ps1 -GenerateKeys
#      私鑰（ECDH P-256）會以 DPAPI（CurrentUser）保護後寫到 ~\.rune\private.key，
#      公鑰同時寫到 ~\.rune\public.pem，畫面另外印出公鑰 PEM 與「公鑰指紋」。
#      私鑰檔只有「同一台機器、同一個 Windows 帳號」能用 DPAPI 解回來，
#      換機器或換帳號一律讀不開，因此不需要另外設密碼。
#   2. 把 public.pem 交給「加密端」，放到該機器的 ~\.rune\public.pem
#      （或用 -PublicKey 指定其他路徑／直接給 PEM 字串本體）。
#   3. 加密端每次執行 -Pack 都會先印出所用公鑰的指紋，請與解密端印出的逐字比對。
#
# 為什麼不內嵌：內嵌只有兩種結果——交付出去的腳本帶著某個人的公鑰（別人拿到就是
# 加密給他），或維持空字串（拿到不能用，人人都得先編輯腳本）。改成執行期讀檔後，
# 本腳本是與金鑰無關的通用工具，任何人配上自己的 public.pem 即可使用。
#
# 為什麼要有指紋：公鑰檔被掉包會讓使用者靜默地把資料加密給攻擊者，而資料檔被換
# 比腳本被改更難察覺——腳本有版本控管，~\.rune\public.pem 什麼都沒有。指紋是這條
# 路徑上唯一的防線，所以 -Pack 每次都印，讓每一次執行都有機會發現異常。
# ==========================================================================

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
#     每次 -Pack 產生一次性 ephemeral ECDH P-256 金鑰對，與執行期載入的收件人
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
# seal + open 共用：只放兩邊都要用到的常數。私鑰相關的路徑常數
# （$Script:DefaultKeyDir / $Script:DefaultKeyFile）刻意不放這裡，改放
# keystore/private-paths.ps1（只給 open 用）——否則只要 seal 端載入了這個
# 共用 fragment，dist/rune-seal.ps1 的原始碼文字裡就會出現 "DefaultKeyFile"
# 這個符號（即使從未被引用），讓「加密端不含任何解密相關符號」這個負面掃描
# 斷言失去意義。兩檔各自獨立算出 $HOME\.rune，屬性上有一行的重複，換來的是
# 這個純文字層級的隔離可被靜態掃描驗證。
$Script:DefaultPublicKeyFile = Join-Path -Path (Join-Path -Path $HOME -ChildPath '.rune') -ChildPath 'public.pem'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'
# open 專用：私鑰檔的路徑常數。刻意與 keystore/paths.ps1（seal + open 共用）
# 分開成獨立 fragment，只給 rune-open.ps1 的 manifest 收錄——確保
# "DefaultKeyFile" 這個符號不會出現在 dist/rune-seal.ps1 的原始碼文字裡。
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
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
# 區塊：金鑰交換與派生（ECDH P-256 + HKDF-SHA256，加解密共用）
# ==========================================================================

function New-RuneEcdhKeyPair {
    <# 產生一個新的 ECDH P-256 金鑰對（同時持有公私鑰） #>
    return [System.Security.Cryptography.ECDiffieHellman]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
}

function Get-RuneKeyFingerprint {
    <#
        公鑰指紋：SHA-256( SubjectPublicKeyInfo DER ) 取前 16 bytes（128 bits），
        大寫 hex 每 4 字元一組、以 '-' 連接，共 8 組 39 個字元。

        輸入取 SPKI DER 而非 PEM 文字，因為 DER 是正規、唯一的序列化（PEM 會因換行、
        尾隨空白、標頭大小寫而變動），而且 DER 內含曲線 OID，指紋因此天生跨曲線域分離。
        使用者也可以不信任本腳本，改用標準工具獨立驗證得到相同摘要：
            openssl pkey -pubin -in public.pem -outform DER | openssl dgst -sha256
        取 16 bytes 而非更短：指紋是公鑰替換攻擊的唯一防線，32 bits 可在筆電上分鐘級
        磨出碰撞，64 bits 昂貴但非不可及，128 bits 則永久出局。
    #>
    param([byte[]] $SpkiDer)
    $digest = [System.Security.Cryptography.SHA256]::HashData($SpkiDer)
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $groups = for ($i = 0; $i -lt $hex.Length; $i += 4) { $hex.Substring($i, 4) }
    return ($groups -join '-')
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
# 區塊：-GenerateKeys / -ExportPublicKey 主流程
# ==========================================================================

function Write-RunePublicKeyBlock {
    <#
        統一的公鑰輸出格式：PEM 全文 + 指紋。兩端要比對的就是這個指紋，所以格式必須一致。
        -PublicKeyFilePath 由呼叫端明確傳入實際寫入的路徑（而非在這裡假設一定是預設
        路徑）——-ExportPublicKey 用非預設 -KeyFile 時會寫到私鑰同目錄，不是預設位置。
    #>
    param(
        [string] $PublicPem,
        [byte[]] $SpkiDer,
        [string] $PublicKeyFilePath
    )
    Write-Host "公鑰已寫入：$PublicKeyFilePath"
    Write-Host '請把這個檔案（或以下 PEM 全文）交給加密端，放到該機器的 ~\.rune\public.pem。'
    Write-Host ''
    Write-Host '===== 公鑰 PEM（加密端使用）====='
    Write-Host $PublicPem
    Write-Host '================================'
    Write-Host ('公鑰指紋：RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $SpkiDer))
    Write-Host '加密端每次 -Pack 都會印出同格式的指紋，請逐字比對；不符代表公鑰在傳遞過程中被掉包。'
}

function Invoke-RuneGenerateKeys {
    # 私鑰已存在一律拒絕：覆蓋私鑰會讓已加密的舊檔案永久無法解密，這條資料遺失防護不變。
    if (Test-Path -LiteralPath $Script:DefaultKeyFile) {
        throw "私鑰檔案已存在，為避免覆蓋既有金鑰（可能導致已加密的舊檔案永久無法解密），已拒絕操作：$($Script:DefaultKeyFile)`n如確定要產生新金鑰，請先手動備份／移除該檔案後再重新執行。"
    }
    # 私鑰不存在但 public.pem 還在：直接覆蓋。孤兒 public.pem（私鑰已遺失）比沒有檔案
    # 更危險——加密端會持續加密給一把沒人持有的金鑰，產出永久無法解讀的密文。

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

        # 寫入順序固定「先私鑰、後公鑰」：若 public.pem 寫入失敗，private.key 仍在，
        # 可用 -ExportPublicKey 補救；反序則會留下一把沒有對應私鑰的公鑰。
        [System.IO.File]::WriteAllBytes($Script:DefaultKeyFile, $protectedBytes)

        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
        [System.IO.File]::WriteAllText($Script:DefaultPublicKeyFile, $publicPem, [System.Text.UTF8Encoding]::new($false))
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
    Write-RunePublicKeyBlock -PublicPem $publicPem -SpkiDer $spkiDer -PublicKeyFilePath $Script:DefaultPublicKeyFile
}

function Invoke-RuneExportPublicKey {
    <#
        從既有私鑰重新導出公鑰。

        存在的必要性：public.pem 由 private.key 可完全重現，因此不珍貴、覆寫無風險；
        但 -GenerateKeys 在私鑰存在時一律拒絕，沒有這個模式的話，使用者一旦刪掉或
        遺失 public.pem 就再也生不回來。兼作「再印一次我的指紋」的工具。

        輸出路徑跟著私鑰走，不永遠寫死預設位置：
          - 未指定 -KeyFile（即沿用預設 ~\.rune\private.key）→ 寫回預設的
            ~\.rune\public.pem，與 -GenerateKeys 的行為一致。
          - 指定了非預設的 -KeyFile → 寫到「該私鑰檔所在目錄」下的 public.pem，
            不去動預設的 public.pem。理由：這裡的「覆寫無風險」只對「這把私鑰
            對應的公鑰檔」成立；拿一把備用／次要私鑰導出，若仍寫回預設路徑，
            會靜默覆蓋主金鑰的 public.pem，讓加密端此後預設加密給錯的收件人。
    #>
    param([string] $KeyFilePath)

    $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath
    try {
        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
    }
    finally {
        $ecdh.Dispose()
    }

    $effectiveKeyPath = if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $Script:DefaultKeyFile } else { $KeyFilePath }
    $isDefaultKey = ([System.IO.Path]::GetFullPath($effectiveKeyPath) -eq [System.IO.Path]::GetFullPath($Script:DefaultKeyFile))

    if ($isDefaultKey) {
        $outDir = $Script:DefaultKeyDir
        $outFile = $Script:DefaultPublicKeyFile
    }
    else {
        $outDir = Split-Path -Path ([System.IO.Path]::GetFullPath($effectiveKeyPath)) -Parent
        $outFile = Join-Path -Path $outDir -ChildPath 'public.pem'
    }

    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($outFile, $publicPem, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    if (-not $isDefaultKey) {
        Write-Host "使用了非預設私鑰：$effectiveKeyPath"
        Write-Host "公鑰已寫到同目錄，未動到預設的 $($Script:DefaultPublicKeyFile)。"
        Write-Host ''
    }
    Write-RunePublicKeyBlock -PublicPem $publicPem -SpkiDer $spkiDer -PublicKeyFilePath $outFile
}
# ==========================================================================
# 進入點
# ==========================================================================

try {
    switch ($PSCmdlet.ParameterSetName) {
        'GenerateKeys' {
            Invoke-RuneGenerateKeys
        }
        'ExportPublicKey' {
            Invoke-RuneExportPublicKey -KeyFilePath $KeyFile
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
