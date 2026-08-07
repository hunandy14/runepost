# 本檔由 build.ps1 自 src/ 組裝產生，請勿直接編輯 —— 請改 src/ 後重跑 build.ps1
# source-digest: de4647891e25
# format: RUNE v2
# product: rune-seal
# fragments: 16
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
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'
$Script:DefaultPublicKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'public.pem'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'

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

function Get-RunePublicKey {
    <#
        取得收件人公鑰（只含公鑰的 ECDH 物件），並驗證曲線為 P-256。

        解析順序（-PublicKey 未指定時退回預設路徑 ~\.rune\public.pem）：
          1. 字串含 -----BEGIN → 視為 PEM 內容本體
          2. 否則               → 視為檔案路徑
    #>
    param([string] $PublicKeyRef)

    if ([string]::IsNullOrWhiteSpace($PublicKeyRef)) {
        $path = $Script:DefaultPublicKeyFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "找不到公鑰：$path。請先在解密端執行 rune-open.ps1 -GenerateKeys，把印出的 public.pem 複製到本機 $path，或用 -PublicKey 指定路徑或 PEM 字串。"
        }
        $pemText = [System.IO.File]::ReadAllText($path)
    }
    elseif ($PublicKeyRef -match '-----BEGIN') {
        $pemText = $PublicKeyRef
    }
    else {
        $path = $PublicKeyRef
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "找不到公鑰：$path。請先在解密端執行 rune-open.ps1 -GenerateKeys，把印出的 public.pem 複製到本機 $path，或用 -PublicKey 指定路徑或 PEM 字串。"
        }
        $pemText = [System.IO.File]::ReadAllText($path)
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $ecdh.ImportFromPem($pemText)
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
        [string] $PublicKeyRef,
        [switch] $ForceOverwrite
    )

    # 公鑰在最前面就載入並印出指紋：三種失敗（找不到公鑰檔、PEM 格式無效、曲線非
    # P-256）都必須在產生任何輸出檔之前結束；指紋每次執行都印，讓使用者每次都有
    # 機會發現 public.pem 被掉包。
    $staticPub = Get-RunePublicKey -PublicKeyRef $PublicKeyRef
    $recipientSpki = $staticPub.ExportSubjectPublicKeyInfo()
    Write-Host ('收件人公鑰指紋：RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $recipientSpki))
    Write-Host '（請與解密端 -GenerateKeys / -ExportPublicKey 印出的指紋逐字比對；不符代表公鑰可能已被掉包）'

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
# 進入點
# ==========================================================================

try {
    Invoke-RuneSeal -PackPath $Pack -OutFilePath $OutFile -PublicKeyRef $PublicKey -ForceOverwrite:$Force
}
catch {
    # 用 [Console]::Error.WriteLine 直接印一行錯誤訊息，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的一行錯誤說明。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
