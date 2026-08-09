# ==========================================================================
# 區塊：-Unpack 主流程
# ==========================================================================

function Invoke-RuneOpen {
    <#
        Base64 解碼 → AES-256-GCM 解密 → Brotli 解壓 → ZIP 解包，回傳
        Rune.OpenResult 物件（目的資料夾與還原檔數），呈現由呼叫端負責。
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $InFilePath,
        [string] $DestinationPath,
        [string] $KeyFilePath,
        # 私鑰為密碼保護的 PKCS#8 PEM 時所需；未提供則於互動環境詢問。
        [securestring] $Passphrase
    )

    if (-not (Test-Path -LiteralPath $InFilePath -PathType Leaf)) {
        throw "Cannot find the input file: $InFilePath"
    }

    $rawText = [System.IO.File]::ReadAllText($InFilePath)
    $cleaned = ($rawText -replace '\s', '')
    if ([string]::IsNullOrEmpty($cleaned)) {
        throw 'The input file is empty and cannot be parsed.'
    }

    try {
        $containerBytes = [Convert]::FromBase64String($cleaned)
    }
    catch {
        throw "Base64 decoding failed. The file content may be corrupted or truncated. $($_.Exception.Message)"
    }

    $parsed = ConvertFrom-RuneContainer -Bytes $containerBytes

    $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath -Passphrase $Passphrase
    $sharedSecret = $null
    try {
        $sharedSecret = Get-RuneSharedSecretForDecrypt -EphPubKeyDer $parsed.EphPubKey -OwnPrivateKey $ecdh
        $infoBytes = Get-RuneHkdfInfo -ContentType $parsed.ContentType -EphPubKeyDer $parsed.EphPubKey
        $aesKey = Get-RuneDerivedAesKey -SharedSecret $sharedSecret -Nonce $parsed.Nonce -InfoBytes $infoBytes
    }
    finally {
        # 派生一併納入這個 try：共享祕密無論派生成功或 Get-RuneDerivedAesKey 中途
        # 拋錯都在 finally 清零，不留金鑰材料在記憶體中。與加密端同一套紀律。
        if ($sharedSecret) {
            [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)
        }
        $ecdh.Dispose()
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
        throw 'Content verification failed (the AES-GCM authentication tag does not match). The ciphertext may have been tampered with or corrupted in transit.'
    }
    catch {
        throw "AES-GCM decryption failed. The content may be corrupted. $($_.Exception.Message)"
    }

    # 內容型別的合法性檢查必須在此——GCM 認證通過之後、解壓之前。
    # contentType 已綁進 HKDF info，tag 驗過就等於這個 byte 是真品；此時值仍未知，
    # 才能斷定是本程式版本落後，而不是資料被竄改。若把這個檢查提前到解析階段，
    # 「位元被翻掉」會被誤報成「不支援的內容型別」，使用者就抓不到真正的問題。
    if ($parsed.ContentType -ne $Script:ContentTypeFileTree) {
        throw ('The content type 0x{0:X2} in this container was produced by a newer version of Rune. Update rune-open.ps1.' -f $parsed.ContentType)
    }

    try {
        $zipBytes = Expand-RuneBrotli -InputBytes $plain
    }
    catch {
        throw "Brotli decompression failed. The data may be corrupted. $($_.Exception.Message)"
    }

    # 先解到 Destination 底下的暫存資料夾，全部成功後才搬到正式位置；
    # 任何一步失敗都清掉暫存資料夾並報錯，Destination 不留半成品。
    $tmpDir = Join-Path -Path $DestinationPath -ChildPath (".rune-tmp-" + [Guid]::NewGuid().ToString('N'))
    $restoredFileCount = 0
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
            throw "ZIP extraction failed. The archive format is not valid, or the archive is corrupted. $($_.Exception.Message)"
        }

        # 還原檔數在搬移前於暫存資料夾清點：搬移後 Destination 可能本來就有其他
        # 無關內容，屆時數出來的不會是「這一份密文還原了幾個檔」。
        $restoredFileCount = @(Get-ChildItem -LiteralPath $tmpDir -Recurse -File -Force).Count

        try {
            Move-RuneExtractedTree -SourceDir $tmpDir -DestDir $DestinationPath
        }
        catch {
            throw "Cannot move the extracted content from the temporary folder to $DestinationPath. $($_.Exception.Message)"
        }
    }
    finally {
        if (Test-Path -LiteralPath $tmpDir) {
            Remove-Item -LiteralPath $tmpDir -Recurse -Force
        }
    }

    return [pscustomobject]@{
        PSTypeName  = 'Rune.OpenResult'
        InFile      = [System.IO.Path]::GetFullPath($InFilePath)
        Destination = (Get-Item -LiteralPath $DestinationPath).FullName
        FileCount   = $restoredFileCount
    }
}
