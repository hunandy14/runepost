# ==========================================================================
# 區塊：-Unpack 主流程
# ==========================================================================

function Invoke-RuneOpen {
    [CmdletBinding()]
    param(
        [string] $InFilePath,
        [string] $DestinationPath,
        [string] $KeyFilePath,
        # 私鑰為密碼保護的 PKCS#8 PEM 時所需；未提供則於互動環境詢問。
        [securestring] $Passphrase
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

    $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath -Passphrase $Passphrase
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
