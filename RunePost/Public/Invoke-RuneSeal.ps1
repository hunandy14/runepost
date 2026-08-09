# ==========================================================================
# 區塊：-Pack 主流程
# ==========================================================================

function Invoke-RuneSeal {
    <#
        打包（ZIP/store）→ 壓縮（Brotli）→ 加密（ECDH P-256 + HKDF-SHA256 +
        AES-256-GCM）→ Base64 落地，回傳 Rune.SealResult 物件。

        本函式不負責呈現。逐步進度與收件人公鑰指紋走資訊串流（Write-Information），
        呼叫端要顯示就帶 -InformationAction Continue；最終結果一律以物件回傳，
        由呼叫端決定印成什麼樣子。
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $PackPath,
        [string] $OutFilePath,
        [string] $PublicKeyRef,
        [switch] $ForceOverwrite
    )

    # 公鑰在最前面就載入並報出指紋：三種失敗（找不到公鑰檔、PEM 格式無效、曲線非
    # P-256）都必須在產生任何輸出檔之前結束；指紋每次執行都報，讓使用者每次都有
    # 機會發現 public.pem 被掉包。
    $staticPub = Get-RunePublicKey -PublicKeyRef $PublicKeyRef
    $recipientSpki = $staticPub.ExportSubjectPublicKeyInfo()
    $recipientFingerprint = Get-RuneKeyFingerprint -SpkiDer $recipientSpki
    Write-Information ('收件人公鑰指紋：RUNE-KEY {0}' -f $recipientFingerprint)
    Write-Information '（請與解密端 -GenerateKeys / -ExportPublicKey 印出的指紋逐字比對；不符代表公鑰可能已被掉包）'

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

    Write-Information "打包中：共 $($plan.Entries.Count) 個項目..."
    $zipBytes = New-RuneZipBytes -Entries $plan.Entries
    $originalSize = $zipBytes.Length

    Write-Information '壓縮中（Brotli, SmallestSize）...'
    $compressed = Compress-RuneBrotli -InputBytes $zipBytes
    $compressedSize = $compressed.Length

    Write-Information '加密中（ECDH P-256 + HKDF-SHA256 + AES-256-GCM）...'
    $ephemeral = New-RuneEcdhKeyPair
    $sharedSecret = $null
    $aesKey = $null
    try {
        $sharedSecret = $ephemeral.DeriveRawSecretAgreement($staticPub.PublicKey)
        $ephPubKeyDer = $ephemeral.ExportSubjectPublicKeyInfo()

        $nonce = [byte[]]::new($Script:NonceLength)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)

        $infoBytes = Get-RuneHkdfInfo -ContentType $Script:ContentTypeFileTree -EphPubKeyDer $ephPubKeyDer
        $aesKey = Get-RuneDerivedAesKey -SharedSecret $sharedSecret -Nonce $nonce -InfoBytes $infoBytes

        $aes = Protect-RuneAesGcm -PlainBytes $compressed -AesKey $aesKey -Nonce $nonce
    }
    finally {
        # 共享祕密與 aesKey 一律在 finally 清零，無論成功或中途拋錯：派生（
        # Get-RuneDerivedAesKey）或加密（Protect-RuneAesGcm）拋例外時，金鑰材料
        # 都不得殘留在記憶體中未被清除。與解密端同一套紀律。
        if ($sharedSecret) {
            [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)
        }
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

    return [pscustomobject]@{
        PSTypeName           = 'Rune.SealResult'
        OutFile              = $OutFilePath
        RecipientFingerprint = $recipientFingerprint
        ItemCount            = $plan.Entries.Count
        OriginalSize         = $originalSize
        CompressedSize       = $compressedSize
        Base64Size           = $b64Size
    }
}
