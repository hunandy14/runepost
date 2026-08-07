
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
