
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
