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
            throw "The ephemeral public key in the container is not valid: $($_.Exception.Message)"
        }
        try {
            return $OwnPrivateKey.DeriveRawSecretAgreement($ephPub.PublicKey)
        }
        catch {
            throw "The ECDH key agreement failed: the private key does not match the public key used for encryption, or the private key file is corrupted. $($_.Exception.Message)"
        }
    }
    finally {
        $ephPub.Dispose()
    }
}
