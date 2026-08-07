
# ==========================================================================
# 區塊：金鑰交換與派生（ECDH P-256 + HKDF-SHA256，加解密共用）
# ==========================================================================

function New-RuneEcdhKeyPair {
    <# 產生一個新的 ECDH P-256 金鑰對（同時持有公私鑰） #>
    return [System.Security.Cryptography.ECDiffieHellman]::Create(
        [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
}
