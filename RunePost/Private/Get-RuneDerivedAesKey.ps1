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
