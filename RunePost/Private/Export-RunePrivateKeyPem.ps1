function Export-RunePrivateKeyPem {
    <#
        把 ECDH 私鑰序列化成 PEM 文字，供 -GenerateKeys 與 -ExportPrivateKey 共用。

          -Protect None        未加密的 PKCS#8 PEM
          -Protect Passphrase  以 $Passphrase 加密的 PKCS#8 PEM（PKCS#5 v2.0：
                               PBKDF2-HMAC-SHA256 + AES-256-CBC，迭代次數見
                               $Script:Pkcs8PbeIterations）

        兩種格式皆為標準 PKCS#8，可用 OpenSSL 等標準工具讀取，不綁定本機或本帳號。
    #>
    param(
        [System.Security.Cryptography.ECDiffieHellman] $Ecdh,
        [string] $Protect,
        [securestring] $Passphrase
    )

    if ($Protect -eq 'None') {
        return $Ecdh.ExportPkcs8PrivateKeyPem()
    }

    $pbe = [System.Security.Cryptography.PbeParameters]::new(
        [System.Security.Cryptography.PbeEncryptionAlgorithm]::Aes256Cbc,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        $Script:Pkcs8PbeIterations)

    return $Ecdh.ExportEncryptedPkcs8PrivateKeyPem(
        (ConvertFrom-RuneSecureString -Secure $Passphrase), $pbe)
}
