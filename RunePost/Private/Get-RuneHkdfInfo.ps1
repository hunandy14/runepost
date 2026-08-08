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
