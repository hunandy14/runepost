function Get-RunePrivateKeyProtectNote {
    <#
        回傳私鑰保護方式的說明文字，供摘要輸出與確認提示共用，使同一種格式在各處
        以同一組詞彙呈現。
    #>
    param([string] $Protect)

    switch ($Protect) {
        'None' { return 'unencrypted PKCS#8 PEM' }
        'Passphrase' { return 'passphrase-protected PKCS#8 PEM' }
        'Dpapi' { return 'DPAPI, readable only on this machine under this Windows account' }
        default { return $Protect }
    }
}
