function Get-RunePrivateKeyProtectNote {
    <#
        回傳私鑰保護方式的說明文字，供摘要輸出與確認提示共用，使同一種格式在各處
        以同一組詞彙呈現。
    #>
    param([string] $Protect)

    switch ($Protect) {
        'None' { return '未加密的 PKCS#8 PEM' }
        'Passphrase' { return '密碼保護的 PKCS#8 PEM' }
        'Dpapi' { return 'DPAPI，僅本機本帳號可解' }
        default { return $Protect }
    }
}
