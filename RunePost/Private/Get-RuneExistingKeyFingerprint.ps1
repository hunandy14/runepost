function Get-RuneExistingKeyFingerprint {
    <#
        供覆蓋提示使用：讀出既有私鑰、算出對應公鑰指紋，回傳可直接顯示的一行文字。

        密碼保護的私鑰不在此處詢問密碼——確認提示問的是「是否覆蓋」，中途插入一個
        密碼提示會讓使用者以為兩者相關，因此一律回傳說明文字，提示流程照常進行。

        私鑰讀不出來（DPAPI 解不開、檔案損壞）時回傳 $null，呼叫端顯示「無法讀取」，
        不得讓提示流程因此中止——使用者仍應看到確認提示，只是少了指紋這項參考資訊。
    #>
    param([string] $KeyFilePath)
    try {
        $path = if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $Script:DefaultKeyFile } else { $KeyFilePath }
        if ((Get-RunePrivateKeyFormat -Content ([System.IO.File]::ReadAllBytes($path))) -eq 'Passphrase') {
            return 'Not shown (the private key is passphrase-protected)'
        }

        $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath -NoPrompt
        try {
            $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
            return ('RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $spkiDer))
        }
        finally {
            $ecdh.Dispose()
        }
    }
    catch {
        return $null
    }
}
