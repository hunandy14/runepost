function Get-RuneExistingKeyFingerprint {
    <#
        供覆蓋提示使用：嘗試讀出既有私鑰、算出對應公鑰指紋。私鑰讀不出來（DPAPI
        解不開／檔案損壞）時回傳 $null，呼叫端顯示「無法讀取」，不得讓提示流程
        因此崩潰——使用者仍應看到確認提示，只是少了指紋這項參考資訊。
    #>
    param([string] $KeyFilePath)
    try {
        $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath
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
