function Get-RunePrivateKeyFormat {
    <#
        由檔案內容判別私鑰的儲存格式，回傳 'None'、'Passphrase' 或 'Dpapi'：

          None        未加密的 PKCS#8 PEM，標頭為 -----BEGIN PRIVATE KEY-----
          Passphrase  密碼保護的 PKCS#8 PEM，標頭為 -----BEGIN ENCRYPTED PRIVATE KEY-----
          Dpapi       DPAPI（CurrentUser）保護的 PKCS#8 位元組，無文字標頭

        三種格式共用同一個路徑（預設 ~\.rune\private.key），因此格式必須由內容判定，
        不得由副檔名或另立檔名推斷。

        比對順序必須先 ENCRYPTED 後 PRIVATE KEY：後者是前者的子字串，順序相反會把
        密碼保護的 PEM 誤判為未加密 PEM。兩個標頭都不存在即視為 DPAPI 位元組。

        位元組先以 UTF-8 解碼再比對標頭。DPAPI blob 是二進位，解碼結果為亂碼，
        不會命中任何一個標頭。
    #>
    param([byte[]] $Content)

    $text = [System.Text.Encoding]::UTF8.GetString($Content)
    if ($text.Contains('-----BEGIN ENCRYPTED PRIVATE KEY-----')) { return 'Passphrase' }
    if ($text.Contains('-----BEGIN PRIVATE KEY-----')) { return 'None' }
    return 'Dpapi'
}
