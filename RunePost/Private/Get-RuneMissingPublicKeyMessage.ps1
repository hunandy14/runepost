function Get-RuneMissingPublicKeyMessage {
    <#
        產生「找不到公鑰檔」的錯誤訊息，依路徑來源分兩種措辭，供
        Get-RunePublicKey 的兩個呼叫點（預設路徑 / -PublicKey 指定路徑）共用。

        兩種措辭必須分開：對使用者自己指定的路徑說「請把 public.pem 複製到本機
        <該路徑>」語意會繞——使用者已經告訴我們要去哪找了，缺的是那個檔案，不是
        「該把檔案放哪」。
    #>
    param([string] $Path, [bool] $IsUserSpecified)

    if ($IsUserSpecified) {
        return "找不到公鑰：$Path（-PublicKey 指定的路徑）。請確認路徑是否正確；" +
        "若尚未取得 public.pem，請先在解密端執行 rune-open.ps1 -GenerateKeys 產生後傳給加密端，" +
        "或改用 -PublicKey 直接傳入 PEM 字串本體。"
    }
    return "找不到公鑰：$Path（預設路徑）。請先在解密端執行 rune-open.ps1 -GenerateKeys，" +
    "把印出的 public.pem 複製到本機 $Path，或用 -PublicKey 指定其他路徑或 PEM 字串。"
}
