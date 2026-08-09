function Get-RuneMissingPublicKeyMessage {
    <#
        產生「找不到公鑰檔」的錯誤訊息，依路徑來源分兩種措辭，供
        Get-RunePublicKey 的兩個呼叫點（預設路徑 / -PublicKey 指定路徑）共用。

        兩種措辭必須分開：對使用者自己指定的路徑說「請把 public.pem 複製到本機
        <該路徑>」語意會繞——使用者已經告訴我們要去哪找了，缺的是那個檔案，不是
        「該把檔案放哪」。
    #>
    param([string] $Path, [bool] $IsUserSpecified)

    $nl = [Environment]::NewLine
    if ($IsUserSpecified) {
        return "Cannot find the recipient public key: $Path." + $nl +
        "The location was specified with -PublicKey. Verify that the path is correct." + $nl +
        "To create a key pair, run 'rune-open.ps1 -GenerateKeys' on the decrypting machine." + $nl +
        "-PublicKey also accepts the PEM content itself instead of a path."
    }
    return "Cannot find the recipient public key: $Path (default path)." + $nl +
    "Run 'rune-open.ps1 -GenerateKeys' on the decrypting machine, then copy 'public.pem' to $Path." + $nl +
    "Alternatively, specify a different location or a PEM string with -PublicKey."
}
