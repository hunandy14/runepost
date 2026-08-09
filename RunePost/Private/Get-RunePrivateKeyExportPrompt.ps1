function Get-RunePrivateKeyExportPrompt {
    <#
        組出「即將匯出私鑰」確認提示的內文；Y/N 的選項由 PowerShell 的 ShouldProcess
        自己補上，這裡只負責內容。

        匯出會把私鑰寫成一個新的、可攜的檔案，-Protect None 產生的檔案更是沒有任何
        加密保護。這是提高私鑰暴露面的動作，因此提示必須把來源、輸出路徑與格式一次
        講清楚，明文格式再多一句後果說明。
    #>
    param(
        [string] $SourceKeyPath,
        [string] $OutFilePath,
        [string] $Protect
    )

    $lines = @(
        "  來源  $SourceKeyPath"
        "  輸出  $OutFilePath"
        "  格式  $(Get-RunePrivateKeyProtectNote -Protect $Protect)"
    )
    if ($Protect -eq 'None') {
        $lines += '匯出檔沒有加密保護，任何能讀取該檔案的人，都能解開所有以對應公鑰加密的密文。'
    }
    return ($lines -join [Environment]::NewLine)
}
