function Confirm-RunePrivateKeyExport {
    <#
        -ExportPrivateKey 的確認提示。規則與 -GenerateKeys 的覆蓋確認一致：

          - -Force：略過提示，直接允許繼續，供非互動情境使用。
          - 非互動環境（標準輸入已重新導向）且未帶 -Force：擲回錯誤，不得停在等待輸入。
          - 互動環境：印出來源、輸出路徑與匯出格式，再讀一行輸入；只有 y 或 yes
            （不分大小寫）視為同意，其餘（含直接按 Enter）一律視為取消。

        匯出會把受保護的私鑰寫成一個新的、可攜的檔案；-Protect None 產生的檔案沒有
        任何加密保護。這是提高私鑰暴露面的動作，因此預設為不繼續。

        回傳 $true 表示可以繼續，$false 表示使用者取消（呼叫端應正常結束，不視為錯誤）。
    #>
    param(
        [switch] $Force,
        [string] $SourceKeyPath,
        [string] $OutFilePath,
        [string] $Protect
    )

    if ($Force) { return $true }

    if ([Console]::IsInputRedirected) {
        throw "私鑰匯出已中止：目前為非互動環境（標準輸入已重新導向），無法顯示確認提示。`n請加上 -Force 略過確認，或於互動環境重新執行。"
    }

    Write-Host '即將匯出私鑰'
    Write-Host "  來源  $SourceKeyPath"
    Write-Host "  輸出  $OutFilePath"
    Write-Host "  格式  $(Get-RunePrivateKeyProtectNote -Protect $Protect)"
    if ($Protect -eq 'None') {
        Write-Host '匯出檔沒有加密保護，任何能讀取該檔案的人，都能解開所有以對應公鑰加密的密文。'
    }
    [Console]::Write('繼續？ (y/N): ')
    $answer = [Console]::ReadLine()
    if ($null -eq $answer) { $answer = '' }
    return ($answer.Trim() -match '^(?i:y|yes)$')
}
