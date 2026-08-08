function Confirm-RuneKeyOverwrite {
    <#
        私鑰已存在時，是否可以繼續產生新金鑰（仿 ssh-keygen 的互動提示）。規則：
          - -Force：略過提示，直接允許繼續（供非互動使用；舊金鑰仍會改名保留，
            由呼叫端處理，這裡只負責「准不准繼續」）。
          - 非互動環境（stdin 被重導向）且未帶 -Force：一律拒絕，不得卡在等輸入
            —— tests/verify.ps1 用子行程跑腳本並關閉 stdin，卡住會讓整套測試掛死。
          - 互動環境：印出現有指紋（讀不出來則顯示「無法讀取」，不得因此崩潰）、
            備份後的檔名、以及「舊密文仍可用 -KeyFile 指向備份路徑解密」這條救援
            路徑，再讀一行輸入；只有 y / yes（不分大小寫）視為同意，其餘（含直接
            Enter）一律視為取消。
        回傳 $true 表示可以繼續，$false 表示使用者取消（呼叫端應正常結束，不視為錯誤）。
    #>
    param([switch] $Force, [pscustomobject] $BackupPlan)

    if ($Force) { return $true }

    if ([Console]::IsInputRedirected) {
        throw "私鑰檔案已存在：$($Script:DefaultKeyFile)`n非互動環境無法提示確認，請加 -Force 直接產生新金鑰（舊金鑰仍會改名保留，不會刪除），或手動處理後再重新執行。"
    }

    $existingFp = Get-RuneExistingKeyFingerprint -KeyFilePath $Script:DefaultKeyFile
    if (-not $existingFp) { $existingFp = '無法讀取' }

    Write-Host "$($Script:DefaultKeyFile) 已存在"
    Write-Host "  現有指紋  $existingFp"
    Write-Host "繼續會產生新金鑰，舊金鑰改名保留為 $($BackupPlan.KeyBackup)"
    Write-Host "舊密文仍可解：rune-open.ps1 -Unpack <檔> -Destination <夾> -KeyFile $($BackupPlan.KeyBackup)"
    [Console]::Write('繼續？ (y/N): ')
    $answer = [Console]::ReadLine()
    if ($null -eq $answer) { $answer = '' }
    return ($answer.Trim() -match '^(?i:y|yes)$')
}
