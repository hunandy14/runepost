function Get-RuneKeyOverwritePrompt {
    <#
        組出「私鑰已存在，是否產生新金鑰」確認提示的內文；Y/N 的選項由 PowerShell
        的 ShouldProcess 自己補上，這裡只負責內容。

        內容含既有金鑰的指紋、備份後的檔名，以及「舊密文仍可用 -KeyFile 指向備份
        路徑解密」這條救援路徑：使用者要能在答覆之前看清楚自己要換掉的是哪一把、
        舊的那把去了哪裡。

        指紋讀不出來（DPAPI 解不開、檔案損壞、私鑰以密碼保護）時顯示替代文字，不得
        因此中止——提示照常出現，只是少了這一項參考資訊。
    #>
    param([pscustomobject] $BackupPlan)

    $existingFp = Get-RuneExistingKeyFingerprint -KeyFilePath $Script:DefaultKeyFile
    if (-not $existingFp) { $existingFp = '無法讀取' }

    return (@(
            "  現有指紋  $existingFp"
            "繼續會產生新金鑰，舊金鑰改名保留為 $($BackupPlan.KeyBackup)"
            "舊密文仍可解：rune-open.ps1 -Unpack <檔> -Destination <夾> -KeyFile $($BackupPlan.KeyBackup)"
        ) -join [Environment]::NewLine)
}
