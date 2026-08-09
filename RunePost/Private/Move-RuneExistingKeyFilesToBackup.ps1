function Move-RuneExistingKeyFilesToBackup {
    <#
        實際執行改名（不是刪除）：private.key -> KeyBackupPath（呼叫前必須已確認
        存在）；public.pem -> PubBackupPath（若存在才搬，不存在不算錯誤）。
        任一步失敗就整個中止：若私鑰改名成功但公鑰改名失敗，會先把私鑰名稱搬回
        原位再往外拋例外，不留下「舊檔已搬走但覆蓋沒有真的發生」的半套狀態。
    #>
    param([string] $KeyBackupPath, [string] $PubBackupPath)

    try {
        Rename-Item -LiteralPath $Script:DefaultKeyFile -NewName (Split-Path -Leaf $KeyBackupPath) -ErrorAction Stop
    }
    catch {
        throw "Cannot back up the existing private key. No new key pair was created. $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $Script:DefaultPublicKeyFile) {
        try {
            Rename-Item -LiteralPath $Script:DefaultPublicKeyFile -NewName (Split-Path -Leaf $PubBackupPath) -ErrorAction Stop
        }
        catch {
            Rename-Item -LiteralPath $KeyBackupPath -NewName (Split-Path -Leaf $Script:DefaultKeyFile) -ErrorAction SilentlyContinue
            throw "Cannot back up the existing public key. The private key was restored to its original name and no new key pair was created. $($_.Exception.Message)"
        }
    }
}
