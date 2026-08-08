function Invoke-RuneGenerateKeys {
    param([switch] $Force)

    $keyExists = Test-Path -LiteralPath $Script:DefaultKeyFile
    $backupPlan = $null
    if ($keyExists) {
        $backupPlan = Get-RuneKeyBackupPaths
        if (-not (Confirm-RuneKeyOverwrite -Force:$Force -BackupPlan $backupPlan)) {
            Write-Host '已取消，未變更任何檔案。'
            return
        }
        Move-RuneExistingKeyFilesToBackup -KeyBackupPath $backupPlan.KeyBackup -PubBackupPath $backupPlan.PubBackup
    }
    # 私鑰不存在但 public.pem 還在：直接覆蓋。孤兒 public.pem（私鑰已遺失）比沒有檔案
    # 更危險——加密端會持續加密給一把沒人持有的金鑰，產出永久無法解讀的密文。

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }

    $ecdh = New-RuneEcdhKeyPair
    $pkcs8Bytes = $null
    try {
        $pkcs8Bytes = $ecdh.ExportPkcs8PrivateKey()
        $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $pkcs8Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

        # 寫入順序固定「先私鑰、後公鑰」：若 public.pem 寫入失敗，private.key 仍在，
        # 可用 -ExportPublicKey 補救；反序則會留下一把沒有對應私鑰的公鑰。
        [System.IO.File]::WriteAllBytes($Script:DefaultKeyFile, $protectedBytes)

        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
        [System.IO.File]::WriteAllText($Script:DefaultPublicKeyFile, $publicPem, [System.Text.UTF8Encoding]::new($false))
    }
    finally {
        if ($pkcs8Bytes) {
            [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
        }
        $ecdh.Dispose()
    }

    if ($backupPlan) {
        Write-RuneKeySummary -Title '已產生 ECDH P-256 金鑰對' -KeyFilePath $Script:DefaultKeyFile `
            -KeyFileNote 'DPAPI，僅本機本帳號可解' -PublicKeyFilePath $Script:DefaultPublicKeyFile `
            -SpkiDer $spkiDer -BackupKeyFilePath $backupPlan.KeyBackup
    }
    else {
        Write-RuneKeySummary -Title '已產生 ECDH P-256 金鑰對' -KeyFilePath $Script:DefaultKeyFile `
            -KeyFileNote 'DPAPI，僅本機本帳號可解' -PublicKeyFilePath $Script:DefaultPublicKeyFile -SpkiDer $spkiDer
    }
}
