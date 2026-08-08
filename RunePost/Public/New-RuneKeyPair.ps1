function New-RuneKeyPair {
    <#
        產生 ECDH P-256 金鑰對：私鑰寫到 ~\.rune\private.key，公鑰寫到
        ~\.rune\public.pem。

        -Protect 決定私鑰的靜態保護方式（預設 None）：

          None        未加密的 PKCS#8 PEM。可直接複製備份；產生時以警告告知檔案性質。
          Passphrase  密碼保護的 PKCS#8 PEM。可備份，還原時需要密碼；未以 -Passphrase
                      傳入時於互動環境詢問。
          Dpapi       DPAPI（CurrentUser）位元組。僅本機本帳號可解，無法備份。
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('None', 'Passphrase', 'Dpapi')]
        [string] $Protect = 'None',
        [securestring] $Passphrase,
        [switch] $Force
    )

    $keyExists = Test-Path -LiteralPath $Script:DefaultKeyFile
    $backupPlan = $null
    if ($keyExists) {
        $backupPlan = Get-RuneKeyBackupPaths
        if (-not (Confirm-RuneKeyOverwrite -Force:$Force -BackupPlan $backupPlan)) {
            Write-Host '已取消，未變更任何檔案。'
            return
        }
    }
    # 私鑰不存在但 public.pem 還在：直接覆蓋。孤兒 public.pem（私鑰已遺失）比沒有檔案
    # 更危險——加密端會持續加密給一把沒人持有的金鑰，產出永久無法解讀的密文。

    # 密碼在任何檔案被改名或寫入之前取得：這一步會擲回錯誤（非互動、兩次輸入不一致、
    # 空密碼），此時既有的 private.key 與 public.pem 必須維持原狀。
    $keyPassphrase = $null
    if ($Protect -eq 'Passphrase') {
        $keyPassphrase = Read-RunePassphrase -Passphrase $Passphrase -ConfirmEntry `
            -Prompt '請輸入用於保護私鑰的密碼'
    }

    if ($keyExists) {
        Move-RuneExistingKeyFilesToBackup -KeyBackupPath $backupPlan.KeyBackup -PubBackupPath $backupPlan.PubBackup
    }

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }

    $ecdh = New-RuneEcdhKeyPair
    $pkcs8Bytes = $null
    try {
        # 寫入順序固定「先私鑰、後公鑰」：若 public.pem 寫入失敗，private.key 仍在，
        # 可用 -ExportPublicKey 補救；反序則會留下一把沒有對應私鑰的公鑰。
        if ($Protect -eq 'Dpapi') {
            $pkcs8Bytes = $ecdh.ExportPkcs8PrivateKey()
            $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
                $pkcs8Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            [System.IO.File]::WriteAllBytes($Script:DefaultKeyFile, $protectedBytes)
        }
        else {
            $privatePem = Export-RunePrivateKeyPem -Ecdh $ecdh -Protect $Protect -Passphrase $keyPassphrase
            [System.IO.File]::WriteAllText($Script:DefaultKeyFile, $privatePem, [System.Text.UTF8Encoding]::new($false))
        }
        Set-RunePrivateKeyAcl -Path $Script:DefaultKeyFile

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

    # 保護方式寫進標題，也就是成功輸出的第一行，且走一般輸出串流：警告串流在輸出被
    # 重新導向時可能被丟棄，使用者不該因此不知道自己手上這把私鑰是不是明文。
    $keyNote = Get-RunePrivateKeyProtectNote -Protect $Protect
    $title = "已產生 ECDH P-256 金鑰對（私鑰保護方式：$keyNote）"
    if ($backupPlan) {
        Write-RuneKeySummary -Title $title -KeyFilePath $Script:DefaultKeyFile `
            -KeyFileNote $keyNote -PublicKeyFilePath $Script:DefaultPublicKeyFile `
            -SpkiDer $spkiDer -BackupKeyFilePath $backupPlan.KeyBackup
    }
    else {
        Write-RuneKeySummary -Title $title -KeyFilePath $Script:DefaultKeyFile `
            -KeyFileNote $keyNote -PublicKeyFilePath $Script:DefaultPublicKeyFile -SpkiDer $spkiDer
    }

    if ($Protect -eq 'None') {
        Write-RunePlainKeyWarning -KeyFilePath $Script:DefaultKeyFile
    }
}
