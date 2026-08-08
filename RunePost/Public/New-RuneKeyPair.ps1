function New-RuneKeyPair {
    <#
        產生 ECDH P-256 金鑰對：私鑰寫到 ~\.rune\private.key，公鑰寫到
        ~\.rune\public.pem。

        -Protect 決定私鑰的靜態保護方式（預設 None）：

          None        未加密的 PKCS#8 PEM。可直接複製備份；產生時以警告告知檔案性質。
          Passphrase  密碼保護的 PKCS#8 PEM。可備份，還原時需要密碼；未以 -Passphrase
                      傳入時於互動環境詢問。
          Dpapi       DPAPI（CurrentUser）位元組。僅本機本帳號可解，無法備份。

        回傳 Rune.KeyPair 物件；使用者在覆蓋確認時選擇不繼續則不回傳任何東西，
        呼叫端據此判斷是否被取消。呈現由呼叫端負責。
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
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

    if ($Protect -eq 'None') {
        Write-RunePlainKeyWarning -KeyFilePath $Script:DefaultKeyFile
    }

    # 公鑰備份只有在舊 public.pem 真的存在時才會產生，因此以落地結果為準，
    # 不直接照抄備份計畫裡的路徑。
    $backupPubFile = if ($backupPlan -and (Test-Path -LiteralPath $backupPlan.PubBackup)) { $backupPlan.PubBackup } else { $null }

    return [pscustomobject]@{
        PSTypeName          = 'Rune.KeyPair'
        Protect             = $Protect
        ProtectNote         = (Get-RunePrivateKeyProtectNote -Protect $Protect)
        KeyFile             = $Script:DefaultKeyFile
        PublicKeyFile       = $Script:DefaultPublicKeyFile
        Fingerprint         = (Get-RuneKeyFingerprint -SpkiDer $spkiDer)
        BackupKeyFile       = $(if ($backupPlan) { $backupPlan.KeyBackup } else { $null })
        BackupPublicKeyFile = $backupPubFile
    }
}
