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

        既有私鑰會被改名保留，屬破壞性動作，因此宣告 ConfirmImpact High：預設就會
        要求確認，-Force（或 -Confirm:$false）略過，-WhatIf 則只說明將要發生什麼、
        不寫入任何檔案。確認只針對這條覆蓋路徑——尚未有金鑰時沒有既有檔案會被動到，
        即使帶了 -Confirm 也不會詢問。
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('None', 'Passphrase', 'Dpapi')]
        [string] $Protect = 'None',
        [securestring] $Passphrase,
        # 略過覆蓋確認，供非互動情境（腳本、排程）使用。舊金鑰仍會改名保留。
        [switch] $Force
    )

    $keyExists = Test-Path -LiteralPath $Script:DefaultKeyFile
    $backupPlan = $null
    if ($keyExists) {
        $backupPlan = Get-RuneKeyBackupPaths
    }

    if (-not $keyExists) {
        # 高衝擊的是「覆蓋既有金鑰」而不是「產生金鑰」本身：第一次產生不會動到任何
        # 既有檔案，沒有東西需要確認。
        $ConfirmPreference = 'None'
    }
    elseif (-not $PSBoundParameters.ContainsKey('Confirm')) {
        # 覆蓋既有金鑰不可逆，因此不接受從呼叫端 session 繼承來的 $ConfirmPreference
        # 作為「不用問」的依據——自動化用的 profile 常把它設成 None，繼承下去就是
        # 沒帶 -Force 也靜默輪替金鑰。沒有明確表態一律問，要免除就寫 -Force（慣例
        # 寫法）或 -Confirm:$false。
        $ConfirmPreference = if ($Force) { 'None' } else { 'High' }
    }

    # 確認提示到底會不會出現：-WhatIf 不問，$ConfirmPreference = None 也不問。
    $willConfirm = (-not $WhatIfPreference) -and ($ConfirmPreference -ne 'None')

    # 非互動防呆疊在 ShouldProcess 之外。PowerShell 在真正的 NonInteractive host 下
    # 呼叫確認會擲回例外而不是卡住，但那依賴 host 正確回報自己不可互動，沒有跨版本
    # 保證；標準輸入被重新導向時一律主動拒絕，並指出 -Force 這條出路。
    if ($keyExists -and $willConfirm -and [Console]::IsInputRedirected) {
        throw "私鑰檔案已存在：$($Script:DefaultKeyFile)`n非互動環境無法提示確認，請加 -Force 直接產生新金鑰（舊金鑰仍會改名保留，不會刪除），或手動處理後再重新執行。"
    }

    $action = if ($keyExists) {
        "產生新的 ECDH P-256 金鑰對，既有金鑰改名保留為 $($backupPlan.KeyBackup)"
    }
    else {
        "產生 ECDH P-256 金鑰對：$($Script:DefaultKeyFile)"
    }
    $caption = if ($keyExists) { "$($Script:DefaultKeyFile) 已存在" } else { '產生 ECDH P-256 金鑰對' }
    # 提示內文要讀出既有私鑰才能算指紋，只有真的要問的時候才付這個代價。
    $query = if ($keyExists -and $willConfirm) { Get-RuneKeyOverwritePrompt -BackupPlan $backupPlan } else { $action }
    if (-not $PSCmdlet.ShouldProcess($action, $query, $caption)) {
        return
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
