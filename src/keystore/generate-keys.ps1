
function Get-RuneKeyBackupPaths {
    <#
        算出「這次要保留舊金鑰」該用的備份路徑：private.key 與 public.pem（若存在）
        用同一個時間戳改名，格式 <原檔名>.bak-yyyyMMdd-HHmmss —— 不會碰撞（同一秒內
        重複執行時退避加 4 碼亂數尾碼）、可排序、一眼看得出是備份。
    #>
    param()
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $keyBackup = '{0}.bak-{1}' -f $Script:DefaultKeyFile, $stamp
    $pubBackup = '{0}.bak-{1}' -f $Script:DefaultPublicKeyFile, $stamp
    if ((Test-Path -LiteralPath $keyBackup) -or (Test-Path -LiteralPath $pubBackup)) {
        $stamp = '{0}-{1}' -f $stamp, ([guid]::NewGuid().ToString('N').Substring(0, 4))
        $keyBackup = '{0}.bak-{1}' -f $Script:DefaultKeyFile, $stamp
        $pubBackup = '{0}.bak-{1}' -f $Script:DefaultPublicKeyFile, $stamp
    }
    return [pscustomobject]@{ KeyBackup = $keyBackup; PubBackup = $pubBackup }
}

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
        throw "備份既有私鑰檔失敗，未產生新金鑰：$($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $Script:DefaultPublicKeyFile) {
        try {
            Rename-Item -LiteralPath $Script:DefaultPublicKeyFile -NewName (Split-Path -Leaf $PubBackupPath) -ErrorAction Stop
        }
        catch {
            Rename-Item -LiteralPath $KeyBackupPath -NewName (Split-Path -Leaf $Script:DefaultKeyFile) -ErrorAction SilentlyContinue
            throw "備份既有公鑰檔失敗，已還原私鑰檔案，未產生新金鑰：$($_.Exception.Message)"
        }
    }
}

function Get-RuneExistingKeyFingerprint {
    <#
        供覆蓋提示使用：嘗試讀出既有私鑰、算出對應公鑰指紋。私鑰讀不出來（DPAPI
        解不開／檔案損壞）時回傳 $null，呼叫端顯示「無法讀取」，不得讓提示流程
        因此崩潰——使用者仍應看到確認提示，只是少了指紋這項參考資訊。
    #>
    param([string] $KeyFilePath)
    try {
        $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath
        try {
            $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
            return ('RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $spkiDer))
        }
        finally {
            $ecdh.Dispose()
        }
    }
    catch {
        return $null
    }
}

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
