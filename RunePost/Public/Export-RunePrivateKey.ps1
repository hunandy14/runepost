function Export-RunePrivateKey {
    <#
        把既有私鑰匯出成可備份的 PKCS#8 PEM。

        存在的必要性：私鑰是密文的唯一還原手段，而密文一旦張貼到公開管道即為永久
        存在。DPAPI 私鑰綁定本機與本 Windows 帳號，本身不可複製備份；本模式讀出
        私鑰後改以標準 PKCS#8 PEM 寫出，使既有的 DPAPI 私鑰也能離機保存。

        參數：
          -OutFilePath   輸出路徑，必填。不提供預設值，避免在使用者未指定位置的
                         情況下產生一份私鑰副本。
          -KeyFilePath   來源私鑰，預設 ~\.rune\private.key。三種格式皆可作為來源。
          -Protect       輸出格式，None（預設）或 Passphrase。不支援 Dpapi。
          -Passphrase    來源私鑰的密碼，來源為密碼保護的 PKCS#8 PEM 時需要。
          -OutPassphrase 輸出檔的密碼，-Protect Passphrase 時需要。與 -Passphrase
                         分開，因為兩者是不同的密碼：來源與備份可以各自設定，
                         也才能在非互動環境下同時指定。
          -Force         允許覆蓋已存在的 -OutFilePath。只管覆蓋這一件事，與確認
                         提示無關——那由 -Confirm / $ConfirmPreference 決定。兩者
                         分開，是因為「我知道那個檔案要被蓋掉」與「我不需要有人再
                         問我一次要不要匯出私鑰」是兩個獨立的判斷。

        回傳 Rune.PrivateKeyExport 物件；使用者在確認提示選擇不繼續則不回傳任何
        東西，呼叫端據此判斷是否被取消。呈現由呼叫端負責。

        匯出會把私鑰寫成一份新的、可攜的檔案，是提高私鑰暴露面的動作，因此宣告
        ConfirmImpact High：預設就會要求確認，-Confirm:$false 略過，-WhatIf 則只
        說明將要發生什麼、不寫入任何檔案。
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $OutFilePath,
        [string] $KeyFilePath,
        [ValidateSet('None', 'Passphrase', 'Dpapi')]
        [string] $Protect = 'None',
        [securestring] $Passphrase,
        [securestring] $OutPassphrase,
        [switch] $Force
    )

    if ($Protect -eq 'Dpapi') {
        throw "私鑰匯出失敗：-ExportPrivateKey 不支援 -Protect Dpapi。`nDPAPI 綁定本機與本 Windows 帳號，產生的檔案在其他機器或帳號無法還原，不具備份用途。`n請改用 -Protect None 或 -Protect Passphrase。"
    }

    if ([string]::IsNullOrWhiteSpace($OutFilePath)) {
        throw '私鑰匯出失敗：-OutFile 未指定輸出路徑。'
    }
    $outFull = [System.IO.Path]::GetFullPath($OutFilePath)

    $sourcePath = if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $Script:DefaultKeyFile } else { $KeyFilePath }
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "私鑰檔案讀取失敗：找不到 $sourcePath（請確認路徑，或先以 -GenerateKeys 產生金鑰）"
    }

    if ((Test-Path -LiteralPath $outFull) -and -not $Force) {
        throw "輸出檔案已存在：$outFull（如需覆蓋請加上 -Force）"
    }

    $outDir = [System.IO.Path]::GetDirectoryName($outFull)
    if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
        throw "私鑰匯出失敗：輸出路徑的資料夾不存在：$outDir"
    }

    # 確認提示到底會不會出現：-WhatIf 不問，-Confirm:$false（或呼叫端把
    # $ConfirmPreference 設成 None）也不問。-Force 不在這個判斷裡——它只管覆蓋。
    $willConfirm = (-not $WhatIfPreference) -and ($ConfirmPreference -ne 'None')

    # 非互動防呆疊在 ShouldProcess 之外，理由同 New-RuneKeyPair：不依賴 host 是否
    # 正確回報自己不可互動，標準輸入被重新導向時一律主動拒絕。
    if ($willConfirm -and [Console]::IsInputRedirected) {
        throw "私鑰匯出已中止：目前為非互動環境（標準輸入已重新導向），無法顯示確認提示。`n請加上 -Confirm:`$false 略過確認（rune-open.ps1 請用 -Force），或於互動環境重新執行。"
    }

    $action = "把 $sourcePath 匯出成 $(Get-RunePrivateKeyProtectNote -Protect $Protect)：$outFull"
    $query = if ($willConfirm) {
        Get-RunePrivateKeyExportPrompt -SourceKeyPath $sourcePath -OutFilePath $outFull -Protect $Protect
    }
    else { $action }
    if (-not $PSCmdlet.ShouldProcess($action, $query, '即將匯出私鑰')) {
        return
    }

    $ecdh = Get-RunePrivateKey -KeyFilePath $sourcePath -Passphrase $Passphrase
    try {
        $exportPassphrase = $null
        if ($Protect -eq 'Passphrase') {
            $exportPassphrase = Read-RunePassphrase -Passphrase $OutPassphrase -ConfirmEntry `
                -ParameterName '-OutPassphrase' -Prompt '請輸入用於保護匯出檔的密碼'
        }

        $privatePem = Export-RunePrivateKeyPem -Ecdh $ecdh -Protect $Protect -Passphrase $exportPassphrase
        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
    }
    finally {
        $ecdh.Dispose()
    }

    # 先寫暫存檔、套好權限，成功後才搬到正式位置。直接寫入目標路徑的話，寫到一半
    # 失敗會留下被截斷的 PEM——而截斷的 PKCS#8 前段仍含私鑰純量，且這是備份指令，
    # 使用者很可能就此以為備份已經完成。暫存檔與目標同資料夾，搬移是同磁碟區的
    # 更名，權限設定會一併帶過去。
    $tmpPath = $outFull + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::WriteAllText($tmpPath, $privatePem, [System.Text.UTF8Encoding]::new($false))
        Set-RunePrivateKeyAcl -Path $tmpPath
        Move-Item -LiteralPath $tmpPath -Destination $outFull -Force
    }
    finally {
        if (Test-Path -LiteralPath $tmpPath) {
            Remove-Item -LiteralPath $tmpPath -Force
        }
    }

    if ($Protect -eq 'None') {
        Write-RunePlainKeyWarning -KeyFilePath $outFull
    }

    return [pscustomobject]@{
        PSTypeName    = 'Rune.PrivateKeyExport'
        Protect       = $Protect
        ProtectNote   = (Get-RunePrivateKeyProtectNote -Protect $Protect)
        SourceKeyFile = $sourcePath
        OutFile       = $outFull
        Fingerprint   = (Get-RuneKeyFingerprint -SpkiDer $spkiDer)
    }
}
