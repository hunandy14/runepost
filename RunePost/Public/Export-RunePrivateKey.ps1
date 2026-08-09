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
        throw "Cannot export the private key: -ExportPrivateKey does not support -Protect Dpapi.`nDPAPI binds the file to this machine and this Windows account, so the exported file cannot be read on another machine or account and does not serve as a backup.`nUse -Protect None or -Protect Passphrase instead."
    }

    if ([string]::IsNullOrWhiteSpace($OutFilePath)) {
        throw 'Cannot export the private key: -OutFile does not specify an output path.'
    }
    $outFull = [System.IO.Path]::GetFullPath($OutFilePath)

    $sourcePath = if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $Script:DefaultKeyFile } else { $KeyFilePath }
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Cannot find the private key: $sourcePath.`nVerify that the path is correct, or run 'rune-open.ps1 -GenerateKeys' to create a key pair."
    }

    if ((Test-Path -LiteralPath $outFull) -and -not $Force) {
        throw "The output file already exists: $outFull.`nSpecify -Force to overwrite it."
    }

    $outDir = [System.IO.Path]::GetDirectoryName($outFull)
    if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
        throw "Cannot export the private key: the output folder does not exist: $outDir"
    }

    if (-not $PSBoundParameters.ContainsKey('Confirm')) {
        # 匯出私鑰一律需要確認，不接受從呼叫端 session 繼承來的 $ConfirmPreference
        # 作為「不用問」的依據，理由同 New-RuneKeyPair。要免除確認就明確寫
        # -Confirm:$false；-Force 只管覆蓋，不代表略過確認。
        $ConfirmPreference = 'High'
    }

    # 確認提示到底會不會出現：-WhatIf 不問，-Confirm:$false 也不問。
    $willConfirm = (-not $WhatIfPreference) -and ($ConfirmPreference -ne 'None')

    # 非互動防呆疊在 ShouldProcess 之外，理由同 New-RuneKeyPair：不依賴 host 是否
    # 正確回報自己不可互動，標準輸入被重新導向時一律主動拒絕。
    if ($willConfirm -and [Console]::IsInputRedirected) {
        throw "Cannot export the private key: this is a non-interactive session (standard input is redirected), so the confirmation prompt cannot be displayed.`nSpecify -Confirm:`$false to skip the confirmation (with rune-open.ps1, specify -Force), or run the command again in an interactive session."
    }

    $action = "Export $sourcePath as $(Get-RunePrivateKeyProtectNote -Protect $Protect): $outFull"
    $query = if ($willConfirm) {
        Get-RunePrivateKeyExportPrompt -SourceKeyPath $sourcePath -OutFilePath $outFull -Protect $Protect
    }
    else { $action }
    if (-not $PSCmdlet.ShouldProcess($action, $query, 'Export the private key')) {
        return
    }

    $ecdh = Get-RunePrivateKey -KeyFilePath $sourcePath -Passphrase $Passphrase
    try {
        $exportPassphrase = $null
        if ($Protect -eq 'Passphrase') {
            $exportPassphrase = Read-RunePassphrase -Passphrase $OutPassphrase -ConfirmEntry `
                -ParameterName '-OutPassphrase' -Prompt 'Enter the passphrase that will protect the exported file'
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
