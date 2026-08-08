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
          -Force         略過確認提示，並允許覆蓋已存在的 -OutFilePath。
    #>
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

    if (-not (Confirm-RunePrivateKeyExport -Force:$Force -SourceKeyPath $sourcePath -OutFilePath $outFull -Protect $Protect)) {
        Write-Host '已取消，未變更任何檔案。'
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

    # 匯出格式放在第一行、走一般輸出串流，理由同 -GenerateKeys 的成功摘要。
    Write-Host "已匯出私鑰（格式：$(Get-RunePrivateKeyProtectNote -Protect $Protect)）"
    Write-Host "  來源  $sourcePath"
    Write-Host "  輸出  $outFull"
    Write-Host ('  指紋  RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $spkiDer))
    Write-Host "還原方式：rune-open.ps1 -Unpack <密文檔> -Destination <目的資料夾> -KeyFile $outFull"

    if ($Protect -eq 'None') {
        Write-RunePlainKeyWarning -KeyFilePath $outFull
    }
}
