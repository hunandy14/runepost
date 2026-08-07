
function Invoke-RuneExportPublicKey {
    <#
        從既有私鑰重新導出公鑰。

        存在的必要性：public.pem 由 private.key 可完全重現，因此不珍貴、覆寫無風險；
        但 -GenerateKeys 在私鑰存在時一律拒絕，沒有這個模式的話，使用者一旦刪掉或
        遺失 public.pem 就再也生不回來。兼作「再印一次我的指紋」的工具。

        輸出路徑跟著私鑰走，不永遠寫死預設位置：
          - 未指定 -KeyFile（即沿用預設 ~\.rune\private.key）→ 寫回預設的
            ~\.rune\public.pem，與 -GenerateKeys 的行為一致。
          - 指定了非預設的 -KeyFile → 寫到「該私鑰檔所在目錄」下的 public.pem，
            不去動預設的 public.pem。理由：這裡的「覆寫無風險」只對「這把私鑰
            對應的公鑰檔」成立；拿一把備用／次要私鑰導出，若仍寫回預設路徑，
            會靜默覆蓋主金鑰的 public.pem，讓加密端此後預設加密給錯的收件人。
    #>
    param([string] $KeyFilePath)

    $ecdh = Get-RunePrivateKey -KeyFilePath $KeyFilePath
    try {
        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
    }
    finally {
        $ecdh.Dispose()
    }

    $effectiveKeyPath = if ([string]::IsNullOrWhiteSpace($KeyFilePath)) { $Script:DefaultKeyFile } else { $KeyFilePath }
    $isDefaultKey = ([System.IO.Path]::GetFullPath($effectiveKeyPath) -eq [System.IO.Path]::GetFullPath($Script:DefaultKeyFile))

    if ($isDefaultKey) {
        $outDir = $Script:DefaultKeyDir
        $outFile = $Script:DefaultPublicKeyFile
    }
    else {
        $outDir = Split-Path -Path ([System.IO.Path]::GetFullPath($effectiveKeyPath)) -Parent
        $outFile = Join-Path -Path $outDir -ChildPath 'public.pem'
    }

    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($outFile, $publicPem, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    if (-not $isDefaultKey) {
        Write-Host "使用了非預設私鑰：$effectiveKeyPath"
        Write-Host "公鑰已寫到同目錄，未動到預設的 $($Script:DefaultPublicKeyFile)。"
        Write-Host ''
    }
    Write-RunePublicKeyBlock -PublicPem $publicPem -SpkiDer $spkiDer -PublicKeyFilePath $outFile
}
