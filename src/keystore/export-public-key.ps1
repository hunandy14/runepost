
function Invoke-RuneExportPublicKey {
    <#
        從既有私鑰重新導出公鑰並「自由覆寫」public.pem。

        存在的必要性：public.pem 由 private.key 可完全重現，因此不珍貴、覆寫無風險；
        但 -GenerateKeys 在私鑰存在時一律拒絕，沒有這個模式的話，使用者一旦刪掉或
        遺失 public.pem 就再也生不回來。兼作「再印一次我的指紋」的工具。
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

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($Script:DefaultPublicKeyFile, $publicPem, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    Write-RunePublicKeyBlock -PublicPem $publicPem -SpkiDer $spkiDer
}
