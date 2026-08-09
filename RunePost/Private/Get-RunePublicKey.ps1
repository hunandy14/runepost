function Get-RunePublicKey {
    <#
        取得收件人公鑰（只含公鑰的 ECDH 物件），並驗證曲線為 P-256。

        解析順序（-PublicKey 未指定時退回預設路徑 ~\.rune\public.pem）：
          1. 字串含 -----BEGIN → 視為 PEM 內容本體
          2. 否則               → 視為檔案路徑
    #>
    param([string] $PublicKeyRef)

    if ([string]::IsNullOrWhiteSpace($PublicKeyRef)) {
        $path = $Script:DefaultPublicKeyFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw (Get-RuneMissingPublicKeyMessage -Path $path -IsUserSpecified $false)
        }
        $pemText = [System.IO.File]::ReadAllText($path)
    }
    elseif ($PublicKeyRef -match '-----BEGIN') {
        $pemText = $PublicKeyRef
    }
    else {
        $path = $PublicKeyRef
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw (Get-RuneMissingPublicKeyMessage -Path $path -IsUserSpecified $true)
        }
        $pemText = [System.IO.File]::ReadAllText($path)
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $ecdh.ImportFromPem($pemText)
    }
    catch {
        $ecdh.Dispose()
        throw "The recipient public key PEM is not valid and cannot be loaded: $($_.Exception.Message)"
    }

    $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
    if ($curveOid -ne $Script:P256CurveOid) {
        $ecdh.Dispose()
        throw "The recipient public key is not P-256: the curve OID is $curveOid. This tool supports P-256 ($($Script:P256CurveOid)) only."
    }

    return $ecdh
}
