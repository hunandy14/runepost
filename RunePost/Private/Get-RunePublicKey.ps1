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
        throw "公鑰 PEM 格式無效，無法載入：$($_.Exception.Message)"
    }

    $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
    if ($curveOid -ne $Script:P256CurveOid) {
        $ecdh.Dispose()
        throw "公鑰不是 P-256：曲線 OID 為 $curveOid，本工具僅支援 P-256（$($Script:P256CurveOid)）"
    }

    return $ecdh
}
