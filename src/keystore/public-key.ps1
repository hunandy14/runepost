
function Get-RuneMissingPublicKeyMessage {
    <#
        產生「找不到公鑰檔」的錯誤訊息，依路徑來源分兩種措辭——只抽出這一段是因為
        兩個呼叫點（預設路徑 / -PublicKey 指定路徑）原本逐字複製了同一句，且對「使用
        者自己指定的路徑」沿用預設路徑那句「複製到本機 <path>」語意會繞：使用者已經
        告訴我們要去哪找了，缺的是那個檔案，不是「該把檔案放哪」。
    #>
    param([string] $Path, [bool] $IsUserSpecified)

    if ($IsUserSpecified) {
        return "找不到公鑰：$Path（-PublicKey 指定的路徑）。請確認路徑是否正確；" +
        "若尚未取得 public.pem，請先在解密端執行 rune-open.ps1 -GenerateKeys 產生後傳給加密端，" +
        "或改用 -PublicKey 直接傳入 PEM 字串本體。"
    }
    return "找不到公鑰：$Path（預設路徑）。請先在解密端執行 rune-open.ps1 -GenerateKeys，" +
    "把印出的 public.pem 複製到本機 $Path，或用 -PublicKey 指定其他路徑或 PEM 字串。"
}

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
