# ==========================================================================
# 區塊：私鑰載入（-Unpack 用；DPAPI CurrentUser 保護的 Pkcs8 私鑰 blob）
# ==========================================================================

function Get-RunePrivateKey {
    <#
        讀取 ~\.rune\private.key（或 -KeyFile 指定路徑），該檔內容是用
        DPAPI（CurrentUser scope）保護過的 ECDH P-256 Pkcs8 私鑰位元組。
        只有「同一台機器、同一個 Windows 帳號」才解得開；否則視為
        「私鑰讀不到／DPAPI 解保護失敗」。
    #>
    param([string] $KeyFilePath)

    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) {
        $KeyFilePath = $Script:DefaultKeyFile
    }

    if (-not (Test-Path -LiteralPath $KeyFilePath -PathType Leaf)) {
        throw "私鑰檔案讀取失敗：找不到 $KeyFilePath（請確認路徑，或先以 -GenerateKeys 產生金鑰）"
    }

    $protectedBytes = [System.IO.File]::ReadAllBytes($KeyFilePath)

    $pkcs8Bytes = $null
    try {
        $pkcs8Bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protectedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
    catch {
        throw "私鑰讀不到／DPAPI 解保護失敗（是否為非本機、非本 Windows 帳號產生的私鑰檔，或檔案已損壞？）：$($_.Exception.Message)"
    }

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        $bytesRead = 0
        try {
            $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead)
        }
        catch {
            throw "私鑰讀不到／DPAPI 解保護失敗：DPAPI 解密後的私鑰內容格式無效（$($_.Exception.Message)）"
        }

        $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
        if ($curveOid -ne $Script:P256CurveOid) {
            throw "私鑰不是 P-256：曲線 OID 為 $curveOid，本工具僅支援 P-256（$($Script:P256CurveOid)）"
        }
    }
    catch {
        $ecdh.Dispose()
        throw
    }
    finally {
        if ($pkcs8Bytes) {
            [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
        }
    }

    return $ecdh
}
