# ==========================================================================
# 區塊：私鑰載入（-Unpack / -ExportPublicKey / -ExportPrivateKey 用）
# ==========================================================================

function Get-RunePrivateKey {
    <#
        讀取 ~\.rune\private.key（或 -KeyFilePath 指定的路徑），回傳可用的
        ECDiffieHellman 物件。

        儲存格式由檔案內容判定（見 Get-RunePrivateKeyFormat），呼叫端不需要、也無法
        指定格式：

          未加密的 PKCS#8 PEM        直接匯入。
          密碼保護的 PKCS#8 PEM      需要密碼；未以 -Passphrase 傳入時，於互動環境
                                     詢問，非互動環境則擲回錯誤。
          DPAPI（CurrentUser）位元組 只有「同一台機器、同一個 Windows 帳號」解得開，
                                     否則視為私鑰讀不到。

        -NoPrompt 供「讀不到就算了」的旁路使用（例如覆蓋確認時顯示現有指紋）：此時
        密碼保護的私鑰在未提供密碼的情況下直接擲回錯誤，不會插入一個使用者沒有預期的
        密碼提示。

        匯入後一律驗證曲線為 P-256，不符即拒絕。
    #>
    param(
        [string] $KeyFilePath,
        [securestring] $Passphrase,
        [switch] $NoPrompt
    )

    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) {
        $KeyFilePath = $Script:DefaultKeyFile
    }

    if (-not (Test-Path -LiteralPath $KeyFilePath -PathType Leaf)) {
        throw "Cannot find the private key: $KeyFilePath.`nVerify that the path is correct, or run 'rune-open.ps1 -GenerateKeys' to create a key pair."
    }

    $fileBytes = [System.IO.File]::ReadAllBytes($KeyFilePath)
    if ($fileBytes.Length -eq 0) {
        throw "Cannot read the private key: $KeyFilePath is an empty file (0 bytes) and holds no key material."
    }
    $format = Get-RunePrivateKeyFormat -Content $fileBytes

    $ecdh = [System.Security.Cryptography.ECDiffieHellman]::Create()
    try {
        switch ($format) {
            'None' {
                $pem = [System.Text.Encoding]::UTF8.GetString($fileBytes)
                try {
                    $ecdh.ImportFromPem($pem)
                }
                catch {
                    throw "Cannot read the private key: the unencrypted PKCS#8 PEM content is not valid. $($_.Exception.Message)"
                }
            }
            'Passphrase' {
                $pem = [System.Text.Encoding]::UTF8.GetString($fileBytes)
                $secret = Read-RunePassphrase -Passphrase $Passphrase -NoPrompt:$NoPrompt `
                    -Prompt "Enter the passphrase for $KeyFilePath"
                try {
                    $ecdh.ImportFromEncryptedPem($pem, (ConvertFrom-RuneSecureString -Secure $secret))
                }
                catch {
                    throw "Cannot read the private key: the supplied passphrase did not open the passphrase-protected PKCS#8 PEM. The passphrase may be incorrect, or the file may be corrupted."
                }
            }
            default {
                $pkcs8Bytes = $null
                try {
                    try {
                        $pkcs8Bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                            $fileBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                    }
                    catch {
                        throw "Cannot read the private key: DPAPI unprotect failed. The file may have been created on another machine or under another Windows account, or it may be corrupted. $($_.Exception.Message)"
                    }

                    $bytesRead = 0
                    try {
                        $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead)
                    }
                    catch {
                        throw "Cannot read the private key: the content decrypted by DPAPI is not a valid private key. $($_.Exception.Message)"
                    }
                }
                finally {
                    if ($pkcs8Bytes) {
                        [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
                    }
                }
            }
        }

        $curveOid = $ecdh.ExportParameters($false).Curve.Oid.Value
        if ($curveOid -ne $Script:P256CurveOid) {
            throw "The private key is not P-256: the curve OID is $curveOid. This tool supports P-256 ($($Script:P256CurveOid)) only."
        }
    }
    catch {
        $ecdh.Dispose()
        throw
    }
    finally {
        # 未加密 PEM 格式時，$fileBytes 就是明文私鑰的位元組，用完即歸零；DPAPI 與
        # 加密 PEM 的內容雖然本身受保護，仍一併清除，讓「私鑰檔內容」只有一種處置方式。
        # 由 $fileBytes 解出的 $pem 字串是不可變的 System.String，結構上無法清零。
        [Array]::Clear($fileBytes, 0, $fileBytes.Length)
    }

    return $ecdh
}
