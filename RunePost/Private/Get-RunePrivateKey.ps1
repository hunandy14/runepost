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
        throw "私鑰檔案讀取失敗：找不到 $KeyFilePath（請確認路徑，或先以 -GenerateKeys 產生金鑰）"
    }

    $fileBytes = [System.IO.File]::ReadAllBytes($KeyFilePath)
    if ($fileBytes.Length -eq 0) {
        throw "私鑰檔案讀取失敗：$KeyFilePath 是空檔案（0 位元組），沒有任何金鑰內容可讀"
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
                    throw "私鑰檔案讀取失敗：未加密的 PKCS#8 PEM 內容無效（$($_.Exception.Message)）"
                }
            }
            'Passphrase' {
                $pem = [System.Text.Encoding]::UTF8.GetString($fileBytes)
                $secret = Read-RunePassphrase -Passphrase $Passphrase -NoPrompt:$NoPrompt `
                    -Prompt "請輸入 $KeyFilePath 的密碼"
                try {
                    $ecdh.ImportFromEncryptedPem($pem, (ConvertFrom-RuneSecureString -Secure $secret))
                }
                catch {
                    throw "私鑰檔案讀取失敗：無法以提供的密碼解開密碼保護的 PKCS#8 PEM（密碼可能不正確，或檔案已損壞）"
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
                        throw "私鑰讀不到／DPAPI 解保護失敗（是否為非本機、非本 Windows 帳號產生的私鑰檔，或檔案已損壞？）：$($_.Exception.Message)"
                    }

                    $bytesRead = 0
                    try {
                        $ecdh.ImportPkcs8PrivateKey($pkcs8Bytes, [ref] $bytesRead)
                    }
                    catch {
                        throw "私鑰讀不到／DPAPI 解保護失敗：DPAPI 解密後的私鑰內容格式無效（$($_.Exception.Message)）"
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
            throw "私鑰不是 P-256：曲線 OID 為 $curveOid，本工具僅支援 P-256（$($Script:P256CurveOid)）"
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
