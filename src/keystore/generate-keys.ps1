
function Invoke-RuneGenerateKeys {
    # 私鑰已存在一律拒絕：覆蓋私鑰會讓已加密的舊檔案永久無法解密，這條資料遺失防護不變。
    if (Test-Path -LiteralPath $Script:DefaultKeyFile) {
        throw "私鑰檔案已存在，為避免覆蓋既有金鑰（可能導致已加密的舊檔案永久無法解密），已拒絕操作：$($Script:DefaultKeyFile)`n如確定要產生新金鑰，請先手動備份／移除該檔案後再重新執行。"
    }
    # 私鑰不存在但 public.pem 還在：直接覆蓋。孤兒 public.pem（私鑰已遺失）比沒有檔案
    # 更危險——加密端會持續加密給一把沒人持有的金鑰，產出永久無法解讀的密文。

    if (-not (Test-Path -LiteralPath $Script:DefaultKeyDir)) {
        New-Item -ItemType Directory -Path $Script:DefaultKeyDir -Force | Out-Null
    }

    Write-Host '產生 ECDH P-256 金鑰對中，請稍候...'
    $ecdh = New-RuneEcdhKeyPair
    $pkcs8Bytes = $null
    try {
        $pkcs8Bytes = $ecdh.ExportPkcs8PrivateKey()
        $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $pkcs8Bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

        # 寫入順序固定「先私鑰、後公鑰」：若 public.pem 寫入失敗，private.key 仍在，
        # 可用 -ExportPublicKey 補救；反序則會留下一把沒有對應私鑰的公鑰。
        [System.IO.File]::WriteAllBytes($Script:DefaultKeyFile, $protectedBytes)

        $publicPem = $ecdh.ExportSubjectPublicKeyInfoPem()
        $spkiDer = $ecdh.ExportSubjectPublicKeyInfo()
        [System.IO.File]::WriteAllText($Script:DefaultPublicKeyFile, $publicPem, [System.Text.UTF8Encoding]::new($false))
    }
    finally {
        if ($pkcs8Bytes) {
            [Array]::Clear($pkcs8Bytes, 0, $pkcs8Bytes.Length)
        }
        $ecdh.Dispose()
    }

    Write-Host ''
    Write-Host "私鑰已寫入（DPAPI CurrentUser 保護）：$($Script:DefaultKeyFile)"
    Write-Host '此檔案只有在這台機器、這個 Windows 帳號下才解得開；請自行備份，'
    Write-Host '遺失或搬到別的機器／帳號，將無法解密任何已用對應公鑰加密的檔案。'
    Write-Host ''
    Write-RunePublicKeyBlock -PublicPem $publicPem -SpkiDer $spkiDer
}
