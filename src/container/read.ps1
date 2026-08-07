
# ==========================================================================
# 區塊：容器二進位格式解析
# ==========================================================================

function ConvertFrom-RuneContainer {
    <#
        只擷取欄位，不做內容型別的合法性驗證：contentType 的 0x00–0xFF 任何值都照原樣
        回傳。型別是否支援必須等 GCM 認證通過之後才能判定，否則「位元被竄改」會被誤報成
        「不支援的內容型別」（詳見 Invoke-RuneOpen）。
    #>
    param([byte[]] $Bytes)

    $headerMin = 4 + 1 + 1 + 2
    if ($Bytes.Length -lt $headerMin) {
        throw '容器格式錯誤：檔頭長度不足，檔案可能已損壞或被截斷'
    }

    $magic = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
    if ($magic -ne $Script:RuneMagic) {
        throw "容器格式錯誤：檔頭 magic 不符（讀到 '$magic'），此檔案可能不是本工具產生的密文"
    }

    $version = $Bytes[4]
    if ($version -ne $Script:RuneVersion) {
        throw "版本不符：檔案版本為 $version，本程式僅支援版本 $($Script:RuneVersion)"
    }

    $contentType = $Bytes[5]

    # 明確指定小端序讀取，對應寫入端 New-RuneContainer 的 WriteUInt16LittleEndian
    $ephPubKeyLenBytes = Get-ByteRange -Source $Bytes -Offset 6 -Length 2
    $ephPubKeyLen = [System.Buffers.Binary.BinaryPrimitives]::ReadUInt16LittleEndian($ephPubKeyLenBytes)
    $offset = 8
    $minTotal = $offset + $ephPubKeyLen + $Script:NonceLength + $Script:TagLength
    if ($Bytes.Length -lt $minTotal) {
        throw '容器格式錯誤：長度不足以包含完整的 ephemeral 公鑰／nonce／tag，檔案可能已損壞或被截斷'
    }

    $ephPubKey = Get-ByteRange -Source $Bytes -Offset $offset -Length $ephPubKeyLen
    $offset += $ephPubKeyLen
    $nonce = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:NonceLength
    $offset += $Script:NonceLength
    $tag = Get-ByteRange -Source $Bytes -Offset $offset -Length $Script:TagLength
    $offset += $Script:TagLength
    $ciphertextLen = $Bytes.Length - $offset
    $ciphertext = Get-ByteRange -Source $Bytes -Offset $offset -Length $ciphertextLen

    return [pscustomobject]@{
        ContentType = $contentType
        EphPubKey   = $ephPubKey
        Nonce       = $nonce
        Tag         = $tag
        Ciphertext  = $ciphertext
    }
}
