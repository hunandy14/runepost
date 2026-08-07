
# ==========================================================================
# 區塊：容器二進位格式組裝
# ==========================================================================

function New-RuneContainer {
    param(
        [byte] $ContentType,
        [byte[]] $EphPubKey,
        [byte[]] $Nonce,
        [byte[]] $Tag,
        [byte[]] $Ciphertext
    )
    $magicBytes = [System.Text.Encoding]::ASCII.GetBytes($Script:RuneMagic)
    # 明確指定小端序寫入，不依賴 BitConverter 隨執行平台而定的位元組順序
    # （Windows 上兩者結果相同，但明確指定較不易出錯，也符合容器格式的
    # 「uint16 LE」宣告）。
    $lenBytes = [byte[]]::new(2)
    [System.Buffers.Binary.BinaryPrimitives]::WriteUInt16LittleEndian($lenBytes, [uint16] $EphPubKey.Length)

    $ms = [System.IO.MemoryStream]::new()
    $ms.Write($magicBytes, 0, $magicBytes.Length)
    $ms.WriteByte($Script:RuneVersion)
    $ms.WriteByte($ContentType)
    $ms.Write($lenBytes, 0, 2)
    $ms.Write($EphPubKey, 0, $EphPubKey.Length)
    $ms.Write($Nonce, 0, $Nonce.Length)
    $ms.Write($Tag, 0, $Tag.Length)
    $ms.Write($Ciphertext, 0, $Ciphertext.Length)
    return , $ms.ToArray()
}
