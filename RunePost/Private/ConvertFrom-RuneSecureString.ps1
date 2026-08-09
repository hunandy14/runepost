function ConvertFrom-RuneSecureString {
    <#
        將 SecureString 還原為一般字串。

        .NET 的 PKCS#8 密碼保護 API（ExportEncryptedPkcs8PrivateKeyPem 與
        ImportFromEncryptedPem）只接受 ReadOnlySpan<char>，沒有 SecureString 多載，
        因此密碼必須在呼叫前還原成字串。

        還原過程配置的非受管記憶體以 ZeroFreeGlobalAllocUnicode 清零並釋放。回傳的
        System.String 不可變、無法主動清零，只能等待記憶體回收，呼叫端應把它限制在
        單一運算式或單一區域變數內，用完即不再持有。
    #>
    param([securestring] $Secure)

    $ptr = [IntPtr]::Zero
    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
        }
    }
}
