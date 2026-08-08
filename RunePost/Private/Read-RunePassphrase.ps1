function Read-RunePassphrase {
    <#
        取得密碼保護 PKCS#8 PEM 所需的密碼，回傳 SecureString。

        取得順序：
          1. 呼叫端已傳入 $Passphrase：直接採用，不顯示任何提示。
          2. 未傳入且允許提示、且標準輸入未被重新導向：以 Read-Host -AsSecureString 詢問。
          3. 其餘情況：擲回錯誤。

        非互動環境（[Console]::IsInputRedirected 為 true）必須直接擲回錯誤而不是顯示
        提示。排程工作與以子行程執行本工具的測試都會關閉標準輸入，此時顯示提示會讓
        行程停在等待輸入而永不結束。

        -ConfirmEntry 用於「設定新密碼」的情境（產生金鑰、匯出私鑰）：要求輸入兩次
        並比對。密碼一旦輸入錯誤，對應的私鑰檔即永久無法還原，此處以二次輸入攔截打字
        錯誤。讀取既有私鑰時不需要，密碼錯誤當場就會失敗。
    #>
    param(
        [securestring] $Passphrase,
        [string] $Prompt,
        [string] $ParameterName = '-Passphrase',
        [switch] $ConfirmEntry,
        [switch] $NoPrompt
    )

    if ($Passphrase) {
        if ($Passphrase.Length -eq 0) {
            throw "私鑰密碼無效：$ParameterName 為空字串，密碼不得為空。"
        }
        return $Passphrase
    }

    if ($NoPrompt) {
        throw "私鑰載入失敗：私鑰以密碼保護，但未提供密碼，且目前的流程不顯示密碼提示。`n請以 $ParameterName 傳入密碼。"
    }

    if ([Console]::IsInputRedirected) {
        throw "私鑰密碼未提供：目前為非互動環境（標準輸入已重新導向），無法顯示密碼提示。`n請以 $ParameterName 傳入 SecureString，例如 $ParameterName (Read-Host -AsSecureString)。"
    }

    $first = Read-Host -Prompt $Prompt -AsSecureString
    if (-not $first -or $first.Length -eq 0) {
        throw '私鑰密碼無效：未輸入任何字元，密碼不得為空。'
    }

    if ($ConfirmEntry) {
        $second = Read-Host -Prompt '請再次輸入密碼以確認' -AsSecureString
        $a = ConvertFrom-RuneSecureString -Secure $first
        $b = ConvertFrom-RuneSecureString -Secure $second
        $same = [string]::Equals($a, $b, [System.StringComparison]::Ordinal)
        if (-not $same) {
            throw '私鑰密碼無效：兩次輸入的密碼不一致，未變更任何檔案。'
        }
    }

    return $first
}
