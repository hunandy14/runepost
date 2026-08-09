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
            throw "The passphrase is not valid: $ParameterName is an empty string. The passphrase cannot be empty."
        }
        return $Passphrase
    }

    if ($NoPrompt) {
        throw "Cannot load the private key: the key is passphrase-protected, no passphrase was supplied, and this operation does not display a passphrase prompt.`nSupply the passphrase with $ParameterName."
    }

    if ([Console]::IsInputRedirected) {
        throw "No passphrase was supplied for the private key. This is a non-interactive session (standard input is redirected), so the passphrase prompt cannot be displayed.`nPass a SecureString with $ParameterName, for example $ParameterName (Read-Host -AsSecureString)."
    }

    $first = Read-Host -Prompt $Prompt -AsSecureString
    if (-not $first -or $first.Length -eq 0) {
        throw 'The passphrase is not valid: no characters were entered. The passphrase cannot be empty.'
    }

    if ($ConfirmEntry) {
        $second = Read-Host -Prompt 'Enter the passphrase again to confirm' -AsSecureString
        $a = ConvertFrom-RuneSecureString -Secure $first
        $b = ConvertFrom-RuneSecureString -Secure $second
        $same = [string]::Equals($a, $b, [System.StringComparison]::Ordinal)
        # 比對結束就放掉這兩份明文，不讓它們活到函式結束
        $a = $null; $b = $null
        if (-not $same) {
            throw 'The passphrase is not valid: the two entries do not match. No files were changed.'
        }
    }

    return $first
}
