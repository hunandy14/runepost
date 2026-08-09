function Set-RunePrivateKeyAcl {
    <#
        把私鑰檔的存取權限收斂到「檔案擁有者 + SYSTEM」兩個帳號，並中斷繼承。

        不設定的話，檔案完全繼承父目錄的權限。一般資料夾繼承下來的項目包含
        BUILTIN\Administrators、NT AUTHORITY\SYSTEM、AppContainer SID 與其他已存在
        的授權對象；私鑰匯出到 C:\Temp 或共用資料夾時，這些對象即可讀取私鑰。

        本工具寫出的私鑰檔一律套用，含 -GenerateKeys 的三種格式與 -ExportPrivateKey
        的輸出檔。DPAPI 格式本身已綁定本機本帳號、不套也不會外洩，仍然一併套用作為
        縱深防禦，使「私鑰檔」這個類別只有一種權限狀態，不必逐處判斷。
        公鑰檔不套用：公鑰本來就是要交出去的。

        SetAccessRuleProtection($true, $false)：第一個參數中斷繼承，第二個參數為
        $false 表示不把繼承來的項目複製成明確項目——複製了就等於沒有收斂。

        目標磁碟不支援 ACL（例如 FAT32 隨身碟）時，Get-Acl／Set-Acl 會失敗。此時
        以警告告知並繼續：私鑰仍然要寫出，只是無法加固權限；為了權限而讓備份整個
        失敗，會把使用者推回「沒有備份」這個更糟的狀態。
    #>
    param([string] $Path)

    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) {
            [void]$acl.RemoveAccessRule($rule)
        }

        $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        foreach ($sid in @($owner, $system)) {
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow))
        }

        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        Write-Warning "無法收斂私鑰檔的存取權限：$Path（$($_.Exception.Message)）"
        Write-Warning '檔案已寫出，但權限沿用所在資料夾的繼承設定，請自行確認沒有其他人可以讀取。'
    }
}
