@{
    RootModule        = 'RunePost.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '1e616c47-1ddf-42b5-942d-e0965cdbc735'
    Author            = 'Charlotte.Hong'
    Description       = '密文傳輸工具（runepost）：兩台自有 Windows 機器間，經公開純文字管道（論壇／pastebin）單向傳檔。ECDH P-256 + HKDF-SHA256 + AES-256-GCM，純 .NET 內建類別實作，零外部依賴。'
    PowerShellVersion = '7.4'

    # 明確清單，絕不用 '*'：萬用字元會讓模組自動載入器為了做命令探索而解析整個
    # 模組，是有效能代價的。新增對外函式時必須同步更新這份清單。
    FunctionsToExport = @(
        'Invoke-RuneSeal'
        'Invoke-RuneOpen'
        'New-RuneKeyPair'
        'Export-RunePublicKey'
        'Export-RunePrivateKey'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags = @('Encryption', 'ECDH', 'AES-GCM', 'Windows', 'DPAPI')
        }
    }
}
