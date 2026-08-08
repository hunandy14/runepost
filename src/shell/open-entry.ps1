# ==========================================================================
# 進入點
# ==========================================================================

try {
    switch ($PSCmdlet.ParameterSetName) {
        'GenerateKeys' {
            Invoke-RuneGenerateKeys -Force:$Force
        }
        'ExportPublicKey' {
            Invoke-RuneExportPublicKey -KeyFilePath $KeyFile
        }
        'Unpack' {
            Invoke-RuneOpen -InFilePath $Unpack -DestinationPath $Destination -KeyFilePath $KeyFile
        }
    }
}
catch {
    # 用 [Console]::Error.WriteLine 直接印一行錯誤訊息，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的一行錯誤說明。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
