function Write-RunePlainKeyWarning {
    <#
        私鑰以未加密的 PKCS#8 PEM 落地時的告知。

        檔案已經寫入、動作已經完成，使用者需要知道這個檔案的性質，因此走警告串流
        （Write-Warning）而不是錯誤。-Protect None 是預設值，凡是以此模式產生或匯出
        私鑰的路徑都必須呼叫本函式，使未加密儲存永遠是一個被明白告知的選擇。
    #>
    param([string] $KeyFilePath)

    Write-Warning "私鑰以未加密的 PKCS#8 PEM 儲存於 $KeyFilePath。"
    Write-Warning '任何能讀取此檔案的人，都能解開所有以對應公鑰加密的密文。'
    Write-Warning '請勿將此檔案置於雲端同步資料夾或版本控管目錄。'
}
