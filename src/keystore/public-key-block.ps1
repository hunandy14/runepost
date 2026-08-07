
# ==========================================================================
# 區塊：-GenerateKeys / -ExportPublicKey 主流程
# ==========================================================================

function Write-RunePublicKeyBlock {
    <#
        統一的公鑰輸出格式：PEM 全文 + 指紋。兩端要比對的就是這個指紋，所以格式必須一致。
        -PublicKeyFilePath 由呼叫端明確傳入實際寫入的路徑（而非在這裡假設一定是預設
        路徑）——-ExportPublicKey 用非預設 -KeyFile 時會寫到私鑰同目錄，不是預設位置。
    #>
    param(
        [string] $PublicPem,
        [byte[]] $SpkiDer,
        [string] $PublicKeyFilePath
    )
    Write-Host "公鑰已寫入：$PublicKeyFilePath"
    Write-Host '請把這個檔案（或以下 PEM 全文）交給加密端，放到該機器的 ~\.rune\public.pem。'
    Write-Host ''
    Write-Host '===== 公鑰 PEM（加密端使用）====='
    Write-Host $PublicPem
    Write-Host '================================'
    Write-Host ('公鑰指紋：RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $SpkiDer))
    Write-Host '加密端每次 -Pack 都會印出同格式的指紋，請逐字比對；不符代表公鑰在傳遞過程中被掉包。'
}
