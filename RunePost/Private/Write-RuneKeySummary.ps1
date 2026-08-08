# ==========================================================================
# 區塊：-GenerateKeys / -ExportPublicKey 主流程
# ==========================================================================

function Write-RuneKeySummary {
    <#
        統一的金鑰摘要輸出（-GenerateKeys / -ExportPublicKey 共用）：標題 + 私鑰／
        公鑰路徑 + 指紋，對齊的三行（有備份時加第四行），刻意不印 PEM 全文——
        路徑已給，要看內容用 Get-Content；原本較長的備份／遺失警語移到
        comment-based help（見 shell/open-help.ps1 的 .DESCRIPTION 與 .EXAMPLE）。
    #>
    param(
        [string] $Title,
        [string] $KeyFilePath,
        [string] $KeyFileNote,
        [string] $PublicKeyFilePath,
        [byte[]] $SpkiDer,
        [string] $BackupKeyFilePath
    )
    Write-Host $Title
    $keyLine = "  私鑰  $KeyFilePath"
    if ($KeyFileNote) { $keyLine += "   ($KeyFileNote)" }
    Write-Host $keyLine
    Write-Host "  公鑰  $PublicKeyFilePath"
    Write-Host ('  指紋  RUNE-KEY {0}' -f (Get-RuneKeyFingerprint -SpkiDer $SpkiDer))
    if ($BackupKeyFilePath) {
        Write-Host "  備份  $BackupKeyFilePath"
    }
}
