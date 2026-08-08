#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具（解密端 + 金鑰管理）— 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：文字解碼（Base64）→ 解密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→
    解壓（Brotli）→ 解包（ZIP/store）。純 .NET 內建類別實作，零外部依賴，全程記憶體操作。

    私鑰以 DPAPI（CurrentUser）保護後存於 ~\.rune\private.key，只有「同一台機器、
    同一個 Windows 帳號」解得開；換機器或換帳號一律讀不開，且不支援另外設密碼。
    請自行額外備份此檔——若檔案本身遺失或損壞（而非被 -GenerateKeys 改名保留，
    見下段），所有用對應公鑰加密過的密文將永久無法解密，沒有任何復原手段。
    公鑰同時寫到 ~\.rune\public.pem，請把這個檔案交給加密端（rune-seal.ps1），
    放到該機器的 ~\.rune\public.pem（或用 -PublicKey 指定其他路徑／直接傳入
    PEM 字串本體）。

    -GenerateKeys 若偵測到 ~\.rune\private.key 已存在，不會直接覆蓋：互動環境下
    會先印出現有金鑰的指紋，提示是否要產生新金鑰（預設為「不繼續」，直接 Enter
    或輸入 y/yes 以外的任何內容都會取消）；一旦確認（或帶 -Force 跳過提示），
    會先把舊的 private.key／public.pem 改名為同一時間戳的 .bak 檔（不是刪除），
    才產生並寫入新金鑰對。舊私鑰仍在，只是換了副檔名，用 -KeyFile 指向備份路徑
    即可繼續解密用舊公鑰加密的密文；但比對指紋仍然重要——確認要換的是哪一把，
    因為換過之後加密端預設用的公鑰就不同了。非互動環境（例如排程工作、管道輸入
    被重導向）一律直接拒絕，不會卡在提示；此時請改用 -Force，或手動處理
    private.key 後重新執行。

    成功輸出只印路徑與指紋，不再印出公鑰 PEM 全文；要看 PEM 內容請自行執行
    Get-Content ~\.rune\public.pem。

.PARAMETER Force
    搭配 -GenerateKeys：當 ~\.rune\private.key 已存在時，略過確認提示直接產生
    新金鑰（舊金鑰仍會改名保留為 .bak 檔，不會刪除），供非互動情境（腳本、
    排程）使用。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對：私鑰以 DPAPI 保護後存到 ~\.rune\private.key，公鑰同時
    寫到 ~\.rune\public.pem，畫面印出兩者路徑與公鑰指紋。若 private.key 已存在，
    會先印出現有指紋並詢問是否繼續（預設不繼續）；確認後舊金鑰會改名保留為
    private.key.bak-<時間戳>（與對應的 public.pem.bak-<時間戳>），舊密文仍可用
    -KeyFile 指向備份路徑解密。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys -Force
    略過確認提示，直接產生新金鑰；既有的 private.key / public.pem 一樣改名保留為
    .bak 檔，不會刪除。供非互動環境使用（stdin 被重導向時必須加此參數，否則會
    直接被拒絕，不會卡住）。

.EXAMPLE
    .\rune-open.ps1 -ExportPublicKey
    從既有的 ~\.rune\private.key 重新導出公鑰，覆寫 ~\.rune\public.pem 並印出
    路徑與指紋。public.pem 遺失時用這個補回來，也可以拿來隨時再看一次自己的指紋。

.EXAMPLE
    .\rune-open.ps1 -Unpack report.docx.txt -Destination C:\out
    在持有私鑰的機器上解密還原檔案。-Unpack 與 -Destination 皆可省略參數名稱、
    依序放位置（.\rune-open.ps1 report.docx.txt C:\out），與 rune-seal.ps1 的
    .\rune-seal.ps1 <路徑> 用法一致。
#>
[CmdletBinding(DefaultParameterSetName = 'Unpack')]
param(
    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true, Position = 0)]
    [string] $Unpack,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true, Position = 1)]
    [string] $Destination,

    [Parameter(ParameterSetName = 'Unpack')]
    [Parameter(ParameterSetName = 'ExportPublicKey')]
    [string] $KeyFile,

    [Parameter(ParameterSetName = 'GenerateKeys', Mandatory = $true)]
    [switch] $GenerateKeys,

    [Parameter(ParameterSetName = 'GenerateKeys')]
    [switch] $Force,

    [Parameter(ParameterSetName = 'ExportPublicKey', Mandatory = $true)]
    [switch] $ExportPublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 進入點
# ==========================================================================

try {
    # Import-Module 放在 try 內：模組資料夾遺失／損壞也走同一個乾淨的錯誤出口，
    # 而不是噴出 PowerShell 原生的多行錯誤記錄。
    # -Force 保留的量測依據見 rune-seal.ps1 同一段註解：全新行程下 -Force 不花錢
    # （單次執行 1632ms vs 1635ms，差異在雜訊內），但能保證同一 session 改過模組
    # 檔後跑到的是磁碟版本，而非 no-op 沿用的舊程式碼。
    Import-Module (Join-Path $PSScriptRoot 'RunePost') -Force

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
