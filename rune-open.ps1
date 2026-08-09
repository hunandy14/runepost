#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具（解密端 + 金鑰管理）— 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：文字解碼（Base64）→ 解密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→
    解壓（Brotli）→ 解包（ZIP/store）。純 .NET 內建類別實作，零外部依賴，全程記憶體操作。

    私鑰存於 ~\.rune\private.key，靜態保護方式由 -GenerateKeys -Protect 決定，共三種：
    None（預設，未加密的 PKCS#8 PEM）、Passphrase（密碼保護的 PKCS#8 PEM）、
    Dpapi（DPAPI CurrentUser 位元組，僅本機本帳號可解）。解密端讀取私鑰時由檔案內容
    自動判別格式，三種格式共用同一個路徑，不需指定。

    選擇取捨：密文張貼到公開管道後即為永久存在，而私鑰是唯一的還原手段——私鑰遺失
    等同所有歷來密文永久無法解密。Dpapi 的靜態保護最強，但綁定本機與本 Windows 帳號，
    重灌或換帳號後即無法還原，也無法備份。None 與 Passphrase 為標準 PKCS#8，可複製到
    離線媒體保存。預設 None 即是以可攜與可備份為優先；選擇 None 時，任何能讀取
    private.key 的人都能解開所有以對應公鑰加密的密文。

    公鑰同時寫到 ~\.rune\public.pem，請把這個檔案交給加密端（rune-seal.ps1），
    放到該機器的 ~\.rune\public.pem（或用 -PublicKey 指定其他路徑／直接傳入
    PEM 字串本體）。

    既有私鑰可用 -ExportPrivateKey 匯出成可備份的 PKCS#8 PEM，來源包含 DPAPI 私鑰；
    這是把 DPAPI 私鑰離機保存的唯一途徑。

    -GenerateKeys 若偵測到 ~\.rune\private.key 已存在，不會直接覆蓋：互動環境下
    會先印出現有金鑰的指紋，再以 PowerShell 標準的確認提示詢問是否產生新金鑰
    （選項 Y／A／N／L／S，預設為 Y，直接按 Enter 即繼續；不要繼續請明確選 N。
    安全性來自舊金鑰改名保留而不是刪除，不依賴提示的預設值）；一旦確認（或帶
    -Force 跳過提示），
    會先把舊的 private.key／public.pem 改名為同一時間戳的 .bak 檔（不是刪除），
    才產生並寫入新金鑰對。舊私鑰仍在，只是換了副檔名，用 -KeyFile 指向備份路徑
    即可繼續解密用舊公鑰加密的密文；但比對指紋仍然重要——確認要換的是哪一把，
    因為換過之後加密端預設用的公鑰就不同了。非互動環境（例如排程工作、管道輸入
    被重導向）一律直接拒絕，不會卡在提示；此時請改用 -Force，或手動處理
    private.key 後重新執行。

    成功輸出只印路徑與指紋，不印出公鑰 PEM 全文；要看 PEM 內容請自行執行
    Get-Content ~\.rune\public.pem。

.PARAMETER Protect
    搭配 -GenerateKeys：私鑰的靜態保護方式，None（預設）／Passphrase／Dpapi。
    搭配 -ExportPrivateKey：匯出檔的格式，None（預設）／Passphrase；不支援 Dpapi，
    因為 DPAPI 檔案在其他機器或帳號無法還原，不具備份用途。

.PARAMETER Passphrase
    密碼保護的 PKCS#8 PEM 所需的密碼，型別為 SecureString。搭配 -GenerateKeys
    -Protect Passphrase 時是新私鑰的密碼；搭配 -Unpack／-ExportPublicKey／
    -ExportPrivateKey 時是「讀取來源私鑰」的密碼。未提供時於互動環境詢問；
    非互動環境（標準輸入已重新導向）一律直接報錯，不會卡在提示。

.PARAMETER OutPassphrase
    搭配 -ExportPrivateKey -Protect Passphrase：匯出檔的密碼，型別為 SecureString。
    與 -Passphrase 分開，因為來源私鑰與匯出檔是兩個各自獨立的密碼。

.PARAMETER OutFile
    搭配 -ExportPrivateKey：匯出檔的輸出路徑，必填。已存在時拒絕覆蓋，需加 -Force。

.PARAMETER KeyFile
    來源私鑰的路徑，預設 ~\.rune\private.key。三種儲存格式皆由內容自動判別。

.PARAMETER Force
    搭配 -GenerateKeys：當 ~\.rune\private.key 已存在時，略過確認提示直接產生
    新金鑰（舊金鑰仍會改名保留為 .bak 檔，不會刪除）。
    搭配 -ExportPrivateKey：略過確認提示，並允許覆蓋已存在的 -OutFile。
    兩者皆供非互動情境（腳本、排程）使用。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對：私鑰以未加密的 PKCS#8 PEM 存到 ~\.rune\private.key，
    公鑰同時寫到 ~\.rune\public.pem，畫面印出兩者路徑與公鑰指紋，並警告私鑰未加密。
    若 private.key 已存在，會先印出現有指紋並詢問是否繼續（PowerShell 標準確認提示，
    預設為繼續，不要繼續請選 N）；確認後舊金鑰
    會改名保留為 private.key.bak-<時間戳>（與對應的 public.pem.bak-<時間戳>），
    舊密文仍可用 -KeyFile 指向備份路徑解密。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys -Protect Passphrase
    產生金鑰對，私鑰以密碼保護的 PKCS#8 PEM 存放。密碼於畫面詢問並要求輸入兩次確認；
    非互動環境請改以 -Passphrase (Read-Host -AsSecureString) 傳入。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys -Protect Dpapi
    產生金鑰對，私鑰以 DPAPI（CurrentUser）保護。此檔只有同一台機器、同一個 Windows
    帳號解得開，無法複製備份；請一併規劃 -ExportPrivateKey 的備份流程。

.EXAMPLE
    .\rune-open.ps1 -ExportPrivateKey -OutFile D:\backup\rune-private.pem
    把 ~\.rune\private.key 匯出成未加密的 PKCS#8 PEM 備份，來源為 DPAPI 私鑰時同樣適用。
    匯出前會顯示來源、輸出路徑與格式並要求確認（-Force 略過）。匯出檔可用
    -KeyFile 指向它來解密，請存放於能控制存取權的離線媒體。

.EXAMPLE
    .\rune-open.ps1 -ExportPrivateKey -OutFile D:\backup\rune-private.pem -Protect Passphrase
    匯出成密碼保護的 PKCS#8 PEM。匯出檔的密碼於畫面詢問並要求輸入兩次確認，
    非互動環境請以 -OutPassphrase 傳入 SecureString。

.EXAMPLE
    .\rune-open.ps1 -ExportPublicKey
    從既有的 ~\.rune\private.key 重新導出公鑰，覆寫 ~\.rune\public.pem 並印出
    路徑與指紋。public.pem 遺失時用這個補回來，也可以拿來隨時再看一次自己的指紋。

.EXAMPLE
    .\rune-open.ps1 -Unpack report.docx.txt -Destination C:\out
    在持有私鑰的機器上解密還原檔案。-Unpack 與 -Destination 皆可省略參數名稱、
    依序放位置（.\rune-open.ps1 report.docx.txt C:\out），與 rune-seal.ps1 的
    .\rune-seal.ps1 <路徑> 用法一致。私鑰為密碼保護的 PKCS#8 PEM 時會詢問密碼，
    非互動環境請以 -Passphrase 傳入。
#>
[CmdletBinding(DefaultParameterSetName = 'Unpack')]
# 本腳本是 CLI 入口，職責就是把模組回傳的結果印給使用者看。Write-Host 在這裡是
# 正確的工具：訊息要無條件出現在畫面上，又不能混進任何回傳值。模組側一律回傳
# 物件、不印字，這條規則只在這一層例外。
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'CLI 入口腳本的呈現層：輸出是給人看的終端訊息，不是回傳值。')]
param(
    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true, Position = 0)]
    [string] $Unpack,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true, Position = 1)]
    [string] $Destination,

    [Parameter(ParameterSetName = 'Unpack')]
    [Parameter(ParameterSetName = 'ExportPublicKey')]
    [Parameter(ParameterSetName = 'ExportPrivateKey')]
    [string] $KeyFile,

    [Parameter(ParameterSetName = 'GenerateKeys', Mandatory = $true)]
    [switch] $GenerateKeys,

    [Parameter(ParameterSetName = 'GenerateKeys')]
    [Parameter(ParameterSetName = 'ExportPrivateKey')]
    [switch] $Force,

    [Parameter(ParameterSetName = 'ExportPublicKey', Mandatory = $true)]
    [switch] $ExportPublicKey,

    [Parameter(ParameterSetName = 'ExportPrivateKey', Mandatory = $true)]
    [switch] $ExportPrivateKey,

    [Parameter(ParameterSetName = 'ExportPrivateKey', Mandatory = $true)]
    [string] $OutFile,

    # -GenerateKeys 時為新私鑰的儲存格式；-ExportPrivateKey 時為匯出檔的格式。
    # 兩者共用一個 ValidateSet，Dpapi 用於匯出的情形由模組函式擋下並說明原因。
    [Parameter(ParameterSetName = 'GenerateKeys')]
    [Parameter(ParameterSetName = 'ExportPrivateKey')]
    [ValidateSet('None', 'Passphrase', 'Dpapi')]
    [string] $Protect = 'None',

    [Parameter(ParameterSetName = 'Unpack')]
    [Parameter(ParameterSetName = 'GenerateKeys')]
    [Parameter(ParameterSetName = 'ExportPublicKey')]
    [Parameter(ParameterSetName = 'ExportPrivateKey')]
    [securestring] $Passphrase,

    [Parameter(ParameterSetName = 'ExportPrivateKey')]
    [securestring] $OutPassphrase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 呈現層
#
# 金鑰摘要的版面（標題 + 私鑰／公鑰路徑 + 指紋，有備份時加第四行）由這裡決定；
# 模組只回傳欄位。刻意不印 PEM 全文——路徑已經給了，要看內容用 Get-Content。
# ==========================================================================

function Show-RuneKeySummary {
    param(
        [string] $Title,
        [string] $KeyFilePath,
        [string] $KeyFileNote,
        [string] $PublicKeyFilePath,
        [string] $Fingerprint,
        [string] $BackupKeyFilePath
    )
    Write-Host $Title
    $keyLine = "  私鑰  $KeyFilePath"
    if ($KeyFileNote) { $keyLine += "   ($KeyFileNote)" }
    Write-Host $keyLine
    Write-Host "  公鑰  $PublicKeyFilePath"
    Write-Host ('  指紋  RUNE-KEY {0}' -f $Fingerprint)
    if ($BackupKeyFilePath) {
        Write-Host "  備份  $BackupKeyFilePath"
    }
}

# 私鑰的保護方式／匯出格式一律放在成功輸出的第一行，且走一般輸出串流：警告串流
# 在輸出被重新導向時可能被丟棄，使用者不該因此不知道自己手上這把私鑰是不是明文。
# 同一個理由也決定了警告的位置——模組的 Write-Warning 由呼叫端收進
# -WarningVariable，等摘要印完才重播，好讓第一行永遠是保護方式而不是警告。
function Show-RuneDeferredWarning {
    param([System.Collections.IEnumerable] $Warnings)
    if ($null -eq $Warnings) { return }
    foreach ($w in $Warnings) { Write-Warning ([string]$w) }
}

# ==========================================================================
# 進入點
# ==========================================================================

try {
    # Import-Module 放在 try 內：模組資料夾遺失／損壞也走同一個乾淨的錯誤出口，
    # 而不是噴出 PowerShell 原生的多行錯誤記錄。
    # -Force 保證跑到的一定是磁碟上的版本，理由見 rune-seal.ps1 的同一段註解。
    Import-Module (Join-Path $PSScriptRoot 'RunePost') -Force

    switch ($PSCmdlet.ParameterSetName) {
        'GenerateKeys' {
            # 這裡不綁 -Confirm：明確綁定的 -Confirm 會蓋過函式內部的判斷，而「金鑰
            # 存不存在、有沒有東西值得問」只有模組答得出來。確認不被呼叫端 session
            # 的 $ConfirmPreference 跳過，由 New-RuneKeyPair 自己保證。
            $result = New-RuneKeyPair -Protect $Protect -Passphrase $Passphrase -Force:$Force `
                -WarningVariable keyWarnings -WarningAction SilentlyContinue
            if ($result) {
                Show-RuneKeySummary -Title "已產生 ECDH P-256 金鑰對（私鑰保護方式：$($result.ProtectNote)）" `
                    -KeyFilePath $result.KeyFile -KeyFileNote $result.ProtectNote `
                    -PublicKeyFilePath $result.PublicKeyFile -Fingerprint $result.Fingerprint `
                    -BackupKeyFilePath $result.BackupKeyFile
            }
            else {
                Write-Host '已取消，未變更任何檔案。'
            }
            Show-RuneDeferredWarning -Warnings $keyWarnings
        }
        'ExportPublicKey' {
            $result = Export-RunePublicKey -KeyFilePath $KeyFile -Passphrase $Passphrase
            if (-not $result.IsDefaultKey) {
                Write-Host "使用了非預設私鑰：$($result.KeyFile)"
                Write-Host "公鑰已寫到同目錄，未動到預設的 $($result.DefaultPublicKeyFile)。"
            }
            Show-RuneKeySummary -Title '已重新導出公鑰' -KeyFilePath $result.KeyFile `
                -PublicKeyFilePath $result.PublicKeyFile -Fingerprint $result.Fingerprint
        }
        'ExportPrivateKey' {
            # CLI 的 -Force 一次表達兩件事：略過確認、允許覆蓋既有的 -OutFile。模組
            # 函式把這兩件事分開，所以在這一層把「略過確認」翻成 -Confirm:$false，
            # 而且只在帶 -Force 時才綁定：明確綁定的 -Confirm 會蓋過函式內部的判斷，
            # 不帶 -Force 時交給 Export-RunePrivateKey 自己決定（它一律要求確認）。
            $confirmArg = @{}
            if ($Force) { $confirmArg['Confirm'] = $false }
            $result = Export-RunePrivateKey -OutFilePath $OutFile -KeyFilePath $KeyFile -Protect $Protect `
                -Passphrase $Passphrase -OutPassphrase $OutPassphrase -Force:$Force @confirmArg `
                -WarningVariable keyWarnings -WarningAction SilentlyContinue
            if ($result) {
                Write-Host "已匯出私鑰（格式：$($result.ProtectNote)）"
                Write-Host "  來源  $($result.SourceKeyFile)"
                Write-Host "  輸出  $($result.OutFile)"
                Write-Host ('  指紋  RUNE-KEY {0}' -f $result.Fingerprint)
                Write-Host "還原方式：rune-open.ps1 -Unpack <密文檔> -Destination <目的資料夾> -KeyFile $($result.OutFile)"
            }
            else {
                Write-Host '已取消，未變更任何檔案。'
            }
            Show-RuneDeferredWarning -Warnings $keyWarnings
        }
        'Unpack' {
            $result = Invoke-RuneOpen -InFilePath $Unpack -DestinationPath $Destination `
                -KeyFilePath $KeyFile -Passphrase $Passphrase
            Write-Host "解密完成，檔案已還原至：$($result.Destination)"
        }
    }
}
catch {
    # 用 [Console]::Error.WriteLine 直接印例外訊息本身，不用 Write-Error——
    # 避免 PowerShell 錯誤記錄框架附加的呼叫堆疊／分類等雜訊，讓使用者只看到
    # 乾淨的錯誤說明。WriteLine 只呼叫一次，但訊息本身可以內嵌換行。
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
