#Requires -Version 7.4
<#
.SYNOPSIS
    runepost decrypting side and key management. Sends files one way between two Windows machines you own, over a public plain-text channel such as a forum post or a pastebin.

.DESCRIPTION
    The pipeline is decode (Base64) -> decrypt (AES-256-GCM with a key derived from
    ephemeral ECDH P-256 and HKDF-SHA256) -> decompress (Brotli) -> extract (ZIP, store).
    Everything is built on the .NET base class library, with no external dependencies, and
    all work happens in memory.

    The private key is stored at ~\.rune\private.key. Its protection mode is chosen with
    -GenerateKeys -Protect and has three values: None (the default, an unencrypted PKCS#8
    PEM), Passphrase (a passphrase-protected PKCS#8 PEM), and Dpapi (DPAPI CurrentUser
    bytes, readable only on this machine under this Windows account). All three modes share
    the same path, and the format is detected from the file content, so it never has to be
    specified when reading the key.

    The trade-off behind the default: ciphertext posted to a public channel is permanent,
    and the private key is the only way to recover it, so losing the private key makes every
    past ciphertext permanently unreadable. Dpapi offers the strongest protection at rest,
    but it binds the file to this machine and this Windows account: after a reinstall or an
    account change the key cannot be read, and it cannot be backed up. None and Passphrase
    are standard PKCS#8 and can be copied to offline media. The default of None puts
    portability and backup ahead of encryption at rest. With None, anyone who can read
    private.key can decrypt every ciphertext encrypted to the matching public key.

    The public key is written to ~\.rune\public.pem at the same time. Transfer that file to
    the encrypting machine (rune-seal.ps1) and place it at ~\.rune\public.pem there, or
    point -PublicKey at another location or pass the PEM content itself.

    An existing private key can be exported as a backup PKCS#8 PEM with -ExportPrivateKey.
    A DPAPI private key is a valid source, and this is the only way to keep a copy of a
    DPAPI private key off the machine.

    When -GenerateKeys finds an existing ~\.rune\private.key, it does not overwrite it. In
    an interactive session it prints the fingerprint of the existing key and then asks for
    confirmation through the standard PowerShell prompt (options Y, A, N, L, S; the default
    is Y, so pressing Enter continues; select N to stop). The safety of this path comes from
    the old key pair being renamed rather than deleted, not from the default answer. Once
    confirmed, or when -Force skips the prompt, the existing private.key and public.pem are
    renamed to .bak files that share one timestamp, and only then is the new key pair
    created and written. The old private key still exists under the new name: point -KeyFile
    at the backup path to keep decrypting ciphertext encrypted to the old public key.
    Comparing fingerprints still matters, because after a rotation the encrypting side uses
    a different public key by default. A non-interactive session, such as a scheduled task
    or a run with standard input redirected, is refused outright rather than waiting at the
    prompt. Specify -Force, or move private.key aside and run the command again.

    Successful output prints paths and fingerprints only, never the public key PEM in full.
    To read the PEM, run Get-Content ~\.rune\public.pem.

.PARAMETER Protect
    With -GenerateKeys: the protection mode of the private key at rest, one of None (the
    default), Passphrase, or Dpapi.
    With -ExportPrivateKey: the format of the exported file, either None (the default) or
    Passphrase. Dpapi is not supported, because a DPAPI file cannot be read on another
    machine or account and does not serve as a backup.

.PARAMETER Passphrase
    The passphrase for a passphrase-protected PKCS#8 PEM, as a SecureString. With
    -GenerateKeys -Protect Passphrase it is the passphrase for the new private key. With
    -Unpack, -ExportPublicKey, or -ExportPrivateKey it is the passphrase of the source
    private key. When it is not supplied, an interactive session prompts for it. A
    non-interactive session, where standard input is redirected, reports an error instead of
    waiting at the prompt.

.PARAMETER OutPassphrase
    With -ExportPrivateKey -Protect Passphrase: the passphrase for the exported file, as a
    SecureString. It is separate from -Passphrase because the source private key and the
    exported file have independent passphrases.

.PARAMETER OutFile
    With -ExportPrivateKey: the output path of the exported file. Required. An existing file
    is not overwritten unless -Force is specified.

.PARAMETER KeyFile
    The path of the source private key. The default is ~\.rune\private.key. All three
    storage formats are detected from the file content.

.PARAMETER Force
    With -GenerateKeys: skip the confirmation prompt when ~\.rune\private.key already exists
    and create a new key pair. The existing key pair is still renamed to .bak files rather
    than deleted.
    With -ExportPrivateKey: skip the confirmation prompt and allow an existing -OutFile to be
    overwritten.
    Both are intended for non-interactive use, such as scripts and scheduled tasks.

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys
    Creates an ECDH P-256 key pair. The private key is written to ~\.rune\private.key as an
    unencrypted PKCS#8 PEM, the public key is written to ~\.rune\public.pem, both paths and
    the public key fingerprint are printed, and a warning states that the private key is not
    encrypted. If private.key already exists, the fingerprint of the existing key is printed
    first and confirmation is requested through the standard PowerShell prompt, whose default
    answer continues; select N to stop. After confirmation the old key pair is renamed to
    private.key.bak-<timestamp> and public.pem.bak-<timestamp>, and existing ciphertext can
    still be decrypted by pointing -KeyFile at the backup path.

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys -Protect Passphrase
    Creates a key pair and stores the private key as a passphrase-protected PKCS#8 PEM. The
    passphrase is requested on screen and must be entered twice. In a non-interactive
    session, pass it with -Passphrase (Read-Host -AsSecureString).

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys -Protect Dpapi
    Creates a key pair and protects the private key with DPAPI (CurrentUser). The file can be
    read only on this machine under this Windows account and cannot be backed up by copying.
    Plan a backup with -ExportPrivateKey at the same time.

.EXAMPLE
    .\rune-open.ps1 -ExportPrivateKey -OutFile D:\backup\rune-private.pem
    Exports ~\.rune\private.key as an unencrypted PKCS#8 PEM backup. A DPAPI private key is a
    valid source. The source, the output path, and the format are shown and confirmation is
    requested; -Force skips the prompt. Point -KeyFile at the exported file to decrypt with
    it, and keep it on offline media whose access you control.

.EXAMPLE
    .\rune-open.ps1 -ExportPrivateKey -OutFile D:\backup\rune-private.pem -Protect Passphrase
    Exports a passphrase-protected PKCS#8 PEM. The passphrase for the exported file is
    requested on screen and must be entered twice. In a non-interactive session, pass a
    SecureString with -OutPassphrase.

.EXAMPLE
    .\rune-open.ps1 -ExportPublicKey
    Re-exports the public key from the existing ~\.rune\private.key, overwrites
    ~\.rune\public.pem, and prints the paths and the fingerprint. Use it to restore a lost
    public.pem, or to print the fingerprint again at any time.

.EXAMPLE
    .\rune-open.ps1 -Unpack report.docx.txt -Destination C:\out
    Decrypts and restores files on the machine that holds the private key. -Unpack and
    -Destination can also be given positionally, as in
    .\rune-open.ps1 report.docx.txt C:\out, matching the .\rune-seal.ps1 <path> form. When
    the private key is a passphrase-protected PKCS#8 PEM, the passphrase is requested. In a
    non-interactive session, pass it with -Passphrase.
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
    $keyLine = "  Private key  $KeyFilePath"
    if ($KeyFileNote) { $keyLine += "   ($KeyFileNote)" }
    Write-Host $keyLine
    Write-Host "  Public key   $PublicKeyFilePath"
    Write-Host ('  Fingerprint  RUNE-KEY {0}' -f $Fingerprint)
    if ($BackupKeyFilePath) {
        Write-Host "  Backup       $BackupKeyFilePath"
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
                Show-RuneKeySummary -Title "Created an ECDH P-256 key pair. Private key protection: $($result.ProtectNote)." `
                    -KeyFilePath $result.KeyFile -KeyFileNote $result.ProtectNote `
                    -PublicKeyFilePath $result.PublicKeyFile -Fingerprint $result.Fingerprint `
                    -BackupKeyFilePath $result.BackupKeyFile
            }
            else {
                Write-Host 'Cancelled. No files were changed.'
            }
            Show-RuneDeferredWarning -Warnings $keyWarnings
        }
        'ExportPublicKey' {
            $result = Export-RunePublicKey -KeyFilePath $KeyFile -Passphrase $Passphrase
            if (-not $result.IsDefaultKey) {
                Write-Host "Used a non-default private key: $($result.KeyFile)."
                Write-Host "The public key was written to the same folder. $($result.DefaultPublicKeyFile) was not changed."
            }
            Show-RuneKeySummary -Title 'Re-exported the public key.' -KeyFilePath $result.KeyFile `
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
                Write-Host "Exported the private key. Format: $($result.ProtectNote)."
                Write-Host "  Source       $($result.SourceKeyFile)"
                Write-Host "  Output       $($result.OutFile)"
                Write-Host ('  Fingerprint  RUNE-KEY {0}' -f $result.Fingerprint)
                Write-Host "To decrypt with this backup: rune-open.ps1 -Unpack <ciphertext file> -Destination <destination folder> -KeyFile $($result.OutFile)"
            }
            else {
                Write-Host 'Cancelled. No files were changed.'
            }
            Show-RuneDeferredWarning -Warnings $keyWarnings
        }
        'Unpack' {
            $result = Invoke-RuneOpen -InFilePath $Unpack -DestinationPath $Destination `
                -KeyFilePath $KeyFile -Passphrase $Passphrase
            Write-Host "Decryption complete. Files were restored to: $($result.Destination)."
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
