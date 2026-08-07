[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Pack,

    [string] $OutFile,

    [switch] $Force,

    # 收件人公鑰：字串含 -----BEGIN 視為 PEM 內容本體，否則視為檔案路徑。
    # 不指定時讀預設路徑 ~\.rune\public.pem。
    [string] $PublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
