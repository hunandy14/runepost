#Requires -Version 7.4
<#
.SYNOPSIS
    密文傳輸工具（解密端 + 金鑰管理）— 兩台自有 Windows 機器間，經公開純文字管道（論壇/pastebin）單向傳檔。

.DESCRIPTION
    流程：文字解碼（Base64）→ 解密（ECDH P-256 + HKDF-SHA256 派生 AES-256-GCM 金鑰）→
    解壓（Brotli）→ 解包（ZIP/store）。純 .NET 內建類別實作，零外部依賴，全程記憶體操作。

    私鑰以 DPAPI（CurrentUser）保護後存於 ~\.rune\private.key，只有「同一台機器、
    同一個 Windows 帳號」解得開。公鑰同時寫到 ~\.rune\public.pem，交給加密端
    （rune-seal.ps1）使用。

.EXAMPLE
    .\rune-open.ps1 -GenerateKeys
    產生 ECDH P-256 金鑰對：私鑰以 DPAPI 保護後存到 ~\.rune\private.key，公鑰同時寫到
    ~\.rune\public.pem，並在畫面印出公鑰 PEM 與公鑰指紋。

.EXAMPLE
    .\rune-open.ps1 -ExportPublicKey
    從既有的 ~\.rune\private.key 重新導出公鑰，覆寫 ~\.rune\public.pem 並印出指紋。
    public.pem 遺失時用這個補回來，也可以拿來隨時再看一次自己的指紋。

.EXAMPLE
    .\rune-open.ps1 -Unpack report.docx.txt -Destination C:\out
    在持有私鑰的機器上解密還原檔案。
#>
