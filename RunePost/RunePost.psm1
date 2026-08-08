#Requires -Version 7.4

# ==========================================================================
# RunePost 模組載入器 + 模組層級常數
#
# 常數為什麼放在 .psm1 本體而不是 Private/Variables.ps1：
#   $Script: 範圍在模組裡就是「模組範圍」，dot-source 進來與寫在本體效果相同，
#   但 Private/ 的規則是「一檔一函式、檔名 = 函式名」，塞一個沒有函式的檔案進去
#   會破壞那條規則，也讓 $Public.BaseName / $Private.BaseName 這類以檔名為準的
#   慣例出現例外。常數只有這一處、量也小，放本體讀者一眼就找得到。
#
# 舊架構對應：src/container/format-spec.ps1、src/keystore/paths.ps1、
#             src/keystore/private-paths.ps1、src/keystore/paths-doc.ps1。
#   paths.ps1 與 private-paths.ps1 原本刻意拆成兩檔，是為了讓 "DefaultKeyFile"
#   這個符號不出現在 dist/rune-seal.ps1 的原始碼文字裡（負面符號掃描）。單檔
#   部署已隨模組化放棄——加密端改為複製整個模組資料夾，seal 與 open 共用同一份
#   程式碼，那個純文字層級的隔離不再成立，兩檔因此合併回這裡。
# ==========================================================================

# 這兩行不是新行為，是把舊架構的既有行為搬過來：舊的 dist/rune-*.ps1 在 param
# 區塊之後就宣告這兩項，整份腳本（含所有函式）都在其效力範圍內。
#
# 兩者的機制不同，理由也不同（皆經探針模組實測，模組本身不宣告任何設定）：
#
#   Set-StrictMode —— 呼叫端的設定**不會**傳進模組。實測：呼叫端設
#     Set-StrictMode -Version Latest 後呼叫模組函式，模組內仍是未生效狀態。
#     不在這裡宣告，模組就永遠跑在寬鬆模式，與舊架構行為不同。
#
#   $ErrorActionPreference —— 呼叫端的設定**會**被模組函式讀到（實測：呼叫端設
#     Stop，模組內就讀到 Stop，非終止錯誤確實終止）。所以這行不是為了「修好
#     繼承」，而是為了**不依賴呼叫端**：使用者 Import-Module RunePost 後直接
#     呼叫 Invoke-RuneSeal 時，session 預設是 Continue，沒有任何入口腳本替他設
#     Stop。在模組範圍宣告會覆蓋呼叫端的值，使模組的行為與呼叫者的偏好無關、
#     恆定為 Stop。
#
# 附帶說明（避免後人高估這兩行）：現有錯誤路徑幾乎都走顯式 throw 或 .NET
# 例外，與 EAP 無關。實測把這兩行分別、一起拿掉共三組，tests\verify.ps1 全套
# 76 案的結果與對照組完全相同。因此這裡**不宣稱**「不設就會壞」，只宣稱
# 「設了才不必依賴呼叫端、行為才與呼叫者的偏好無關」。
# 這是預防性的契約宣告，不是在修一個看得見的 bug。
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================================
# 金鑰的取得與擺放（公鑰不內嵌在腳本裡）
#
#   1. 在「解密端」（保管私鑰的那台機器）執行：
#        pwsh .\rune-open.ps1 -GenerateKeys
#      私鑰（ECDH P-256）會以 DPAPI（CurrentUser）保護後寫到 ~\.rune\private.key，
#      公鑰同時寫到 ~\.rune\public.pem，畫面另外印出「公鑰指紋」。
#      私鑰檔只有「同一台機器、同一個 Windows 帳號」能用 DPAPI 解回來，
#      換機器或換帳號一律讀不開，因此不需要另外設密碼。
#   2. 把 public.pem 交給「加密端」，放到該機器的 ~\.rune\public.pem
#      （或用 -PublicKey 指定其他路徑／直接給 PEM 字串本體）。
#   3. 加密端每次執行 -Pack 都會先印出所用公鑰的指紋，請與解密端印出的逐字比對。
#
# 為什麼不內嵌：內嵌只有兩種結果——交付出去的腳本帶著某個人的公鑰（別人拿到就是
# 加密給他），或維持空字串（拿到不能用，人人都得先編輯腳本）。改成執行期讀檔後，
# 本工具是與金鑰無關的通用工具，任何人配上自己的 public.pem 即可使用。
#
# 為什麼要有指紋：公鑰檔被掉包會讓使用者靜默地把資料加密給攻擊者，而資料檔被換
# 比腳本被改更難察覺——腳本有版本控管，~\.rune\public.pem 什麼都沒有。指紋是這條
# 路徑上唯一的防線，所以 -Pack 每次都印，讓每一次執行都有機會發現異常。
# ==========================================================================

# ==========================================================================
# 容器二進位格式（加密前於記憶體組好，再整體 Base64）：
#   magic "RUNE"(4B ASCII) | version 0x02(1B) | contentType(1B) | ephPubKeyLen(uint16 LE)
#   | ephemeral ECDH P-256 公鑰（SubjectPublicKeyInfo DER）| nonce(12B) | tag(16B) | ciphertext
#
#   欄位位移：magic@0 version@4 contentType@5 ephPubKeyLen@6 ephPubKey@8
#            nonce@8+n tag@20+n ciphertext@36+n（n = ephPubKeyLen），header 最小長度 8。
#
#   contentType（1 byte，明文）：
#     0x01 = 檔案樹，明文側被加密的內容 = Brotli( Zip( 輸入 ) )
#     0x02 = UTF-8 純文字，明文側 = Brotli( UTF8( 文字 ) )，無 ZIP 層【保留，本版尚未實作】
#   放在 version 之後，是為了讓 magic+version（byte 0–4）成為所有版本共通、永遠可解析的
#   前綴；未來版本可自 byte 5 起重新定義而不失去「這是 Rune 檔、版本是 N」的判讀能力。
#   以明文存放的代價只是洩漏「這是檔案還是文字」，而負載大小早就洩漏了同一件事。
#
#   金鑰交換／派生（version 2）：
#     每次 -Pack 產生一次性 ephemeral ECDH P-256 金鑰對，與執行期載入的收件人
#     公鑰做 ECDH（DeriveRawSecretAgreement）得共享祕密；再以
#     HKDF-SHA256(ikm = 共享祕密, salt = nonce,
#                 info = magic + version + contentType + ephemeral公鑰DER)
#     派生 32 bytes 的 AES-256-GCM 金鑰。salt 選用 nonce（而非空）是為了讓每次
#     Pack 產生的金鑰額外與該次的 nonce 綁定；info 內含 magic/version/contentType/
#     ephemeral 公鑰，確保派生結果與容器內容一一對應、不可跨欄位替換。
#
#   【contentType 必須進 HKDF info】本工具的 AES-GCM 未使用 AAD，tag 只涵蓋 ciphertext，
#   涵蓋不到 header 任何一個 byte。若 contentType 不進 info，攻擊者把 0x01 翻成 0x02
#   後 tag 仍會驗過，解密端就會把一串 ZIP 位元組當成 UTF-8 文字處理——這是 content-type
#   confusion。綁進 info 之後，翻位元 → 派生金鑰不同 → tag 不符，直接走既有的認證失敗路徑。
#   也因此「型別是否支援」的檢查必須放在 GCM 解密成功之後（見 Invoke-RuneOpen）：
#   tag 驗過就等於這個 byte 是真品，此時值仍未知才能斷定是版本落後而非資料被竄改。
#
#   【新舊互斥】RUNE v2 與舊工具的 CTXT v2 無血緣關係，version 編號重用純屬巧合，
#   兩者靠 magic 互斥：magic 檢查排在 version 檢查之前（見 ConvertFrom-RuneContainer），
#   舊 CTXT 密文餵進來一定先被 magic 擋掉，永遠到不了 version 比對；反向亦然。
#   縱深防禦：magic 亦在 HKDF info 內，即使強行跳過檢查，派生金鑰也不同 → tag 不符。
# ==========================================================================
$Script:RuneMagic = 'RUNE'
$Script:RuneVersion = [byte] 2
# 內容型別列舉：0x01 檔案樹（本版唯一會產生也唯一支援的型別）、0x02 UTF-8 純文字（保留）
$Script:ContentTypeFileTree = [byte] 1
$Script:ContentTypeText = [byte] 2
$Script:NonceLength = 12
$Script:TagLength = 16

# 金鑰檔路徑與曲線 OID
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'
$Script:DefaultPublicKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'public.pem'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'

# ==========================================================================
# 載入器：Private 先於 Public（Public 依賴 Private，但 dot-source 只是定義函式，
# 順序其實不影響解析；先私後公純粹是讀起來合理）。只匯出 Public\ 底下的函式名，
# 不用萬用字元——FunctionsToExport = '*' 會讓模組自動載入器為了做命令探索而解析
# 整個模組，是有實測代價的效能陷阱。
# ==========================================================================
$Private = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private\*.ps1') -ErrorAction SilentlyContinue)
$Public = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public\*.ps1') -ErrorAction SilentlyContinue)

foreach ($file in @($Private) + @($Public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "載入模組檔案失敗：$($file.FullName)（$($_.Exception.Message)）"
    }
}

Export-ModuleMember -Function $Public.BaseName
