# seal + open 共用：只放兩邊都要用到的常數。私鑰相關的路徑常數
# （$Script:DefaultKeyDir / $Script:DefaultKeyFile）刻意不放這裡，改放
# keystore/private-paths.ps1（只給 open 用）——否則只要 seal 端載入了這個
# 共用 fragment，dist/rune-seal.ps1 的原始碼文字裡就會出現 "DefaultKeyFile"
# 這個符號（即使從未被引用），讓「加密端不含任何解密相關符號」這個負面掃描
# 斷言失去意義。兩檔各自獨立算出 $HOME\.rune，屬性上有一行的重複，換來的是
# 這個純文字層級的隔離可被靜態掃描驗證。
$Script:DefaultPublicKeyFile = Join-Path -Path (Join-Path -Path $HOME -ChildPath '.rune') -ChildPath 'public.pem'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'
