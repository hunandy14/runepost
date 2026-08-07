# open 專用：私鑰檔的路徑常數。刻意與 keystore/paths.ps1（seal + open 共用）
# 分開成獨立 fragment，只給 rune-open.ps1 的 manifest 收錄——確保
# "DefaultKeyFile" 這個符號不會出現在 dist/rune-seal.ps1 的原始碼文字裡。
$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'
