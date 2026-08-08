function Get-RuneKeyBackupPaths {
    <#
        算出「這次要保留舊金鑰」該用的備份路徑：private.key 與 public.pem（若存在）
        用同一個時間戳改名，格式 <原檔名>.bak-yyyyMMdd-HHmmss —— 不會碰撞（同一秒內
        重複執行時退避加 4 碼亂數尾碼）、可排序、一眼看得出是備份。
    #>
    param()
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $keyBackup = '{0}.bak-{1}' -f $Script:DefaultKeyFile, $stamp
    $pubBackup = '{0}.bak-{1}' -f $Script:DefaultPublicKeyFile, $stamp
    if ((Test-Path -LiteralPath $keyBackup) -or (Test-Path -LiteralPath $pubBackup)) {
        $stamp = '{0}-{1}' -f $stamp, ([guid]::NewGuid().ToString('N').Substring(0, 4))
        $keyBackup = '{0}.bak-{1}' -f $Script:DefaultKeyFile, $stamp
        $pubBackup = '{0}.bak-{1}' -f $Script:DefaultPublicKeyFile, $stamp
    }
    return [pscustomobject]@{ KeyBackup = $keyBackup; PubBackup = $pubBackup }
}
