function Move-RuneExtractedTree {
    <#
        把 $SourceDir 底下的內容遞迴搬到 $DestDir（同名目錄就合併、同名檔案就覆蓋），
        用於 -Unpack 的「先解到暫存資料夾，全部成功後才搬到正式 Destination」流程。
    #>
    param(
        [string] $SourceDir,
        [string] $DestDir
    )

    if (-not (Test-Path -LiteralPath $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }

    foreach ($child in Get-ChildItem -LiteralPath $SourceDir -Force) {
        $targetPath = Join-Path -Path $DestDir -ChildPath $child.Name
        if ($child.PSIsContainer) {
            if (Test-Path -LiteralPath $targetPath -PathType Container) {
                Move-RuneExtractedTree -SourceDir $child.FullName -DestDir $targetPath
            }
            else {
                Move-Item -LiteralPath $child.FullName -Destination $targetPath -Force
            }
        }
        else {
            Move-Item -LiteralPath $child.FullName -Destination $targetPath -Force
        }
    }
}
