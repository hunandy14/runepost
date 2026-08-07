
# ==========================================================================
# 區塊：ZIP 解包
# ==========================================================================

function Expand-RuneZip {
    <# 將 ZIP 位元組解開到目的資料夾（手動走 stream，防 zip-slip） #>
    param(
        [byte[]] $ZipBytes,
        [string] $Destination
    )

    $ms = [System.IO.MemoryStream]::new($ZipBytes)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new(
            $ms, [System.IO.Compression.ZipArchiveMode]::Read, $false, [System.Text.Encoding]::UTF8)
        try {
            $destRoot = (New-Item -ItemType Directory -Path $Destination -Force).FullName
            $destRootWithSep = $destRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

            foreach ($entry in $zip.Entries) {
                # (a) 本工具自家產物一律用 '/' 當目錄分隔符（打包端 Get-RunePackPlan 已把
                #     '\' 轉成 '/'，見該函式內的 -replace '\\', '/'）。因此 entry 名稱只要
                #     含反斜線，就一定不是自家封裝，直接拒絕，不嘗試解讀成相對路徑。
                if ($entry.FullName -match '\\') {
                    throw [System.Security.SecurityException]::new(
                        "偵測到不安全的封存路徑（entry 名稱含反斜線）：$($entry.FullName)")
                }

                $relPath = $entry.FullName -replace '/', [System.IO.Path]::DirectorySeparatorChar
                $destPath = Join-Path -Path $destRoot -ChildPath $relPath

                # (b) 防禦性檢查：不用字串樣式（只擋 "../"）比對，改用正規化後的
                #     包含性判斷——把 destPath 解析成絕對路徑，要求其開頭必須是
                #     「$destRoot + 目錄分隔符」，否則一律視為跳脫目的資料夾。
                $fullResolved = [System.IO.Path]::GetFullPath($destPath)
                if (-not $fullResolved.StartsWith($destRootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw [System.Security.SecurityException]::new(
                        "偵測到不安全的封存路徑（跳脫目的資料夾）：$($entry.FullName)")
                }

                if ($entry.FullName.EndsWith('/')) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                    continue
                }

                $destDir = Split-Path -Path $destPath -Parent
                if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }

                $entryStream = $entry.Open()
                try {
                    $outStream = [System.IO.File]::Create($destPath)
                    try {
                        $entryStream.CopyTo($outStream)
                    }
                    finally {
                        $outStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $ms.Dispose()
    }
}

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
