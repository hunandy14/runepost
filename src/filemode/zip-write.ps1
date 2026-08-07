
function New-RuneZipBytes {
    <# 依項目清單建立 ZIP（store，UTF-8 檔名），回傳位元組陣列。含資料夾模式列舉的空目錄 entry。 #>
    param([object[]] $Entries)

    $ms = [System.IO.MemoryStream]::new()
    $zip = [System.IO.Compression.ZipArchive]::new(
        $ms, [System.IO.Compression.ZipArchiveMode]::Create, $true, [System.Text.Encoding]::UTF8)
    try {
        foreach ($e in $Entries) {
            if ($e.IsDirectory) {
                $dirName = ($e.EntryName -replace '\\', '/').TrimEnd('/') + '/'
                [void]$zip.CreateEntry($dirName, [System.IO.Compression.CompressionLevel]::NoCompression)
                continue
            }
            $entry = $zip.CreateEntry($e.EntryName, [System.IO.Compression.CompressionLevel]::NoCompression)
            $entryStream = $entry.Open()
            try {
                $fileStream = [System.IO.File]::OpenRead($e.SourcePath)
                try {
                    $fileStream.CopyTo($entryStream)
                }
                finally {
                    $fileStream.Dispose()
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
    return , $ms.ToArray()
}
