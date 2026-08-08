# ==========================================================================
# 區塊：壓縮（Brotli）— 壓縮方向
# ==========================================================================

function Compress-RuneBrotli {
    param([byte[]] $InputBytes)
    $outMs = [System.IO.MemoryStream]::new()
    $brotli = [System.IO.Compression.BrotliStream]::new(
        $outMs, [System.IO.Compression.CompressionLevel]::SmallestSize, $true)
    try {
        $brotli.Write($InputBytes, 0, $InputBytes.Length)
    }
    finally {
        $brotli.Dispose()
    }
    return , $outMs.ToArray()
}
