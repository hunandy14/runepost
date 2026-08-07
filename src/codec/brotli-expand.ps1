
# ==========================================================================
# 區塊：解壓（Brotli）— 解壓方向
# ==========================================================================

function Expand-RuneBrotli {
    param([byte[]] $InputBytes)
    $inMs = [System.IO.MemoryStream]::new($InputBytes)
    $outMs = [System.IO.MemoryStream]::new()
    $brotli = [System.IO.Compression.BrotliStream]::new(
        $inMs, [System.IO.Compression.CompressionMode]::Decompress, $false)
    try {
        $brotli.CopyTo($outMs)
    }
    finally {
        $brotli.Dispose()
    }
    return , $outMs.ToArray()
}
