# ==========================================================================
# 區塊：打包（ZIP / store，UTF-8 檔名）
# ==========================================================================

function Get-RunePackPlan {
    <#
        依 -Pack 參數判斷輸入型態（單檔 / wildcard / 資料夾），
        回傳要打包的項目清單，以及推導輸出檔名用的基底名稱。
    #>
    param([string] $PackPath)

    if ($PackPath -match '[*?]') {
        # --- wildcard：Get-Item 展開，僅當層不遞迴。wildcard 命中的子目錄一律
        #     略過並警告（不遞迴打包目錄），不再靜默把目錄當空 entry 塞進封存包。
        $items = @(Get-Item -Path $PackPath -ErrorAction SilentlyContinue)
        if ($items.Count -eq 0) {
            throw "找不到符合萬用字元的項目：$PackPath"
        }
        $parent = Split-Path -Path $PackPath -Parent
        if ([string]::IsNullOrEmpty($parent)) {
            $parent = (Get-Location).Path
        }
        else {
            $parent = (Resolve-Path -LiteralPath $parent).Path
        }
        $fileItems = @(foreach ($item in $items) {
            if ($item.PSIsContainer) {
                Write-Warning "wildcard 不遞迴，已略過目錄：$($item.Name)"
                continue
            }
            $item
        })
        if ($fileItems.Count -eq 0) {
            throw "找不到符合萬用字元的項目：$PackPath（僅匹配到目錄，wildcard 不遞迴打包目錄）"
        }
        $entries = foreach ($item in $fileItems) {
            [pscustomobject]@{
                EntryName   = $item.Name
                SourcePath  = $item.FullName
                IsDirectory = $false
            }
        }
        return [pscustomobject]@{
            Entries         = @($entries)
            DefaultBaseName = (Split-Path -Path $parent -Leaf)
        }
    }
    elseif (Test-Path -LiteralPath $PackPath -PathType Container) {
        # --- 資料夾：遞迴整包，保留子目錄結構（含空子目錄） ---
        $root = (Get-Item -LiteralPath $PackPath).FullName.TrimEnd('\', '/')
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)
        $allDirs = @(Get-ChildItem -LiteralPath $root -Recurse -Directory -Force)
        if ($files.Count -eq 0 -and $allDirs.Count -eq 0) {
            throw "資料夾內沒有可打包的檔案：$PackPath"
        }
        $fileEntries = foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
            [pscustomobject]@{
                EntryName   = $rel
                SourcePath  = $f.FullName
                IsDirectory = $false
            }
        }
        # 空子目錄（本身及遞迴子孫都不含任何檔案）額外列舉成目錄 entry，
        # 讓 -Unpack 端可以還原出空的目錄結構，而不是被靜默丟棄。
        $emptyDirEntries = foreach ($d in $allDirs) {
            $hasAnyFile = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Force).Count -gt 0
            if (-not $hasAnyFile) {
                $rel = $d.FullName.Substring($root.Length + 1) -replace '\\', '/'
                [pscustomobject]@{
                    EntryName   = $rel
                    SourcePath  = $null
                    IsDirectory = $true
                }
            }
        }
        return [pscustomobject]@{
            Entries         = @($fileEntries) + @($emptyDirEntries)
            DefaultBaseName = (Split-Path -Path $root -Leaf)
        }
    }
    elseif (Test-Path -LiteralPath $PackPath -PathType Leaf) {
        # --- 單檔 ---
        $file = Get-Item -LiteralPath $PackPath
        return [pscustomobject]@{
            Entries         = @([pscustomobject]@{
                EntryName   = $file.Name
                SourcePath  = $file.FullName
                IsDirectory = $false
            })
            DefaultBaseName = $file.Name
        }
    }
    else {
        throw "找不到指定的路徑：$PackPath"
    }
}
