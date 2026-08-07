
function Get-RuneKeyFingerprint {
    <#
        公鑰指紋：SHA-256( SubjectPublicKeyInfo DER ) 取前 16 bytes（128 bits），
        大寫 hex 每 4 字元一組、以 '-' 連接，共 8 組 39 個字元。

        輸入取 SPKI DER 而非 PEM 文字，因為 DER 是正規、唯一的序列化（PEM 會因換行、
        尾隨空白、標頭大小寫而變動），而且 DER 內含曲線 OID，指紋因此天生跨曲線域分離。
        使用者也可以不信任本腳本，改用標準工具獨立驗證得到相同摘要：
            openssl pkey -pubin -in public.pem -outform DER | openssl dgst -sha256
        取 16 bytes 而非更短：指紋是公鑰替換攻擊的唯一防線，32 bits 可在筆電上分鐘級
        磨出碰撞，64 bits 昂貴但非不可及，128 bits 則永久出局。
    #>
    param([byte[]] $SpkiDer)
    $digest = [System.Security.Cryptography.SHA256]::HashData($SpkiDer)
    $hex = [Convert]::ToHexString($digest, 0, 16)
    $groups = for ($i = 0; $i -lt $hex.Length; $i += 4) { $hex.Substring($i, 4) }
    return ($groups -join '-')
}
