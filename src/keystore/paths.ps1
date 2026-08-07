$Script:DefaultKeyDir = Join-Path -Path $HOME -ChildPath '.rune'
$Script:DefaultKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'private.key'
$Script:DefaultPublicKeyFile = Join-Path -Path $Script:DefaultKeyDir -ChildPath 'public.pem'
$Script:P256CurveOid = '1.2.840.10045.3.1.7'
