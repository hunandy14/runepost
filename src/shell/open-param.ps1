[CmdletBinding(DefaultParameterSetName = 'Unpack')]
param(
    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Unpack,

    [Parameter(ParameterSetName = 'Unpack', Mandatory = $true)]
    [string] $Destination,

    [Parameter(ParameterSetName = 'Unpack')]
    [Parameter(ParameterSetName = 'ExportPublicKey')]
    [string] $KeyFile,

    [Parameter(ParameterSetName = 'GenerateKeys', Mandatory = $true)]
    [switch] $GenerateKeys,

    [Parameter(ParameterSetName = 'ExportPublicKey', Mandatory = $true)]
    [switch] $ExportPublicKey
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
