# Verify preserved implementation files without compiling or opening hardware.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$manifest = Get-Content -LiteralPath (Join-Path $repoRoot 'MANIFEST-WINDOWS-SOURCE.json') -Raw | ConvertFrom-Json
$failures = @()
foreach ($entry in $manifest.files) {
    $sourcePath = [IO.Path]::GetFullPath((Join-Path $repoRoot $entry.path))
    if (-not $sourcePath.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest path escapes the repository: $($entry.path)"
    }
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        $failures += "Missing: $($entry.path)"
        continue
    }
    $actual = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.sha256 -or (Get-Item -LiteralPath $sourcePath).Length -ne $entry.bytes) {
        $failures += "Changed: $($entry.path)"
    }
}
if ($failures.Count -gt 0) {
    $failures | Write-Output
    throw "$($failures.Count) preserved source file(s) failed verification."
}
Write-Output "Verified $($manifest.files.Count) Windows implementation files against the 0.4.0 source manifest."
