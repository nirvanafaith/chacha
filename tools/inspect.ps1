param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string[]]$ArgList = @()
)
# Launch a GUI exe, dump its control tree (geometry / enabled / items / progress),
# flag out-of-bounds, degenerate and overlapping rectangles, then close it.
# The actual inspection code lives in inspect.cs.
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -Path (Join-Path $PSScriptRoot "inspect.cs")
Add-Type -Path (Join-Path $PSScriptRoot "drive.cs")

$launch = @{ FilePath = $Exe; PassThru = $true }
if ($ArgList.Count -gt 0) { $launch.ArgumentList = $ArgList }
$p = Start-Process @launch
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Milliseconds 150
    try { $p.Refresh() } catch { break }
    if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $h = $p.MainWindowHandle; break }
}
if ($h -eq [IntPtr]::Zero) {
    Write-Host "no main window appeared for $Exe"
    exit 1
}
Start-Sleep -Milliseconds 800
$report = [Inspect]::Dump($h)
Write-Host $report
$failed = $report.Contains('PROBLEM')
[Drive]::Close($h)
Start-Sleep -Milliseconds 300
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
if ($failed) { exit 1 }
exit 0
