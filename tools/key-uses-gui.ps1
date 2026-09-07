# Run only after rebuilding both native executables.
param(
    [string]$Dist = (Join-Path $PSScriptRoot '..\dist'),
    [ValidateRange(10, 120)][int]$TimeoutSeconds = 40
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Add-Type -Path (Join-Path $PSScriptRoot 'drive.cs')
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KeyUsesDrive {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out Rect r);
    [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int ht, bool repaint);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    public static int Get(IntPtr h) { return (int)SendMessageW(h, 0x147, IntPtr.Zero, IntPtr.Zero); }
    public static int Count(IntPtr h) { return (int)SendMessageW(h, 0x146, IntPtr.Zero, IntPtr.Zero); }
    public static void Select(IntPtr h, int index) { SendMessageW(h, 0x14e, (IntPtr)index, IntPtr.Zero); }
}
'@
$enc = (Resolve-Path (Join-Path $Dist 'enc\chacha-enc.exe')).Path
$dec = (Resolve-Path (Join-Path $Dist 'dec\chacha-dec.exe')).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('chacha-key-uses-' + [guid]::NewGuid().ToString('N'))
$script:ownedProcess = $null
$originalClipboard = [Windows.Forms.Clipboard]::GetDataObject()
$clipboardBefore = New-Object Windows.Forms.DataObject
if ($null -ne $originalClipboard) {
    foreach ($format in $originalClipboard.GetFormats($false)) {
        $clipboardBefore.SetData($format, $false, $originalClipboard.GetData($format, $false))
    }
}
$settings = @{}
foreach ($exe in @($enc, $dec)) {
    $path = Join-Path (Split-Path $exe) (([IO.Path]::GetFileNameWithoutExtension($exe)) + '.settings')
    $settings[$path] = if (Test-Path -LiteralPath $path) { [IO.File]::ReadAllBytes($path) } else { $null }
}
$screenshots = Join-Path $PSScriptRoot '..\target\key-usage-gui'
New-Item -ItemType Directory -Force -Path $screenshots | Out-Null
$clipboardLast = $null
$created = $false
function Check([string]$Name, [bool]$Ok) {
    if (-not $Ok) { throw "FAIL: $Name" }
    Write-Host "PASS: $Name"
}
function Wait-Until([string]$Name, [scriptblock]$Condition) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 20
    }
    throw "Timed out: $Name"
}
function Dialog {
    $d = [Drive]::WaitDialog([uint32]$script:ownedProcess.Id, $TimeoutSeconds * 1000)
    Check 'owned dialog found' ($d -ne [IntPtr]::Zero)
    return $d
}
function Dismiss([IntPtr]$Dialog, [int]$Button = 0) {
    Wait-Until 'modal button ready' { ([Drive]::Item($Dialog, 1) -ne [IntPtr]::Zero) -or ([Drive]::Item($Dialog, 2) -ne [IntPtr]::Zero) }
    if ($Button -eq 0) { $Button = if ([Drive]::Item($Dialog, 1) -ne [IntPtr]::Zero) { 1 } else { 2 } }
    [Drive]::Click($Dialog, $Button)
    Wait-Until 'modal dismissed' { -not [Drive]::DialogAlive($Dialog) }
}
function Copy-Envelope([IntPtr]$Window, [string]$Path) {
    $oldStatus = [Drive]::Text($Window, 7)
    [Drive]::Click($Window, 23)
    Wait-Until 'copy status updated' { [Drive]::Text($Window, 7) -ne $oldStatus }
    $script:clipboardLast = [Windows.Forms.Clipboard]::GetText()
    $hex = $script:clipboardLast -replace '\s', ''
    Check 'clipboard is full hex envelope, never raw key' (($hex.Length -eq 274) -and ($hex -match '\A[0-9a-fA-F]+\z'))
    [IO.File]::WriteAllText($Path, $script:clipboardLast, [Text.Encoding]::ASCII)
    $bytes = New-Object byte[] 137
    for ($i = 0; $i -lt 137; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    return ,$bytes
}
function Screenshot([IntPtr]$Window, [string]$Name) {
    $rect = New-Object KeyUsesDrive+Rect
    [KeyUsesDrive]::GetWindowRect($Window, [ref]$rect) | Out-Null
    $bitmap = New-Object Drawing.Bitmap ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $dc = $graphics.GetHdc()
    try { Check 'capture native window' ([KeyUsesDrive]::PrintWindow($Window, $dc, 0)) }
    finally { $graphics.ReleaseHdc($dc); $graphics.Dispose() }
    try { $bitmap.Save((Join-Path $screenshots $Name), [Drawing.Imaging.ImageFormat]::Png) }
    finally { $bitmap.Dispose() }
}
function Check-DecoderLastUse([string]$Package, [string]$Key, [string]$Name) {
    $exhausted = [regex]::Unescape('\u5bc6\u94a5\u6b21\u6570\u5df2\u8017\u5c3d')
    for ($open = 0; $open -lt 2; $open++) {
        $out = Join-Path $root ($Name + '-gui-' + $open)
        $script:ownedProcess = Start-Process -FilePath $dec -ArgumentList ('"{0}" --key "{1}" --out "{2}"' -f $Package, $Key, $out) -PassThru
        Wait-Until 'decoder window' { $script:ownedProcess.Refresh(); $script:ownedProcess.MainWindowHandle -ne [IntPtr]::Zero }
        $window = $script:ownedProcess.MainWindowHandle
        if ($open -eq 0) {
            Wait-Until 'last use enabled' { [Drive]::Enabled($window, 24) }
            [Drive]::Click($window, 24)
            $dialog = Dialog
            Dismiss $dialog
            Check 'last use output created' (Test-Path -LiteralPath $out)
        }
        Wait-Until 'exhausted decoder info2' { [Drive]::Text($window, 9) -eq $exhausted }
        Check ('decoder exhausted label open ' + $open) ([Drive]::Text($window, 9) -eq $exhausted)
        Check ('decoder exhausted go disabled open ' + $open) (-not [Drive]::Enabled($window, 24))
        Screenshot $window ($Name + '-decoder-exhausted-' + $open + '.png')
        [Drive]::Close($window)
        Check 'decoder closed' ($script:ownedProcess.WaitForExit(5000))
        $script:ownedProcess.Dispose()
        $script:ownedProcess = $null
    }
}
function Check-Uses([string]$Package, [string]$Key, [int]$Uses, [string]$Name) {
    for ($i = 1; $i -le ($Uses + 1); $i++) {
        if ($Name -eq 'success-saved' -and $i -eq $Uses) {
            Check-DecoderLastUse $Package $Key $Name
            continue
        }
        $out = Join-Path $root ($Name + '-out-' + $i)
        $child = Start-Process -FilePath $dec -ArgumentList ('--decrypt "{0}" --key "{1}" --out "{2}"' -f $Package, $Key, $out) -PassThru
        try {
            if (-not $child.WaitForExit($TimeoutSeconds * 1000)) { $child.Kill(); throw 'CLI decrypt timed out' }
            $child.Refresh()
            Check ($Name + ' attempt ' + $i) (($i -le $Uses -and $child.ExitCode -eq 0) -or ($i -gt $Uses -and $child.ExitCode -ne 0))
        } finally { $child.Dispose() }
    }
}
try {
    Check 'fixture path absent' (-not (Test-Path -LiteralPath $root))
    New-Item -ItemType Directory -Path $root | Out-Null
    $created = $true
    foreach ($recover in @($false, $true)) {
        $name = if ($recover) { 'recovery' } else { 'success' }
        $uses = if ($recover) { 4 } else { 2 }
        $src = Join-Path $root $name
        New-Item -ItemType Directory -Path $src | Out-Null
        $file = Join-Path $src 'fixture.bin'
        $stream = [IO.File]::Create($file)
        try { $stream.SetLength(32MB) } finally { $stream.Dispose() }
        $hash = (Get-FileHash -LiteralPath $file).Hash
        $package = $src + '.chacha'
        $key = $src + '.chacha.key'
        $script:ownedProcess = Start-Process -FilePath $enc -ArgumentList ('"{0}"' -f $src) -PassThru
        Wait-Until 'main window' { $script:ownedProcess.Refresh(); $script:ownedProcess.MainWindowHandle -ne [IntPtr]::Zero }
        $h = $script:ownedProcess.MainWindowHandle
        Wait-Until 'prefill ready' { [Drive]::Enabled($h, 25) -and [Drive]::Text($h, 13) -eq $key }
        $combo = [Drive]::Item($h, 34)
        Check 'dropdown exists and is enabled' (($combo -ne [IntPtr]::Zero) -and [Drive]::Enabled($h, 34))
        Check 'dropdown has seven values and defaults to one' (([KeyUsesDrive]::Count($combo) -eq 7) -and ([KeyUsesDrive]::Get($combo) -eq 0))
        [KeyUsesDrive]::Select($combo, $uses - 1)
        Check 'dropdown selection readable' ([KeyUsesDrive]::Get($combo) -eq ($uses - 1))
        if (-not $recover) {
            Screenshot $h 'encoder-normal.png'
            [KeyUsesDrive]::MoveWindow($h, 60, 60, 560, 580, $true) | Out-Null
            Screenshot $h 'encoder-minimum.png'
            [KeyUsesDrive]::MoveWindow($h, 60, 60, 680, 640, $true) | Out-Null
        }
        if ($recover) { [IO.File]::WriteAllText($key, 'owned collision sentinel') }
        [Drive]::Click($h, 25)
        Wait-Until 'busy controls' { [Drive]::Visible($h, 26) }
        Check 'dropdown disabled while busy' (-not [Drive]::Enabled($h, 34))
        $d = Dialog
        Dismiss $d
        $before = $null
        if ($recover) {
            Check 'dropdown disabled while unsaved' (-not [Drive]::Enabled($h, 34))
            Check 'unsaved blocks next operation' (-not [Drive]::Enabled($h, 25))
            Check 'collision never overwritten' ([IO.File]::ReadAllText($key) -eq 'owned collision sentinel')
            # Even a programmatic selection change must not alter issued metadata.
            [KeyUsesDrive]::Select($combo, 6)
            $before = Join-Path $root 'unsaved-copy.key'
            $beforeBytes = Copy-Envelope $h $before
            [Drive]::Close($h)
            $d = Dialog
            Dismiss $d 2
            Check 'reject unsaved close keeps application alive' (-not $script:ownedProcess.HasExited)
            Remove-Item -LiteralPath $key
            [Drive]::Click($h, 24)
            $d = Dialog
            Wait-Until 'save file field' { ([Drive]::Item($d, 1148) -ne [IntPtr]::Zero) -or ([Drive]::Item($d, 1152) -ne [IntPtr]::Zero) }
            Check 'set recovery filename' ([Drive]::SetSaveFileName($d, $key))
            Dismiss $d 1
            $d = Dialog
            Dismiss $d
        }
        Check 'dropdown enabled after save' ([Drive]::Enabled($h, 34))
        Check 'saved envelope exists' ((Test-Path -LiteralPath $key) -and ((Get-Item -LiteralPath $key).Length -eq 137))
        [KeyUsesDrive]::Select($combo, 6)
        Check 'next key selection changed to seven before copy' ([KeyUsesDrive]::Get($combo) -eq 6)
        $copy = Join-Path $root ($name + '-copy.key')
        $copyBytes = Copy-Envelope $h $copy
        $savedBytes = [IO.File]::ReadAllBytes($key)
        Check 'copy retains envelope header, package ID and creation timestamp' ([Convert]::ToBase64String($copyBytes[0..31]) -eq [Convert]::ToBase64String($savedBytes[0..31]))
        if ($recover) { Check 'unsaved copy retains same package identity' ([Convert]::ToBase64String($beforeBytes[0..31]) -eq [Convert]::ToBase64String($savedBytes[0..31])) }
        [Drive]::Close($h)
        Check 'saved-key close exits without prompt' ($script:ownedProcess.WaitForExit(5000))
        $script:ownedProcess.Dispose()
        $script:ownedProcess = $null
        Check-Uses $package $key $uses ($name + '-saved')
        Check-Uses $package $copy $uses ($name + '-copied')
        if ($recover) { Check-Uses $package $before $uses 'recovery-unsaved-copy' }
        Check 'source unchanged' ((Get-FileHash -LiteralPath $file).Hash -eq $hash)
    }
    Write-Host 'PASS: all native key-use GUI regressions'
} finally {
    if ($null -ne $script:ownedProcess) {
        $script:ownedProcess.Refresh()
        if (-not $script:ownedProcess.HasExited) { $script:ownedProcess.Kill(); $script:ownedProcess.WaitForExit(5000) | Out-Null }
        $script:ownedProcess.Dispose()
    }
    foreach ($path in $settings.Keys) {
        if ($null -ne $settings[$path]) { [IO.File]::WriteAllBytes($path, $settings[$path]) }
        elseif (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    # Do not overwrite a clipboard change made by the user during this test.
    if ($null -ne $clipboardLast -and [Windows.Forms.Clipboard]::GetText() -eq $clipboardLast) {
        if ($null -ne $clipboardBefore) { [Windows.Forms.Clipboard]::SetDataObject($clipboardBefore, $true) } else { [Windows.Forms.Clipboard]::Clear() }
    }
    if ($created) { Remove-Item -LiteralPath $root -Recurse -Force }
}
