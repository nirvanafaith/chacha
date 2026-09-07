# Regression: a key-save collision must never be reported as encryption success.
# Run against the rebuilt GUI on an interactive Windows desktop.
param(
    [string]$Exe = (Join-Path $PSScriptRoot '..\dist\enc\chacha-enc.exe'),
    [ValidateRange(5, 60)][int]$TimeoutSeconds = 20,
    [switch]$AcceptUnsavedClose
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (-not ('Drive' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'drive.cs')
}
$Exe = (Resolve-Path -LiteralPath $Exe).Path

# Keep this script ASCII-compatible with Windows PowerShell 5.1.
function U([string]$Text) { return [regex]::Unescape($Text) }
$saveFailure = U '\u5bc6\u94a5\u4fdd\u5b58\u5931\u8d25'
$unsaved = U '\u5bc6\u94a5\u672a\u4fdd\u5b58'
$closeWarning = U '\u5bc6\u94a5\u5c1a\u672a\u4fdd\u5b58'
$saveAs = U '\u53e6\u5b58\u5bc6\u94a5'
$saved = U '\u5bc6\u94a5\u5df2\u4fdd\u5b58'
$complete = U '\u5b8c\u6210'
$encryptComplete = U '\u52a0\u5bc6\u5b8c\u6210'

function Assert-Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if (-not $Ok) { throw "FAIL: $Name. $Detail" }
    Write-Host ("PASS: {0} {1}" -f $Name, $Detail)
}

function Wait-Until([string]$Name, [scriptblock]$Condition) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) { return }
        if ($null -ne $script:ownedProcess) {
            $script:ownedProcess.Refresh()
            if ($script:ownedProcess.HasExited) { throw "Process exited while waiting for $Name" }
        }
        Start-Sleep -Milliseconds 60
    }
    throw "Timed out waiting for $Name after $TimeoutSeconds seconds"
}

function Wait-OwnedDialog([string]$Name) {
    $dialog = [Drive]::WaitDialog([uint32]$script:ownedProcess.Id, $TimeoutSeconds * 1000)
    Assert-Check $Name ($dialog -ne [IntPtr]::Zero)
    return $dialog
}

function Dismiss-Dialog([IntPtr]$Dialog, [ValidateSet('Acknowledge', 'Accept', 'Reject')][string]$Action) {
    $button = if ($Action -eq 'Reject') { 2 } else { 1 }
    Wait-Until 'dialog button creation' {
        ([Drive]::Item($Dialog, $button) -ne [IntPtr]::Zero) -or
        (($Action -eq 'Acknowledge') -and ([Drive]::Item($Dialog, 2) -ne [IntPtr]::Zero))
    }
    # MB_OK can expose its sole OK button as IDCANCEL. Never apply that fallback to Accept.
    if (($Action -eq 'Acknowledge') -and ([Drive]::Item($Dialog, 1) -eq [IntPtr]::Zero)) { $button = 2 }
    [Drive]::Focus($Dialog)
    [Drive]::Click($Dialog, $button)
    Wait-Until 'dialog dismissal' { -not [Drive]::DialogAlive($Dialog) }
}

function Assert-UnsavedState([IntPtr]$Window) {
    Assert-Check 'new encryption disabled' (-not [Drive]::Enabled($Window, 25))
    Assert-Check 'source selection disabled' (-not [Drive]::Enabled($Window, 21))
    Assert-Check 'destination selection disabled' (-not [Drive]::Enabled($Window, 22))
    Assert-Check 'copy key enabled' ([Drive]::Enabled($Window, 23))
    Assert-Check 'save key enabled' ([Drive]::Enabled($Window, 24))
    Assert-Check 'save key action label' ([Drive]::Text($Window, 24) -eq $saveAs)
    Assert-Check 'cancel operation hidden' (-not [Drive]::Visible($Window, 26))
    $status = [Drive]::Text($Window, 7)
    Assert-Check 'unsaved status retained' ($status.Contains($unsaved)) $status
    Assert-Check 'no success status' (-not $status.StartsWith($complete)) $status
}

$ownedRoot = Join-Path ([IO.Path]::GetTempPath()) ('chacha-key-save-gui-' + [guid]::NewGuid().ToString('N'))
$ownedRootCreated = $false
$script:ownedProcess = $null
$exitCode = 1
try {
    # Never reuse or delete a preexisting fixture directory.
    Assert-Check 'unique fixture path' (-not (Test-Path -LiteralPath $ownedRoot))
    New-Item -ItemType Directory -Path $ownedRoot | Out-Null
    $ownedRootCreated = $true
    $source = Join-Path $ownedRoot 'source'
    New-Item -ItemType Directory -Path $source | Out-Null
    $sourceFile = Join-Path $source 'fixture.txt'
    $fixture = 'key-save GUI regression fixture'
    [IO.File]::WriteAllText($sourceFile, $fixture, [Text.Encoding]::ASCII)
    $sourceHash = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash
    $packagePath = Join-Path $ownedRoot 'source.chacha'
    $keyPath = Join-Path $ownedRoot 'source.chacha.key'

    # Quote the single positional argument, including temporary paths with spaces.
    $script:ownedProcess = Start-Process -FilePath $Exe -ArgumentList ('"{0}"' -f $source) -PassThru
    Wait-Until 'prefilled main window' {
        $script:ownedProcess.Refresh()
        $script:ownedProcess.MainWindowHandle -ne [IntPtr]::Zero
    }
    $window = $script:ownedProcess.MainWindowHandle
    Wait-Until 'prefill and source scan' {
        ([Drive]::Text($window, 13) -eq $keyPath) -and [Drive]::Enabled($window, 25)
    }
    Assert-Check 'predicted package path' ([Drive]::Text($window, 12) -eq $packagePath)
    Assert-Check 'fixture listed' ([Drive]::ListItems($window, 31) -eq 1)
    Assert-Check 'stale copy action disabled' (-not [Drive]::Enabled($window, 23))
    Assert-Check 'stale open action disabled' (-not [Drive]::Enabled($window, 24))
    Assert-Check 'predicted key initially absent' (-not (Test-Path -LiteralPath $keyPath))

    # Inject only AFTER suggest_names has run and BEFORE the worker starts.
    $sentinel = 'owned-key-path-collision-sentinel'
    $stream = [IO.File]::Open($keyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes($sentinel)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }
    Assert-Check 'prefill unchanged after collision' ([Drive]::Text($window, 13) -eq $keyPath)
    [Drive]::Click($window, 25)
    $dialog = Wait-OwnedDialog 'key-save failure dialog'
    $message = [Drive]::DialogText($dialog)
    Assert-Check 'failure rather than success modal' ($message.StartsWith($saveFailure) -and -not $message.StartsWith($encryptComplete)) $message
    Assert-Check 'failure body identifies colliding key path' ($message.Contains($keyPath))
    Assert-Check 'package exists despite key-save failure' (Test-Path -LiteralPath (Join-Path $packagePath 'package.chx') -PathType Leaf)
    Assert-Check 'existing key path was not overwritten' ([IO.File]::ReadAllText($keyPath) -eq $sentinel)
    Dismiss-Dialog $dialog Acknowledge
    Assert-UnsavedState $window

    [Drive]::Close($window)
    $dialog = Wait-OwnedDialog 'unsaved close warning'
    $message = [Drive]::DialogText($dialog)
    Assert-Check 'close warns of unsaved key' ($message.StartsWith($closeWarning)) $message
    Dismiss-Dialog $dialog Reject
    $script:ownedProcess.Refresh()
    Assert-Check 'rejecting close keeps app alive' (-not $script:ownedProcess.HasExited)
    Assert-UnsavedState $window

    if ($AcceptUnsavedClose) {
        [Drive]::Close($window)
        $dialog = Wait-OwnedDialog 'second unsaved close warning'
        Assert-Check 'accept targets unsaved warning' ([Drive]::DialogText($dialog).StartsWith($closeWarning))
        Dismiss-Dialog $dialog Accept
        Assert-Check 'accepting unsaved close exits app' ($script:ownedProcess.WaitForExit(5000))
        Assert-Check 'accepting close preserves blocker' ([IO.File]::ReadAllText($keyPath) -eq $sentinel)
        Assert-Check 'accepting close preserves source' ((Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash -eq $sourceHash)
        $exitCode = 0
    } else {
        # Use an explicit owned path: common dialogs can restore another initial directory.
        # Removing our sentinel makes that filename safe to accept without overwrite prompts.
        Assert-Check 'blocker still owned before removal' ([IO.File]::ReadAllText($keyPath) -eq $sentinel)
        Remove-Item -LiteralPath $keyPath -Force
        [Drive]::Click($window, 24)
        $dialog = Wait-OwnedDialog 'save-key retry dialog'
        Assert-Check 'save dialog caption' ([Drive]::DialogText($dialog).StartsWith($saveAs)) ([Drive]::DialogText($dialog))
        Wait-Until 'save filename field' {
            ([Drive]::Item($dialog, 1148) -ne [IntPtr]::Zero) -or ([Drive]::Item($dialog, 1152) -ne [IntPtr]::Zero)
        }
        Assert-Check 'set exact owned recovery path' ([Drive]::SetSaveFileName($dialog, $keyPath))
        Dismiss-Dialog $dialog Accept
        $dialog = Wait-OwnedDialog 'key recovery confirmation'
        $message = [Drive]::DialogText($dialog)
        Assert-Check 'recovery reports saved key' ($message.StartsWith($saved)) $message
        Assert-Check 'recovery message contains requested path' ($message.Contains($keyPath))
        Assert-Check 'recovered key exists at requested path' (Test-Path -LiteralPath $keyPath -PathType Leaf)
        Assert-Check 'recovered binary key length' ((Get-Item -LiteralPath $keyPath).Length -eq 68)
        Dismiss-Dialog $dialog Acknowledge
        Assert-Check 'new encryption restored after recovery' ([Drive]::Enabled($window, 25))
        Assert-Check 'source selection restored after recovery' ([Drive]::Enabled($window, 21))
        Assert-Check 'destination selection restored after recovery' ([Drive]::Enabled($window, 22))
        Assert-Check 'copy remains available after recovery' ([Drive]::Enabled($window, 23))
        Assert-Check 'save action reverted after recovery' ([Drive]::Text($window, 24) -ne $saveAs)
        Assert-Check 'success only after recovery' ([Drive]::Text($window, 7).StartsWith($complete))
        Assert-Check 'source bytes untouched' ((Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash -eq $sourceHash)
        [Drive]::Close($window)
        Assert-Check 'saved-key close needs no warning' ($script:ownedProcess.WaitForExit(5000))
        $exitCode = 0
    }
} catch {
    Write-Host ("FAIL: {0}" -f $_.Exception.Message)
} finally {
    # Only touch the exact process object and GUID fixture created by this run.
    $processStopped = $true
    if ($null -ne $script:ownedProcess) {
        try {
            $script:ownedProcess.Refresh()
            if (-not $script:ownedProcess.HasExited) {
                $script:ownedProcess.Kill()
                $processStopped = $script:ownedProcess.WaitForExit(5000)
            }
        } catch {
            $processStopped = $false
            Write-Host ("FAIL: owned process cleanup: {0}" -f $_.Exception.Message)
        }
        $script:ownedProcess.Dispose()
    }
    if (-not $processStopped) {
        $exitCode = 1
        Write-Host "Retained owned fixture because process termination was not confirmed: $ownedRoot"
    } elseif ($ownedRootCreated) {
        try {
            Remove-Item -LiteralPath $ownedRoot -Recurse -Force
        } catch {
            $exitCode = 1
            Write-Host ("FAIL: fixture cleanup {0}: {1}" -f $ownedRoot, $_.Exception.Message)
        }
    }
}
exit $exitCode
