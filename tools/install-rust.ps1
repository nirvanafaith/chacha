$ErrorActionPreference = "Continue"
$log = "E:\chacha\tools\rustup-install.log"
function Log($m) {
    $line = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m
    Add-Content -Path $log -Value $line -Encoding UTF8
    Write-Host $line
}
New-Item -ItemType Directory -Force -Path "E:\chacha\tools" | Out-Null
Set-Content -Path $log -Value "install start" -Encoding UTF8

$env:CARGO_HOME = "E:\chacha\tools\cargo"
$env:RUSTUP_HOME = "E:\chacha\tools\rustup"
$env:PATH = "$env:CARGO_HOME\bin;$env:PATH"
$env:RUSTUP_IO_THREADS = "1"

$settings = @"
version = "12"
default_host_tuple = "x86_64-pc-windows-msvc"
profile = "minimal"

[overrides]
"@
Set-Content -Path "$env:RUSTUP_HOME\settings.toml" -Value $settings -Encoding ASCII

$rustup = Join-Path $env:CARGO_HOME "bin\rustup.exe"
if (-not (Test-Path $rustup)) {
    Log "rustup.exe missing"
    exit 1
}

Log "uninstall incomplete toolchains"
& $rustup toolchain uninstall 1.44.0-i686-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append
& $rustup toolchain uninstall 1.44.0-x86_64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append
& $rustup toolchain uninstall 1.44.0-i686-pc-windows-gnu 2>&1 | Tee-Object -FilePath $log -Append
& $rustup toolchain uninstall 1.44.0-x86_64-pc-windows-gnu 2>&1 | Tee-Object -FilePath $log -Append

Log "install 1.44.0-x86_64-pc-windows-msvc"
& $rustup toolchain install 1.44.0-x86_64-pc-windows-msvc --profile minimal -c rust-std-i686-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) {
    Log "msvc toolchain failed: $LASTEXITCODE"
}

Log "install 1.44.0-i686-pc-windows-gnu --force-non-host"
& $rustup toolchain install 1.44.0-i686-pc-windows-gnu --force-non-host --profile minimal 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) {
    Log "gnu toolchain failed: $LASTEXITCODE"
}

Log "set default x86_64 msvc 1.44.0"
& $rustup default 1.44.0-x86_64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append
& $rustup target add i686-pc-windows-msvc --toolchain 1.44.0-x86_64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $log -Append

Log "rustup show"
& $rustup show 2>&1 | Tee-Object -FilePath $log -Append
Log "rustc"
& "$env:CARGO_HOME\bin\rustc.exe" --version --verbose 2>&1 | Tee-Object -FilePath $log -Append
Log "done"
