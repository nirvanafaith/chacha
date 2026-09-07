# 构建两个程序（加密端 / 解密端），32 位，XP SP3 ~ Win11。
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:CARGO_HOME = Join-Path $Root "tools\cargo"
$env:RUSTUP_HOME = Join-Path $Root "tools\rustup"
$gnu = Join-Path $env:RUSTUP_HOME "toolchains\1.44.0-i686-pc-windows-gnu"
$mingwBin = Join-Path $gnu "lib\rustlib\i686-pc-windows-gnu\bin"
$env:PATH = "$(Join-Path $env:CARGO_HOME 'bin');$(Join-Path $gnu 'bin');$mingwBin;$env:PATH"
$env:RUSTUP_TOOLCHAIN = "1.44.0-i686-pc-windows-gnu"

Set-Location $Root
Write-Host "rustc: $(rustc --version)"
cargo build --release --target i686-pc-windows-gnu
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$rel = Join-Path $Root "target\i686-pc-windows-gnu\release"
foreach ($pair in @(@("chacha-enc", "enc"), @("chacha-dec", "dec"))) {
    $bin = $pair[0]
    $sub = $pair[1]
    $outDir = Join-Path $Root "dist\$sub"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Copy-Item (Join-Path $rel "$bin.exe") (Join-Path $outDir "$bin.exe") -Force
    Copy-Item (Join-Path $Root "app.manifest") (Join-Path $outDir "$bin.exe.manifest") -Force
    Write-Host "OK  dist\$sub\$bin.exe"
}
