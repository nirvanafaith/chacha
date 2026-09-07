$ErrorActionPreference = "Continue"
$log = "E:\chacha\tools\dist-install.log"
function Log($m) { $l = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss"), $m; Add-Content $log $l -Encoding UTF8; Write-Host $l }
Log "start dist install"
$ Progressive = $true
$dest = "E:\chacha\tools\dist"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$files = @(
  @{ n = "rust-1.44.0-x86_64-pc-windows-msvc.tar.gz"; u = "https://static.rust-lang.org/dist/2020-06-04/rust-1.44.0-x86_64-pc-windows-msvc.tar.gz" },
  @{ n = "rust-std-1.44.0-i686-pc-windows-msvc.tar.gz"; u = "https://static.rust-lang.org/dist/2020-06-04/rust-std-1.44.0-i686-pc-windows-msvc.tar.gz" }
)
foreach ($f in $files) {
  $out = Join-Path $dest $f.n
  if ((Test-Path $out) -and ((Get-Item $out).Length -gt 1000000)) { Log "already have $($f.n) size=$((Get-Item $out).Length)"; continue }
  Log "download $($f.u)"
  try {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($f.u, $out)
    Log "downloaded $($f.n) size=$((Get-Item $out).Length)"
  } catch {
    Log "download failed $($f.n): $_"
  }
}
Log "extract rust host"
$rustRoot = "E:\chacha\tools\rust-1.44"
New-Item -ItemType Directory -Force -Path $rustRoot | Out-Null
$gz1 = Join-Path $dest "rust-1.44.0-x86_64-pc-windows-msvc.tar.gz"
$gz2 = Join-Path $dest "rust-std-1.44.0-i686-pc-windows-msvc.tar.gz"
if (Test-Path $gz1) {
  Log "tar xf host"
  & tar -xf $gz1 -C $dest
  Log "tar host exit $LASTEXITCODE"
}
if (Test-Path $gz2) {
  Log "tar xf i686 std"
  & tar -xf $gz2 -C $dest
  Log "tar std exit $LASTEXITCODE"
}
Log "list dist"
Get-ChildItem $dest -Directory | ForEach-Object { Log $_.FullName }
# install.bat style copy: the tarball contains rust-1.44.0-x86_64-pc-windows-msvc/rustc, cargo, rust-std
$hostDir = Join-Path $dest "rust-1.44.0-x86_64-pc-windows-msvc"
$stdDir = Join-Path $dest "rust-std-1.44.0-i686-pc-windows-msvc"
if (Test-Path "$hostDir\install.sh") { Log "found host install.sh" }
if (Test-Path $hostDir) { Get-ChildItem $hostDir | ForEach-Object { Log ("host " + $_.Name) } }
if (Test-Path $stdDir) { Get-ChildItem $stdDir | ForEach-Object { Log ("std " + $_.Name) } }
Log "finished stage1"
