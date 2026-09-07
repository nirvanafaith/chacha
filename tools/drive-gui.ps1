# GUI end-to-end acceptance for both apps.
# Run after: cargo build --release --target i686-pc-windows-gnu  (and copying to dist\)
$ErrorActionPreference = "Continue"
Add-Type -Path "E:\chacha\tools\drive.cs"
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$G = "E:\chacha\dist\gui"
$testDist = if ($env:CHACHA_TEST_DIST) { $env:CHACHA_TEST_DIST } else { "E:\chacha\dist" }
$ENC = Join-Path $testDist "enc\chacha-enc.exe"
$DEC = Join-Path $testDist "dec\chacha-dec.exe"
$results = @()

function Check($name, $ok, $detail) {
    $script:results += [pscustomobject]@{ Item = $name; Res = $(if ($ok) { "PASS" } else { "FAIL" }); Info = $detail }
    Write-Host ("[{0}] {1}  {2}" -f $(if ($ok) { "PASS" } else { "FAIL" }), $name, $detail)
}
function Wait-Hwnd($p) {
    for ($i = 0; $i -lt 80; $i++) {
        Start-Sleep -Milliseconds 150
        try { $p.Refresh() } catch { return [IntPtr]::Zero }
        if ($p.MainWindowHandle -ne [IntPtr]::Zero) { return $p.MainWindowHandle }
    }
    return [IntPtr]::Zero
}
function Run-Until-Done($h, $maxSec) {
    $poss = @(); $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $maxSec) {
        $pos = [Drive]::Pos($h, 32)
        if ($pos -lt 0) { break }
        if ($poss.Count -eq 0 -or $poss[-1] -ne $pos) { $poss += $pos }
        if ($pos -ge 1000) { break }
        Start-Sleep -Milliseconds 15
    }
    return ,$poss
}

# ---------- fixture ----------
# Do not close unrelated user application processes.
# $G is an isolated test directory; remove only this script-owned fixture.
Remove-Item $G -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "$G\BIG\子目录" | Out-Null
for ($i = 1; $i -le 6; $i++) {
    $fs = [IO.File]::Create("$G\BIG\大文件$i.bin"); $buf = New-Object byte[] 1048576
    (New-Object Random $i).NextBytes($buf)
    for ($k = 0; $k -lt 50; $k++) { $fs.Write($buf, 0, $buf.Length) }
    $fs.Close()
}
[IO.File]::WriteAllBytes("$G\BIG\子目录\空.bin", [byte[]](1..100))
[IO.File]::WriteAllBytes("$G\BIG\子目录\名字 (带括号).dat", [byte[]](9..0))
Set-Content "$G\BIG\说明.txt" "GUI 端到端" -Encoding UTF8
$srcFiles = @(Get-ChildItem "$G\BIG" -Recurse -File)
Write-Host ("fixture: {0} files / {1:N0} MB`n" -f $srcFiles.Count, (($srcFiles | Measure-Object Length -Sum).Sum / 1MB))

# ---------- A. encrypt ----------
Write-Host "===== A. encrypt GUI ====="
$p = Start-Process $ENC -ArgumentList "$G\BIG" -PassThru
$h = Wait-Hwnd $p
Check "A1 window" ($h -ne [IntPtr]::Zero) "hwnd=$h"
Check "A2 go enabled" ([Drive]::Enabled($h, 25)) "status=$([Drive]::Text($h,7))"
Check "A3 list filled" ([Drive]::ListItems($h, 31) -eq ($srcFiles.Count + 1)) "$([Drive]::ListItems($h,31)) rows (files + dir)"
[Drive]::Click($h, 25)
Start-Sleep -Milliseconds 60
Check "A4 busy: cancel shown" ([Drive]::Visible($h, 26)) ""
Check "A5 busy: src browse locked" (-not [Drive]::Enabled($h, 21)) ""
$poss = Run-Until-Done $h 120
$mono = $true
for ($i = 1; $i -lt $poss.Count; $i++) { if ($poss[$i] -lt $poss[$i - 1]) { $mono = $false } }
Check "A6 progress bar moves" ($poss.Count -ge 4 -and $mono -and $poss[-1] -eq 1000) "$($poss.Count) steps $($poss[0])->$($poss[-1])"
$dlg = [Drive]::WaitDialog($p.Id, 30000)
Check "A7 done dialog" ($dlg -ne [IntPtr]::Zero) ([Drive]::DialogText($dlg))
[Drive]::DialogOk($dlg); Start-Sleep -Milliseconds 700
Check "A8 dialog dismissed" (-not [Drive]::DialogAlive($dlg)) ""
Check "A9 controls restored" (([Drive]::Enabled($h, 25)) -and (-not [Drive]::Visible($h, 26))) "status=$([Drive]::Text($h,7))"
Check "A10 key actions live" (([Drive]::Enabled($h, 23)) -and ([Drive]::Enabled($h, 24))) ""
[Drive]::Close($h); Start-Sleep -Milliseconds 400
Check "A11 package created" (Test-Path "$G\BIG.chacha\package.chx") ""
Check "A12 blobs complete" ((@(Get-ChildItem "$G\BIG.chacha\blobs").Count) -eq $srcFiles.Count) "$((@(Get-ChildItem "$G\BIG.chacha\blobs")).Count) blobs"
Check "A13 key file 68 bytes" ((Get-Item "$G\BIG.chacha.key").Length -eq 68) "$((Get-Item "$G\BIG.chacha.key").Length) bytes"
Check "A14 source untouched" ((@(Get-ChildItem "$G\BIG" -Recurse -File).Count) -eq $srcFiles.Count) ""

# ---------- B. cancel ----------
Write-Host "`n===== B. cancel cleanup ====="
$p = Start-Process $ENC -ArgumentList "$G\BIG" -PassThru
$h = Wait-Hwnd $p
[Drive]::Click($h, 25)
Start-Sleep -Milliseconds 300
$at = [Drive]::Pos($h, 32)
[Drive]::Click($h, 26)
$dlg = [Drive]::WaitDialog($p.Id, 30000)
Check "B1 cancel dialog" (($dlg -ne [IntPtr]::Zero) -and ([Drive]::DialogText($dlg) -like '*已取消*')) ([Drive]::DialogText($dlg))
[Drive]::DialogOk($dlg); Start-Sleep -Milliseconds 700
Check "B2 go re-enabled" ([Drive]::Enabled($h, 25)) "cancelled at $at per-mille"
[Drive]::Close($h); Start-Sleep -Milliseconds 500
$left = @(Get-ChildItem $G | Where-Object { $_.Name -like "BIG (2)*" })
Check "B3 no half-written package" ($left.Count -eq 0) "leftover: $($left.Name -join ', ')"
Check "B4 no stray key file" (@(Get-ChildItem $G -Filter "*.key").Count -eq 1) "$(@(Get-ChildItem $G -Filter '*.key').Count) key files"

# ---------- C. decrypt ----------
Write-Host "`n===== C. decrypt GUI ====="
$out = "$G\out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$preview = Start-Process $DEC -ArgumentList "$G\BIG.chacha" -PassThru
$previewH = Wait-Hwnd $preview
Check "C0 names without any key" (([Drive]::ListItems($previewH,31) -eq ($srcFiles.Count + 1)) -and (-not [Drive]::Enabled($previewH,24))) "preview only"
[Drive]::Close($previewH)
$preview.WaitForExit(5000) | Out-Null
$p = Start-Process $DEC -ArgumentList "$G\BIG.chacha", "--key", "$G\BIG.chacha.key", "--out", $out -PassThru
$h = Wait-Hwnd $p
Check "C1 window" ($h -ne [IntPtr]::Zero) "hwnd=$h"
Check "C2 names listed without key" ([Drive]::ListItems($h, 31) -eq ($srcFiles.Count + 1)) "$([Drive]::ListItems($h,31)) rows"
Check "C3 key validated" ([Drive]::Text($h, 9) -like "*可以还原*") ([Drive]::Text($h, 9))
Check "C4 go enabled when ready" ([Drive]::Enabled($h, 24)) "status=$([Drive]::Text($h,7))"
[Drive]::Click($h, 24)
$poss = Run-Until-Done $h 120
Check "C5 progress bar moves" ($poss.Count -ge 3 -and $poss[-1] -eq 1000) "$($poss.Count) steps"
$dlg = [Drive]::WaitDialog($p.Id, 30000)
Check "C6 done dialog" ($dlg -ne [IntPtr]::Zero) ([Drive]::DialogText($dlg))
[Drive]::DialogOk($dlg); Start-Sleep -Milliseconds 700
Check "C7 open-result live" ([Drive]::Enabled($h, 26)) "status=$([Drive]::Text($h,7))"
[Drive]::Close($h); Start-Sleep -Milliseconds 400
$restored = "$out\BIG"
$a = @(Get-ChildItem "$G\BIG" -Recurse -File | Sort-Object FullName)
$b = @(Get-ChildItem $restored -Recurse -File | Sort-Object FullName)
$badContent = 0; $badTime = 0
for ($i = 0; $i -lt [Math]::Min($a.Count, $b.Count); $i++) {
    $ra = $a[$i].FullName.Substring("$G\BIG".Length); $rb = $b[$i].FullName.Substring($restored.Length)
    if ($ra -ne $rb) { $badContent++; break }
    if ((Get-FileHash $a[$i].FullName -Algorithm SHA256).Hash -ne (Get-FileHash $b[$i].FullName -Algorithm SHA256).Hash) { $badContent++; break }
    if ($a[$i].LastWriteTime.Ticks -ne $b[$i].LastWriteTime.Ticks) { $badTime++ }
}
Check "C8 byte-for-byte + names" (($badContent -eq 0) -and ($a.Count -eq $b.Count) -and ($a.Count -gt 0)) "$($a.Count) vs $($b.Count) files"
Check "C9 mtime exact (100ns)" ($badTime -eq 0) "$badTime differ"
$dirs = @(Get-ChildItem "$G\BIG" -Recurse -Directory | ForEach-Object { $_.FullName.Substring("$G\BIG".Length) })
$miss = @($dirs | Where-Object { -not (Test-Path ($restored + $_)) })
Check "C10 empty dirs restored" ($miss.Count -eq 0) "dirs: $($dirs -join ', ')"

# ---------- D. mismatched key / prefill edge cases ----------
Write-Host "`n===== D. wrong key ====="
New-Item -ItemType Directory -Force -Path "$G\OTHER" | Out-Null
Set-Content "$G\OTHER\x.txt" "other" -Encoding UTF8
Start-Process $ENC -ArgumentList @("--encrypt", "$G\OTHER", "--package", "$G\OTHER.chacha", "--keyout", "$G\OTHER.chacha.key") -Wait -NoNewWindow | Out-Null
$p = Start-Process $DEC -ArgumentList "$G\BIG.chacha", "--key", "$G\OTHER.chacha.key", "--out", "$G\out2" -PassThru
$h = Wait-Hwnd $p
Check "D1 mismatched key rejected" (([Drive]::Text($h, 9) -like "*不是这个加密包*" -or [Drive]::Text($h, 9) -like "*未认证*") -and (-not [Drive]::Enabled($h, 24))) ([Drive]::Text($h, 9))
[Drive]::Close($h); Start-Sleep -Milliseconds 400
$p = Start-Process $DEC -ArgumentList "$G\BIG.chacha.key" -PassThru
$h = Wait-Hwnd $p
$modal = [Drive]::WaitDialog($p.Id, 1200)
Check "D2 key-only prefill, no modal at startup" (($h -ne [IntPtr]::Zero) -and ($modal -eq [IntPtr]::Zero)) ([Drive]::Text($h, 9))
[Drive]::Close($h); Start-Sleep -Milliseconds 300

# ---------- summary ----------
Write-Host "`n===== summary ====="
$results | ForEach-Object { Write-Host ("{0}: {1}" -f $_.Res, $_.Item) }
$fail = @($results | Where-Object Res -eq "FAIL")
Write-Host ("{0} / {1} PASS" -f ($results.Count - $fail.Count), $results.Count)
if ($fail.Count) { exit 1 } else { exit 0 }
