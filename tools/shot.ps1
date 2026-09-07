param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Out,
    [string[]]$ArgList = @()
)
# 启动 GUI 程序，等窗口出现，截屏保存，然后关闭。
Add-Type -AssemblyName System.Drawing
$sig = @'
using System;
using System.Runtime.InteropServices;
public static class W {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [StructLayout(LayoutKind.Sequential)] public struct R { public int Left, Top, Right, Bottom; }
}
'@
Add-Type -TypeDefinition $sig -Language CSharp

if ($ArgList.Count -gt 0) {
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -PassThru
} else {
    $p = Start-Process -FilePath $Exe -PassThru
}
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 150
    try { $p.Refresh() } catch {}
    if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $h = $p.MainWindowHandle; break }
}
if ($h -eq [IntPtr]::Zero) { Write-Host "WINDOW NOT FOUND"; exit 1 }
if ([W]::IsIconic($h)) { [W]::ShowWindow($h, 9) | Out-Null }  # SW_RESTORE
[W]::BringWindowToTop($h) | Out-Null
[W]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 900
$r = New-Object W+R
[W]::GetWindowRect($h, [ref]$r) | Out-Null
$w = $r.Right - $r.Left; $hh = $r.Bottom - $r.Top
Write-Host ("window={0} {1}x{2} at {3},{4}" -f $h, $w, $hh, $r.Left, $r.Top)
$bmp = New-Object System.Drawing.Bitmap($w, $hh)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $hh)))
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "saved $Out"
[W]::PostMessageW($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # WM_CLOSE
Start-Sleep -Milliseconds 300
exit 0
