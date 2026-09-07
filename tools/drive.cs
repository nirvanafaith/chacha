using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// 驱动 GUI：点按钮、读状态、等待并关闭模态对话框。
public static class Drive
{
    [DllImport("user32.dll")] static extern IntPtr GetDlgItem(IntPtr h, int id);
    [DllImport("user32.dll")] static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, StringBuilder text, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool BringWindowToTop(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr GetParent(IntPtr h);
    [DllImport("user32.dll")] static extern bool EnumThreadWindows(uint tid, EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    delegate bool EnumProc(IntPtr h, IntPtr l);

    const uint BM_CLICK = 0x00F5;
    const uint PBM_GETPOS = 0x0408; // WM_USER+8
    const uint WM_COMMAND = 0x0111;
    const int IDOK = 1;

    public static void Click(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        // 必须用 PostMessage：SendMessage(BM_CLICK) 会一直阻塞到按钮处理函数返回，
        // 而"浏览…"这类按钮会在里面跑一个模态对话框。
        if (h != IntPtr.Zero) PostMessageW(h, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    }

    /// 直接暴露子句柄，便于按控件 ID 精确定位（通用对话框的文件名框是 1001）。
    public static IntPtr Item(IntPtr parent, int id) { return GetDlgItem(parent, id); }

    public static string Text(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        if (h == IntPtr.Zero) return "(no control " + id + ")";
        StringBuilder sb = new StringBuilder(1024);
        IntPtr result;
        SendMessageTimeoutW(h, 0x000D, (IntPtr)1024, sb, 2, 2000, out result);
        return sb.ToString();
    }

    public static int Pos(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        return h == IntPtr.Zero ? -1 : (int)SendMessageW(h, PBM_GETPOS, IntPtr.Zero, IntPtr.Zero);
    }

    public static bool Enabled(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        return h != IntPtr.Zero && IsWindowEnabled(h);
    }

    public static bool Visible(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        return h != IntPtr.Zero && IsWindowVisible(h);
    }

    /// 列表控件的真实条目数（LVM_GETITEMCOUNT），比 UIA 遍历可靠。
    public static int ListItems(IntPtr parent, int id)
    {
        IntPtr h = GetDlgItem(parent, id);
        return h == IntPtr.Zero ? -1 : (int)SendMessageW(h, 0x1004, IntPtr.Zero, IntPtr.Zero);
    }

    static IntPtr found;
    static uint wantPid;

    /// 找到该进程弹出的模态对话框（#32770）。
    public static IntPtr WaitDialog(uint pid, int timeoutMs)
    {
        wantPid = pid;
        long until = DateTime.Now.AddMilliseconds(timeoutMs).Ticks;
        while (DateTime.Now.Ticks < until)
        {
            found = IntPtr.Zero;
            foreach (System.Diagnostics.ProcessThread t in System.Diagnostics.Process.GetProcessById((int)pid).Threads)
            {
                EnumThreadWindows((uint)t.Id, Cb, IntPtr.Zero);
                if (found != IntPtr.Zero) return found;
            }
            System.Threading.Thread.Sleep(60);
        }
        return IntPtr.Zero;
    }

    static bool Cb(IntPtr h, IntPtr l)
    {
        StringBuilder c = new StringBuilder(64);
        GetClassNameW(h, c, 64);
        if (c.ToString() == "#32770" && IsWindowVisible(h)) { found = h; return false; }
        return true;
    }

    public static string DialogText(IntPtr dlg)
    {
        StringBuilder sb = new StringBuilder(2048);
        GetWindowTextW(dlg, sb, 2048);
        string caption = sb.ToString();
        // MessageBox static text uses unsigned control ID 0xFFFF (GetDlgItem takes signed int).
        IntPtr body = GetDlgItem(dlg, 0xFFFF);
        StringBuilder b2 = new StringBuilder(2048);
        if (body != IntPtr.Zero) GetWindowTextW(body, b2, 2048);
        return caption + " || " + b2.ToString().Replace("\r\n", " / ");
    }

    public static bool SetSaveFileName(IntPtr dlg, string path)
    {
        IntPtr field = GetDlgItem(dlg, 1148); // Explorer-style filename ComboBoxEx.
        if (field == IntPtr.Zero) field = GetDlgItem(dlg, 1152); // Legacy edt1.
        if (field == IntPtr.Zero) return false;
        IntPtr child;
        while ((child = GetDlgItem(field, 1148)) != IntPtr.Zero) field = child;
        IntPtr result;
        // Quoting preserves the exact extension, even with a multi-part default extension.
        StringBuilder text = new StringBuilder("\"" + path + "\"");
        return SendMessageTimeoutW(field, 0x000C, IntPtr.Zero, text, 2, 2000, out result) != IntPtr.Zero
            && result != IntPtr.Zero;
    }

    public static void DialogOk(IntPtr dlg)
    {
        IntPtr ok = GetDlgItem(dlg, IDOK);
        if (ok != IntPtr.Zero) SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
        System.Threading.Thread.Sleep(250);
        if (dlg != IntPtr.Zero && IsWindowVisible(dlg))
            PostMessageW(dlg, 0x0010, IntPtr.Zero, IntPtr.Zero); // WM_CLOSE
    }

    public static bool DialogAlive(IntPtr dlg)
    {
        return dlg != IntPtr.Zero && IsWindowVisible(dlg);
    }

    public static void Close(IntPtr h) { PostMessageW(h, 0x0010, IntPtr.Zero, IntPtr.Zero); }

    public static void Focus(IntPtr h)
    {
        BringWindowToTop(h); SetForegroundWindow(h);
    }
}
