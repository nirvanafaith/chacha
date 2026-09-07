using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// 启动 GUI 后枚举控件树，检查越界/重叠/退化尺寸，输出可读清单。
public static class Inspect
{
    delegate bool EnumProc(IntPtr h, IntPtr l);

    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] static extern bool ScreenToClient(IntPtr h, ref POINT p);
    [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);

    [StructLayout(LayoutKind.Sequential)] struct RECT { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] struct POINT { public int X, Y; }

    class Row
    {
        public int Id; public string Cls, Txt, Extra = "";
        public int X, Y, W, H; public bool En, Vis;
    }

    static IntPtr root;
    static List<Row> rows;

    public static string Dump(IntPtr hwnd)
    {
        root = hwnd;
        rows = new List<Row>();
        StringBuilder sb = new StringBuilder();
        RECT cr; GetClientRect(hwnd, out cr);
        sb.AppendFormat("client {0}x{1}\r\n", cr.Right, cr.Bottom);
        EnumChildWindows(hwnd, Cb, IntPtr.Zero);
        rows.Sort(delegate (Row a, Row b) { return a.Y != b.Y ? a.Y.CompareTo(b.Y) : a.X.CompareTo(b.X); });
        foreach (Row r in rows)
            sb.AppendLine(string.Format("#{0,-4} {1,-18} ({2,4},{3,4}) {4,5}x{5,4} en={6} vis={7}{8}  \"{9}\"",
                r.Id, r.Cls, r.X, r.Y, r.W, r.H, r.En, r.Vis, r.Extra, r.Txt));
        int bad = 0;
        // SysHeader32 是 SysListView32 自带的子窗口，不参与同级重叠判定；
        // EDIT 的文字跨进程读回来的是创建时的缓存值，只作参考。
        List<Row> watched = new List<Row>();
        foreach (Row r in rows)
            if (r.Cls != "SysHeader32") watched.Add(r);
        foreach (Row r in watched)
        {
            if (!r.Vis) continue;
            if (r.X < 0 || r.Y < 0 || r.X + r.W > cr.Right || r.Y + r.H > cr.Bottom)
            { sb.AppendLine("PROBLEM out-of-bounds: " + r.Cls + " id=" + r.Id + " " + r.Txt); bad++; }
            if (r.W <= 8 || r.H <= 8) { sb.AppendLine("PROBLEM degenerate: " + r.Cls + " id=" + r.Id); bad++; }
        }
        for (int i = 0; i < watched.Count; i++)
            for (int j = i + 1; j < watched.Count; j++)
            {
                Row a = watched[i], b = watched[j];
                if (!a.Vis || !b.Vis) continue;
                int ox = Math.Min(a.X + a.W, b.X + b.W) - Math.Max(a.X, b.X);
                int oy = Math.Min(a.Y + a.H, b.Y + b.H) - Math.Max(a.Y, b.Y);
                if (ox > 2 && oy > 2)
                {
                    sb.AppendLine(string.Format("PROBLEM overlap {0}px2: {1}#{2} \"{3}\" vs {4}#{5} \"{6}\"",
                        ox * oy, a.Cls, a.Id, a.Txt, b.Cls, b.Id, b.Txt));
                    bad++;
                }
            }
        sb.AppendLine(bad == 0 ? "LAYOUT OK" : ("LAYOUT PROBLEMS: " + bad));
        PostMessageW(hwnd, 0x0010, IntPtr.Zero, IntPtr.Zero);
        return sb.ToString();
    }

    static bool Cb(IntPtr h, IntPtr l)
    {
        StringBuilder cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
        StringBuilder txt = new StringBuilder(1024); GetWindowTextW(h, txt, 1024);
        RECT r; GetWindowRect(h, out r);
        POINT tl = new POINT(); tl.X = r.Left; tl.Y = r.Top;
        POINT br = new POINT(); br.X = r.Right; br.Y = r.Bottom;
        ScreenToClient(root, ref tl); ScreenToClient(root, ref br);
        Row row = new Row();
        row.Id = GetDlgCtrlID(h);
        row.Cls = cls.ToString();
        row.Txt = txt.ToString();
        row.X = tl.X; row.Y = tl.Y; row.W = br.X - tl.X; row.H = br.Y - tl.Y;
        row.En = IsWindowEnabled(h); row.Vis = IsWindowVisible(h);
        if (row.Cls == "SysListView32")
        {
            row.Extra = " items=" + (int)SendMessageW(h, 0x1004, IntPtr.Zero, IntPtr.Zero);
            for (int c = 0; c < 3; c++)
            {
                int width = (int)SendMessageW(h, 0x101D, (IntPtr)c, IntPtr.Zero);
                row.Extra += " col" + c + "=" + width;
                if (width < 60) row.Extra += " PROBLEM column-too-narrow";
            }
        }
        else if (row.Cls == "msctls_progress32")
            row.Extra = " pos=" + (int)SendMessageW(h, 0x0408 /*PBM_GETPOS*/, IntPtr.Zero, IntPtr.Zero);
        rows.Add(row);
        return true;
    }
}
