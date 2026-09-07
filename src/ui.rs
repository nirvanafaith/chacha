//! 极简 Win32 工具箱：不依赖任何第三方库，只用 user32/gdi32/comctl32/shell32/comdlg32。
//!
//! 两个程序共用这里的控件与视觉语言，保证外观与手感一致。

#![allow(dead_code)]

use core::ffi::c_void;
use std::path::{Path, PathBuf};

pub type HWND = *mut c_void;
pub type HDC = *mut c_void;
pub type HBRUSH = *mut c_void;
pub type HFONT = *mut c_void;
pub type HICON = *mut c_void;
pub type HINSTANCE = *mut c_void;
pub type HANDLE = *mut c_void;
pub type WPARAM = usize;
pub type LPARAM = isize;
pub type LRESULT = isize;

pub const WM_CREATE: u32 = 0x0001;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_SIZE: u32 = 0x0005;
pub const WM_GETMINMAXINFO: u32 = 0x0024;
pub const WM_SETTEXT: u32 = 0x000C;
pub const WM_SETFONT: u32 = 0x0030;
pub const WM_GETTEXT: u32 = 0x000D;
pub const WM_CLOSE: u32 = 0x0010;
pub const WM_COMMAND: u32 = 0x0111;
pub const WM_TIMER: u32 = 0x0113;
pub const WM_CTLCOLOREDIT: u32 = 0x0133;
pub const WM_CTLCOLORSTATIC: u32 = 0x0138;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_APP: u32 = 0x8000;
pub const WM_APP_DONE: u32 = WM_APP + 1;

pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;
pub const WS_GROUP: u32 = 0x0002_0000;
pub const WS_EX_CONTROLPARENT: u32 = 0x0001_0000;
pub const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;

pub const ES_READONLY: u32 = 0x0000_0800;
pub const ES_AUTOHSCROLL: u32 = 0x0000_0080;

pub const SS_LEFT: u32 = 0x0000_0000;
pub const SS_RIGHT: u32 = 0x0000_0002;

pub const BS_DEFPUSHBUTTON: u32 = 0x0000_0001;

pub const SW_SHOWNORMAL: i32 = 1;
pub const SW_SHOW: i32 = 5;
pub const SW_HIDE: i32 = 0;

pub const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;

pub const GWL_USERDATA: i32 = -21;

pub const VK_ESCAPE: u32 = 0x1B;
pub const VK_CONTROL: u32 = 0x11;
pub const VK_O: u32 = 0x4F;
pub const VK_RETURN: u32 = 0x0D;

/// 近白底，比纯白柔和；正文墨色偏暖，长时间看不刺眼。
pub const COLOR_BG: u32 = 0x00FC_FCFC;
pub const INK: u32 = 0x0040_3830;
pub const INK_HEADING: u32 = 0x002A_2220;
pub const INK_SUBTLE: u32 = 0x008A_7C70;
pub const INK_OK: u32 = 0x002C_7030;
pub const INK_BAD: u32 = 0x0028_38B4;

// -------------------- FFI --------------------

#[repr(C)]
pub struct WNDCLASSW {
    pub style: u32,
    pub lpfn_wnd_proc: usize,
    pub cb_cls_extra: i32,
    pub cb_wnd_extra: i32,
    pub h_instance: HINSTANCE,
    pub h_icon: HICON,
    pub h_cursor: *mut c_void,
    pub hbr_background: HBRUSH,
    pub lpsz_menu_name: *const u16,
    pub lpsz_class_name: *const u16,
}

#[repr(C)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: u32,
    pub wparam: WPARAM,
    pub lparam: LPARAM,
    pub time: u32,
    pub pt_x: i32,
    pub pt_y: i32,
}

#[repr(C)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
pub struct LOGFONTW {
    pub lf_height: i32,
    pub lf_width: i32,
    pub lf_escapement: i32,
    pub lf_orientation: i32,
    pub lf_weight: u32,
    pub lf_italic: u8,
    pub lf_underline: u8,
    pub lf_strikeout: u8,
    pub lf_char_set: u8,
    pub lf_out_precision: u8,
    pub lf_clip_precision: u8,
    pub lf_quality: u8,
    pub lf_pitch_and_family: u8,
    pub lf_face_name: [u16; 32],
}

#[repr(C)]
pub struct LVITEMW {
    pub mask: u32,
    pub i_item: i32,
    pub i_subitem: i32,
    pub state: u32,
    pub state_mask: u32,
    pub text: *mut u16,
    pub text_max: i32,
    pub image: i32,
    pub lparam: LPARAM,
}

#[repr(C)]
pub struct LVCOLUMNW {
    pub mask: u32,
    pub fmt: i32,
    pub cx: i32,
    pub text: *mut u16,
    pub text_max: i32,
    pub i_subitem: i32,
    pub i_image: i32,
    pub order: i32,
}

#[repr(C)]
pub struct BROWSEINFOW {
    pub hwnd_owner: HWND,
    pub pidl_root: *mut c_void,
    pub psz_display_name: *mut u16,
    pub lpsz_title: *const u16,
    pub ul_flags: u32,
    pub lpfn: usize,
    pub lparam: LPARAM,
    pub i_image: i32,
}

#[repr(C)]
pub struct OPENFILENAMEW {
    pub l_struct_size: u32,
    pub hwnd_owner: HWND,
    pub h_instance: HINSTANCE,
    pub lpstr_filter: *const u16,
    pub lpstr_custom_filter: *mut u16,
    pub n_max_cust_filter: u32,
    pub n_filter_index: u32,
    pub lpstr_file: *mut u16,
    pub n_max_file: u32,
    pub lpstr_file_title: *mut u16,
    pub n_max_file_title: u32,
    pub lpstr_initial_dir: *const u16,
    pub lpstr_title: *const u16,
    pub flags: u32,
    pub n_file_offset: u16,
    pub n_file_extension: u16,
    pub lpstr_def_ext: *const u16,
    pub l_cust_data: LPARAM,
    pub lpfn_hook: usize,
    pub lp_template_name: *const u16,
    pub pv_reserved: *mut c_void,
    pub dw_reserved: u32,
    pub flags_ex: u32,
}

#[repr(C)]
pub struct ICC {
    pub dw_icc: u32,
}

#[repr(C)]
pub struct MINMAXINFO {
    pub pt_reserved_x: i32,
    pub pt_reserved_y: i32,
    pub pt_max_size_x: i32,
    pub pt_max_size_y: i32,
    pub pt_max_position_x: i32,
    pub pt_max_position_y: i32,
    pub pt_min_track_x: i32,
    pub pt_min_track_y: i32,
    pub pt_max_track_x: i32,
    pub pt_max_track_y: i32,
}

#[link(name = "user32")]
extern "system" {
    pub fn RegisterClassW(cls: *const WNDCLASSW) -> u16;
    pub fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        title: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: HWND,
        menu: *mut c_void,
        inst: HINSTANCE,
        param: *mut c_void,
    ) -> HWND;
    pub fn DefWindowProcW(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    pub fn GetMessageW(m: *mut MSG, h: HWND, first: u32, last: u32) -> i32;
    pub fn TranslateMessage(m: *const MSG) -> i32;
    pub fn DispatchMessageW(m: *const MSG) -> LRESULT;
    pub fn IsDialogMessageW(h: HWND, m: *mut MSG) -> i32;
    pub fn PostQuitMessage(code: i32);
    pub fn PostMessageW(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> i32;
    pub fn SendMessageW(h: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    pub fn ShowWindow(h: HWND, cmd: i32) -> i32;
    pub fn UpdateWindow(h: HWND) -> i32;
    pub fn DestroyWindow(h: HWND) -> i32;
    pub fn GetClientRect(h: HWND, r: *mut RECT) -> i32;
    pub fn MoveWindow(h: HWND, x: i32, y: i32, w: i32, ht: i32, repaint: i32) -> i32;
    pub fn SetWindowTextW(h: HWND, s: *const u16) -> i32;
    pub fn GetWindowTextW(h: HWND, buf: *mut u16, max: i32) -> i32;
    pub fn GetDlgItem(parent: HWND, id: i32) -> HWND;
    pub fn GetDlgCtrlID(h: HWND) -> i32;
    pub fn LoadCursorW(h: HINSTANCE, name: *const u16) -> *mut c_void;
    pub fn MessageBoxW(h: HWND, text: *const u16, cap: *const u16, utype: u32) -> i32;
    pub fn EnableWindow(h: HWND, enable: i32) -> i32;
    pub fn SetFocus(h: HWND) -> HWND;
    pub fn SetTimer(h: HWND, id: usize, elapse: u32, proc: usize) -> usize;
    pub fn KillTimer(h: HWND, id: usize) -> i32;
    pub fn OpenClipboard(h: HWND) -> i32;
    pub fn CloseClipboard() -> i32;
    pub fn EmptyClipboard() -> i32;
    pub fn SetClipboardData(fmt: u32, data: HANDLE) -> HANDLE;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
    pub fn GlobalAlloc(flags: u32, bytes: usize) -> HANDLE;
    pub fn GlobalLock(h: HANDLE) -> *mut c_void;
    pub fn GlobalUnlock(h: HANDLE) -> i32;
    pub fn GetLastError() -> u32;
}

#[link(name = "gdi32")]
extern "system" {
    pub fn CreateFontIndirectW(lf: *const LOGFONTW) -> HFONT;
    pub fn GetDeviceCaps(hdc: HDC, index: i32) -> i32;
    pub fn GetDC(h: HWND) -> HDC;
    pub fn ReleaseDC(h: HWND, dc: HDC) -> i32;
    pub fn CreateSolidBrush(color: u32) -> HBRUSH;
    pub fn SetTextColor(hdc: HDC, color: u32) -> u32;
    pub fn SetBkColor(hdc: HDC, color: u32) -> u32;
    pub fn SetBkMode(hdc: HDC, mode: i32) -> i32;
}

#[link(name = "comctl32")]
extern "system" {
    pub fn InitCommonControlsEx(icc: *const ICC) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    pub fn SHBrowseForFolderW(bi: *mut BROWSEINFOW) -> *mut c_void;
    pub fn SHGetPathFromIDListW(pidl: *mut c_void, path: *mut u16) -> i32;
    pub fn ShellExecuteW(
        h: HWND,
        op: *const u16,
        file: *const u16,
        params: *const u16,
        dir: *const u16,
        show: i32,
    ) -> isize;
}

#[link(name = "ole32")]
extern "system" {
    pub fn CoInitialize(reserved: *mut c_void) -> i32;
    pub fn CoUninitialize();
    pub fn CoTaskMemFree(p: *mut c_void);
}

#[link(name = "comdlg32")]
extern "system" {
    pub fn GetOpenFileNameW(ofn: *mut OPENFILENAMEW) -> i32;
    pub fn GetSaveFileNameW(ofn: *mut OPENFILENAMEW) -> i32;
}

#[cfg(target_pointer_width = "32")]
#[link(name = "user32")]
extern "system" {
    fn SetWindowLongW(h: HWND, idx: i32, val: i32) -> i32;
    fn GetWindowLongW(h: HWND, idx: i32) -> i32;
}

#[cfg(target_pointer_width = "64")]
#[link(name = "user32")]
extern "system" {
    fn SetWindowLongPtrW(h: HWND, idx: i32, val: isize) -> isize;
    fn GetWindowLongPtrW(h: HWND, idx: i32) -> isize;
}

pub unsafe fn set_userdata(h: HWND, p: usize) {
    #[cfg(target_pointer_width = "32")]
    {
        SetWindowLongW(h, GWL_USERDATA, p as i32);
    }
    #[cfg(target_pointer_width = "64")]
    {
        SetWindowLongPtrW(h, GWL_USERDATA, p as isize);
    }
}

pub unsafe fn get_userdata(h: HWND) -> usize {
    #[cfg(target_pointer_width = "32")]
    {
        GetWindowLongW(h, GWL_USERDATA) as usize
    }
    #[cfg(target_pointer_width = "64")]
    {
        GetWindowLongPtrW(h, GWL_USERDATA) as usize
    }
}

// -------------------- 基础 --------------------

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

static mut DPI: i32 = 96;

/// 初始化公共控件与 OLE，并取一次 DPI 作为缩放基准。
pub fn init() {
    unsafe {
        CoInitialize(core::ptr::null_mut());
        // LISTVIEW | BAR | PROGRESS | STANDARD | DATEPICKER | REBAR | TOOLBAR | HEADER
        let icc = ICC {
            dw_icc: 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0100 | 0x0200 | 0x2000 | 0x0020,
        };
        InitCommonControlsEx(&icc);
        let dc = GetDC(core::ptr::null_mut());
        let d = GetDeviceCaps(dc, 88); // LOGPIXELSX
        if d > 0 {
            DPI = d;
        }
        ReleaseDC(core::ptr::null_mut(), dc);
    }
}

pub fn dpi() -> i32 {
    unsafe { DPI }
}

/// 以 96dpi 为基准缩放，高分屏下布局不塌。
pub fn px(v: i32) -> i32 {
    (v * dpi()) / 96
}

pub fn set_text(h: HWND, s: &str) {
    if h.is_null() {
        return;
    }
    let w = wide(s);
    unsafe {
        SendMessageW(h, WM_SETTEXT, 0, w.as_ptr() as LPARAM);
    }
}

pub fn get_text(h: HWND) -> String {
    if h.is_null() {
        return String::new();
    }
    let mut buf = vec![0u16; 4096];
    let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

pub fn enable(h: HWND, on: bool) {
    if !h.is_null() {
        unsafe {
            EnableWindow(h, if on { 1 } else { 0 });
        }
    }
}

pub fn set_font(h: HWND, f: HFONT) {
    if !h.is_null() {
        unsafe {
            SendMessageW(h, WM_SETFONT, f as usize, 1);
        }
    }
}

pub fn show(h: HWND, on: bool) {
    if !h.is_null() {
        unsafe {
            ShowWindow(h, if on { SW_SHOW } else { SW_HIDE });
        }
    }
}

pub const FW_NORMAL: u32 = 400;
pub const FW_SEMIBOLD: u32 = 600;
pub const FW_BOLD: u32 = 700;

/// 创建字体。`pt` 为磅值，内部按 DPI 换算字高。
pub fn make_font(name: &str, pt: i32, weight: u32) -> HFONT {
    unsafe {
        let mut lf: LOGFONTW = core::mem::zeroed();
        lf.lf_height = -(pt * dpi() / 72);
        lf.lf_weight = weight;
        lf.lf_char_set = 134; // GB2312：XP 上中文回退正确
        lf.lf_quality = 2; // CLEARTYPE_QUALITY
        let w = wide(name);
        let n = if w.len() - 1 < 32 { w.len() - 1 } else { 31 };
        lf.lf_face_name[..n].copy_from_slice(&w[..n]);
        CreateFontIndirectW(&lf)
    }
}

// -------------------- 控件 --------------------

pub fn add(parent: HWND, class: &str, text: &str, style: u32, ex: u32, id: i32) -> HWND {
    let c = wide(class);
    let t = wide(text);
    let h = unsafe {
        CreateWindowExW(
            ex,
            c.as_ptr(),
            t.as_ptr(),
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            0,
            0,
            parent,
            id as *mut c_void,
            GetModuleHandleW(core::ptr::null()),
            core::ptr::null_mut(),
        )
    };
    if h.is_null() {
        report_failed(class, id, style, ex);
    }
    h
}

/// 控件创建失败在 GUI 程序里完全静默，调试版必须留一条痕迹。
#[cfg(debug_assertions)]
fn report_failed(class: &str, id: i32, style: u32, ex: u32) {
    let e = unsafe { GetLastError() };
    crate::util::console::eprint(&format!(
        "add failed: class={} id={} style=0x{:08X} ex=0x{:X} err={}\n",
        class, id, style, ex, e
    ));
}

#[cfg(not(debug_assertions))]
fn report_failed(_class: &str, _id: i32, _style: u32, _ex: u32) {}

pub fn label(parent: HWND, id: i32, text: &str) -> HWND {
    add(parent, "STATIC", text, SS_LEFT, 0, id)
}

pub fn label_right(parent: HWND, id: i32, text: &str) -> HWND {
    add(parent, "STATIC", text, SS_RIGHT, 0, id)
}

pub fn button(parent: HWND, id: i32, text: &str, primary: bool) -> HWND {
    let style = if primary { BS_DEFPUSHBUTTON } else { 0u32 };
    add(parent, "BUTTON", text, style | WS_TABSTOP | WS_GROUP, 0, id)
}

/// 只读路径框：像字段但不会误编辑。
pub fn path_field(parent: HWND, id: i32, text: &str) -> HWND {
    add(
        parent,
        "EDIT",
        text,
        ES_READONLY | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
        0,
        id,
    )
}

const PBM_SETRANGE32: u32 = 0x0406;
const PBM_SETPOS: u32 = 0x0402; // WM_USER+2（0x0401 是 PBM_SETRANGE，别混）
const PBM_GETPOS: u32 = 0x0408; // WM_USER+8

pub fn progress_pos(h: HWND) -> i32 {
    if h.is_null() {
        return -1;
    }
    unsafe { SendMessageW(h, PBM_GETPOS, 0, 0) as i32 }
}

pub fn progress(parent: HWND, id: i32) -> HWND {
    let h = add(parent, "msctls_progress32", "", 0, 0, id);
    unsafe {
        SendMessageW(h, PBM_SETRANGE32, 0, 1000); // 千分比，进度更平滑
    }
    h
}

pub fn set_progress(h: HWND, permille: i32) {
    if !h.is_null() {
        let v = if permille < 0 {
            0
        } else if permille > 1000 {
            1000
        } else {
            permille
        };
        unsafe {
            SendMessageW(h, PBM_SETPOS, v as usize, 0);
        }
    }
}

const LVM_FIRST: u32 = 0x1000;
const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 13;
const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
const LVM_GETCOLUMNWIDTH: u32 = LVM_FIRST + 29;
const LVM_SETCOLUMNWIDTH: u32 = LVM_FIRST + 30;
const LVIF_TEXT: u32 = 0x0001;
const LVNI_SELECTED: u32 = 0x0002;
const LVS_REPORT: u32 = 0x0001;
const LVS_SINGLESEL: u32 = 0x0004;
const LVS_SHOWSELALWAYS: u32 = 0x0008;
const LVS_EX_FULLROWSELECT: u32 = 0x0000_0020;
const LVS_EX_DOUBLEBUFFER: u32 = 0x0001_0000;

const LVCF_FMT: u32 = 0x0001;
const LVCF_WIDTH: u32 = 0x0002;
const LVCF_TEXT: u32 = 0x0004;
const LVCF_SUBITEM: u32 = 0x0008;

pub const LVCFMT_LEFT: i32 = 0x0000;
pub const LVCFMT_RIGHT: i32 = 0x0001;
pub const LVCFMT_CENTER: i32 = 0x0002;

pub struct List {
    pub hwnd: HWND,
}

impl List {
    /// `cols` 为 (标题, 96dpi 下的推荐宽度)。大小列默认右对齐，其它左对齐。
    pub fn new(parent: HWND, id: i32, cols: &[(&str, i32)]) -> List {
        let style = LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER | WS_TABSTOP;
        let hwnd = add(parent, "SysListView32", "", style, WS_EX_CLIENTEDGE, id);
        unsafe {
            SendMessageW(
                hwnd,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as usize,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as LPARAM,
            );
        }
        let l = List { hwnd };
        for (i, (t, w)) in cols.iter().enumerate() {
            let fmt = if i == 1 { LVCFMT_RIGHT } else { LVCFMT_LEFT };
            l.insert_col(i as i32, t, px(*w), fmt);
        }
        l
    }

    fn insert_col(&self, i: i32, title: &str, width: i32, fmt: i32) {
        let t = wide(title);
        unsafe {
            let mut col: LVCOLUMNW = core::mem::zeroed();
            col.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
            col.text = t.as_ptr() as *mut u16;
            col.cx = width;
            col.i_subitem = i;
            col.fmt = fmt;
            SendMessageW(
                self.hwnd,
                LVM_INSERTCOLUMNW,
                i as usize,
                &mut col as *mut _ as LPARAM,
            );
        }
    }

    pub fn set_col_width(&self, col: i32, width: i32) {
        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETCOLUMNWIDTH,
                col as usize,
                width as LPARAM,
            );
        }
    }

    /// 针对 3 列文件列表（文件名、大小、修改时间）自适应计算分配宽度：
    /// 大小列固定 95px（右对齐）、修改时间列固定 145px（左对齐），
    /// 文件名列自适应占满剩余宽度（扣除滚动条裕量），确保所有列首清晰可见且信息排版合理。
    pub fn layout_three_cols(&self, list_width: i32) {
        let size_w = px(95);
        let time_w = px(145);
        let scroll_allowance = px(24);
        let file_w = (list_width - size_w - time_w - scroll_allowance).max(px(120));
        self.set_col_width(0, file_w);
        self.set_col_width(1, size_w);
        self.set_col_width(2, time_w);
    }

    pub fn clear(&self) {
        unsafe {
            SendMessageW(self.hwnd, LVM_DELETEALLITEMS, 0, 0);
        }
    }

    pub fn count(&self) -> usize {
        let n = unsafe { SendMessageW(self.hwnd, LVM_GETITEMCOUNT, 0, 0) };
        if n < 0 {
            0
        } else {
            n as usize
        }
    }

    pub fn add(&self, cells: &[&str]) -> i32 {
        let first = wide(if cells.is_empty() { "" } else { cells[0] });
        let mut it: LVITEMW = unsafe { core::mem::zeroed() };
        it.mask = LVIF_TEXT;
        it.text = first.as_ptr() as *mut u16;
        let idx = unsafe { SendMessageW(self.hwnd, LVM_INSERTITEMW, 0, &mut it as *mut _ as LPARAM) };
        if idx < 0 {
            return -1;
        }
        let idx = idx as i32;
        let mut i = 1usize;
        while i < cells.len() {
            let t = wide(cells[i]);
            let mut sub: LVITEMW = unsafe { core::mem::zeroed() };
            sub.mask = LVIF_TEXT;
            sub.i_item = idx;
            sub.i_subitem = i as i32;
            sub.text = t.as_ptr() as *mut u16;
            unsafe {
                SendMessageW(
                    self.hwnd,
                    LVM_SETITEMTEXTW,
                    idx as usize,
                    &mut sub as *mut _ as LPARAM,
                );
            }
            i += 1;
        }
        idx
    }

    pub fn selected(&self) -> i32 {
        unsafe {
            SendMessageW(self.hwnd, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED as LPARAM) as i32
        }
    }

    /// 兼容接口
    pub fn fit_last(&self, _cols: usize, width: i32) {
        self.layout_three_cols(width);
    }
}

// -------------------- 选择对话框 --------------------

const BIF_RETURNONLYFSDIRS: u32 = 0x0001;
const BIF_NEWDIALOGSTYLE: u32 = 0x0040;
const BIF_EDITBOX: u32 = 0x0010;
const OFN_HIDEREADONLY: u32 = 0x0000_0004;
const OFN_PATHMUSTEXIST: u32 = 0x0000_0800;
const OFN_FILEMUSTEXIST: u32 = 0x0000_1000;
const OFN_OVERWRITEPROMPT: u32 = 0x0000_0002;
const OFN_EXPLORER: u32 = 0x0008_0000;

pub fn pick_folder(owner: HWND, title: &str) -> Option<PathBuf> {
    let mut display = [0u16; 260];
    let t = wide(title);
    let pidl = unsafe {
        let mut bi: BROWSEINFOW = core::mem::zeroed();
        bi.hwnd_owner = owner;
        bi.pidl_root = core::ptr::null_mut();
        bi.psz_display_name = display.as_mut_ptr();
        bi.lpsz_title = t.as_ptr();
        bi.ul_flags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
        SHBrowseForFolderW(&mut bi)
    };
    if pidl.is_null() {
        return None;
    }
    let mut buf = [0u16; 260];
    let ok = unsafe { SHGetPathFromIDListW(pidl, buf.as_mut_ptr()) };
    unsafe {
        CoTaskMemFree(pidl);
    }
    if ok == 0 {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
    if n == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
}

/// 描述与模式用 `\0` 分隔，多个筛选项串在一起。
pub fn make_filter(pairs: &[(&str, &str)]) -> String {
    let mut s = String::new();
    for (desc, pat) in pairs {
        s.push_str(desc);
        s.push('\0');
        s.push_str(pat);
        s.push('\0');
    }
    s.push('\0');
    s
}

fn file_dialog(
    owner: HWND,
    title: &str,
    filter: &str,
    initial: &Path,
    save: bool,
    ext: &str,
) -> Option<PathBuf> {
    let mut buf: Vec<u16> = initial
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    buf.resize(2048, 0);
    let f: Vec<u16> = filter
        .encode_utf16()
        .chain(std::iter::once(0))
        .chain(std::iter::once(0))
        .collect();
    let t = wide(title);
    let dir_w = initial
        .parent()
        .map(|p| wide(&p.to_string_lossy()))
        .unwrap_or_else(|| vec![0u16]);
    let e = wide(ext);
    let mut ofn: OPENFILENAMEW = unsafe { core::mem::zeroed() };
    ofn.l_struct_size = core::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwnd_owner = owner;
    ofn.lpstr_filter = f.as_ptr();
    ofn.lpstr_file = buf.as_mut_ptr();
    ofn.n_max_file = buf.len() as u32;
    ofn.lpstr_initial_dir = dir_w.as_ptr();
    ofn.lpstr_title = t.as_ptr();
    ofn.lpstr_def_ext = e.as_ptr();
    ofn.flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_EXPLORER | 0x0000_0040
        | if save { OFN_OVERWRITEPROMPT } else { OFN_FILEMUSTEXIST };
    let ok = unsafe {
        if save {
            GetSaveFileNameW(&mut ofn)
        } else {
            GetOpenFileNameW(&mut ofn)
        }
    };
    if ok == 0 {
        return None;
    }
    let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
    if n == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
}

pub fn pick_file(owner: HWND, title: &str, filter: &str, initial: &Path) -> Option<PathBuf> {
    file_dialog(owner, title, filter, initial, false, "")
}

pub fn save_file(
    owner: HWND,
    title: &str,
    filter: &str,
    initial: &Path,
    ext: &str,
) -> Option<PathBuf> {
    file_dialog(owner, title, filter, initial, true, ext)
}

// -------------------- 消息框 / 剪贴板 / 定位 --------------------

const MB_OK: u32 = 0;
const MB_OKCANCEL: u32 = 1;
const MB_ICONINFORMATION: u32 = 0x40;
const MB_ICONWARNING: u32 = 0x30;
const MB_ICONERROR: u32 = 0x10;
const IDOK: i32 = 1;

pub fn info(owner: HWND, title: &str, msg: &str) {
    box_msg(owner, title, msg, MB_OK | MB_ICONINFORMATION);
}

pub fn warn(owner: HWND, title: &str, msg: &str) {
    box_msg(owner, title, msg, MB_OK | MB_ICONWARNING);
}

pub fn error(owner: HWND, title: &str, msg: &str) {
    box_msg(owner, title, msg, MB_OK | MB_ICONERROR);
}

pub fn confirm(owner: HWND, title: &str, msg: &str) -> bool {
    box_msg(owner, title, msg, MB_OKCANCEL | MB_ICONINFORMATION) == IDOK
}

fn box_msg(owner: HWND, title: &str, msg: &str, kind: u32) -> i32 {
    let t = wide(title);
    let m = wide(msg);
    unsafe { MessageBoxW(owner, m.as_ptr(), t.as_ptr(), kind) }
}

pub fn copy_text(owner: HWND, s: &str) -> bool {
    let bytes = s.as_bytes();
    unsafe {
        if OpenClipboard(owner) == 0 {
            return false;
        }
        EmptyClipboard();
        let h = GlobalAlloc(0x0042, bytes.len() + 1); // GMEM_MOVEABLE | GMEM_ZEROINIT
        if h.is_null() {
            CloseClipboard();
            return false;
        }
        let p = GlobalLock(h);
        if !p.is_null() {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len());
            GlobalUnlock(h);
        }
        let ok = !SetClipboardData(1, h).is_null(); // CF_TEXT
        CloseClipboard();
        ok
    }
}

/// 在资源管理器中打开该位置（文件则打开其所在目录）。
pub fn reveal(path: &Path) {
    let target = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| path.to_path_buf())
    };
    let op = wide("open");
    let f = wide(&target.to_string_lossy());
    unsafe {
        ShellExecuteW(
            core::ptr::null_mut(),
            op.as_ptr(),
            f.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

// -------------------- 窗口与消息循环 --------------------

pub type WndProc = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

pub unsafe fn register_class(name: &str, proc: WndProc, bg: HBRUSH) -> bool {
    let n = wide(name);
    let cls = WNDCLASSW {
        style: 0x0003, // CS_VREDRAW | CS_HREDRAW
        lpfn_wnd_proc: proc as usize,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: GetModuleHandleW(core::ptr::null()),
        h_icon: core::ptr::null_mut(),
        h_cursor: LoadCursorW(core::ptr::null_mut(), 32512u16 as *const u16), // IDC_ARROW
        hbr_background: bg,
        lpsz_menu_name: core::ptr::null(),
        lpsz_class_name: n.as_ptr(),
    };
    RegisterClassW(&cls) != 0
}

pub unsafe fn create_window(class: &str, title: &str, w: i32, h: i32, param: *mut c_void) -> HWND {
    let c = wide(class);
    let t = wide(title);
    CreateWindowExW(
        WS_EX_CONTROLPARENT,
        c.as_ptr(),
        t.as_ptr(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        w,
        h,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        GetModuleHandleW(core::ptr::null()),
        param,
    )
}

/// 标准消息循环。IsDialogMessage 让 Tab / Enter / Esc 在控件间正常工作。
pub fn run_loop() -> i32 {
    unsafe {
        let mut m: MSG = core::mem::zeroed();
        loop {
            let r = GetMessageW(&mut m, core::ptr::null_mut(), 0, 0);
            if r <= 0 {
                return m.wparam as i32;
            }
            let hwnd = m.hwnd;
            if !hwnd.is_null() && IsDialogMessageW(hwnd, &mut m) != 0 {
                continue;
            }
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

/// WM_GETMINMAXINFO：限制最小尺寸，避免布局被压坏。
pub unsafe fn enforce_min(l: LPARAM, min_w: i32, min_h: i32) {
    let mm = l as *mut MINMAXINFO;
    (*mm).pt_min_track_x = min_w;
    (*mm).pt_min_track_y = min_h;
}

/// 在 WM_CTLCOLORSTATIC / WM_CTLCOLOREDIT 中按 id 上色。
pub unsafe fn paint_text(
    hdc: HDC,
    hwnd: HWND,
    table: &[(i32, u32)],
    brush: HBRUSH,
    default_ink: u32,
) -> LRESULT {
    let id = GetDlgCtrlID(hwnd);
    let mut ink = default_ink;
    for (i, c) in table {
        if *i == id {
            ink = *c;
            break;
        }
    }
    SetBkMode(hdc, 1); // TRANSPARENT
    SetTextColor(hdc, ink);
    SetBkColor(hdc, COLOR_BG);
    brush as LRESULT
}

pub fn solid(color: u32) -> HBRUSH {
    unsafe { CreateSolidBrush(color) }
}
