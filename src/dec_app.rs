//! 解密端：加密包 B + 密钥文件 → 还原文件夹 A。
//!
//! 清单是明文，所以第 ① 步就能列出包内文件名；第 ② 步导入密钥并即时校验；
//! 两步都满足才允许第 ③ 步还原，避免用户白等一趟。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::package;
use crate::pool::{self, Job};
use crate::ui::{self, HWND, LPARAM, LRESULT, WPARAM};
use crate::util;

const ID_TITLE: i32 = 1;
const ID_SUB: i32 = 2;
const ID_H1: i32 = 3;
const ID_H2: i32 = 4;
const ID_H3: i32 = 5;
const ID_INFO: i32 = 6;
const ID_STATUS: i32 = 7;
const ID_INFO2: i32 = 9;
const ID_PATH_PKG: i32 = 11;
const ID_PATH_KEY: i32 = 12;
const ID_PATH_OUT: i32 = 13;
const ID_BTN_PKG: i32 = 21;
const ID_BTN_KEY: i32 = 22;
const ID_BTN_OUT: i32 = 23;
const ID_BTN_GO: i32 = 24;
const ID_BTN_CANCEL: i32 = 25;
const ID_BTN_OPEN: i32 = 26;
const ID_LIST: i32 = 31;
const ID_BAR: i32 = 32;

const IDCANCEL: i32 = 2;
const TIMER_PROGRESS: usize = 1;

type Done = Arc<Mutex<Option<Result<package::Summary, String>>>>;

struct State {
    hwnd: HWND,
    fonts: Vec<ui::HFONT>,
    brush: ui::HBRUSH,
    ink: Vec<(i32, u32)>,

    title: HWND,
    sub: HWND,
    h1: HWND,
    h2: HWND,
    h3: HWND,
    info: HWND,
    info2: HWND,
    status: HWND,
    path_pkg: HWND,
    path_key: HWND,
    path_out: HWND,
    btn_pkg: HWND,
    btn_key: HWND,
    btn_out: HWND,
    btn_go: HWND,
    btn_cancel: HWND,
    btn_open: HWND,
    list: ui::List,
    bar: HWND,

    pkg_dir: Option<PathBuf>,
    pkg: Option<Arc<package::Package>>,
    key_path: Option<PathBuf>,
    keyfile: Option<package::KeyFile>,
    key_error: Option<String>,
    key_ok: bool,
    out_dir: Option<PathBuf>,
    restored: Option<PathBuf>,

    busy: bool,
    job: Option<Arc<Job>>,
    done: Done,
    worker: Option<std::thread::JoinHandle<()>>,
    prefill_pkg: Option<PathBuf>,
    prefill_key: Option<PathBuf>,
    prefill_out: Option<PathBuf>,
}

static mut PENDING: *mut State = core::ptr::null_mut();

/// 启动时预填的三项，任意为空就留给用户去选。
pub struct Prefill {
    pub pkg: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub out: Option<PathBuf>,
}

impl Prefill {
    pub fn empty() -> Prefill {
        Prefill {
            pkg: None,
            key: None,
            out: None,
        }
    }
}

pub fn run(pf: Prefill) -> i32 {
    ui::init();
    let ink_table: Vec<(i32, u32)> = vec![
        (ID_TITLE, ui::INK_HEADING),
        (ID_SUB, ui::INK_SUBTLE),
        (ID_H1, ui::INK_HEADING),
        (ID_H2, ui::INK_HEADING),
        (ID_H3, ui::INK_HEADING),
        (ID_INFO, ui::INK_SUBTLE),
        (ID_INFO2, ui::INK_SUBTLE),
        (ID_STATUS, ui::INK),
    ];
    let fonts = vec![
        ui::make_font("Tahoma", 15, ui::FW_SEMIBOLD),
        ui::make_font("Tahoma", 9, ui::FW_NORMAL),
        ui::make_font("Tahoma", 10, ui::FW_SEMIBOLD),
        ui::make_font("Consolas", 9, ui::FW_NORMAL),
    ];
    let brush = ui::solid(ui::COLOR_BG);
    let st = Box::new(State {
        hwnd: core::ptr::null_mut(),
        fonts,
        brush,
        ink: ink_table,
        title: core::ptr::null_mut(),
        sub: core::ptr::null_mut(),
        h1: core::ptr::null_mut(),
        h2: core::ptr::null_mut(),
        h3: core::ptr::null_mut(),
        info: core::ptr::null_mut(),
        info2: core::ptr::null_mut(),
        status: core::ptr::null_mut(),
        path_pkg: core::ptr::null_mut(),
        path_key: core::ptr::null_mut(),
        path_out: core::ptr::null_mut(),
        btn_pkg: core::ptr::null_mut(),
        btn_key: core::ptr::null_mut(),
        btn_out: core::ptr::null_mut(),
        btn_go: core::ptr::null_mut(),
        btn_cancel: core::ptr::null_mut(),
        btn_open: core::ptr::null_mut(),
        list: ui::List { hwnd: core::ptr::null_mut() },
        bar: core::ptr::null_mut(),
        pkg_dir: None,
        pkg: None,
        key_path: None,
        keyfile: None,
        key_error: None,
        key_ok: false,
        out_dir: None,
        restored: None,
        busy: false,
        job: None,
        done: Arc::new(Mutex::new(None)),
        worker: None,
        prefill_pkg: pf.pkg.clone(),
        prefill_key: pf.key.clone(),
        prefill_out: pf.out.clone(),
    });
    unsafe {
        PENDING = Box::into_raw(st);
        if !ui::register_class("CHACHADec", wnd_proc, brush) {
            return 3;
        }
        let hwnd = ui::create_window(
            "CHACHADec",
            "铁道资源解密",
            ui::px(700),
            ui::px(640),
            core::ptr::null_mut(),
        );
        if hwnd.is_null() {
            return 4;
        }
        ui::ShowWindow(hwnd, ui::SW_SHOWNORMAL);
        ui::UpdateWindow(hwnd);
        let code = ui::run_loop();
        ui::CoUninitialize();
        code
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if msg == ui::WM_CREATE {
        ui::set_userdata(hwnd, PENDING as usize);
        let st = &mut *(ui::get_userdata(hwnd) as *mut State);
        st.hwnd = hwnd;
        build(hwnd, st);
        return 0;
    }
    let st_ptr = ui::get_userdata(hwnd);
    if st_ptr == 0 {
        return ui::DefWindowProcW(hwnd, msg, w, l);
    }
    let st = &mut *(st_ptr as *mut State);
    match msg {
        ui::WM_GETMINMAXINFO => {
            ui::enforce_min(l, ui::px(560), ui::px(580));
            0
        }
        ui::WM_SIZE => {
            layout(st);
            0
        }
        ui::WM_CTLCOLORSTATIC | ui::WM_CTLCOLOREDIT => {
            ui::paint_text(w as ui::HDC, l as HWND, &st.ink, st.brush, ui::INK)
        }
        ui::WM_COMMAND => {
            let id = (w & 0xffff) as u16 as i32;
            command(st, id);
            0
        }
        ui::WM_TIMER => {
            if w == TIMER_PROGRESS {
                poll_progress(st);
            }
            0
        }
        ui::WM_APP_DONE => {
            finish(st);
            0
        }
        ui::WM_CLOSE => {
            if st.busy {
                if let Some(j) = &st.job {
                    j.cancel();
                }
                ui::set_text(st.status, "正在取消，请稍候…");
                return 0;
            }
            ui::DestroyWindow(hwnd);
            0
        }
        ui::WM_DESTROY => {
            if let Some(j) = &st.job {
                j.cancel();
            }
            if let Some(h) = st.worker.take() {
                let _ = h.join();
            }
            ui::KillTimer(hwnd, TIMER_PROGRESS);
            ui::PostQuitMessage(0);
            0
        }
        _ => ui::DefWindowProcW(hwnd, msg, w, l),
    }
}

unsafe fn build(hwnd: HWND, st: &mut State) {
    let (f_title, f_body, f_head, f_mono) = (st.fonts[0], st.fonts[1], st.fonts[2], st.fonts[3]);
    st.title = ui::label(hwnd, ID_TITLE, "铁道资源解密");
    st.sub = ui::label(
        hwnd,
        ID_SUB,
        "选择加密包即可看到包内文件；导入密钥文件后原样还原整个文件夹。",
    );
    st.h1 = ui::label(hwnd, ID_H1, "①  选择加密包");
    st.path_pkg = ui::path_field(hwnd, ID_PATH_PKG, "（尚未选择）");
    st.btn_pkg = ui::button(hwnd, ID_BTN_PKG, "浏览…", false);
    st.info = ui::label(hwnd, ID_INFO, "选择后这里显示包信息与文件清单。");

    st.h2 = ui::label(hwnd, ID_H2, "②  导入密钥文件");
    st.path_key = ui::path_field(hwnd, ID_PATH_KEY, "（尚未选择）");
    st.btn_key = ui::button(hwnd, ID_BTN_KEY, "浏览…", false);
    st.info2 = ui::label(hwnd, ID_INFO2, "未导入密钥");

    st.h3 = ui::label(hwnd, ID_H3, "③  还原到");
    st.path_out = ui::path_field(hwnd, ID_PATH_OUT, "（尚未选择）");
    st.btn_out = ui::button(hwnd, ID_BTN_OUT, "浏览…", false);
    st.btn_open = ui::button(hwnd, ID_BTN_OPEN, "打开结果", false);
    ui::enable(st.btn_open, false);

    st.list = ui::List::new(
        hwnd,
        ID_LIST,
        &[("包内文件", 370), ("大小", 95), ("修改时间", 145)],
    );
    st.status = ui::label(hwnd, ID_STATUS, "就绪");
    st.bar = ui::progress(hwnd, ID_BAR);
    st.btn_go = ui::button(hwnd, ID_BTN_GO, "解 密 还 原", true);
    st.btn_cancel = ui::button(hwnd, ID_BTN_CANCEL, "取消", false);
    ui::show(st.btn_cancel, false);
    ui::enable(st.btn_go, false);
    for h in &[
        st.sub, st.info, st.info2, st.status,
    ] {
        ui::set_font(*h, f_body);
    }
    ui::set_font(st.title, f_title);
    ui::set_font(st.h1, f_head);
    ui::set_font(st.h2, f_head);
    ui::set_font(st.h3, f_head);
    ui::set_font(st.path_pkg, f_mono);
    ui::set_font(st.path_key, f_mono);
    ui::set_font(st.path_out, f_mono);
    ui::set_font(st.list.hwnd, f_body);
    for b in &[st.btn_pkg, st.btn_key, st.btn_out, st.btn_go, st.btn_cancel, st.btn_open] {
        ui::set_font(*b, f_body);
    }
    layout(st);
    // 命令行预填：双击密钥文件、或快捷方式里写死路径时，界面直接就绪。
    if let Some(p) = st.prefill_pkg.clone() {
        load_package(st, &p);
    }
    if let Some(p) = st.prefill_key.clone() {
        load_key(st, &p);
    }
    if let Some(p) = st.prefill_out.clone() {
        load_out(st, &p);
    }
    refresh(st);
}

unsafe fn layout(st: &mut State) {
    if st.title.is_null() {
        return;
    }
    let mut rc = ui::RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    ui::GetClientRect(st.hwnd, &mut rc);
    let m = ui::px(22);
    let w = rc.right - rc.left;
    let inner = w - m * 2;
    let btn_w = ui::px(96);
    let row_h = ui::px(24);
    let gap = ui::px(6);

    let mut y = m;
    ui::MoveWindow(st.title, m, y, inner, ui::px(24), 1);
    y += ui::px(28);
    ui::MoveWindow(st.sub, m, y, inner, ui::px(16), 1);
    y += ui::px(26);

    ui::MoveWindow(st.h1, m, y, inner, ui::px(16), 1);
    y += ui::px(20);
    ui::MoveWindow(st.btn_pkg, w - m - btn_w, y - 1, btn_w, row_h + 2, 1);
    ui::MoveWindow(st.path_pkg, m, y, inner - btn_w - gap, row_h, 1);
    y += row_h + ui::px(4);
    ui::MoveWindow(st.info, m, y, inner, ui::px(16), 1);
    y += ui::px(22);

    ui::MoveWindow(st.h2, m, y, inner, ui::px(16), 1);
    y += ui::px(20);
    ui::MoveWindow(st.btn_key, w - m - btn_w, y - 1, btn_w, row_h + 2, 1);
    ui::MoveWindow(st.path_key, m, y, inner - btn_w - gap, row_h, 1);
    y += row_h + ui::px(4);
    ui::MoveWindow(st.info2, m, y, inner, ui::px(16), 1);
    y += ui::px(22);

    ui::MoveWindow(st.h3, m, y, inner, ui::px(16), 1);
    y += ui::px(20);
    let small_w = ui::px(84);
    ui::MoveWindow(st.btn_out, w - m - btn_w, y - 1, btn_w, row_h + 2, 1);
    ui::MoveWindow(st.btn_open, w - m - btn_w - small_w - gap, y - 1, small_w, row_h + 2, 1);
    ui::MoveWindow(
        st.path_out,
        m,
        y,
        inner - btn_w - small_w - gap * 2,
        row_h,
        1,
    );
    y += row_h + ui::px(14);

    let status_h = ui::px(16);
    let btn_h = ui::px(34);
    let bar_h = ui::px(16);
    let bottom = rc.bottom - m;
    let btn_y = bottom - btn_h;
    let bar_y = btn_y - ui::px(8) - bar_h;
    let status_y = bar_y - ui::px(4) - status_h;
    let list_top = y;
    let list_bottom = status_y - ui::px(8);
    let list_h = if list_bottom > list_top + ui::px(60) {
        list_bottom - list_top
    } else {
        ui::px(60)
    };
    ui::MoveWindow(st.list.hwnd, m, list_top, inner, list_h, 1);
    st.list.layout_three_cols(inner);
    ui::MoveWindow(st.status, m, status_y, inner, status_h, 1);
    ui::MoveWindow(st.bar, m, bar_y, inner, bar_h, 1);
    let cancel_w = ui::px(96);
    let go_w = if st.busy { inner - cancel_w - gap } else { inner };
    ui::MoveWindow(st.btn_go, m, btn_y, go_w, btn_h, 1);
    ui::MoveWindow(st.btn_cancel, w - m - cancel_w, btn_y, cancel_w, btn_h, 1);
}

unsafe fn command(st: &mut State, id: i32) {
    if st.busy && id != ID_BTN_CANCEL && id != IDCANCEL {
        return;
    }
    match id {
        ID_BTN_PKG => pick_package(st),
        ID_BTN_KEY => pick_key(st),
        ID_BTN_OUT => pick_out(st),
        ID_BTN_GO => start(st),
        ID_BTN_CANCEL => {
            if let Some(j) = &st.job {
                j.cancel();
            }
            ui::set_text(st.status, "正在取消…");
        }
        ID_BTN_OPEN => {
            if let Some(p) = st.restored.clone() {
                ui::reveal(&p);
            }
        }
        IDCANCEL => {
            if st.busy {
                if let Some(j) = &st.job {
                    j.cancel();
                }
            } else {
                ui::DestroyWindow(st.hwnd);
            }
        }
        _ => {}
    }
}

unsafe fn pick_package(st: &mut State) {
    if let Some(p) = ui::pick_folder(st.hwnd, "选择加密包（包含 package.chx 的文件夹）") {
        load_package(st, &p);
    }
    refresh(st);
}

/// 只读清单就能列出包内文件——这是解密端第 ① 步的意义。
unsafe fn load_package(st: &mut State, p: &Path) {
    st.restored = None;
    ui::enable(st.btn_open, false);
    match package::open_package(p) {
        Ok(pkg) => {
            ui::set_text(st.path_pkg, &p.to_string_lossy());
            fill_list(st, &pkg);
            st.pkg_dir = Some(p.to_path_buf());
            st.pkg = Some(Arc::new(pkg));
            // 换包后还原位置要重挑，但已载入的密钥留着——它会立刻重新校验，
            // 配对不上就当场提示，不用用户再导一次。
            st.out_dir = None;
            ui::set_text(st.path_out, "（尚未选择）");
            ui::set_text(st.status, "清单预览未认证");
            validate_key(st);
        }
        Err(e) => {
            st.pkg = None;
            st.pkg_dir = None;
            st.out_dir = None;
            st.list.clear();
            ui::set_text(st.path_pkg, "（尚未选择）");
            ui::set_text(st.path_out, "（尚未选择）");
            ui::set_text(st.info, "无法读取该加密包。");
            validate_key(st);
            ui::error(st.hwnd, "无法打开加密包", &e);
        }
    }
}

unsafe fn fill_list(st: &mut State, pkg: &package::Package) {
    st.list.clear();
    let cap = 5000;
    let mut n = 0usize;
    for d in &pkg.dirs {
        if n >= cap {
            break;
        }
        st.list.add(&[&format!("{}/", d), "-", "-"]);
        n += 1;
    }
    for (file_index, f) in pkg.files.iter().enumerate() {
        if n >= cap {
            st.list.add(&[&format!("… 其余 {} 项文件未显示", pkg.files.len() - file_index), "", ""]);
            break;
        }
        st.list.add(&[&f.rel, &util::format_size(f.size), &util::format_time(f.mtime)]);
        n += 1;
    }
}

unsafe fn pick_key(st: &mut State) {
    let filter = ui::make_filter(&[("CHACHA 密钥文件", "*.chacha.key"), ("所有文件", "*.*")]);
    let initial: PathBuf = st
        .pkg_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("key.chacha.key"));
    if let Some(p) = ui::pick_file(st.hwnd, "选择密钥文件", &filter, &initial) {
        load_key(st, &p);
    }
    refresh(st);
}

/// 读密钥文件并立刻做完整性校验：不对就在界面上说清楚，别等解到一半才失败。
unsafe fn load_key(st: &mut State, p: &Path) {
    ui::set_text(st.path_key, &p.to_string_lossy());
    st.key_path = Some(p.to_path_buf());
    reload_key(st);
    if let Some(e) = &st.key_error {
        if e != package::KEY_EXHAUSTED {
            ui::error(st.hwnd, "密钥文件读取失败", e);
        }
    }
}

unsafe fn reload_key(st: &mut State) {
    st.keyfile = None;
    st.key_error = None;
    if let Some(p) = &st.key_path {
        match package::read_key_file(p) {
            Ok(kf) => st.keyfile = Some(kf),
            Err(e) => st.key_error = Some(e),
        }
    }
    validate_key(st);
}

/// 密钥与加密包是两件事，谁先到都行：凑齐了才判定配对，缺谁就提示缺谁。
unsafe fn validate_key(st: &mut State) {
    let kf = st.keyfile.clone();
    let pkg = st.pkg.as_ref().map(|p| Arc::clone(p));
    st.key_ok = false;
    let text = match (&kf, &pkg) {
        (None, _) if st.key_error.is_some() => st.key_error.as_deref().unwrap(),
        (None, Some(_)) => "清单未认证，未导入密钥",
        (None, None) => "未导入密钥",
        (Some(k), _) if k.remaining == Some(0) => package::KEY_EXHAUSTED,
        (Some(_), None) => "密钥已载入，请先选择加密包",
        (Some(k), Some(p)) => {
            let bound_ok = !k.bound || k.id == p.id;
            let good = bound_ok && package::check_key(p, &k.key);
            st.key_ok = good;
            if good {
                "清单已认证，可以还原"
            } else if !bound_ok {
                "清单未认证，密钥与加密包不配对"
            } else {
                "清单未认证：密钥错误或清单已被改动"
            }
        }
    };
    ui::set_text(st.info2, text);
    if let Some(p) = &pkg {
        ui::set_text(
            st.info,
            &format!(
                "{} · 源文件夹 {} · {} 个文件 · {} · 创建于 {}",
                if st.key_ok { "已认证" } else { "未认证预览" },
                p.src_name,
                p.file_count(),
                p.size_text(),
                util::format_time(p.created)
            ),
        );
    }
}

unsafe fn pick_out(st: &mut State) {
    if let Some(p) = ui::pick_folder(st.hwnd, "选择还原位置（将在其中建立同名文件夹）") {
        load_out(st, &p);
    }
    refresh(st);
}

unsafe fn load_out(st: &mut State, p: &Path) {
    st.restored = None;
    ui::enable(st.btn_open, false);
    st.out_dir = Some(p.to_path_buf());
    let target = st.pkg.as_ref()
        .map(|pkg| package::restore_target(p, pkg))
        .unwrap_or_else(|| p.join("restored"));
    ui::set_text(st.path_out, &target.to_string_lossy());
}

unsafe fn refresh(st: &mut State) {
    if st.busy {
        return;
    }
    let ready = st.pkg.is_some() && st.key_path.is_some() && st.key_ok && st.out_dir.is_some();
    ui::enable(st.btn_go, ready);
    let hint = if st.key_error.as_deref() == Some(package::KEY_EXHAUSTED) {
        package::KEY_EXHAUSTED
    } else if st.pkg.is_none() {
        "请先选择加密包"
    } else if !st.key_ok {
        "清单未认证，请导入正确的密钥文件"
    } else if st.out_dir.is_none() {
        "请选择还原位置"
    } else {
        "就绪：点击「解密还原」"
    };
    ui::set_text(st.status, hint);
}

unsafe fn start(st: &mut State) {
    if st.busy {
        return;
    }
    let (dir, pkg, key_path) = match (&st.pkg_dir, &st.pkg, &st.key_path) {
        (Some(d), Some(p), Some(k)) => (d.clone(), Arc::clone(p), k.clone()),
        _ => return,
    };
    reload_key(st);
    refresh(st);
    if let Some(e) = &st.key_error {
        if e != package::KEY_EXHAUSTED {
            ui::error(st.hwnd, "密钥文件读取失败", e);
        }
        return;
    }
    if !st.key_ok {
        ui::error(st.hwnd, "密钥无效", "密钥无法通过这个加密包的完整性校验，请确认密钥文件是否正确。");
        return;
    }
    let out = match &st.out_dir {
        Some(o) => package::restore_target(o, &pkg),
        None => return,
    };
    match std::fs::symlink_metadata(&out) {
        Ok(_) => {
            ui::error(st.hwnd, "目标已存在", "还原目标已存在，不能覆盖（空文件夹也不例外）。请选择另一个还原位置。\n已有内容不会被改动。");
            return;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            ui::error(st.hwnd, "无法检查还原位置", &e.to_string());
            return;
        }
    }
    let job = Job::new(pkg.total_bytes, pkg.file_count());
    st.job = Some(Arc::clone(&job));
    st.done = Arc::new(Mutex::new(None));
    let done: Done = Arc::clone(&st.done);
    st.busy = true;
    st.restored = Some(out.clone());
    ui::enable(st.btn_go, false);
    ui::enable(st.btn_pkg, false);
    ui::enable(st.btn_key, false);
    ui::enable(st.btn_out, false);
    ui::enable(st.btn_open, false);
    ui::show(st.btn_cancel, true);
    layout(st);
    ui::set_progress(st.bar, 0);
    ui::set_text(st.status, "准备中…");
    ui::SetTimer(st.hwnd, TIMER_PROGRESS, 100, 0);

    let hwnd_c = st.hwnd as usize;
    let threads = pool::cpu_count();
    let worker = std::thread::spawn(move || {
        let r = package::restore_package_with_key_file(&dir, &pkg, &key_path, &out, &job, threads);
        if let Ok(mut g) = done.lock() {
            *g = Some(r);
        }
        ui::PostMessageW(hwnd_c as HWND, ui::WM_APP_DONE, 0, 0);
    });
    st.worker = Some(worker);
}

unsafe fn poll_progress(st: &mut State) {
    if !st.busy {
        return;
    }
    let job = match &st.job {
        Some(j) => Arc::clone(j),
        None => return,
    };
    let perm = job.permille() as i32;
    ui::set_progress(st.bar, perm);
    let name = job.current_name();
    let txt = format!(
        "解密中 {}%  ·  {} / {}  ·  {}",
        perm / 10,
        util::format_size(job.done_bytes()),
        util::format_size(job.total_bytes()),
        if name.is_empty() { "…" } else { &name }
    );
    ui::set_text(st.status, &txt);
}

unsafe fn finish(st: &mut State) {
    ui::KillTimer(st.hwnd, TIMER_PROGRESS);
    st.busy = false;
    ui::show(st.btn_cancel, false);
    ui::enable(st.btn_pkg, true);
    ui::enable(st.btn_key, true);
    ui::enable(st.btn_out, true);
    if let Some(h) = st.worker.take() {
        let _ = h.join();
    }
    let res = match st.done.lock() {
        Ok(mut g) => g.take(),
        Err(_) => None,
    };
    reload_key(st);
    refresh(st);
    match res {
        Some(Ok(sum)) => {
            ui::set_progress(st.bar, 1000);
            ui::set_text(
                st.status,
                &format!(
                    "完成：{} 个文件 · {} · {:.1} 秒 · {}",
                    sum.files,
                    util::format_size(sum.bytes),
                    sum.secs,
                    sum.rate()
                ),
            );
            ui::enable(st.btn_open, true);
            let where_ = st
                .restored
                .clone()
                .unwrap_or_else(|| PathBuf::from("(未知)"));
            util::save_settings(
                "chacha-dec",
                &[(
                    "out",
                    st.out_dir
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )],
            );
            ui::info(
                st.hwnd,
                "还原完成",
                &format!(
                    "已还原 {} 个文件（{}）到：\n{}\n\n文件内容与目录结构按加密前原样恢复，修改时间也已还原。",
                    sum.files,
                    util::format_size(sum.bytes),
                    where_.display()
                ),
            );
        }
        Some(Err(e)) => {
            st.restored = None;
            ui::set_progress(st.bar, 0);
            ui::set_text(st.status, "未完成");
            if e == "已取消" {
                ui::warn(st.hwnd, "已取消", "解密已取消，输出文件夹里可能残留不完整的内容。");
            } else {
                ui::error(st.hwnd, "解密失败", &e);
            }
        }
        None => {
            st.restored = None;
            ui::set_progress(st.bar, 0);
            ui::set_text(st.status, "未完成：工作线程未返回结果");
        }
    }
    layout(st);
}

/// 命令行入口：`chacha-dec --decrypt <B> --key <K> --out <目录>`
pub fn cli(args: &[String]) -> i32 {
    let mut pkg: Option<PathBuf> = None;
    let mut keyf: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--decrypt" if i + 1 < args.len() => {
                pkg = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--key" if i + 1 < args.len() => {
                keyf = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--out" if i + 1 < args.len() => {
                out = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let (pkg, keyf, out) = match (pkg, keyf, out) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            util::console::print("用法: chacha-dec --decrypt <加密包B> --key <密钥文件> --out <还原目录>\n");
            return 2;
        }
    };
    let p = match package::open_package(&pkg) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            return 1;
        }
    };
    let kf = match package::read_key_file(&keyf) {
        Ok(k) => k,
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            return 1;
        }
    };
    if (kf.bound && kf.id != p.id) || !package::check_key(&p, &kf.key) {
        util::console::eprint("密钥不正确，或与这个加密包不配对。\n");
        return 1;
    }
    let target = package::restore_target(&out, &p);
    let job = Job::new(p.total_bytes, p.file_count());
    match package::restore_package_with_key_file(&pkg, &p, &keyf, &target, &job, pool::cpu_count()) {
        Ok(s) => {
            util::console::print(&format!(
                "已还原 {} 个文件 · {} · {:.1}s ({})\n→ {}\n",
                s.files,
                util::format_size(s.bytes),
                s.secs,
                s.rate(),
                target.display()
            ));
            0
        }
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            1
        }
    }
}

pub fn usage() {
    util::console::print(
        "CHACHA 解密端\n\
         \n\
         图形界面:\n\
         \x20 chacha-dec                                   打开界面\n\
         \x20 chacha-dec <加密包B>                          预填第 ① 步（支持拖到图标 / 打开方式）\n\
         \x20 chacha-dec <密钥文件>                          预填第 ② 步\n\
         \x20 chacha-dec <B> --key <K> --out <目录>          三步全预填，打开就能直接点解密\n\
         \n\
         命令行:\n\
         \x20 chacha-dec --info <B>                          列出包内文件（无需密钥）\n\
         \x20 chacha-dec --decrypt <B> --key <K> --out <D>    解密还原到 D\\<原文件夹名>\n\
         \x20 chacha-dec --self-test                         自检加密内核与完整往返\n\
         \x20 chacha-dec --bench                             测速\n",
    );
}
