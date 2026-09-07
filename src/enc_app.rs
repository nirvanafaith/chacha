//! 加密端：文件夹 A → 加密包 B + 密钥文件。
//!
//! 界面按「① 选源 → ② 定位置 → ③ 开始」三步排布，主操作在拇指区（底部），
//! 未满足前置条件的步骤按钮保持禁用，避免误操作。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::crypto;
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
const ID_PATH_SRC: i32 = 11;
const ID_PATH_DST: i32 = 12;
const ID_PATH_KEY: i32 = 13;
const ID_BTN_SRC: i32 = 21;
const ID_BTN_DST: i32 = 22;
const ID_BTN_COPY: i32 = 23;
const ID_BTN_OPEN: i32 = 24;
const ID_BTN_GO: i32 = 25;
const ID_BTN_CANCEL: i32 = 26;
const ID_LIST: i32 = 31;
const ID_BAR: i32 = 32;
const ID_USES_LABEL: i32 = 33;
const ID_USES: i32 = 34;

const CBS_DROPDOWNLIST: u32 = 0x0003;
const CB_ADDSTRING: u32 = 0x0143;
const CB_GETCURSEL: u32 = 0x0147;
const CB_SETCURSEL: u32 = 0x014e;

const IDCANCEL: i32 = 2;
const TIMER_PROGRESS: usize = 1;

enum EncError {
    Package(String),
    KeySave(package::Package, String),
}

type Done = Arc<Mutex<Option<Result<package::Package, EncError>>>>;

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
    uses_label: HWND,
    uses: HWND,
    info: HWND,
    status: HWND,
    path_src: HWND,
    path_dst: HWND,
    path_key: HWND,
    btn_src: HWND,
    btn_dst: HWND,
    btn_copy: HWND,
    btn_open: HWND,
    btn_go: HWND,
    btn_cancel: HWND,
    list: ui::List,
    bar: HWND,

    src: Option<PathBuf>,
    dst_parent: Option<PathBuf>,
    pkg_dir: Option<PathBuf>,
    key_path: Option<PathBuf>,
    key: Option<[u8; 32]>,
    issued_key: Option<([u8; 16], u64, u8)>,
    issued_uses: u8,
    unsaved_key: Option<([u8; 16], u64, u8)>,
    scan: Option<package::Scan>,

    busy: bool,
    job: Option<Arc<Job>>,
    done: Done,
    worker: Option<std::thread::JoinHandle<()>>,
    last_pkg: Option<PathBuf>,
    last_key: Option<PathBuf>,
    initial_src: Option<PathBuf>,
    initial_dst: Option<PathBuf>,
}

static mut PENDING: *mut State = core::ptr::null_mut();

/// 启动时预填：源文件夹、以及加密包的保存位置（父目录）。
pub struct Prefill {
    pub src: Option<PathBuf>,
    pub dst_parent: Option<PathBuf>,
}

impl Prefill {
    pub fn empty() -> Prefill {
        Prefill {
            src: None,
            dst_parent: None,
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
        uses_label: core::ptr::null_mut(),
        uses: core::ptr::null_mut(),
        info: core::ptr::null_mut(),
        status: core::ptr::null_mut(),
        path_src: core::ptr::null_mut(),
        path_dst: core::ptr::null_mut(),
        path_key: core::ptr::null_mut(),
        btn_src: core::ptr::null_mut(),
        btn_dst: core::ptr::null_mut(),
        btn_copy: core::ptr::null_mut(),
        btn_open: core::ptr::null_mut(),
        btn_go: core::ptr::null_mut(),
        btn_cancel: core::ptr::null_mut(),
        list: ui::List { hwnd: core::ptr::null_mut() },
        bar: core::ptr::null_mut(),
        src: None,
        dst_parent: None,
        pkg_dir: None,
        key_path: None,
        key: None,
        issued_key: None,
        issued_uses: 1,
        unsaved_key: None,
        scan: None,
        busy: false,
        job: None,
        done: Arc::new(Mutex::new(None)),
        worker: None,
        last_pkg: None,
        last_key: None,
        initial_src: pf.src.clone(),
        initial_dst: pf.dst_parent.clone(),
    });
    unsafe {
        PENDING = Box::into_raw(st);
        if !ui::register_class("CHACHAEnc", wnd_proc, brush) {
            return 3;
        }
        let hwnd = ui::create_window(
            "CHACHAEnc",
            "CHACHA · 文件夹加密",
            ui::px(680),
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
        let st = &mut *(PENDING as *mut State);
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
            if st.unsaved_key.is_some() && !ui::confirm(hwnd, "密钥尚未保存", "密钥文件尚未保存。关闭将丢失内存中的密钥，加密包将无法解密。\n建议取消关闭，使用「另存密钥」或「复制密钥」先备份。\n\n仍要关闭吗？") {
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
    st.title = ui::label(hwnd, ID_TITLE, "文件夹加密");
    st.sub = ui::label(
        hwnd,
        ID_SUB,
        "把整个文件夹加密成一个自包含的加密包，并生成一个密钥文件。",
    );
    st.h1 = ui::label(hwnd, ID_H1, "①  选择要加密的文件夹");
    st.path_src = ui::path_field(hwnd, ID_PATH_SRC, "（尚未选择）");
    st.btn_src = ui::button(hwnd, ID_BTN_SRC, "浏览…", false);
    st.info = ui::label(hwnd, ID_INFO, "选择后这里显示文件数量与总大小。");

    st.h2 = ui::label(hwnd, ID_H2, "②  加密包与密钥保存位置");
    st.path_dst = ui::path_field(hwnd, ID_PATH_DST, "（选择源文件夹后自动建议）");
    st.btn_dst = ui::button(hwnd, ID_BTN_DST, "改到别处…", false);
    st.h3 = ui::label(hwnd, ID_H3, "③  密钥文件");
    st.uses_label = ui::label(hwnd, ID_USES_LABEL, "可用次数");
    st.uses = ui::add(hwnd, "COMBOBOX", "", CBS_DROPDOWNLIST | ui::WS_TABSTOP, 0, ID_USES);
    for uses in 1..=7 {
        let text = ui::wide(&uses.to_string());
        ui::SendMessageW(st.uses, CB_ADDSTRING, 0, text.as_ptr() as LPARAM);
    }
    ui::SendMessageW(st.uses, CB_SETCURSEL, 0, 0);
    ui::set_font(st.uses_label, f_body);
    ui::set_font(st.uses, f_body);
    st.path_key = ui::path_field(hwnd, ID_PATH_KEY, "（与加密包同目录，可改）");
    st.btn_copy = ui::button(hwnd, ID_BTN_COPY, "复制密钥", false);
    st.btn_open = ui::button(hwnd, ID_BTN_OPEN, "打开位置", false);
    ui::enable(st.btn_copy, false);
    ui::enable(st.btn_open, false);

    st.list = ui::List::new(
        hwnd,
        ID_LIST,
        &[("文件", 350), ("大小", 95), ("修改时间", 145)],
    );
    st.status = ui::label(hwnd, ID_STATUS, "就绪");
    st.bar = ui::progress(hwnd, ID_BAR);
    st.btn_go = ui::button(hwnd, ID_BTN_GO, "开 始 加 密", true);
    st.btn_cancel = ui::button(hwnd, ID_BTN_CANCEL, "取消", false);
    ui::show(st.btn_cancel, false);
    ui::enable(st.btn_go, false);
    for h in &[
        st.title, st.sub, st.h1, st.info, st.h2, st.h3, st.path_key, st.status,
    ] {
        ui::set_font(*h, f_body);
    }
    ui::set_font(st.title, f_title);
    ui::set_font(st.h1, f_head);
    ui::set_font(st.h2, f_head);
    ui::set_font(st.h3, f_head);
    ui::set_font(st.path_src, f_mono);
    ui::set_font(st.path_dst, f_mono);
    ui::set_font(st.list.hwnd, f_body);
    ui::set_font(st.btn_src, f_body);
    ui::set_font(st.btn_dst, f_body);
    ui::set_font(st.btn_copy, f_body);
    ui::set_font(st.btn_open, f_body);
    ui::set_font(st.btn_go, f_body);
    ui::set_font(st.btn_cancel, f_body);
    layout(st);
    // 命令行预填：拖到图标上、或快捷方式里写死路径时，打开就能直接加密。
    if let Some(p) = st.initial_dst.clone() {
        st.dst_parent = Some(p);
    }
    if let Some(p) = st.initial_src.clone() {
        load_source(st, &p);
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
    let small_w = ui::px(84);
    let row_h = ui::px(24);
    let gap = ui::px(6);

    let mut y = m;
    ui::MoveWindow(st.title, m, y, inner, ui::px(24), 1);
    y += ui::px(28);
    ui::MoveWindow(st.sub, m, y, inner, ui::px(16), 1);
    y += ui::px(26);

    ui::MoveWindow(st.h1, m, y, inner, ui::px(16), 1);
    y += ui::px(20);
    ui::MoveWindow(st.btn_src, w - m - btn_w, y - 1, btn_w, row_h + 2, 1);
    ui::MoveWindow(st.path_src, m, y, inner - btn_w - gap, row_h, 1);
    y += row_h + ui::px(6);
    ui::MoveWindow(st.info, m, y, inner, ui::px(16), 1);
    y += ui::px(22);

    ui::MoveWindow(st.h2, m, y, inner, ui::px(16), 1);
    y += ui::px(20);
    ui::MoveWindow(st.btn_dst, w - m - btn_w, y - 1, btn_w, row_h + 2, 1);
    ui::MoveWindow(st.path_dst, m, y, inner - btn_w - gap, row_h, 1);
    y += row_h + ui::px(14);

    ui::MoveWindow(st.h3, m, y, ui::px(132), ui::px(16), 1);
    ui::MoveWindow(st.uses_label, m + ui::px(144), y, ui::px(62), ui::px(16), 1);
    ui::MoveWindow(st.uses, m + ui::px(210), y - ui::px(4), ui::px(60), ui::px(180), 1);
    y += ui::px(24);
    let mut x = w - m;
    x -= small_w;
    ui::MoveWindow(st.btn_open, x, y - 1, small_w, row_h + 2, 1);
    x -= small_w + gap;
    ui::MoveWindow(st.btn_copy, x, y - 1, small_w, row_h + 2, 1);
    x -= gap;
    ui::MoveWindow(st.path_key, m, y, x - m, row_h, 1);
    y += row_h + ui::px(16);

    // 底部固定区：状态 / 进度 / 主按钮
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
    ui::MoveWindow(
        st.btn_cancel,
        w - m - cancel_w,
        btn_y,
        cancel_w,
        btn_h,
        1,
    );
}

unsafe fn command(st: &mut State, id: i32) {
    if st.busy && id != ID_BTN_CANCEL && id != IDCANCEL {
        return;
    }
    if st.unsaved_key.is_some() && (id == ID_BTN_SRC || id == ID_BTN_DST || id == ID_BTN_GO) {
        return;
    }
    match id {
        ID_BTN_SRC => pick_source(st),
        ID_BTN_DST => pick_dest(st),
        ID_BTN_GO => start(st),
        ID_BTN_CANCEL => {
            if let Some(j) = &st.job {
                j.cancel();
            }
            ui::set_text(st.status, "正在取消…");
        }
        ID_BTN_COPY => copy_key(st),
        ID_BTN_OPEN => {
            if st.unsaved_key.is_some() {
                save_key_again(st);
                return;
            }
            if let Some(p) = st.last_pkg.clone() {
                ui::reveal(&p);
            }
        }
        IDCANCEL => {
            if st.busy {
                if let Some(j) = &st.job {
                    j.cancel();
                }
            } else {
                ui::PostMessageW(st.hwnd, ui::WM_CLOSE, 0, 0);
            }
        }
        _ => {}
    }
}

unsafe fn pick_source(st: &mut State) {
    if let Some(p) = ui::pick_folder(st.hwnd, "选择要加密的文件夹") {
        load_source(st, &p);
    }
    refresh(st);
}

/// 读入源文件夹：扫描、填清单、给出包与密钥的建议路径。
unsafe fn load_source(st: &mut State, p: &Path) {
    match package::scan_folder(p) {
        Ok(scan) => {
            let dirs = scan.dirs.len();
            ui::set_text(
                st.info,
                &format!(
                    "{} 个文件 · {} · {} 个子文件夹",
                    scan.files.len(),
                    util::format_size(scan.total),
                    dirs
                ),
            );
            st.scan = Some(scan);
            st.src = Some(p.to_path_buf());
            fill_list(st);
            suggest_paths(st);
            ui::set_text(st.path_src, &p.to_string_lossy());
        }
        Err(e) => {
            st.scan = None;
            st.src = None;
            st.list.clear();
            ui::set_text(st.path_src, "（尚未选择）");
            ui::set_text(st.info, "无法读取该文件夹。");
            ui::error(st.hwnd, "无法读取", &e);
        }
    }
}

unsafe fn pick_dest(st: &mut State) {
    if let Some(p) = ui::pick_folder(st.hwnd, "选择加密包的保存位置（其父文件夹）") {
        st.dst_parent = Some(p);
        suggest_paths(st);
    }
    refresh(st);
}

/// 根据源文件夹名与父目录算出包与密钥的完整路径（不覆盖已有内容）。
unsafe fn suggest_paths(st: &mut State) {
    let src = match &st.src {
        Some(s) => s.clone(),
        None => return,
    };
    let parent = st
        .dst_parent
        .clone()
        .unwrap_or_else(|| src.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")));
    let (pkg, key) = package::suggest_names(&src, &parent);
    st.pkg_dir = Some(pkg.clone());
    st.key_path = Some(key.clone());
    ui::set_text(st.path_dst, &pkg.to_string_lossy());
    ui::set_text(st.path_key, &key.to_string_lossy());
}

unsafe fn fill_list(st: &mut State) {
    st.list.clear();
    let scan = match &st.scan {
        Some(s) => s,
        None => return,
    };
    let cap = 3000;
    let mut n = 0usize;
    for (rel, size, mt) in &scan.files {
        if n >= cap {
            st.list.add(&[
                &format!("… 其余 {} 项未显示", scan.files.len() - n),
                "",
                "",
            ]);
            break;
        }
        st.list.add(&[rel, &util::format_size(*size), &util::format_time(*mt)]);
        n += 1;
    }
    for d in &scan.dirs {
        if n >= cap {
            break;
        }
        st.list.add(&[&format!("{}/", d), "-", "-"]);
        n += 1;
    }
}

unsafe fn refresh(st: &mut State) {
    let ready = st.src.is_some() && st.scan.is_some() && st.pkg_dir.is_some();
    ui::enable(st.uses, !st.busy && st.unsaved_key.is_none());
    if !st.busy {
        let unsaved = st.unsaved_key.is_some();
        ui::enable(st.btn_go, ready && !unsaved);
        ui::enable(st.btn_src, !unsaved);
        ui::enable(st.btn_dst, st.src.is_some() && !unsaved);
        let hint = if unsaved {
            "未完成：密钥未保存，请另存密钥或复制备份"
        } else if !ready {
            "请先选择要加密的文件夹"
        } else {
            "就绪：点击「开始加密」"
        };
        ui::set_text(st.status, hint);
    }
}

unsafe fn start(st: &mut State) {
    if st.busy || st.unsaved_key.is_some() {
        return;
    }
    let src = match &st.src {
        Some(p) => p.clone(),
        None => return,
    };
    let dst = match &st.pkg_dir {
        Some(p) => p.clone(),
        None => return,
    };
    let keyp = match &st.key_path {
        Some(p) => p.clone(),
        None => return,
    };
    if util::is_same_or_child(&src, &dst) {
        ui::error(st.hwnd, "位置冲突", "加密包不能放在要加密的文件夹里面，请换一个保存位置。");
        return;
    }
    if util::is_same_or_child(&dst, &src) {
        ui::error(st.hwnd, "位置冲突", "要加密的文件夹不能是加密包本身。");
        return;
    }
    let selection = ui::SendMessageW(st.uses, CB_GETCURSEL, 0, 0);
    if !(0..=6).contains(&selection) {
        ui::error(st.hwnd, "密钥次数无效", "请选择 1 到 7 次。");
        return;
    }
    let uses = selection as u8 + 1;
    st.issued_uses = uses;
    st.issued_key = None;
    st.key = None;
    st.last_pkg = None;
    st.last_key = None;
    ui::enable(st.btn_copy, false);
    ui::enable(st.btn_open, false);
    ui::set_text(st.btn_open, "打开位置");
    let total = st.scan.as_ref().map(|s| s.total).unwrap_or(0);
    let files = st.scan.as_ref().map(|s| s.files.len()).unwrap_or(0);
    let key = match package::new_key() {
        Ok(k) => k,
        Err(e) => {
            ui::error(st.hwnd, "随机数失败", &e);
            return;
        }
    };
    st.key = Some(key);
    let job = Job::new(total, files);
    st.job = Some(Arc::clone(&job));
    st.done = Arc::new(Mutex::new(None));
    let done: Done = Arc::clone(&st.done);
    st.busy = true;
    ui::enable(st.uses, false);
    ui::enable(st.btn_go, false);
    ui::enable(st.btn_src, false);
    ui::enable(st.btn_dst, false);
    ui::show(st.btn_cancel, true);
    layout(st);
    ui::set_progress(st.bar, 0);
    ui::set_text(st.status, "准备中…");
    ui::SetTimer(st.hwnd, TIMER_PROGRESS, 100, 0);

    let hwnd_c = st.hwnd as usize;
    let threads = pool::cpu_count();
    let worker = std::thread::spawn(move || {
        let r = match package::create_package(&src, &dst, &key, &job, threads) {
            Ok(pkg) => match package::write_key_file(&keyp, &pkg.id, pkg.created, &key, uses) {
                Ok(()) => Ok(pkg),
                Err(e) => Err(EncError::KeySave(pkg, e)),
            },
            Err(e) => Err(EncError::Package(e)),
        };
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
        "加密中 {}%  ·  {} / {}  ·  {}",
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
    ui::enable(st.btn_src, true);
    ui::enable(st.btn_dst, true);
    if let Some(h) = st.worker.take() {
        let _ = h.join();
    }
    let res = match st.done.lock() {
        Ok(mut g) => g.take(),
        Err(_) => None,
    };
    refresh(st);
    match res {
        Some(Ok(pkg)) => {
            st.issued_key = Some((pkg.id, pkg.created, st.issued_uses));
            ui::set_progress(st.bar, 1000);
            ui::set_text(
                st.status,
                &format!(
                    "完成：{} 个文件 · {}",
                    pkg.file_count(),
                    pkg.size_text()
                ),
            );
            ui::enable(st.btn_copy, true);
            ui::enable(st.btn_open, true);
            st.last_pkg = st.pkg_dir.clone();
            st.last_key = st.key_path.clone();
            let kp = st
                .key_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("(未知)"));
            let pd = st.pkg_dir.clone().unwrap_or_else(|| PathBuf::from("(未知)"));
            util::save_settings(
                "chacha-enc",
                &[("src", st.src.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default())],
            );
            ui::info(
                st.hwnd,
                "加密完成",
                &format!(
                    "加密包：{}\n密钥文件：{}\n\n请立即把密钥文件复制到安全的地方（U 盘、密码管理器）。\n密钥文件丢失将无法解密，软件本身不保存密钥。\n\n源文件夹未被改动，可自行删除前先核对。",
                    pd.display(),
                    kp.display()
                ),
            );
            // 下一次默认建议到别的名字，避免覆盖
            st.pkg_dir = None;
            st.key_path = None;
            suggest_paths(st);
        }
        Some(Err(EncError::KeySave(pkg, e))) => {
            st.issued_key = Some((pkg.id, pkg.created, st.issued_uses));
            st.unsaved_key = st.issued_key;
            st.last_pkg = st.pkg_dir.clone();
            st.last_key = None;
            ui::enable(st.btn_copy, true);
            ui::enable(st.btn_open, true);
            ui::set_text(st.btn_open, "另存密钥");
            ui::set_progress(st.bar, 0);
            refresh(st);
            ui::error(
                st.hwnd,
                "密钥保存失败",
                &format!("{}\n\n加密包已生成，但操作尚未完成。源文件夹未改动。\n请勿关闭窗口，点击「另存密钥」保存到可写位置。\n也可「复制密钥」，粘贴到纯文本文件后作为密钥文件导入解密端。", e),
            );
        }
        Some(Err(EncError::Package(e))) => {
            st.key = None;
            ui::set_progress(st.bar, 0);
            ui::set_text(st.status, "未完成");
            if e == "已取消" {
                ui::warn(st.hwnd, "已取消", "加密已取消。\n未完成的输出文件夹已清理，也没有写出密钥文件。");
            } else {
                ui::error(st.hwnd, "加密失败", &e);
            }
        }
        None => {
            st.key = None;
            ui::set_progress(st.bar, 0);
            ui::set_text(st.status, "未完成：工作线程未返回结果");
        }
    }
    layout(st);
}

unsafe fn save_key_again(st: &mut State) {
    let (id, created, uses, key) = match (st.unsaved_key, st.key) {
        (Some((id, created, uses)), Some(key)) => (id, created, uses, key),
        _ => return,
    };
    let initial = st.key_path.clone().unwrap_or_else(|| PathBuf::from("key.chacha.key"));
    let filter = ui::make_filter(&[("CHACHA 密钥文件", "*.chacha.key"), ("所有文件", "*.*")]);
    let path = match ui::save_file(st.hwnd, "另存密钥", &filter, &initial, "key") {
        Some(p) => p,
        None => return,
    };
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            ui::error(st.hwnd, "目标已存在", "请选择一个新的密钥文件名，不要覆盖已有文件。");
            return;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            ui::error(st.hwnd, "无法检查密钥位置", &e.to_string());
            return;
        }
    }
    if let Err(e) = package::write_key_file(&path, &id, created, &key, uses) {
        ui::error(st.hwnd, "密钥保存失败", &e);
        return;
    }
    st.unsaved_key = None;
    st.last_key = Some(path.clone());
    ui::set_text(st.btn_open, "打开位置");
    ui::set_progress(st.bar, 1000);
    suggest_paths(st);
    refresh(st);
    ui::set_text(st.status, "完成：密钥已保存");
    ui::info(st.hwnd, "密钥已保存", &format!("密钥文件：{}\n\n请将密钥文件备份到安全位置，丢失后将无法解密。", path.display()));
}

unsafe fn copy_key(st: &mut State) {
    let (key, id, created, uses) = match (st.key, st.issued_key) {
        (Some(key), Some((id, created, uses))) => (key, id, created, uses),
        _ => {
            ui::warn(st.hwnd, "没有密钥", "还没有生成密钥。");
            return;
        }
    };
    // Copy the issued envelope, independent of the selection for the next key.
    let envelope = match package::encode_key_file(&id, created, &key, uses) {
        Ok(bytes) => bytes,
        Err(e) => {
            ui::error(st.hwnd, "密钥编码失败", &e);
            return;
        }
    };
    let hex = util::hex_encode_grouped(&envelope);
    if ui::copy_text(st.hwnd, &hex) {
        ui::set_text(st.status, if st.unsaved_key.is_some() {
            "密钥已复制，尚未保存文件；请另存密钥或粘贴备份"
        } else {
            "密钥已复制到剪贴板（十六进制）"
        });
    } else {
        ui::warn(st.hwnd, "复制失败", "剪贴板被占用，请重试。");
    }
}

fn parse_uses(value: Option<&str>) -> Result<u8, &'static str> {
    match value {
        Some("1") => Ok(1),
        Some("2") => Ok(2),
        Some("3") => Ok(3),
        Some("4") => Ok(4),
        Some("5") => Ok(5),
        Some("6") => Ok(6),
        Some("7") => Ok(7),
        Some(_) => Err("--uses 必须是 1 到 7 的整数。\n"),
        None => Err("--uses 缺少参数，请指定 1 到 7。\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::{cli, parse_uses};

    #[test]
    fn accepts_all_supported_use_counts() {
        for uses in 1u8..=7 {
            assert_eq!(parse_uses(Some(&uses.to_string())), Ok(uses));
        }
    }

    #[test]
    fn rejects_missing_or_noncanonical_use_counts() {
        assert!(parse_uses(None).is_err());
        for value in &["", "0", "8", "255", "256", "-1", "+1", "01", "1.0", " 1", "1 ", "--keyout"] {
            assert!(parse_uses(Some(value)).is_err(), "accepted {:?}", value);
        }
    }

    #[test]
    fn cli_rejects_invalid_uses_before_io() {
        assert_eq!(cli(&["--uses".into()]), 2);
        assert_eq!(cli(&["--uses".into(), "0".into()]), 2);
        assert_eq!(cli(&["--uses".into(), "8".into()]), 2);
        assert_eq!(cli(&["--uses".into(), "--encrypt".into()]), 2);
    }
}

/// 命令行入口：`chacha-enc --encrypt <A> --package <B> --keyout <K> [--uses <1..7>]`
pub fn cli(args: &[String]) -> i32 {
    let mut src: Option<PathBuf> = None;
    let mut pkg: Option<PathBuf> = None;
    let mut keyout: Option<PathBuf> = None;
    let mut uses = 1u8;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--encrypt" if i + 1 < args.len() => {
                src = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--package" if i + 1 < args.len() => {
                pkg = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--keyout" if i + 1 < args.len() => {
                keyout = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--uses" => {
                uses = match parse_uses(args.get(i + 1).map(String::as_str)) {
                    Ok(value) => value,
                    Err(e) => {
                        util::console::eprint(e);
                        return 2;
                    }
                };
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let (src, pkg, keyout) = match (src, pkg, keyout) {
        (Some(a), Some(b), Some(k)) => (a, b, k),
        _ => {
            util::console::print("用法: chacha-enc --encrypt <文件夹A> --package <加密包B> --keyout <密钥文件> [--uses <1..7>]（默认 1 次）\n");
            return 2;
        }
    };
    match std::fs::symlink_metadata(&keyout) {
        Ok(_) => {
            util::console::eprint("密钥目标已存在，拒绝覆盖。\n");
            return 1;
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => {
            util::console::eprint(&format!("无法检查密钥目标：{}\n", e));
            return 1;
        }
    }
    let scan = match package::scan_folder(&src) {
        Ok(s) => s,
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            return 1;
        }
    };
    let key = match package::new_key() {
        Ok(k) => k,
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            return 1;
        }
    };
    let job = Job::new(scan.total, scan.files.len());
    let t0 = std::time::Instant::now();
    let j2 = Arc::clone(&job);
    let threads = pool::cpu_count();
    let r = package::create_package(&src, &pkg, &key, &j2, threads);
    match r {
        Ok(p) => {
            if let Err(e) = package::write_key_file(&keyout, &p.id, p.created, &key, uses) {
                util::console::eprint(&format!("{}\n", e));
                return 1;
            }
            let secs = t0.elapsed().as_secs_f64();
            util::console::print(&format!(
                "包 ID  {}\n文件  {}\n大小  {}\n用时  {:.1}s ({} MiB/s)\n加密包  {}\n密钥    {}\n",
                p.id_hex(),
                p.file_count(),
                p.size_text(),
                secs,
                (scan.total as f64 / (1024.0 * 1024.0)) / secs.max(1e-6),
                pkg.display(),
                keyout.display()
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
        "CHACHA 加密端\n\
         \n\
         图形界面:\n\
         \x20 chacha-enc                                 打开界面\n\
         \x20 chacha-enc <文件夹A>                        预填第 ① 步（支持拖到图标 / 打开方式）\n\
         \x20 chacha-enc <A> --to <目录>                   再指定加密包存到哪里\n\
         \n\
         命令行:\n\
         \x20 chacha-enc --encrypt <A> --package <B> --keyout <K> [--uses <1..7>]   加密 A，产出包 B 与密钥 K\n\
         \x20 --uses <1..7>                             密钥可用次数，默认 1 次\n\
         \x20 chacha-enc --info <B>                      查看加密包清单（无需密钥）\n\
         \x20 chacha-enc --self-test                     自检加密内核与完整往返\n\
         \x20 chacha-enc --bench                         测速（各加速档位）\n",
    );
}

/// 打印包清单，两个端都用得到。
pub fn print_package_info(dir: &Path) -> i32 {
    match package::open_package(dir) {
        Ok(p) => {
            util::console::print(&format!(
                "包 ID    {}\n源文件夹  {}\n创建于    {}\n文件    {} 个 · {}\n\n",
                p.id_hex(),
                if p.src_path.is_empty() { &p.src_name } else { &p.src_path },
                util::format_time(p.created),
                p.file_count(),
                p.size_text()
            ));
            for f in &p.files {
                util::console::print(&format!(
                    "  {:<56} {:>10}  {}\n",
                    f.rel,
                    util::format_size(f.size),
                    util::format_time(f.mtime)
                ));
            }
            0
        }
        Err(e) => {
            util::console::eprint(&format!("{}\n", e));
            1
        }
    }
}

pub fn bench() {
    let len = 8 * 1024 * 1024;
    for t in [crypto::Tier::Scalar, crypto::Tier::Sse2, crypto::Tier::Avx2].iter() {
        let r = crypto::throughput(*t, len);
        util::console::print(&format!("{:<10} {:>8.0} MiB/s\n", crypto::tier_name(*t), r));
    }
    util::console::print(&format!(
        "当前使用  {}（{} 线程）\n",
        crypto::tier_name(crypto::best_tier()),
        pool::cpu_count()
    ));
}
