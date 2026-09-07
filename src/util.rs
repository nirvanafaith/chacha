//! 通用工具：字节序、十六进制、随机数、路径、时间、设置文件。

#![allow(dead_code)]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const PKG_ID_LEN: usize = 16;

pub fn read_u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

pub fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn read_u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub fn write_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_encode_grouped(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2 + bytes.len() / 2);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push(' ');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut nibble: Option<u8> = None;
    for c in s.chars() {
        if c.is_whitespace() || c == '-' || c == ':' {
            continue;
        }
        let v = match c {
            '0'..='9' => c as u8 - b'0',
            'a'..='f' => c as u8 - b'a' + 10,
            'A'..='F' => c as u8 - b'A' + 10,
            _ => return Err("密钥含有非法字符".to_string()),
        };
        match nibble {
            None => nibble = Some(v),
            Some(hi) => {
                out.push((hi << 4) | v);
                nibble = None;
            }
        }
    }
    if nibble.is_some() {
        return Err("密钥长度不是偶数".to_string());
    }
    Ok(out)
}

/// 长度无关的恒定时间比较，用于校验标签。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// 密钥文件完整性用的 CRC-32（IEEE，逐位实现，无查表）。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        let mut i = 0;
        while i < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
            i += 1;
        }
    }
    !crc
}

pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn ensure_dir(path: &Path) -> io::Result<()> {
    if path.exists() {
        if path.is_dir() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "路径已存在且不是文件夹",
            ))
        }
    } else {
        fs::create_dir_all(path)
    }
}

pub fn format_size(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if n >= GB {
        format!("{:.2} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1} KB", n as f64 / KB as f64)
    } else {
        format!("{} B", n)
    }
}

/// 当前 UTC 时间戳，单位是「自 1970-01-01 起的 100 纳秒间隔数」。
/// NTFS 存修改时间用的就是这个刻度，所以只有按它存，才能真正做到原样还原。
pub fn now_stamp() -> u64 {
    stamp_from_systemtime(std::time::SystemTime::now())
}

pub fn stamp_from_systemtime(t: std::time::SystemTime) -> u64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d
            .as_secs()
            .saturating_mul(10_000_000)
            .saturating_add((d.subsec_nanos() / 100) as u64),
        // 1970 年以前的时间戳：存 0，还原时按"不设时间"处理
        Err(_) => 0,
    }
}

pub fn join_rel(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        p.push(part);
    }
    p
}

pub fn path_to_rel(root: &Path, file: &Path) -> Option<String> {
    let rel = file.strip_prefix(root).ok()?;
    let mut s = String::new();
    for (i, c) in rel.components().enumerate() {
        match c {
            std::path::Component::Normal(os) => {
                if i > 0 {
                    s.push('/');
                }
                s.push_str(&os.to_string_lossy());
            }
            _ => return None,
        }
    }
    Some(s)
}

/// `child` 是否等于或在 `parent` 之内（大小写不敏感，忽略结尾分隔符）。
pub fn is_same_or_child(parent: &Path, child: &Path) -> bool {
    let norm = |p: &Path| -> String {
        let s = p.to_string_lossy().replace('/', "\\");
        let s = s.trim_end_matches('\\').to_lowercase();
        s
    };
    let a = norm(parent);
    let b = norm(child);
    b == a || b.starts_with(&format!("{}\\", a))
}

/// 同目录下不冲突的新名字：`x` → `x (2)` → `x (3)` …
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let mut n = 2;
    loop {
        let cand = dir.join(format!("{} ({}){}", stem, n, ext));
        if !cand.exists() {
            return cand;
        }
        n += 1;
        if n > 999 {
            return cand;
        }
    }
}

pub fn write_all_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path)
}

// -------------------- 设置文件（记住上次路径） --------------------

pub fn settings_path(app: &str) -> PathBuf {
    exe_dir().join(format!("{}.settings", app))
}

pub fn load_settings(app: &str) -> Vec<(String, String)> {
    let p = settings_path(app);
    let s = match fs::read_to_string(&p) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in s.lines() {
        if let Some(i) = line.find('=') {
            out.push((line[..i].trim().to_string(), line[i + 1..].trim().to_string()));
        }
    }
    out
}

pub fn save_settings(app: &str, kv: &[(&str, String)]) {
    let mut s = String::new();
    for (k, v) in kv {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    let _ = fs::write(settings_path(app), s.as_bytes());
}

pub fn setting(map: &[(String, String)], key: &str) -> Option<PathBuf> {
    map.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| PathBuf::from(v))
        .filter(|p| !p.as_os_str().is_empty())
}

// -------------------- 时间与文件属性（Win32） --------------------

#[cfg(windows)]
mod win {
    use super::*;
    use core::ffi::c_void;

    #[repr(C)]
    struct FILETIME {
        lo: u32,
        hi: u32,
    }

    #[repr(C)]
    struct SYSTEMTIME {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        min: u16,
        sec: u16,
        ms: u16,
    }

    extern "system" {
        fn FileTimeToLocalFileTime(utc: *const FILETIME, local: *mut FILETIME) -> i32;
        fn FileTimeToSystemTime(ft: *const FILETIME, st: *mut SYSTEMTIME) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn SetFileTime(h: *mut c_void, c: *const FILETIME, a: *const FILETIME, w: *const FILETIME) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    const OPEN_EXISTING: u32 = 3;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_SHARE_ALL: u32 = 0x07;

    /// 100ns 间隔（自 1970）→ FILETIME（100ns 间隔，自 1601）。
    /// 1601-01-01 到 1970-01-01 = 369 年 = 11644473600 秒 = 116_444_736_000_000_000 个 100ns。
    fn stamp_to_ft(stamp: u64) -> FILETIME {
        let t = stamp.saturating_add(116_444_736_000_000_000);
        FILETIME {
            lo: (t & 0xffff_ffff) as u32,
            hi: (t >> 32) as u32,
        }
    }

    /// 时间戳 → "2026-09-01 21:59"（本地时区）。
    pub fn format_time(stamp: u64) -> String {
        if stamp == 0 {
            return "-".to_string();
        }
        unsafe {
            let utc = stamp_to_ft(stamp);
            let mut local = FILETIME { lo: 0, hi: 0 };
            if FileTimeToLocalFileTime(&utc, &mut local) == 0 {
                return "-".to_string();
            }
            let mut st = SYSTEMTIME {
                year: 0,
                month: 0,
                day_of_week: 0,
                day: 0,
                hour: 0,
                min: 0,
                sec: 0,
                ms: 0,
            };
            if FileTimeToSystemTime(&local, &mut st) == 0 {
                return "-".to_string();
            }
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                st.year, st.month, st.day, st.hour, st.min
            )
        }
    }

    pub fn set_mtime(path: &Path, stamp: u64) {
        let _ = try_set_mtime(path, stamp);
    }

    pub fn try_set_mtime(path: &Path, stamp: u64) -> std::io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path.as_os_str().encode_wide()
            .chain(std::iter::once(0)).collect();
        unsafe {
            let h = CreateFileW(
                wide.as_ptr(),
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_ALL,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS permits directory handles.
                core::ptr::null_mut(),
            );
            if h as isize == -1 || h.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let ft = stamp_to_ft(stamp);
            let result = if SetFileTime(h, core::ptr::null(), core::ptr::null(), &ft) == 0 {
                Err(std::io::Error::last_os_error())
            } else { Ok(()) };
            CloseHandle(h);
            result
        }
    }
}

#[cfg(windows)]
pub use self::win::{format_time, set_mtime, try_set_mtime};

#[cfg(not(windows))]
pub fn format_time(stamp: u64) -> String {
    if stamp == 0 {
        "-".to_string()
    } else {
        format!("@{}", stamp / 10_000_000)
    }
}

#[cfg(not(windows))]
pub fn set_mtime(_path: &Path, _stamp: u64) {}

#[cfg(not(windows))]
pub fn try_set_mtime(_path: &Path, _stamp: u64) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Other, "Timestamp restoration requires Windows"))
}

// -------------------- 随机数 --------------------

#[cfg(windows)]
pub fn random_bytes(buf: &mut [u8]) -> bool {
    #[link(name = "advapi32")]
    extern "system" {
        fn SystemFunction036(buffer: *mut u8, length: u32) -> u8;
    }
    if buf.is_empty() {
        return true;
    }
    unsafe { SystemFunction036(buf.as_mut_ptr(), buf.len() as u32) != 0 }
}

#[cfg(not(windows))]
pub fn random_bytes(buf: &mut [u8]) -> bool {
    use std::fs::File;
    use std::io::Read;
    if let Ok(mut f) = File::open("/dev/urandom") {
        return f.read_exact(buf).is_ok();
    }
    false
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    if random_bytes(buf) {
        return Ok(());
    }
    Err("无法从系统获取随机数".to_string())
}

// -------------------- 控制台输出（GUI 子系统下也能打印） --------------------

#[cfg(windows)]
pub mod console {
    use core::ffi::c_void;

    extern "system" {
        fn AttachConsole(attach: u32) -> i32;
        fn AllocConsole() -> i32;
        fn GetStdHandle(which: u32) -> *mut c_void;
        fn GetConsoleMode(h: *mut c_void, mode: *mut u32) -> i32;
        fn WriteFile(h: *mut c_void, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> i32;
    }

    const ATTACH_PARENT_PROCESS: u32 = 0xffffffff;
    const STD_OUTPUT_HANDLE: u32 = 0xffff_fff5;
    const STD_ERROR_HANDLE: u32 = 0xffff_fff4;

    fn std_handle(which: u32) -> *mut c_void {
        unsafe {
            let h = GetStdHandle(which);
            if h.is_null() || h as isize == -1 {
                core::ptr::null_mut()
            } else {
                h
            }
        }
    }

    /// GUI 程序通常没有控制台。只有在标准句柄确实不可用时才挂接父控制台——
    /// 否则会把重定向过来的句柄换成屏幕缓冲区，导致 `> file` 抓不到输出。
    pub fn attach() {
        unsafe {
            let h = std_handle(STD_OUTPUT_HANDLE);
            if !h.is_null() {
                let mut mode = 0u32;
                // 句柄有效即可使用（无论是控制台还是重定向文件/管道）
                let _ = GetConsoleMode(h, &mut mode);
                return;
            }
            if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
                AllocConsole();
            }
        }
    }

    pub fn print(msg: &str) {
        write_to(STD_OUTPUT_HANDLE, msg);
    }

    pub fn eprint(msg: &str) {
        write_to(STD_ERROR_HANDLE, msg);
    }

    fn write_to(which: u32, msg: &str) {
        let bytes = msg.as_bytes();
        unsafe {
            let h = std_handle(which);
            if h.is_null() {
                return;
            }
            let mut written = 0u32;
            WriteFile(h, bytes.as_ptr(), bytes.len() as u32, &mut written, core::ptr::null_mut());
        }
    }
}

#[cfg(not(windows))]
pub mod console {
    use std::io::Write;
    pub fn attach() {}
    pub fn print(msg: &str) {
        let _ = write!(std::io::stdout(), "{}", msg);
        let _ = std::io::stdout().flush();
    }
    pub fn eprint(msg: &str) {
        let _ = write!(std::io::stderr(), "{}", msg);
        let _ = std::io::stderr().flush();
    }
}
