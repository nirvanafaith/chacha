//! 自包含加密包（文件夹 B）与密钥文件。
//!
//! 文件夹 B 结构：
//!
//! ```text
//! B/
//!   package.chx          明文清单：包 ID、原始文件夹名、文件列表（名称/大小/时间）、校验块
//!   blobs/
//!     000000.chx         每个源文件一个密文对象
//!     000001.chx
//! ```
//!
//! 清单是明文，所以解密端**不需要密钥就能列出包内文件名**；文件内容全部由
//! XChaCha20-Poly1305 保护，AAD 绑定「包 ID + 相对路径 + 块序号 + 块长度」，
//! 换包、改名、挪动块都会导致标签校验失败。
//!
//! 密钥单独存成 `.chxkey` 文件（含包 ID 与 CRC，便于核对是否配对）。

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::crypto;
use crate::pool::{self, Job};
use crate::util::{
    ensure_dir, fill_random, format_size, hex_encode, join_rel,
    now_stamp, read_u16_le, read_u32_le, read_u64_le, write_u16_le, write_u32_le,
    write_u64_le, KEY_LEN, NONCE_LEN, PKG_ID_LEN, TAG_LEN,
};

pub const INFO_NAME: &str = "package.chx";
pub const BLOBS_DIR: &str = "blobs";
pub const CHUNK_SIZE: u64 = 1024 * 1024;
pub const PACKAGE_SUFFIX: &str = ".chacha";
pub const KEY_SUFFIX: &str = ".chacha.key";

const INFO_MAGIC: &[u8; 8] = b"CHAPKG01";
const BLOB_MAGIC: &[u8; 4] = b"CXBL";
const KEY_MAGIC: &[u8; 8] = b"CHAKY001";
/// magic(8) + 包 ID(16) + 创建时间(8) + 密钥(32) + CRC32(4)
const KEY_FILE_LEN: usize = 68;
const LIMITED_KEY_MAGIC: &[u8; 8] = b"CHAKY002";
// Header + random wrapping key + nonce + encrypted (package key, 3-bit count) + tag.
const LIMITED_KEY_LEN: usize = 137;
pub const KEY_EXHAUSTED: &str = "密钥次数已耗尽";
const VERSION: u16 = 2;
// Explicit budgets keep parsing and task planning bounded on 32-bit XP.
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_PATH: usize = 4096;
const MAX_DEPTH: usize = 64;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_CHUNKS: u64 = 1024 * 1024;
const MANIFEST_DOMAIN: &[u8] = b"CHACHA-MANIFEST-V2\0";
const CHUNK_DOMAIN: &[u8] = b"CHACHA-CHUNK-V2\0";
/// 密文对象头固定长度（含补齐），保证块偏移可直接算出来，从而支持并行随机写。
const HDR: u64 = 32;
/// 每块附加开销：nonce(24) + 长度(4) + 标签(16)
const REC_OVER: u64 = NONCE_LEN as u64 + 4 + TAG_LEN as u64;

// -------------------- 数据结构 --------------------

#[derive(Clone)]
pub struct FileRec {
    pub rel: String,
    pub size: u64,
    /// Modification time in 100ns ticks since 1970 UTC; zero means do not set.
    pub mtime: u64,
    pub blob: u32,
}

pub struct Package {
    pub id: [u8; PKG_ID_LEN],
    /// 建包时间，100ns 间隔（自 1970-01-01 UTC）。
    pub created: u64,
    pub src_name: String,
    pub src_path: String,
    pub chunk_size: u32,
    pub files: Vec<FileRec>,
    pub dirs: Vec<String>,
    pub dir_mtimes: Vec<u64>,
    pub root_mtime: u64,
    pub total_bytes: u64,
    pub verify_nonce: [u8; NONCE_LEN],
    pub verify_tag: [u8; TAG_LEN],
    pub verify_ct: Vec<u8>,
}

impl Package {
    pub fn id_hex(&self) -> String {
        hex_encode(&self.id)
    }
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
    pub fn size_text(&self) -> String {
        format_size(self.total_bytes)
    }
    pub fn chunk(&self) -> u64 {
        CHUNK_SIZE
    }
    pub fn blob_name(blob: u32) -> String {
        format!("{:06}.chx", blob)
    }
    pub fn blob_path(dir: &Path, blob: u32) -> PathBuf {
        dir.join(BLOBS_DIR).join(Self::blob_name(blob))
    }
}

#[derive(Clone)]
pub struct KeyFile {
    pub id: [u8; PKG_ID_LEN],
    pub created: u64,
    pub key: [u8; KEY_LEN],
    /// 来自纯文本十六进制密钥文件时为 false（无法核对包 ID）。
    pub bound: bool,
    pub remaining: Option<u8>,
}

pub struct Summary {
    pub files: usize,
    pub bytes: u64,
    pub secs: f64,
}

impl Summary {
    pub fn rate(&self) -> String {
        if self.secs <= 0.0 {
            return "-".to_string();
        }
        let mibs = (self.bytes as f64 / (1024.0 * 1024.0)) / self.secs;
        format!("{:.0} MiB/s", mibs)
    }
}

// -------------------- 目录扫描 --------------------

pub struct Scan {
    pub files: Vec<(String, u64, u64)>,
    pub dirs: Vec<String>,
    pub dir_mtimes: Vec<u64>,
    pub root_mtime: u64,
    pub total: u64,
}

fn plain_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let md = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot inspect {}: {}", path.display(), e))?;
    if md.file_type().is_symlink() || is_reparse(&md) {
        return Err(format!("Links/reparse points are not supported: {}", path.display()));
    }
    if !md.is_file() && !md.is_dir() {
        return Err(format!("Unsupported filesystem object: {}", path.display()));
    }
    Ok(md)
}

#[cfg(windows)]
fn is_reparse(md: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_md: &fs::Metadata) -> bool { false }

fn modified_stamp(md: &fs::Metadata) -> Result<u64, String> {
    let time = md.modified().map_err(|e| format!("Cannot read modification time: {}", e))?;
    let duration = time.duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Pre-1970 modification times are not supported".to_string())?;
    duration.as_secs().checked_mul(10_000_000)
        .and_then(|n| n.checked_add(duration.subsec_nanos() as u64 / 100))
        .filter(|n| *n <= u64::max_value() - 116_444_736_000_000_000)
        .ok_or_else(|| "Modification time exceeds format limits".to_string())
}

pub fn scan_folder(root: &Path) -> Result<Scan, String> {
    let md = plain_metadata(root)?;
    if !md.is_dir() { return Err(format!("Not a directory: {}", root.display())); }
    let name = root.file_name().and_then(|s| s.to_str())
        .ok_or_else(|| "Source must have a valid UTF-8 root name".to_string())?;
    validate_component(name)?;
    let mut out = Scan {
        files: Vec::new(), dirs: Vec::new(), dir_mtimes: Vec::new(),
        root_mtime: modified_stamp(&md)?, total: 0,
    };
    let mut manifest_budget = 1024usize;
    scan_into(root, "", &mut out, &mut manifest_budget)?;
    out.files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut dirs: Vec<(String, u64)> = out.dirs.into_iter().zip(out.dir_mtimes.into_iter()).collect();
    dirs.sort_by(|a, b| a.0.cmp(&b.0));
    let (names, times) = dirs.into_iter().unzip();
    out.dirs = names;
    out.dir_mtimes = times;
    validate_paths(out.files.iter().map(|f| f.0.as_str()), &out.dirs)?;
    Ok(out)
}

fn scan_into(root: &Path, rel: &str, out: &mut Scan, budget: &mut usize) -> Result<(), String> {
    let before = plain_metadata(root)?;
    let before_time = modified_stamp(&before)?;
    if !rel.is_empty() {
        validate_rel(rel)?;
        out.dirs.push(rel.to_string());
        out.dir_mtimes.push(before_time);
    }
    let entries = fs::read_dir(root).map_err(|e| format!("Cannot enumerate {}: {}", root.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("Directory enumeration failed: {}", e))?;
        let name = entry.file_name().into_string()
            .map_err(|_| "Filename is not valid UTF-8".to_string())?;
        validate_component(&name)?;
        let child_rel = if rel.is_empty() { name } else { format!("{}/{}", rel, name) };
        validate_rel(&child_rel)?;
        *budget = budget.checked_add(22 + child_rel.len()).filter(|n| *n <= MAX_MANIFEST)
            .ok_or_else(|| "Source manifest exceeds 16 MiB limit".to_string())?;
        if out.files.len() + out.dirs.len() >= MAX_ENTRIES {
            return Err("Too many source entries".into());
        }
        let path = entry.path();
        let md = plain_metadata(&path)?;
        if md.is_dir() {
            scan_into(&path, &child_rel, out, budget)?;
        } else {
            out.total = out.total.checked_add(md.len()).filter(|n| *n <= MAX_TOTAL)
                .ok_or_else(|| "Source exceeds total size limit (1 TiB)".to_string())?;
            out.files.push((child_rel, md.len(), modified_stamp(&md)?));
        }
    }
    if before_time != modified_stamp(&plain_metadata(root)?)? {
        return Err(format!("Source directory changed while scanning: {}", root.display()));
    }
    Ok(())
}

// -------------------- 块布局 --------------------

fn chunk_count(size: u64, chunk: u64) -> u32 {
    if size == 0 || chunk == 0 { 0 } else {
        (1 + (size - 1) / chunk).min(u32::max_value() as u64) as u32
    }
}

fn chunk_len(size: u64, idx: u32, chunk: u64) -> u64 {
    let start = idx as u64 * chunk;
    if start >= size {
        0
    } else {
        let n = size - start;
        if n < chunk {
            n
        } else {
            chunk
        }
    }
}

/// 第 idx 块的记录起始偏移（前面所有块都是满块，可直接算）。
fn rec_off(idx: u32, chunk: u64) -> u64 {
    HDR + idx as u64 * (REC_OVER + chunk)
}

fn blob_size(size: u64, chunk: u64) -> u64 {
    let n = chunk_count(size, chunk) as u64;
    // Validated package sizes cannot reach the saturation boundary.
    n.checked_mul(REC_OVER).and_then(|n| n.checked_add(HDR))
        .and_then(|n| n.checked_add(size)).unwrap_or(u64::max_value())
}

fn chunk_aad(id: &[u8; PKG_ID_LEN], rec: &FileRec, idx: u32, len: u32, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(CHUNK_DOMAIN);
    write_u16_le(out, VERSION);
    out.extend_from_slice(id);
    put_str(out, &rec.rel);
    write_u32_le(out, rec.blob);
    write_u64_le(out, rec.size);
    write_u32_le(out, chunk_count(rec.size, CHUNK_SIZE));
    write_u32_le(out, idx);
    write_u32_le(out, len);
}

// -------------------- 清单编解码 --------------------

fn validate_component(s: &str) -> Result<(), String> {
    if s.is_empty() || s == "." || s == ".." || s.encode_utf16().count() > 255
        || s.ends_with('.') || s.ends_with(' ')
        || s.chars().any(|c| c.is_control() || "\\/:*?\"<>|".contains(c)) {
        return Err(format!("Unsafe Windows name: {:?}", s));
    }
    let upper = s.to_uppercase();
    let stem = upper.split('.').next().unwrap_or("").trim_end_matches(' ');
    let reserved = stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL"
        || stem == "CLOCK$" || stem == "CONIN$" || stem == "CONOUT$";
    let numbered = if stem.starts_with("COM") || stem.starts_with("LPT") {
        let tail = &stem[3..];
        tail.len() == 1 && tail.as_bytes()[0] >= b'0' && tail.as_bytes()[0] <= b'9'
            || tail == "\u{b9}" || tail == "\u{b2}" || tail == "\u{b3}"
    } else { false };
    // Short-name aliases can collide with another entry's filesystem-generated 8.3 name.
    if reserved || numbered || s.contains('~') {
        return Err(format!("Reserved or alias-prone Windows name: {:?}", s));
    }
    Ok(())
}

fn validate_rel(s: &str) -> Result<(), String> {
    if s.len() > MAX_PATH || s.split('/').count() > MAX_DEPTH {
        return Err("Manifest path exceeds length/depth limits".into());
    }
    for component in s.split('/') { validate_component(component)?; }
    Ok(())
}

fn validate_paths<'a, I: Iterator<Item = &'a str>>(files: I, dirs: &[String]) -> Result<(), String> {
    let mut entries: HashMap<String, bool> = HashMap::new();
    for dir in dirs {
        validate_rel(dir)?;
        if entries.insert(dir.to_uppercase(), true).is_some() {
            return Err(format!("Duplicate/colliding directory: {}", dir));
        }
    }
    for file in files {
        validate_rel(file)?;
        if entries.insert(file.to_uppercase(), false).is_some() {
            return Err(format!("Duplicate/colliding file: {}", file));
        }
    }
    for name in entries.keys() {
        let mut parent = name.as_str();
        while let Some(pos) = parent.rfind('/') {
            parent = &parent[..pos];
            if entries.get(parent) != Some(&true) {
                return Err(format!("Missing directory or file/directory collision: {}", parent));
            }
        }
    }
    Ok(())
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Only validated strings are encoded by the package/authentication entry points.
    write_u16_le(out, s.len() as u16);
    out.extend_from_slice(s.as_bytes());
}

struct Cursor<'a> { bytes: &'a [u8], pos: usize }
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "Truncated or invalid manifest".to_string())?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u16(&mut self) -> Result<u16, String> { Ok(read_u16_le(self.take(2)?)) }
    fn u32(&mut self) -> Result<u32, String> { Ok(read_u32_le(self.take(4)?)) }
    fn u64(&mut self) -> Result<u64, String> { Ok(read_u64_le(self.take(8)?)) }
    fn string(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        if n > MAX_PATH { return Err("Manifest string exceeds limit".into()); }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "Manifest contains invalid UTF-8".into())
    }
}

impl Package {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_fields(true)
    }

    fn manifest_aad(&self) -> Vec<u8> {
        let mut aad = MANIFEST_DOMAIN.to_vec();
        aad.extend_from_slice(&self.encode_fields(false));
        aad
    }

    fn validate(&self) -> Result<(), String> {
        validate_component(&self.src_name)?;
        if self.src_path.len() > MAX_PATH || self.src_path.contains('\0')
            || self.chunk_size != CHUNK_SIZE as u32 || !self.verify_ct.is_empty()
            || self.files.len() + self.dirs.len() > MAX_ENTRIES
            || self.dirs.len() != self.dir_mtimes.len() {
            return Err("Unsupported or excessive manifest metadata".into());
        }
        validate_paths(self.files.iter().map(|f| f.rel.as_str()), &self.dirs)?;
        let mut sum = 0u64;
        let mut chunks = 0u64;
        let mut blobs = HashSet::new();
        let mut encoded_len = 8 + 2 + 2 + PKG_ID_LEN + 8 + 2 + self.src_name.len()
            + 2 + self.src_path.len() + 4 + 4 + 4 + 8 + 8 + NONCE_LEN + TAG_LEN + 4;
        for f in &self.files {
            sum = sum.checked_add(f.size).filter(|n| *n <= MAX_TOTAL)
                .ok_or_else(|| "Manifest exceeds total size limit (1 TiB)".to_string())?;
            chunks = chunks.checked_add(chunk_count(f.size, CHUNK_SIZE) as u64)
                .filter(|n| *n <= MAX_CHUNKS)
                .ok_or_else(|| "Manifest exceeds chunk/task budget".to_string())?;
            if f.blob as usize >= self.files.len() || !blobs.insert(f.blob) {
                return Err("Invalid or duplicate blob mapping".into());
            }
            encoded_len = encoded_len.checked_add(22 + f.rel.len())
                .ok_or_else(|| "Manifest size overflow".to_string())?;
        }
        for d in &self.dirs {
            encoded_len = encoded_len.checked_add(10 + d.len())
                .ok_or_else(|| "Manifest size overflow".to_string())?;
        }
        if encoded_len > MAX_MANIFEST || sum != self.total_bytes {
            return Err("Manifest size or total byte count is invalid".into());
        }
        if self.files.iter().map(|f| f.mtime).chain(self.dir_mtimes.iter().cloned())
            .chain(std::iter::once(self.root_mtime)).chain(std::iter::once(self.created))
            .any(|t| t > u64::max_value() - 116_444_736_000_000_000) {
            return Err("Manifest timestamp exceeds supported range".into());
        }
        Ok(())
    }

    fn encode_fields(&self, verification: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(INFO_MAGIC);
        write_u16_le(&mut v, VERSION);
        write_u16_le(&mut v, 0);
        v.extend_from_slice(&self.id);
        write_u64_le(&mut v, self.created);
        put_str(&mut v, &self.src_name);
        put_str(&mut v, &self.src_path);
        write_u32_le(&mut v, self.chunk_size);
        write_u32_le(&mut v, self.files.len() as u32);
        write_u32_le(&mut v, self.dirs.len() as u32);
        write_u64_le(&mut v, self.total_bytes);
        write_u64_le(&mut v, self.root_mtime);
        if verification {
            v.extend_from_slice(&self.verify_nonce);
            v.extend_from_slice(&self.verify_tag);
            write_u32_le(&mut v, self.verify_ct.len() as u32);
            v.extend_from_slice(&self.verify_ct);
        }
        for f in &self.files {
            put_str(&mut v, &f.rel);
            write_u64_le(&mut v, f.size);
            write_u64_le(&mut v, f.mtime);
            write_u32_le(&mut v, f.blob);
        }
        for (i, d) in self.dirs.iter().enumerate() {
            put_str(&mut v, d);
            write_u64_le(&mut v, self.dir_mtimes.get(i).cloned().unwrap_or(0));
        }
        v
    }

    pub fn decode(b: &[u8]) -> Result<Package, String> {
        if b.len() > MAX_MANIFEST { return Err("Manifest exceeds 16 MiB limit".into()); }
        let mut c = Cursor { bytes: b, pos: 0 };
        if c.take(8)? != INFO_MAGIC { return Err("Not a CHACHA package manifest".into()); }
        let ver = c.u16()?;
        if ver == 1 {
            return Err("Legacy package version 1 is unauthenticated and is not supported; use an explicit trusted legacy recovery tool".into());
        }
        if ver != VERSION { return Err(format!("Unsupported package version: {}", ver)); }
        if c.u16()? != 0 { return Err("Unsupported manifest flags".into()); }
        let mut id = [0u8; PKG_ID_LEN];
        id.copy_from_slice(c.take(PKG_ID_LEN)?);
        let created = c.u64()?;
        let src_name = c.string()?;
        let src_path = c.string()?;
        let chunk_size = c.u32()?;
        let nf = c.u32()? as usize;
        let nd = c.u32()? as usize;
        if nf > MAX_ENTRIES || nd > MAX_ENTRIES || nf + nd > MAX_ENTRIES {
            return Err("Manifest entry count exceeds limit".into());
        }
        let total_bytes = c.u64()?;
        let root_mtime = c.u64()?;
        let mut verify_nonce = [0u8; NONCE_LEN];
        verify_nonce.copy_from_slice(c.take(NONCE_LEN)?);
        let mut verify_tag = [0u8; TAG_LEN];
        verify_tag.copy_from_slice(c.take(TAG_LEN)?);
        if c.u32()? != 0 { return Err("Version 2 requires empty verification ciphertext".into()); }
        let minimum = nf.checked_mul(23).and_then(|n| nd.checked_mul(11).and_then(|d| n.checked_add(d)))
            .ok_or_else(|| "Manifest count overflow".to_string())?;
        if minimum > b.len() - c.pos { return Err("Truncated manifest entries".into()); }
        let mut files = Vec::with_capacity(nf.min(1024));
        for _ in 0..nf {
            let rel = c.string()?;
            let size = c.u64()?;
            let mtime = c.u64()?;
            let blob = c.u32()?;
            files.push(FileRec { rel, size, mtime, blob });
        }
        let mut dirs = Vec::with_capacity(nd.min(1024));
        let mut dir_mtimes = Vec::with_capacity(nd.min(1024));
        for _ in 0..nd { dirs.push(c.string()?); dir_mtimes.push(c.u64()?); }
        if c.pos != b.len() { return Err("Unexpected trailing manifest data".into()); }
        let pkg = Package {
            id, created, src_name, src_path, chunk_size, files, dirs, dir_mtimes,
            root_mtime, total_bytes, verify_nonce, verify_tag, verify_ct: Vec::new(),
        };
        pkg.validate()?;
        Ok(pkg)
    }
}

// -------------------- 密钥文件 --------------------

pub fn new_key() -> Result<[u8; KEY_LEN], String> {
    let mut k = [0u8; KEY_LEN];
    fill_random(&mut k)?;
    Ok(k)
}

pub fn new_pkg_id() -> Result<[u8; PKG_ID_LEN], String> {
    let mut b = [0u8; PKG_ID_LEN];
    fill_random(&mut b)?;
    Ok(b)
}

pub fn encode_key_file(id: &[u8; PKG_ID_LEN], created: u64, key: &[u8; KEY_LEN], uses: u8) -> Result<Vec<u8>, String> {
    if uses < 1 || uses > 7 { return Err("密钥可用次数必须为 1–7".into()); }
    encode_limited_key(id, created, key, uses)
}

fn encode_limited_key(id: &[u8; PKG_ID_LEN], created: u64, key: &[u8; KEY_LEN], remaining: u8) -> Result<Vec<u8>, String> {
    let mut v = Vec::with_capacity(LIMITED_KEY_LEN);
    v.extend_from_slice(LIMITED_KEY_MAGIC);
    v.extend_from_slice(id);
    write_u64_le(&mut v, created);
    // This self-contained wrapping hides the field, not a secret from the holder.
    // Fresh key/nonce on every rewrite avoids reusing an AEAD nonce.
    let wrapping = new_key()?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    v.extend_from_slice(&wrapping);
    v.extend_from_slice(&nonce);
    let mut payload = key.to_vec();
    payload.push(remaining);
    let (ct, tag) = crypto::xchacha20_poly1305_encrypt(&wrapping, &nonce, &v, &payload);
    v.extend_from_slice(&ct);
    v.extend_from_slice(&tag);
    Ok(v)
}

pub fn write_key_file(path: &Path, id: &[u8; PKG_ID_LEN], created: u64, key: &[u8; KEY_LEN], uses: u8) -> Result<(), String> {
    let v = encode_key_file(id, created, key, uses)?;
    let destination = checked_destination(path)?;
    let mut stage = Staging::new(&destination)?;
    let temporary = stage.path.join("key");
    let result = (|| {
        let mut file = OpenOptions::new().read(true).write(true).create_new(true).open(&temporary)
            .map_err(|e| format!("Cannot create temporary key: {}", e))?;
        file.write_all(&v).and_then(|_| file.sync_all())
            .map_err(|e| format!("Cannot persist key: {}", e))?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut saved = vec![0u8; v.len()];
        file.read_exact(&mut saved).map_err(|e| e.to_string())?;
        if !crate::util::ct_eq(&saved, &v) { return Err("Key readback mismatch".into()); }
        drop(file);
        publish_noreplace(&temporary, &destination)?;
        fs::remove_dir(&stage.path).map_err(|e| format!("Key saved, but staging cleanup failed at {}: {}", stage.path.display(), e))?;
        stage.owned = false;
        Ok(())
    })();
    stage.finish(result)
}

pub fn read_key_file(path: &Path) -> Result<KeyFile, String> {
    let b = read_bounded(path, 4096).map_err(|e| format!("Cannot read key file: {}", e))?;
    decode_key_file(&b)
}

fn decode_key_file(input: &[u8]) -> Result<KeyFile, String> {
    let decoded;
    let b = if input.starts_with(KEY_MAGIC) || input.starts_with(LIMITED_KEY_MAGIC) {
        input
    } else {
        decoded = crate::util::hex_decode(&String::from_utf8_lossy(input))?;
        &decoded[..]
    };
    if b.starts_with(LIMITED_KEY_MAGIC) {
        if b.len() != LIMITED_KEY_LEN { return Err("密钥文件已损坏（长度不对）".into()); }
        let mut id = [0u8; PKG_ID_LEN];
        id.copy_from_slice(&b[8..24]);
        let mut wrapping = [0u8; KEY_LEN];
        wrapping.copy_from_slice(&b[32..64]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[64..88]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&b[121..]);
        let payload = crypto::xchacha20_poly1305_decrypt(&wrapping, &nonce, &b[..88], &b[88..121], &tag)
            .map_err(|_| "密钥文件已损坏（认证失败）".to_string())?;
        let remaining = payload[32];
        if remaining > 7 { return Err("密钥文件已损坏（次数无效）".into()); }
        if remaining == 0 { return Err(KEY_EXHAUSTED.into()); }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&payload[..32]);
        return Ok(KeyFile { id, created: read_u64_le(&b[24..32]), key, bound: true, remaining: Some(remaining) });
    }
    if b.starts_with(KEY_MAGIC) {
        if b.len() != KEY_FILE_LEN {
            return Err("密钥文件已损坏（长度不对）".into());
        }
        let crc = read_u32_le(&b[KEY_FILE_LEN - 4..]);
        if crc != crate::util::crc32(&b[..KEY_FILE_LEN - 4]) {
            return Err("密钥文件已损坏（校验和不匹配）".into());
        }
        let mut id = [0u8; PKG_ID_LEN];
        id.copy_from_slice(&b[8..24]);
        let created = read_u64_le(&b[24..]);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&b[32..64]);
        return Ok(KeyFile {
            id,
            created,
            key,
            bound: true,
            remaining: None,
        });
    }
    // 退路：纯文本十六进制密钥
    if b.len() != KEY_LEN {
        return Err(format!(
            "不是有效的密钥文件（{} 字节，应为 {}）",
            b.len(),
            KEY_LEN
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(b);
    Ok(KeyFile {
        id: [0u8; PKG_ID_LEN],
        created: 0,
        key,
        bound: false,
        remaining: None,
    })
}

// -------------------- Owned staging and bounded I/O --------------------

fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Cannot inspect destination {}: {}", path.display(), e)),
        Ok(_) => Err(format!("Destination already exists; overwrite is disabled: {}", path.display())),
    }
}

fn checked_destination(path: &Path) -> Result<PathBuf, String> {
    let name = path.file_name().and_then(|n| n.to_str())
        .ok_or_else(|| "Destination needs a valid final component".to_string())?;
    validate_component(name)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|e| format!("Cannot resolve destination parent: {}", e))?;
    if !plain_metadata(&parent)?.is_dir() { return Err("Destination parent is not a directory".into()); }
    let destination = parent.join(name);
    require_absent(&destination)?;
    Ok(destination)
}

fn restore_destination(path: &Path) -> Result<PathBuf, String> {
    use std::path::Component;
    let name = path.file_name().and_then(|n| n.to_str())
        .ok_or_else(|| "Destination needs a valid final component".to_string())?;
    validate_component(name)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if parent.components().count() > MAX_DEPTH + 2 { return Err("Output parent is too deep".into()); }
    for component in parent.components() {
        match component {
            Component::ParentDir => return Err("Parent traversal in output path is not supported".into()),
            Component::Prefix(_) if !parent.is_absolute() => return Err("Drive-relative output paths are not supported".into()),
            Component::Normal(n) => validate_component(n.to_str()
                .ok_or_else(|| "Output path is not valid UTF-8".to_string())?)?,
            _ => {},
        }
    }
    let mut current = if parent.is_absolute() { PathBuf::new() } else {
        std::env::current_dir().map_err(|e| e.to_string())?
    };
    // Make parents individually and reject existing reparse points. These empty
    // parents may remain on failure; never recursively delete a user-selected tree.
    for component in parent.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {},
            Component::Normal(n) => {
                current.push(n);
                match fs::symlink_metadata(&current) {
                    Ok(_) => {},
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                        match fs::create_dir(&current) {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                            Err(e) => return Err(format!("Cannot create output parent {}: {}", current.display(), e)),
                        }
                    },
                    Err(e) => return Err(format!("Cannot inspect output parent {}: {}", current.display(), e)),
                }
                if !plain_metadata(&current)?.is_dir() {
                    return Err(format!("Output parent is not a regular directory: {}", current.display()));
                }
            },
            Component::ParentDir => return Err("Parent traversal in output path is not supported".into()),
        }
    }
    checked_destination(&current.join(name))
}

// Ownership comes only from exclusive creation, never from path existence.
// This does not isolate against a same-user process actively replacing our paths;
// inherited directory ACLs and ordinary deletion are not secrecy/secure-erasure guarantees.
struct Staging { path: PathBuf, owned: bool }
impl Staging {
    fn new(destination: &Path) -> Result<Staging, String> {
        let parent = destination.parent().ok_or_else(|| "Missing destination parent".to_string())?;
        for _ in 0..32 {
            let mut random = [0u8; 16];
            fill_random(&mut random)?;
            let path = parent.join(format!(".chacha-stage-{}", hex_encode(&random)));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Staging { path, owned: true }),
                Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(format!("Cannot create exclusive staging directory: {}", e)),
            }
        }
        Err("Cannot allocate a unique staging directory".into())
    }
    fn publish(&mut self, destination: &Path) -> Result<(), String> {
        require_absent(destination)?;
        publish_noreplace(&self.path, destination)?;
        self.owned = false;
        Ok(())
    }
    fn finish<T>(&mut self, result: Result<T, String>) -> Result<T, String> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if self.owned {
                    self.owned = false;
                    if let Err(cleanup) = fs::remove_dir_all(&self.path) {
                        return Err(format!("{}; cleanup failed: {}. Sensitive staging data may remain at {}",
                            error, cleanup, self.path.display()));
                    }
                }
                if error == "已取消" || error == "Cancelled" { return Err("已取消".into()); }
                Err(format!("{}; owned staging removed (ordinary deletion is not secure erasure)", error))
            }
        }
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if self.owned { let _ = fs::remove_dir_all(&self.path); }
    }
}

#[cfg(windows)]
fn publish_noreplace(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" { fn MoveFileW(source: *const u16, destination: *const u16) -> i32; }
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // MoveFileW is XP-compatible and never replaces an existing destination.
    if unsafe { MoveFileW(source.as_ptr(), destination.as_ptr()) } == 0 {
        return Err(format!("Cannot publish without replacement: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_noreplace(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::ffi::CString;
    extern "C" { fn renameat2(oldfd: i32, old: *const i8, newfd: i32, new: *const i8, flags: u32) -> i32; }
    let old = CString::new(source.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let new = CString::new(destination.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    if unsafe { renameat2(-100, old.as_ptr(), -100, new.as_ptr(), 1) } != 0 {
        return Err(format!("Cannot publish without replacement: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn publish_noreplace(_source: &Path, _destination: &Path) -> Result<(), String> {
    Err("Atomic no-replace publication is not supported on this platform".into())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let md = plain_metadata(path)?;
    if !md.is_file() || md.len() > limit as u64 { return Err("Input exceeds file size limit".into()); }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > limit { return Err("Input exceeds file size limit".into()); }
    Ok(bytes)
}

fn open_source(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        // Deny concurrent write and delete sharing while this handle is in use.
        options.share_mode(1);
    }
    options.open(path).map_err(|e| format!("Cannot obtain stable source handle {}: {}", path.display(), e))
}

fn check_source(file: &File, path: &Path, rec: &FileRec) -> Result<(), String> {
    let path_md = plain_metadata(path)?;
    let handle_md = file.metadata().map_err(|e| e.to_string())?;
    if !path_md.is_file() || !handle_md.is_file() || path_md.len() != rec.size
        || handle_md.len() != rec.size || modified_stamp(&path_md)? != rec.mtime
        || modified_stamp(&handle_md)? != rec.mtime {
        return Err(format!("Source changed during encryption: {}", rec.rel));
    }
    Ok(())
}

// -------------------- 加密 --------------------

struct EncCtx {
    src: PathBuf,
    blobs: PathBuf,
    pkg: Package,
    key: Vec<u8>,
    tasks: Vec<(usize, u32, u32)>,
    job: Arc<Job>,
}

/// 建包：扫描 → 写密文对象头 → 并行分块加密 → 写清单。
/// Existing destinations are always refused; failure only removes owned random staging.
/// Source checks detect ordinary changes, but do not constitute an atomic filesystem snapshot.
pub fn create_package(
    src: &Path,
    dst: &Path,
    key: &[u8; KEY_LEN],
    job: &Arc<Job>,
    threads: usize,
) -> Result<Package, String> {
    let dst = checked_destination(dst)?;
    plain_metadata(src)?;
    let src = fs::canonicalize(src).map_err(|e| format!("Cannot resolve source: {}", e))?;
    plain_metadata(&src)?;
    let source_parts: Vec<String> = src.components().map(|c| c.as_os_str().to_string_lossy().to_uppercase()).collect();
    let dest_parts: Vec<String> = dst.components().map(|c| c.as_os_str().to_string_lossy().to_uppercase()).collect();
    if dest_parts.starts_with(&source_parts) { return Err("Package destination must be outside the source tree".into()); }
    let scan = scan_folder(&src)?;
    if job.cancelled() { return Err("已取消".into()); }
    let mut stage = Staging::new(&dst)?;
    let result = create_package_inner(&src, &stage.path, key, job, threads, scan)
        .and_then(|pkg| { stage.publish(&dst)?; Ok(pkg) });
    stage.finish(result)
}

fn create_package_inner(
    src: &Path,
    dst: &Path,
    key: &[u8; KEY_LEN],
    job: &Arc<Job>,
    threads: usize,
    scan: Scan,
) -> Result<Package, String> {
    let blobs = dst.join(BLOBS_DIR);
    fs::create_dir(&blobs).map_err(|e| format!("Cannot create blobs directory: {}", e))?;

    let id = new_pkg_id()?;
    let mut pkg = Package {
        id,
        created: now_stamp(),
        src_name: src
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("folder")),
        src_path: String::new(),
        chunk_size: CHUNK_SIZE as u32,
        files: Vec::new(),
        dirs: scan.dirs.clone(),
        dir_mtimes: scan.dir_mtimes.clone(),
        root_mtime: scan.root_mtime,
        total_bytes: scan.total,
        verify_nonce: [0u8; NONCE_LEN],
        verify_tag: [0u8; TAG_LEN],
        verify_ct: Vec::new(),
    };

    pkg.files = scan.files.iter().enumerate().map(|(i, f)| FileRec {
        rel: f.0.clone(), size: f.1, mtime: f.2, blob: i as u32,
    }).collect();
    pkg.validate()?;
    // Headers are created exclusively inside the owned staging directory.
    for i in 0..scan.files.len() {
        let (rel, size, mt) = &scan.files[i];
        let _ = rel;
        let blob = i as u32;
        let path = blobs.join(Package::blob_name(blob));
        let mut f = OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|e| format!("Cannot create {}: {}", path.display(), e))?;
        let mut h: Vec<u8> = Vec::with_capacity(HDR as usize);
        h.extend_from_slice(BLOB_MAGIC);
        write_u16_le(&mut h, VERSION);
        write_u32_le(&mut h, CHUNK_SIZE as u32);
        write_u64_le(&mut h, *size);
        write_u32_le(&mut h, chunk_count(*size, CHUNK_SIZE));
        h.resize(HDR as usize, 0);
        f.write_all(&h)
            .map_err(|e| format!("写入头部失败：{}", e))?;
        f.set_len(blob_size(*size, CHUNK_SIZE))
            .map_err(|e| format!("预分配失败：{}", e))?;
        let _ = mt;
    }

    pkg.validate()?;
    let tasks = plan_tasks(&pkg, threads);
    let ctx = Arc::new(EncCtx {
        src: src.to_path_buf(),
        blobs,
        pkg: Package {
            verify_ct: Vec::new(),
            ..clone_pkg(&pkg)
        },
        key: key.to_vec(),
        tasks,
        job: Arc::clone(job),
    });
    run_enc(ctx.clone());
    if let Some(e) = job.first_error() {
        return Err(e);
    }
    if job.cancelled() {
        return Err("已取消".into());
    }

    let after = scan_folder(src)?;
    if after.files != scan.files || after.dirs != scan.dirs || after.dir_mtimes != scan.dir_mtimes
        || after.root_mtime != scan.root_mtime {
        return Err("Source changed during encryption; no package was published".into());
    }
    for rec in &pkg.files {
        let file = OpenOptions::new().write(true).open(Package::blob_path(dst, rec.blob))
            .map_err(|e| format!("Cannot reopen blob for synchronization: {}", e))?;
        file.sync_all().map_err(|e| format!("Cannot synchronize blob: {}", e))?;
    }
    let aad = pkg.manifest_aad();
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let (ct, tag) = crypto::xchacha20_poly1305_encrypt(key, &nonce, &aad, &[]);
    pkg.verify_nonce = nonce;
    pkg.verify_tag = tag;
    pkg.verify_ct = ct;

    let info = dst.join(INFO_NAME);
    let bytes = pkg.encode();
    let mut file = OpenOptions::new().write(true).create_new(true).open(&info)
        .map_err(|e| format!("Cannot create manifest: {}", e))?;
    file.write_all(&bytes).and_then(|_| file.sync_all())
        .map_err(|e| format!("Cannot persist manifest: {}", e))?;
    if job.cancelled() { return Err("已取消".into()); }
    Ok(pkg)
}

fn clone_pkg(p: &Package) -> Package {
    Package {
        id: p.id,
        created: p.created,
        src_name: p.src_name.clone(),
        src_path: p.src_path.clone(),
        chunk_size: p.chunk_size,
        files: p.files.clone(),
        dirs: p.dirs.clone(),
        dir_mtimes: p.dir_mtimes.clone(),
        root_mtime: p.root_mtime,
        total_bytes: p.total_bytes,
        verify_nonce: p.verify_nonce,
        verify_tag: p.verify_tag,
        verify_ct: p.verify_ct.clone(),
    }
}

/// 把每个文件的块切成任务组：任务数约为线程数的 4 倍，兼顾均衡与开销。
fn plan_tasks(pkg: &Package, threads: usize) -> Vec<(usize, u32, u32)> {
    let chunk = pkg.chunk();
    let mut total_chunks = 0usize;
    for f in &pkg.files {
        total_chunks += chunk_count(f.size, chunk) as usize;
    }
    let want = threads.max(1).min(64) * 4;
    let per = if total_chunks == 0 {
        1
    } else {
        let p = (total_chunks + want - 1) / want;
        if p < 1 {
            1
        } else if p > 16 {
            16
        } else {
            p
        }
    };
    let mut tasks = Vec::new();
    for (i, f) in pkg.files.iter().enumerate() {
        let n = chunk_count(f.size, chunk);
        if n == 0 {
            tasks.push((i, 0, 0));
            continue;
        }
        let mut c = 0u32;
        let per = per as u32;
        while c < n {
            let cnt = if n - c < per { n - c } else { per };
            tasks.push((i, c, cnt));
            c += cnt;
        }
    }
    tasks
}

fn run_enc(ctx: Arc<EncCtx>) {
    let n = ctx.tasks.len();
    let threads = pool::plan_threads(n, ctx.pkg.total_bytes);
    pool::run(n, threads, move |i| {
        let (fi, first, count) = ctx.tasks[i];
        let rec = &ctx.pkg.files[fi];
        if ctx.job.cancelled() {
            return;
        }
        let chunk = ctx.pkg.chunk();
        if ctx.key.len() != KEY_LEN {
            ctx.job.fail("密钥长度错误".into());
            return;
        }
        let mut kbuf = [0u8; KEY_LEN];
        kbuf.copy_from_slice(&ctx.key);
        let key = &kbuf;
        let src_path = join_rel(&ctx.src, &rec.rel);
        let mut src = match open_source(&src_path) {
            Ok(f) => f,
            Err(e) => {
                ctx.job.fail(format!("无法读取 {}：{}", rec.rel, e));
                return;
            }
        };
        if let Err(e) = check_source(&src, &src_path, rec) { ctx.job.fail(e); return; }
        let blob_path = ctx.blobs.join(Package::blob_name(rec.blob));
        let mut dst = match OpenOptions::new().write(true).open(&blob_path) {
            Ok(f) => f,
            Err(e) => {
                ctx.job.fail(format!("无法写入 {}：{}", rec.rel, e));
                return;
            }
        };
        let mut buf = vec![0u8; chunk as usize];
        let mut aad = Vec::with_capacity(64 + rec.rel.len());
        let mut c = first;
        let end = first + count;
        let mut done = 0u64;
        while c < end {
            if ctx.job.cancelled() { return; }
            let len = chunk_len(rec.size, c, chunk) as usize;
            if let Err(e) = src.seek(SeekFrom::Start(c as u64 * chunk)) {
                ctx.job.fail(format!("{}：{}", rec.rel, e));
                return;
            }
            if let Err(e) = read_exact_n(&mut src, &mut buf[..len]) {
                ctx.job.fail(format!("读取 {} 失败：{}", rec.rel, e));
                return;
            }
            let mut nonce = [0u8; NONCE_LEN];
            if fill_random(&mut nonce).is_err() {
                ctx.job.fail("随机数生成失败".into());
                return;
            }
            chunk_aad(&ctx.pkg.id, rec, c, len as u32, &mut aad);
            let tag = crypto::xchacha20_poly1305_encrypt_in_place(
                key,
                &nonce,
                &aad,
                &mut buf[..len],
            );
            let mut rec_bytes = Vec::with_capacity(len + REC_OVER as usize);
            rec_bytes.extend_from_slice(&nonce);
            write_u32_le(&mut rec_bytes, len as u32);
            rec_bytes.extend_from_slice(&buf[..len]);
            rec_bytes.extend_from_slice(&tag);
            if let Err(e) = dst.seek(SeekFrom::Start(rec_off(c, chunk))) {
                ctx.job.fail(format!("{}：{}", rec.rel, e));
                return;
            }
            if let Err(e) = dst.write_all(&rec_bytes) {
                ctx.job.fail(format!("写入 {} 失败：{}", rec.rel, e));
                return;
            }
            done += len as u64;
            c += 1;
        }
        if let Err(e) = check_source(&src, &src_path, rec) { ctx.job.fail(e); return; }
        if let Err(e) = dst.flush() { ctx.job.fail(format!("Cannot flush ciphertext: {}", e)); return; }
        ctx.job.tick(done, &rec.rel);
    });
}

fn read_exact_n(f: &mut File, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        match f.read(&mut buf[off..]) {
            Ok(0) => return Err("文件比记录的长度短".into()),
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

// -------------------- 读取包 / 校验密钥 --------------------

pub fn info_path(dir: &Path) -> PathBuf {
    dir.join(INFO_NAME)
}

pub fn looks_like_package(dir: &Path) -> bool {
    dir.join(INFO_NAME).is_file()
}

pub fn open_package(dir: &Path) -> Result<Package, String> {
    let p = info_path(dir);
    if !p.is_file() {
        if dir.join(BLOBS_DIR).is_dir() {
            return Err("加密包不完整：缺少 package.chx（加密可能未正常结束）".into());
        }
        return Err("所选文件夹里没有 package.chx，不是 CHACHA 加密包。".into());
    }
    let b = read_bounded(&p, MAX_MANIFEST).map_err(|e| format!("Cannot read manifest: {}", e))?;
    let pkg = Package::decode(&b)?;
    if !dir.join(BLOBS_DIR).is_dir() {
        return Err("加密包不完整：缺少 blobs 目录。".into());
    }
    Ok(pkg)
}

/// Authenticate all v2 manifest metadata. This does not authenticate blob contents.
pub fn check_key(pkg: &Package, key: &[u8; KEY_LEN]) -> bool {
    if pkg.validate().is_err() { return false; }
    let aad = pkg.manifest_aad();
    match crypto::xchacha20_poly1305_decrypt(
        key,
        &pkg.verify_nonce,
        &aad,
        &pkg.verify_ct,
        &pkg.verify_tag,
    ) {
        Ok(pt) => pt.is_empty(),
        Err(_) => false,
    }
}

// -------------------- 解密 --------------------

struct DecCtx {
    pkg_dir: PathBuf,
    out: PathBuf,
    pkg: Package,
    key: Vec<u8>,
    tasks: Vec<(usize, u32, u32)>,
    job: Arc<Job>,
}

/// Reopen and exclusively hold the key file through debit and restoration.
pub fn restore_package_with_key_file(
    pkg_dir: &Path, pkg: &Package, key_path: &Path, out_root: &Path,
    job: &Arc<Job>, threads: usize,
) -> Result<Summary, String> {
    let preview = read_key_file(key_path)?;
    if preview.bound && preview.id != pkg.id { return Err("密钥与加密包不配对".into()); }
    if preview.remaining.is_none() {
        return restore_package(pkg_dir, pkg, &preview.key, out_root, job, threads);
    }
    if !plain_metadata(key_path)?.is_file() { return Err("密钥不是普通文件".into()); }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)] {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    #[cfg(not(windows))] {
        return Err("Limited keys require Windows exclusive file access".into());
    }
    let mut file = options.open(key_path)
        .map_err(|e| format!("无法更新密钥次数，请确认密钥文件可写且未被占用：{}", e))?;
    let mut bytes = Vec::new();
    (&mut file).take(4097).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 4096 { return Err("密钥文件过大".into()); }
    let kf = decode_key_file(&bytes)?;
    if kf.remaining.is_none() || kf.id != pkg.id { return Err("密钥文件已变化或与加密包不配对".into()); }
    restore_package_impl(pkg_dir, pkg, &kf.key, out_root, job, threads, Some((&mut file, &kf)))
}

// Persist before any plaintext is produced. Interrupted writes fail closed;
// a backup can still roll back this offline counter, which is not DRM.
fn debit_key(file: &mut File, kf: &KeyFile) -> Result<(), String> {
    let left = kf.remaining.ok_or_else(|| "Missing key usage count".to_string())?;
    if left == 0 { return Err(KEY_EXHAUSTED.into()); }
    let bytes = encode_limited_key(&kf.id, kf.created, &kf.key, left - 1)?;
    let result = (|| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let mut saved = vec![0u8; bytes.len()];
        file.read_exact(&mut saved)?;
        if saved != bytes { return Err(std::io::Error::new(std::io::ErrorKind::Other, "Key readback mismatch")); }
        Ok(())
    })();
    result.map_err(|e| format!("密钥次数写回失败，未开始解密；密钥可能已扣次或损坏：{}", e))
}

/// 还原整包：先建目录与空文件，再并行分块解密，最后恢复修改时间。
pub fn restore_package(
    pkg_dir: &Path,
    pkg: &Package,
    key: &[u8; KEY_LEN],
    out_root: &Path,
    job: &Arc<Job>,
    threads: usize,
) -> Result<Summary, String> {
    restore_package_impl(pkg_dir, pkg, key, out_root, job, threads, None)
}

fn restore_package_impl(
    pkg_dir: &Path, pkg: &Package, key: &[u8; KEY_LEN], out_root: &Path,
    job: &Arc<Job>, threads: usize, debit: Option<(&mut File, &KeyFile)>,
) -> Result<Summary, String> {
    let t0 = std::time::Instant::now();
    pkg.validate()?;
    if !check_key(pkg, key) { return Err("Wrong key or unauthenticated/tampered manifest; no output was created".into()); }
    validate_blobs(pkg_dir, pkg)?;
    if job.cancelled() { return Err("已取消".into()); }
    let destination = restore_destination(out_root)?;
    let mut stage = Staging::new(&destination)?;
    let prepared = match debit {
        Some((file, kf)) => debit_key(file, kf),
        None => Ok(()),
    };
    let result = prepared.and_then(|_| restore_package_inner(pkg_dir, pkg, key, &stage.path, job, threads))
        .and_then(|_| { stage.publish(&destination)?; Ok(Summary {
            files: pkg.files.len(), bytes: pkg.total_bytes, secs: t0.elapsed().as_secs_f64(),
        }) });
    stage.finish(result)
}

fn restore_package_inner(
    pkg_dir: &Path, pkg: &Package, key: &[u8; KEY_LEN], out_root: &Path,
    job: &Arc<Job>, threads: usize,
) -> Result<(), String> {
    for d in &pkg.dirs {
        let p = join_rel(out_root, d);
        ensure_dir(&p).map_err(|e| format!("无法创建 {}：{}", d, e))?;
    }
    for f in &pkg.files {
        let p = join_rel(out_root, &f.rel);
        if let Some(par) = p.parent() {
            ensure_dir(par).map_err(|e| format!("Cannot create output parent: {}", e))?;
        }
        let file = OpenOptions::new().write(true).create_new(true).open(&p)
            .map_err(|e| format!("Cannot exclusively create {}: {}", f.rel, e))?;
        if f.size > 0 {
            file.set_len(f.size)
                .map_err(|e| format!("预分配 {} 失败：{}", f.rel, e))?;
        }
    }

    let tasks = plan_tasks(pkg, threads);
    let ctx = Arc::new(DecCtx {
        pkg_dir: pkg_dir.to_path_buf(),
        out: out_root.to_path_buf(),
        pkg: clone_pkg(pkg),
        key: key.to_vec(),
        tasks,
        job: Arc::clone(job),
    });
    run_dec(ctx.clone());
    if let Some(e) = job.first_error() {
        return Err(e);
    }
    if job.cancelled() {
        return Err("已取消".into());
    }
    validate_blobs(pkg_dir, pkg)?;
    for f in &pkg.files {
        let path = join_rel(out_root, &f.rel);
        set_mtime_checked(&path, f.mtime)?;
        OpenOptions::new().write(true).open(&path).and_then(|file| file.sync_all())
            .map_err(|e| format!("Cannot synchronize restored file {}: {}", f.rel, e))?;
    }
    let mut order: Vec<usize> = (0..pkg.dirs.len()).collect();
    order.sort_by(|a, b| pkg.dirs[*b].split('/').count().cmp(&pkg.dirs[*a].split('/').count()));
    for i in order { set_mtime_checked(&join_rel(out_root, &pkg.dirs[i]), pkg.dir_mtimes[i])?; }
    set_mtime_checked(out_root, pkg.root_mtime)?;
    if job.cancelled() { return Err("已取消".into()); }
    Ok(())
}

fn check_blob(file: &mut File, rec: &FileRec) -> Result<(), String> {
    let md = file.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() || md.len() != blob_size(rec.size, CHUNK_SIZE) {
        return Err(format!("Blob length differs from manifest: {}", rec.rel));
    }
    let mut header = [0u8; HDR as usize];
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    file.read_exact(&mut header).map_err(|e| format!("Missing blob header: {}", e))?;
    if &header[..4] != BLOB_MAGIC || read_u16_le(&header[4..]) != VERSION
        || read_u32_le(&header[6..]) != CHUNK_SIZE as u32
        || read_u64_le(&header[10..]) != rec.size
        || read_u32_le(&header[18..]) != chunk_count(rec.size, CHUNK_SIZE)
        || header[22..].iter().any(|b| *b != 0) {
        return Err(format!("Invalid blob header: {}", rec.rel));
    }
    Ok(())
}

fn validate_blobs(dir: &Path, pkg: &Package) -> Result<(), String> {
    if !plain_metadata(dir)?.is_dir() || !plain_metadata(&dir.join(BLOBS_DIR))?.is_dir() {
        return Err("Package/blob path is not a regular directory".into());
    }
    let expected: HashSet<String> = pkg.files.iter().map(|f| Package::blob_name(f.blob)).collect();
    let mut found = 0usize;
    for entry in fs::read_dir(dir.join(BLOBS_DIR)).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().into_string().map_err(|_| "Invalid blob name".to_string())?;
        if !expected.contains(&name) { return Err(format!("Unexpected blob object: {}", name)); }
        if !plain_metadata(&entry.path())?.is_file() { return Err("Blob is not a regular file".into()); }
        found += 1;
        if found > pkg.files.len() { return Err("Too many blob objects".into()); }
    }
    if found != pkg.files.len() { return Err("Missing blob objects".into()); }
    for rec in &pkg.files {
        let mut file = open_source(&Package::blob_path(dir, rec.blob))?;
        check_blob(&mut file, rec)?;
    }
    Ok(())
}

fn set_mtime_checked(path: &Path, stamp: u64) -> Result<(), String> {
    crate::util::try_set_mtime(path, stamp)
        .map_err(|e| format!("Cannot restore modification time {}: {}", path.display(), e))
}

fn run_dec(ctx: Arc<DecCtx>) {
    let n = ctx.tasks.len();
    let threads = pool::plan_threads(n, ctx.pkg.total_bytes);
    pool::run(n, threads, move |i| {
        let (fi, first, count) = ctx.tasks[i];
        let rec = &ctx.pkg.files[fi];
        if ctx.job.cancelled() {
            return;
        }
        let chunk = ctx.pkg.chunk();
        if ctx.key.len() != KEY_LEN {
            ctx.job.fail("密钥长度错误".into());
            return;
        }
        let mut kbuf = [0u8; KEY_LEN];
        kbuf.copy_from_slice(&ctx.key);
        let key = &kbuf;
        let blob_path = ctx.pkg_dir.join(BLOBS_DIR).join(Package::blob_name(rec.blob));
        let mut src = match open_source(&blob_path) {
            Ok(f) => f,
            Err(e) => {
                ctx.job.fail(format!("无法读取密文（{}）：{}", rec.rel, e));
                return;
            }
        };
        if let Err(e) = check_blob(&mut src, rec) { ctx.job.fail(e); return; }
        let out_path = join_rel(&ctx.out, &rec.rel);
        let mut dst = match OpenOptions::new().write(true).open(&out_path) {
            Ok(f) => f,
            Err(e) => {
                ctx.job.fail(format!("无法写入 {}：{}", rec.rel, e));
                return;
            }
        };
        let mut aad = Vec::with_capacity(64 + rec.rel.len());
        let mut c = first;
        let end = first + count;
        let mut done = 0u64;
        while c < end {
            if ctx.job.cancelled() { return; }
            let expect = chunk_len(rec.size, c, chunk) as usize;
            if let Err(e) = src.seek(SeekFrom::Start(rec_off(c, chunk))) {
                ctx.job.fail(format!("{}：{}", rec.rel, e));
                return;
            }
            let mut head = [0u8; NONCE_LEN + 4];
            if read_exact_n(&mut src, &mut head).is_err() {
                ctx.job.fail(format!("{}：密文块头缺失，包可能不完整", rec.rel));
                return;
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&head[..NONCE_LEN]);
            let len = read_u32_le(&head[NONCE_LEN..]) as usize;
            if len != expect {
                ctx.job.fail(format!("{}：块长度与清单不符，包已被改动", rec.rel));
                return;
            }
            let mut buf = vec![0u8; len + TAG_LEN];
            if read_exact_n(&mut src, &mut buf).is_err() {
                ctx.job.fail(format!("{}：密文块缺失", rec.rel));
                return;
            }
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&buf[len..]);
            chunk_aad(&ctx.pkg.id, rec, c, len as u32, &mut aad);
            if crypto::xchacha20_poly1305_decrypt_in_place(
                key,
                &nonce,
                &aad,
                &mut buf[..len],
                &tag,
            )
            .is_err()
            {
                ctx.job.fail(format!(
                    "{}：完整性校验失败（密钥不正确，或数据已损坏/被篡改）",
                    rec.rel
                ));
                return;
            }
            if let Err(e) = dst.seek(SeekFrom::Start(c as u64 * chunk)) {
                ctx.job.fail(format!("{}：{}", rec.rel, e));
                return;
            }
            if let Err(e) = dst.write_all(&buf[..len]) {
                ctx.job.fail(format!("写入 {} 失败：{}", rec.rel, e));
                return;
            }
            done += len as u64;
            c += 1;
        }
        if let Err(e) = check_blob(&mut src, rec) { ctx.job.fail(e); return; }
        if let Err(e) = dst.flush() { ctx.job.fail(format!("Cannot flush plaintext: {}", e)); return; }
        ctx.job.tick(done, &rec.rel);
    });
}

// -------------------- 命名建议 --------------------

pub fn suggest_names(src: &Path, parent: &Path) -> (PathBuf, PathBuf) {
    let base = src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::from("folder"));
    let safe: String = base
        .chars()
        .map(|c| match c {
            ':' | '/' | '\\' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect();
    let safe = if safe.is_empty() { String::from("folder") } else { safe };
    let (pn, kn) = free_pair(parent, &safe);
    (parent.join(pn), parent.join(kn))
}

/// 包与密钥必须成对让位，否则会出现 `X.chacha` 配 `X (2).chacha.key` 这种不配套的名字。
fn free_pair(parent: &Path, safe: &str) -> (String, String) {
    let mut n = 0u32;
    let (mut pkg, mut key) = (
        format!("{}{}", safe, PACKAGE_SUFFIX),
        format!("{}{}", safe, KEY_SUFFIX),
    );
    while n < 999 {
        let busy = parent.join(&pkg).exists() || parent.join(&key).exists();
        if !busy {
            break;
        }
        n += 1;
        let stem = format!("{} ({})", safe, n + 1);
        pkg = format!("{}{}", stem, PACKAGE_SUFFIX);
        key = format!("{}{}", stem, KEY_SUFFIX);
    }
    (pkg, key)
}

/// 输出目录里还原出的顶层文件夹名。
pub fn restore_target(out_root: &Path, pkg: &Package) -> PathBuf {
    let name: &str = if validate_component(&pkg.src_name).is_err() {
        "restored"
    } else {
        pkg.src_name.as_str()
    };
    out_root.join(name)
}

pub fn total_kb(bytes: u64) -> usize {
    (bytes / 1024 + if bytes % 1024 != 0 { 1 } else { 0 }).min(usize::max_value() as u64) as usize
}

// -------------------- 端到端自检 --------------------

/// 建样例文件夹 → 加密 → 读清单 → 校验密钥 → 解密 → 逐字节比对。
/// 证明「原封不动」这条主链路在目标机器上真的成立。
pub fn self_roundtrip() -> Result<(usize, u64), String> {
    let temporary = std::env::temp_dir().join("chacha-self");
    let owned = Staging::new(&temporary)?;
    let base = owned.path.clone();
    let src = base.join("A");
    let pkg = base.join("B");
    let out = base.join("out");
    fs::create_dir_all(src.join("子目录/更深")).map_err(|e| e.to_string())?;
    fs::write(src.join("文本.txt"), "hello 中文\n".as_bytes()).map_err(|e| e.to_string())?;
    fs::write(src.join("empty.bin"), &[]).map_err(|e| e.to_string())?;
    let big: Vec<u8> = (0usize..(2 * 1024 * 1024 + 7)).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("子目录/大图.dat"), &big).map_err(|e| e.to_string())?;
    fs::write(src.join("子目录/更深/note.md"), b"# note").map_err(|e| e.to_string())?;

    let r = self_roundtrip_inner(&src, &pkg, &out);
    let mut owned = owned;
    let cleanup = fs::remove_dir_all(&base);
    owned.owned = false;
    cleanup.map_err(|e| format!("Self-test cleanup failed at {}: {}", base.display(), e))?;
    r
}

fn self_roundtrip_inner(src: &Path, pkg: &Path, out: &Path) -> Result<(usize, u64), String> {
    let scan = scan_folder(src)?;
    let key = new_key()?;
    let job = Job::new(scan.total, scan.files.len());
    create_package(src, pkg, &key, &job, pool::cpu_count())?;
    if job.cancelled() {
        return Err("自检异常：任务被取消".into());
    }
    // 清单必须无需密钥即可读取（解密端第 ① 步依赖这一点）
    let p2 = open_package(pkg)?;
    if p2.files.len() != scan.files.len() {
        return Err(format!(
            "清单文件数不符：{} vs {}",
            p2.files.len(),
            scan.files.len()
        ));
    }
    if !check_key(&p2, &key) {
        return Err("密钥校验失败".into());
    }
    let wrong = [0u8; KEY_LEN];
    if check_key(&p2, &wrong) {
        return Err("错误密钥竟然通过了校验".into());
    }
    let job2 = Job::new(p2.total_bytes, p2.file_count());
    restore_package(pkg, &p2, &key, out, &job2, pool::cpu_count())?;
    compare_trees(src, out)
}

fn compare_trees(src: &Path, out: &Path) -> Result<(usize, u64), String> {
    let a = scan_folder(src)?;
    let b = scan_folder(out)?;
    if a.files.len() != b.files.len() {
        return Err(format!(
            "文件数不符：{} vs {}",
            a.files.len(),
            b.files.len()
        ));
    }
    if a.dirs.len() != b.dirs.len() {
        return Err("目录结构不符".into());
    }
    let mut total = 0u64;
    for i in 0..a.files.len() {
        if a.files[i].0 != b.files[i].0 {
            return Err(format!("第 {} 项名称不符", i + 1));
        }
        let pa = join_rel(src, &a.files[i].0);
        let pb = join_rel(out, &b.files[i].0);
        let da = fs::read(&pa).map_err(|e| format!("{}：{}", a.files[i].0, e))?;
        let db = fs::read(&pb).map_err(|e| format!("{}：{}", b.files[i].0, e))?;
        if da != db {
            return Err(format!("{}：内容不一致", a.files[i].0));
        }
        // 修改时间也要还原。留 2 秒容差（=2000 万个 100ns）是因为 FAT 只有 2 秒精度，
        // 但单位/纪元换算写错会一下差出几十年，这种一定抓得到。
        let (ma, mb) = (a.files[i].2, b.files[i].2);
        let gap = if ma > mb { ma - mb } else { mb - ma };
        if gap > 20_000_000 {
            return Err(format!(
                "{}：修改时间没还原对（{} vs {}）",
                a.files[i].0, ma, mb
            ));
        }
        total += da.len() as u64;
    }
    Ok((a.files.len(), total))
}

#[cfg(test)]
mod key_usage_tests {
    use super::*;

    #[test]
    fn limited_envelope_boundaries_and_text() {
        let id = [3u8; 16];
        let key = [7u8; 32];
        for uses in 1..=7 {
            let bytes = encode_key_file(&id, 123, &key, uses).unwrap();
            assert_eq!(bytes.len(), LIMITED_KEY_LEN);
            let parsed = decode_key_file(&bytes).unwrap();
            assert_eq!(parsed.id, id);
            assert_eq!(parsed.created, 123);
            assert_eq!(parsed.key, key);
            assert_eq!(parsed.remaining, Some(uses));
            let text = crate::util::hex_encode_grouped(&bytes);
            assert_eq!(decode_key_file(text.as_bytes()).unwrap().remaining, Some(uses));
        }
        assert!(encode_key_file(&id, 0, &key, 0).is_err());
        assert!(encode_key_file(&id, 0, &key, 8).is_err());
        assert!(encode_key_file(&id, 0, &key, 255).is_err());
        let exhausted = encode_limited_key(&id, 0, &key, 0).unwrap();
        assert_eq!(decode_key_file(&exhausted).err().unwrap(), KEY_EXHAUSTED);
        let invalid = encode_limited_key(&id, 0, &key, 8).unwrap();
        assert!(decode_key_file(&invalid).is_err());
    }

    #[test]
    fn limited_envelope_rejects_every_modified_byte_and_truncation() {
        let bytes = encode_key_file(&[1; 16], 123, &[2; 32], 7).unwrap();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(decode_key_file(&bad).is_err(), "modified byte {}", i);
            assert!(decode_key_file(&bytes[..i]).is_err(), "truncated at {}", i);
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_key_file(&extra).is_err());
    }

    #[test]
    fn legacy_binary_and_raw_hex_remain_compatible() {
        let key = [9u8; 32];
        let mut bytes = KEY_MAGIC.to_vec();
        bytes.extend_from_slice(&[1u8; 16]);
        write_u64_le(&mut bytes, 123);
        bytes.extend_from_slice(&key);
        let crc = crate::util::crc32(&bytes);
        write_u32_le(&mut bytes, crc);
        let parsed = decode_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert!(parsed.bound);
        assert_eq!(parsed.remaining, None);
        let parsed = decode_key_file(hex_encode(&key).as_bytes()).unwrap();
        assert_eq!(parsed.key, key);
        assert!(!parsed.bound);
        assert_eq!(parsed.remaining, None);
    }
}

pub fn est_blob_total(pkg: &Package) -> u64 {
    let chunk = pkg.chunk();
    let mut n = 0u64;
    for f in &pkg.files {
        n = n.saturating_add(blob_size(f.size, chunk));
    }
    n
}
