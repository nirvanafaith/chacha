//! XP 兼容垫片。
//!
//! Rust 1.44 的 libstd 会硬导入若干 Vista+ 才有的 kernel32 导出。PE 加载器在
//! XP 上找不到这些入口点会直接拒绝启动，所以这里用**同名定义**把它们抢过来：
//! MinGW 的 kernel32.a 是导入库（归档），目标文件里的定义优先，归档成员因此
//! 不会被拉入，导入表里也就不再出现这些符号。运行时再用 GetProcAddress 尝试
//! 调用真正的系统实现，不存在时退回 XP 可用的等价 API。

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;

extern "system" {
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
}

unsafe fn kernel32(name: &[u8]) -> *mut c_void {
    let k = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if k.is_null() {
        return core::ptr::null_mut();
    }
    GetProcAddress(k, name.as_ptr())
}

unsafe fn module(dll: &[u8], name: &[u8]) -> *mut c_void {
    let m = GetModuleHandleA(dll.as_ptr());
    if m.is_null() {
        return core::ptr::null_mut();
    }
    GetProcAddress(m, name.as_ptr())
}

/// Vista+。XP 退回 WaitForSingleObject（忽略 alertable）。
#[no_mangle]
pub unsafe extern "system" fn WaitForSingleObjectEx(
    handle: *mut c_void,
    ms: u32,
    alertable: i32,
) -> u32 {
    type W = unsafe extern "system" fn(*mut c_void, u32, i32) -> u32;
    let p = kernel32(b"WaitForSingleObjectEx\0");
    if !p.is_null() {
        let f: W = core::mem::transmute(p);
        return f(handle, ms, alertable);
    }
    WaitForSingleObject(handle, ms)
}

/// Vista+ 的 kernel32 转发；XP 上只有 ntdll 版本。仅用于栈回溯。
#[no_mangle]
pub unsafe extern "system" fn RtlCaptureContext(ctx: *mut c_void) {
    type C = unsafe extern "system" fn(*mut c_void);
    let mut p = kernel32(b"RtlCaptureContext\0");
    if p.is_null() {
        p = module(b"ntdll.dll\0", b"RtlCaptureContext\0");
    }
    if !p.is_null() {
        let f: C = core::mem::transmute(p);
        f(ctx);
    }
}

/// Windows XP SP2+ 才有；更早的版本返回 NULL 表示未安装处理器。
#[no_mangle]
pub unsafe extern "system" fn AddVectoredExceptionHandler(
    first: u32,
    handler: *mut c_void,
) -> *mut c_void {
    type V = unsafe extern "system" fn(u32, *mut c_void) -> *mut c_void;
    let p = kernel32(b"AddVectoredExceptionHandler\0");
    if p.is_null() {
        return core::ptr::null_mut();
    }
    let f: V = core::mem::transmute(p);
    f(first, handler)
}
