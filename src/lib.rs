//! CHACHA 核心库：加密内核、自包含加密包格式、线程池、Win32 UI 工具箱。
//!
//! 两个可执行文件共用本库：
//! - `chacha-enc`：文件夹 A → 加密包 B + 密钥文件
//! - `chacha-dec`：加密包 B + 密钥文件 → 还原文件夹 A

pub mod crypto;
pub mod dec_app;
pub mod enc_app;
pub mod package;
pub mod pool;
pub mod ui;
pub mod util;

// libtest imports the same exception symbols; keep XP shims in production only.
#[cfg(not(test))]
mod xpcompat;
