#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! CHACHA 解密端。

use std::env;
use std::path::PathBuf;

use chacha::{crypto, dec_app, enc_app, package, pool, util};

fn main() {
    let all: Vec<String> = env::args().collect();
    let args: Vec<String> = all.into_iter().skip(1).collect();
    let cli_mode = args.iter().any(|a| {
        a == "--decrypt" || a == "--info" || a == "--self-test" || a == "--bench" || a == "--help"
    });
    let code = if cli_mode {
        util::console::attach();
        dispatch(&args)
    } else {
        // 没有命令行任务：进图形界面，能预填的就预填
        dec_app::run(prefill(&args))
    };
    std::process::exit(code);
}

/// 图形界面的预填参数。裸路径按「加密包 / 密钥文件 / 还原目录」的顺序认领，
/// 所以把加密包或密钥文件直接拖到程序图标上就能用。
fn prefill(args: &[String]) -> dec_app::Prefill {
    let mut pf = dec_app::Prefill::empty();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if (a == "--key" || a == "-k") && i + 1 < args.len() {
            pf.key = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        if (a == "--out" || a == "-o") && i + 1 < args.len() {
            pf.out = Some(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        let pb = PathBuf::from(a);
        if pf.pkg.is_none() && package::looks_like_package(&pb) {
            pf.pkg = Some(pb);
        } else if pf.key.is_none() && a.ends_with(package::KEY_SUFFIX) {
            pf.key = Some(pb);
        } else if pf.out.is_none() && pb.is_dir() {
            pf.out = Some(pb);
        }
        i += 1;
    }
    pf
}

fn dispatch(args: &[String]) -> i32 {
    match args[0].as_str() {
        "--self-test" => {
            if let Err(e) = crypto::self_test() {
                util::console::eprint(&format!("自检失败：{}\n", e));
                return 1;
            }
            util::console::print(&format!("加密内核 ok  ({})\n", crypto::backend_label()));
            match package::self_roundtrip() {
                Ok((n, bytes)) => {
                    util::console::print(&format!(
                        "加解密往返 ok  ({} 个文件 · {} · {} 线程)\n",
                        n,
                        util::format_size(bytes),
                        pool::cpu_count()
                    ));
                    0
                }
                Err(e) => {
                    util::console::eprint(&format!("加解密往返失败：{}\n", e));
                    1
                }
            }
        }
        "--bench" => {
            enc_app::bench();
            0
        }
        "--info" if args.len() > 1 => enc_app::print_package_info(&PathBuf::from(&args[1])),
        "--decrypt" => dec_app::cli(args),
        "--help" | "-h" | "/?" => {
            dec_app::usage();
            0
        }
        other => {
            util::console::eprint(&format!("未知参数：{}\n\n", other));
            dec_app::usage();
            2
        }
    }
}
