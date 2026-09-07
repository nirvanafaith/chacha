@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul
set CARGO_HOME=E:\chacha\tools\cargo
set RUSTUP_HOME=E:\chacha\tools\rustup
set RUSTUP_TOOLCHAIN=1.44.0-x86_64-pc-windows-msvc
set PATH=E:\chacha\tools\cargo\bin;%PATH%
cd /d E:\chacha
echo rustc:
rustc --version
echo link:
where link
echo cargo:
cargo build --release --target i686-pc-windows-msvc
echo cargo_exit=%ERRORLEVEL%
