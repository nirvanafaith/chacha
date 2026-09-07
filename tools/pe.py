#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PE 兼容性审计：确认这两个 exe 真能在 Windows XP 上跑。

检查四件事：
  1. 32 位 (0x14c) + PE32 (0x10b)，不是 PE32+
  2. 子系统版本 = 5.01（XP），加载器会按它拒绝在更老的系统上跑
  3. 依赖里没有 libgcc / winpthread 这类会被杀软盯上的额外 DLL
  4. 没有 Vista 及以后才出现的导出函数（这是最容易翻车的地方）
"""
import struct
import sys

try:  # 控制台默认可能是 GBK，统一切到 UTF-8，避免打印 DLL 名时炸码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Windows 版本 -> 该版本（含更早）没有的常见导出
VISTA_PLUS = {
    "GetFileInformationByHandleEx",
    "SetProcessDPIAware", "GetSystemTimePreciseAsFileTime",
    "GetTickCount64", "TaskDialog", "TaskDialogIndirect",
    "SleepConditionVariableCS", "SleepConditionVariableSRW",
    "WakeAllConditionVariable", "WakeConditionVariable",
    "InitializeConditionVariable", "InitializeSRWLock", "AcquireSRWLockExclusive",
    "ReleaseSRWLockExclusive", "TryAcquireSRWLockExclusive",
    "InitOnceExecuteOnce",
    "GetUserDefaultLocaleName", "LCIDToLocaleName", "LocaleNameToLCID",
    "SHGetKnownFolderPath", "SetDefaultDllDirectories", "IsProcessDPIAware",
    "GetErrorMode", "SetThreadStackGuarantee", "K32GetModuleFileNameExW",
    "QueryThreadCycleTime", "GetLogicalProcessorInformation",
    "FileTimeToSystemTime",  # 占位，下面单独放行
}
# 这些其实从 NT 3.1/Win95 就有，早先被误报过，明确放行
ALLOWED = {
    "FileTimeToSystemTime", "SystemTimeToFileTime", "FileTimeToLocalFileTime",
    "LocalFileTimeToFileTime", "SetFileTime", "GetFileTime", "GetSystemTime",
    "SetEndOfFile", "SetFilePointerEx",
}

KNOWN_DLLS = {
    "KERNEL32.dll", "USER32.dll", "GDI32.dll", "ADVAPI32.dll", "SHELL32.dll",
    "COMCTL32.dll", "COMDLG32.dll", "OLE32.dll", "msvcrt.dll", "WINSPOOL.DRV",
    "UDDATA.DLL",
}


def rva_to_off(data, sections, rva):
    for s in sections:
        vs, vsz, praw, prsz = s
        if vs <= rva < vs + max(vsz, prsz):
            return praw + (rva - vs)
    raise ValueError("rva %x not in any section" % rva)


def cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("latin-1")


def analyze(path):
    data = open(path, "rb").read()
    problems = []
    if data[:2] != b"MZ":
        return ["不是 PE 文件"]
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return ["不是 PE 文件"]
    machine, nsec = struct.unpack_from("<HH", data, pe + 4)
    opt_off = pe + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    os_maj, os_min = struct.unpack_from("<HH", data, opt_off + 40)
    sub_maj, sub_min = struct.unpack_from("<HH", data, opt_off + 48)
    subsys = struct.unpack_from("<H", data, opt_off + 68)[0]
    size_opt = struct.unpack_from("<H", data, pe + 20)[0]  # COFF.SizeOfOptionalHeader
    print("%s" % path)
    print("  machine      0x%04x  (%s)" % (machine, "x86 32 位" if machine == 0x14C else "非 32 位!"))
    print("  magic        0x%04x  (%s)" % (magic, "PE32" if magic == 0x10B else "PE32+!"))
    print("  OS version   %d.%d" % (os_maj, os_min))
    print("  SubsysVer    %d.%d" % (sub_maj, sub_min))
    print("  Subsystem    %d (%s)" % (subsys, "GUI" if subsys == 2 else "console" if subsys == 3 else "?"))
    if machine != 0x14C:
        problems.append("不是 32 位")
    if magic != 0x10B:
        problems.append("不是 PE32")
    if (sub_maj, sub_min) > (5, 1):
        problems.append("子系统版本高于 5.01，XP 会拒绝加载")
    if (os_maj, os_min) > (5, 1):
        problems.append("OS 版本高于 5.01")
    if subsys != 2:
        problems.append("不是 GUI 子系统")

    # sections
    sec_off = opt_off + size_opt
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        # +8 VirtualSize, +12 VirtualAddress, +16 SizeOfRawData, +20 PointerToRawData
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        sections.append((vaddr, vsize, rawptr, rawsize))
    # data directories: index 1 = import table
    dd_off = opt_off + 96 if magic == 0x10B else opt_off + 112
    imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)
    if imp_rva == 0:
        problems.append("没有导入表？")
        return problems
    io = rva_to_off(data, sections, imp_rva)
    dlls = []
    idx = 0
    while True:
        e = io + idx * 20
        # IMAGE_IMPORT_DESCRIPTOR: +0 OriginalFirstThunk +4 TimeDateStamp
        #                          +8 ForwarderChain +12 Name +16 FirstThunk
        orig, ts, fwd, name_rva, th_rva = struct.unpack_from("<IIIII", data, e)
        if name_rva == 0 and th_rva == 0 and orig == 0:
            break
        dll = cstr(data, rva_to_off(data, sections, name_rva))
        funcs = []
        if th_rva:
            to = rva_to_off(data, sections, th_rva)
            j = 0
            while True:
                ent = struct.unpack_from("<I", data, to + j * 4)[0]
                if ent == 0:
                    break
                if ent & 0x80000000:
                    funcs.append("#%d" % (ent & 0xFFFF))
                else:
                    fo = rva_to_off(data, sections, ent & 0x7FFFFFFF)
                    funcs.append(cstr(data, fo + 2))
                j += 1
        dlls.append((dll, funcs))
        idx += 1
    print("  imports:")
    for dll, funcs in dlls:
        print("    %-16s %d 个函数" % (dll, len(funcs)))
        bad = [f for f in funcs if f in VISTA_PLUS and f not in ALLOWED]
        if bad:
            problems.append("%s 里有 Vista+ 函数: %s" % (dll, ", ".join(sorted(set(bad)))))
        if dll.lower() not in {k.lower() for k in KNOWN_DLLS}:
            problems.append("意外的依赖 DLL: %s" % dll)
    return problems


def main():
    targets = sys.argv[1:] or [
        r"E:\chacha\dist\enc\chacha-enc.exe",
        r"E:\chacha\dist\dec\chacha-dec.exe",
    ]
    allbad = []
    for t in targets:
        allbad += analyze(t)
        print("")
    if allbad:
        print("PROBLEMS:")
        for p in allbad:
            print("  - " + p)
        return 1
    print("PE AUDIT: PASS (static checks only; XP runtime verification still required)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
