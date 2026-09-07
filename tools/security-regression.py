"""Security integration tests for already-built dist binaries (Python stdlib only).

Run after rebuilding both executables:
    python tools/security-regression.py
    python tools/security-regression.py --timeout 30 -v

Never builds, edits dist, or uses dist as a scratch directory. Fixtures are small
and reused; every destructive test gets a disposable copy in the system temp dir.
Manifest serialization mirrors Package::encode_fields in src/package.rs (v2).
"""

import argparse
import contextlib
import copy
import ctypes
import dataclasses
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
DIST = Path(os.environ.get("CHACHA_TEST_DIST", str(ROOT / "dist")))
CHUNK = 1024 * 1024
HEADER = 32
RECORD_OVERHEAD = 24 + 4 + 16
TIMEOUT = 30.0
COMMANDS = 0


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def string(value):
    encoded = value.encode("utf-8")
    return struct.pack("<H", len(encoded)) + encoded


class Cursor:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.boundaries = {0}

    def take(self, length):
        end = self.pos + length
        require(end <= len(self.data), "test parser: truncated v2 manifest")
        result = self.data[self.pos:end]
        self.pos = end
        self.boundaries.add(end)
        return result

    def number(self, fmt):
        return struct.unpack("<" + fmt, self.take(struct.calcsize("<" + fmt)))[0]

    def text(self):
        return self.take(self.number("H")).decode("utf-8")


@dataclasses.dataclass
class Manifest:
    package_id: bytes
    created: int
    src_name: str
    src_path: str
    chunk: int
    total: int
    root_mtime: int
    nonce: bytes
    tag: bytes
    verification: bytes
    files: list
    dirs: list

    @classmethod
    def decode(cls, data):
        c = Cursor(data)
        require(c.take(8) == b"CHAPKG01", "unexpected manifest magic")
        require(c.number("H") == 2, "expected v2; rebuild dist before running")
        require(c.number("H") == 0, "unexpected manifest flags")
        package_id, created = c.take(16), c.number("Q")
        src_name, src_path = c.text(), c.text()
        chunk, nf, nd = c.number("I"), c.number("I"), c.number("I")
        total, root_mtime = c.number("Q"), c.number("Q")
        nonce, tag = c.take(24), c.take(16)
        verification = c.take(c.number("I"))
        files = [(c.text(), c.number("Q"), c.number("Q"), c.number("I"))
                 for _ in range(nf)]
        dirs = [(c.text(), c.number("Q")) for _ in range(nd)]
        require(c.pos == len(data), "test parser: unexpected v2 trailing layout")
        result = cls(package_id, created, src_name, src_path, chunk, total,
                     root_mtime, nonce, tag, verification, files, dirs)
        require(result.encode() == data, "test serializer differs from v2 encoder")
        return result, c.boundaries

    def encode(self):
        data = (b"CHAPKG01" + struct.pack("<HH", 2, 0) + self.package_id
                + struct.pack("<Q", self.created)
                + string(self.src_name) + string(self.src_path)
                + struct.pack("<IIIQQ", self.chunk, len(self.files), len(self.dirs),
                              self.total, self.root_mtime)
                + self.nonce + self.tag
                + struct.pack("<I", len(self.verification)) + self.verification)
        for rel, size, mtime, blob in self.files:
            data += string(rel) + struct.pack("<QQI", size, mtime, blob)
        for rel, mtime in self.dirs:
            data += string(rel) + struct.pack("<Q", mtime)
        return data


def snapshot(root):
    require(root.exists(), "missing tree: " + str(root))
    result = {}
    for path in [root] + sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        stat = path.stat()
        result[rel] = ("dir" if path.is_dir() else "file", stat.st_mtime_ns,
                       None if path.is_dir() else hashlib.sha256(path.read_bytes()).digest())
    return result


def same_tree(expected, actual, tolerance_ns=0):
    require(expected.keys() == actual.keys(),
            "tree entries differ: " + repr(sorted(expected.keys() ^ actual.keys())))
    for name, (kind, mtime, digest) in expected.items():
        other_kind, other_mtime, other_digest = actual[name]
        require((kind, digest) == (other_kind, other_digest),
                "type/content changed: " + name)
        require(abs(mtime - other_mtime) <= tolerance_ns,
                "mtime changed: {} ({} vs {})".format(name, mtime, other_mtime))


class SecurityRegression(unittest.TestCase):
    @classmethod
    def invoke(cls, exe, *args, reject=False):
        global COMMANDS
        COMMANDS += 1
        command = [str(exe)] + [str(arg) for arg in args]
        try:
            result = subprocess.run(command, cwd=cls.work, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=TIMEOUT, check=False)
        except subprocess.TimeoutExpired as error:
            raise AssertionError("CLI timeout after {}s: {}".format(TIMEOUT, command)) from error
        output = (result.stdout + result.stderr).decode("utf-8", "replace")
        detail = "rc={} (0x{:08x}): {}\n{}".format(
            result.returncode, result.returncode & 0xffffffff, command, output[-2400:])
        # Abort can be 3, 101, a negative signal, or a Windows NTSTATUS. None is
        # a successful rejection. Restrict to the CLI's documented error exits.
        require(result.returncode in ((1, 2) if reject else (0,)), detail)
        require("panicked at" not in output.lower(), "Rust panic: " + detail)
        return output

    @classmethod
    def setUpClass(cls):
        cls.enc = DIST / "enc" / "chacha-enc.exe"
        cls.dec = DIST / "dec" / "chacha-dec.exe"
        for exe in (cls.enc, cls.dec):
            require(exe.is_file(), "missing executable; build first: " + str(exe))
        temp_parent = Path(tempfile.gettempdir()).resolve()
        require(not temp_parent.is_relative_to(DIST.resolve()),
                "system temp directory is inside dist; set TEMP outside dist")
        cls.temp = tempfile.TemporaryDirectory(prefix="chacha-security-", dir=temp_parent)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.source = cls.work / "source"
        (cls.source / "notes" / "empty directory").mkdir(parents=True)
        (cls.source / "empty").mkdir()
        (cls.source / "a-big.bin").write_bytes(bytes(range(256)) * (2 * CHUNK // 256))
        (cls.source / "notes" / "read me.txt").write_bytes(b"security regression\r\n")
        (cls.source / "notes" / "\u6587\u4ef6.txt").write_bytes("\u5185\u5bb9\n".encode("utf-8"))
        (cls.source / "z-empty.bin").write_bytes(b"")
        # Stamp after creating every child, including distinct empty-dir/root times.
        for i, path in enumerate(sorted(cls.source.rglob("*")) + [cls.source]):
            stamp = (1_600_000_000 + i * 100) * 1_000_000_000
            os.utime(path, ns=(stamp, stamp))
        cls.original = snapshot(cls.source)
        cls.package = cls.work / "baseline.chacha"
        cls.key = cls.work / "baseline.chacha.key"
        cls.invoke(cls.enc, "--encrypt", cls.source, "--package", cls.package,
                   "--keyout", cls.key)
        same_tree(cls.original, snapshot(cls.source))
        cls.raw = (cls.package / "package.chx").read_bytes()
        cls.manifest, cls.boundaries = Manifest.decode(cls.raw)
        require(cls.manifest.chunk == CHUNK, "unexpected chunk size")
        require(cls.manifest.src_name == cls.source.name, "unexpected source root")
        require(not cls.manifest.verification, "v2 must authenticate an empty verification payload")

    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="case-", dir=self.work) as name:
            root = Path(name)
            package = root / "package.chacha"
            shutil.copytree(self.package, package)
            # Two parent levels keep dot/dot-dot traversal probes inside scratch.
            out = root / "restore" / "destination"
            out.mkdir(parents=True)
            yield root, package, out, copy.deepcopy(self.manifest)

    def decrypt(self, package, out, reject=False, key=None):
        if key is not None:
            return self.invoke(self.dec, "--decrypt", package, "--key", key,
                               "--out", out, reject=reject)
        # Each probe needs an unused key so exhaustion cannot mask its rejection.
        with tempfile.TemporaryDirectory(prefix="key-", dir=self.work) as name:
            fresh = Path(name) / "fresh.chacha.key"
            shutil.copyfile(self.key, fresh)
            return self.invoke(self.dec, "--decrypt", package, "--key", fresh,
                               "--out", out, reject=reject)

    def reject_restore(self, package, out, key=None):
        self.decrypt(package, out, reject=True, key=key)
        require(not list(out.iterdir()), "rejected restore left final/staging output")

    def save_manifest(self, package, manifest):
        data = manifest.encode()
        Manifest.decode(data)
        (package / "package.chx").write_bytes(data)

    def test_01_valid_roundtrip_and_keyless_info(self):
        with self.case() as (_, package, out, _manifest):
            for exe in (self.enc, self.dec):
                info = self.invoke(exe, "--info", package)
                require("a-big.bin" in info and "read me.txt" in info,
                        "keyless info omitted fixture records")
            self.decrypt(package, out)
            same_tree(self.original, snapshot(out / self.source.name),
                      tolerance_ns=2_000_000_000)  # FAT timestamp resolution.

    def test_02_existing_package_is_not_deleted(self):
        with self.case() as (root, package, _out, _manifest):
            before = snapshot(package)
            new_key = root / "new.key"
            self.invoke(self.enc, "--encrypt", self.source, "--package", package,
                        "--keyout", new_key, reject=True)
            same_tree(before, snapshot(package))
            require(not new_key.exists(), "rejected package created a key")

    def test_03_existing_key_is_not_overwritten(self):
        with self.case() as (root, _package, _out, _manifest):
            key = root / "existing.key"
            key.write_bytes(b"existing key must survive unchanged\n")
            before = snapshot(key)
            self.invoke(self.enc, "--encrypt", self.source,
                        "--package", root / "fresh.chacha", "--keyout", key, reject=True)
            same_tree(before, snapshot(key))

    def test_04_existing_restore_targets_are_untouched(self):
        for kind in ("nonempty", "empty", "file"):
            with self.subTest(kind=kind), self.case() as (_, package, out, _manifest):
                target = out / self.source.name
                if kind == "file":
                    target.write_bytes(b"original target file")
                else:
                    target.mkdir()
                    if kind == "nonempty":
                        (target / "a-big.bin").write_bytes(b"do not truncate")
                        (target / "sentinel").write_bytes(b"preserve")
                before = snapshot(target)
                self.decrypt(package, out, reject=True)
                same_tree(before, snapshot(target))
                require(list(out.iterdir()) == [target], "rejection left staging output")

    def test_05_bad_blob_tag_has_no_final_output(self):
        with self.case() as (_, package, out, manifest):
            rec = next(f for f in manifest.files if f[0] == "a-big.bin")
            path = package / "blobs" / "{:06}.chx".format(rec[3])
            data = bytearray(path.read_bytes())
            data[-1] ^= 0x80
            path.write_bytes(data)
            self.reject_restore(package, out)

    def test_06_wrong_key_and_manifest_tag_rejected(self):
        with self.case() as (root, package, out, manifest):
            wrong = root / "wrong.key"
            wrong.write_text("00" * 32, encoding="ascii")
            self.reject_restore(package, out, key=wrong)
            manifest.tag = bytes([manifest.tag[0] ^ 1]) + manifest.tag[1:]
            self.save_manifest(package, manifest)
            self.reject_restore(package, out)

    def test_07_full_manifest_metadata_is_authenticated(self):
        for field in ("file_mtime", "dir_mtime", "root_mtime", "src_name", "src_path", "created"):
            with self.subTest(field=field), self.case() as (_, package, out, manifest):
                if field == "file_mtime":
                    rel, size, mtime, blob = manifest.files[0]
                    manifest.files[0] = (rel, size, mtime + 10_000_000, blob)
                elif field == "dir_mtime":
                    rel, mtime = manifest.dirs[0]
                    manifest.dirs[0] = (rel, mtime + 10_000_000)
                elif field == "src_name":
                    manifest.src_name = "rename"
                elif field == "src_path":
                    manifest.src_path += "-changed"
                else:
                    setattr(manifest, field, getattr(manifest, field) + 10_000_000)
                self.save_manifest(package, manifest)
                # These are valid metadata edits, so failure must not merely be
                # malformed parsing. --info is deliberately unauthenticated.
                self.invoke(self.dec, "--info", package)
                self.reject_restore(package, out)

    def test_08_changed_size_and_full_chunk_truncation_rejected(self):
        for mode in ("size-only", "physical-truncation", "consistent-truncation"):
            with self.subTest(mode=mode), self.case() as (_, package, out, manifest):
                index = next(i for i, f in enumerate(manifest.files) if f[0] == "a-big.bin")
                rel, size, mtime, blob = manifest.files[index]
                require(size == 2 * CHUNK, "fixture must contain two complete chunks")
                path = package / "blobs" / "{:06}.chx".format(blob)
                if mode != "size-only":
                    data = bytearray(path.read_bytes()[:HEADER + RECORD_OVERHEAD + CHUNK])
                    if mode == "consistent-truncation":
                        struct.pack_into("<Q", data, 10, CHUNK)
                        struct.pack_into("<I", data, 18, 1)
                    path.write_bytes(data)
                if mode != "physical-truncation":
                    new_size = CHUNK if mode == "consistent-truncation" else size - 1
                    manifest.files[index] = (rel, new_size, mtime, blob)
                    manifest.total -= size - new_size
                    self.save_manifest(package, manifest)
                self.reject_restore(package, out)

    def test_09_empty_records_cannot_be_added_or_removed(self):
        for mode in ("add-file", "add-dir", "remove-file", "remove-dir"):
            with self.subTest(mode=mode), self.case() as (_, package, out, manifest):
                if mode == "add-file":
                    blob = len(manifest.files)
                    manifest.files.append(("injected-empty.bin", 0, manifest.root_mtime, blob))
                    header = struct.pack("<4sHIQI", b"CXBL", 2, CHUNK, 0, 0).ljust(HEADER, b"\0")
                    (package / "blobs" / "{:06}.chx".format(blob)).write_bytes(header)
                elif mode == "add-dir":
                    manifest.dirs.append(("injected-empty", manifest.root_mtime))
                elif mode == "remove-file":
                    rec = manifest.files[-1]
                    require(rec[0] == "z-empty.bin" and rec[1] == 0,
                            "last file must be the empty fixture")
                    manifest.files.pop()
                    (package / "blobs" / "{:06}.chx".format(rec[3])).unlink()
                else:
                    manifest.dirs = [d for d in manifest.dirs if d[0] != "empty"]
                self.save_manifest(package, manifest)
                self.reject_restore(package, out)

    def test_10_source_root_and_record_paths_are_safe(self):
        bad_names = ("../escape", "..\\escape", ".", "..", "NUL", "COM1.txt",
                     "bad:name", "trailing.", "trailing ", "short~1", "")
        for field in ("src_name", "file", "dir"):
            for name in bad_names:
                with self.subTest(field=field, name=name), self.case() as (root, package, out, manifest):
                    if field == "src_name":
                        manifest.src_name = name
                    elif field == "file":
                        manifest.files[0] = (name,) + manifest.files[0][1:]
                    else:
                        manifest.dirs[0] = (name, manifest.dirs[0][1])
                    self.save_manifest(package, manifest)
                    self.invoke(self.dec, "--info", package, reject=True)
                    self.reject_restore(package, out)
                    require(not (root / "restore" / "escape").exists(), "root traversal escaped output")
        with self.case() as (root, package, out, manifest):
            escaped = root / "absolute-escape"
            manifest.src_name = str(escaped.resolve())
            self.save_manifest(package, manifest)
            self.invoke(self.dec, "--info", package, reject=True)
            self.reject_restore(package, out)
            require(not escaped.exists(), "absolute root escaped output")

    def test_11_truncated_info_never_crashes(self):
        # Cover fixed header bytes and both sides of every scalar/string boundary,
        # including all file/directory records, without starting one process per byte.
        lengths = set(range(41))
        for boundary in self.boundaries:
            lengths.update((boundary - 1, boundary, boundary + 1))
        with self.case() as (_, package, _out, _manifest):
            info = package / "package.chx"
            for length in sorted(n for n in lengths if 0 <= n < len(self.raw)):
                for exe in (self.enc, self.dec):
                    with self.subTest(length=length, exe=exe.name):
                        info.write_bytes(self.raw[:length])
                        self.invoke(exe, "--info", package, reject=True)

    def test_12_malformed_info_never_crashes(self):
        prefix = 36 + len(string(self.manifest.src_name)) + len(string(self.manifest.src_path))
        variants = {"trailing-byte": self.raw + b"\0", "bad-magic": b"BADMAGIC" + self.raw[8:]}
        for name, offset, fmt, value in (
                ("old-version", 8, "H", 1), ("future-version", 8, "H", 65535),
                ("flags", 10, "H", 1), ("root-string-length", 36, "H", 65535),
                ("zero-chunk", prefix, "I", 0), ("huge-chunk", prefix, "I", 0xffffffff),
                ("huge-files", prefix + 4, "I", 0xffffffff),
                ("huge-dirs", prefix + 8, "I", 0xffffffff),
                ("huge-total", prefix + 12, "Q", 0xffffffffffffffff),
                ("huge-verification", prefix + 68, "I", 0xffffffff)):
            raw = bytearray(self.raw)
            struct.pack_into("<" + fmt, raw, offset, value)
            variants[name] = bytes(raw)
        raw = bytearray(self.raw)
        raw[38] = 0xff
        variants["invalid-utf8"] = bytes(raw)
        with self.case() as (_, package, _out, _manifest):
            for name, raw in variants.items():
                for exe in (self.enc, self.dec):
                    with self.subTest(name=name, exe=exe.name):
                        (package / "package.chx").write_bytes(raw)
                        self.invoke(exe, "--info", package, reject=True)


def main():
    global TIMEOUT
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=30.0, help="per-process timeout in seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be greater than zero and at most 300 seconds")
    TIMEOUT = args.timeout
    if os.name == "nt":
        # Inherited by subprocesses: a regression must fail, not open a crash dialog.
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002)
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityRegression)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    print("\nSecurity summary: {} test groups, {} CLI calls, {} failures, {} errors, {:.2f}s; {}".format(
        result.testsRun, COMMANDS, len(result.failures), len(result.errors),
        time.monotonic() - started, "PASS" if result.wasSuccessful() else "FAIL"), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
