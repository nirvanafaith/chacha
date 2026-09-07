"""Key-use integration regressions for already-built binaries (stdlib only).

Run: python tools/key-usage-regression.py [-v] [--timeout 30]
Set CHACHA_TEST_DIST to override the repository's dist directory.
All fixtures and destructive mutations stay in disposable system-temp directories.
"""

import argparse
import concurrent.futures
import ctypes
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
DIST = Path(os.environ.get("CHACHA_TEST_DIST", str(ROOT / "dist")))
EXHAUSTED = "\u5bc6\u94a5\u6b21\u6570\u5df2\u8017\u5c3d"
TIMEOUT = 30.0


class KeyUsageRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.enc = DIST / "enc" / "chacha-enc.exe"
        cls.dec = DIST / "dec" / "chacha-dec.exe"
        for exe in (cls.enc, cls.dec):
            if not exe.is_file():
                raise AssertionError("missing executable; build first: " + str(exe))
        if os.name != "nt":
            raise unittest.SkipTest("limited keys require Windows exclusive file access")

    def setUp(self):
        parent = Path(tempfile.gettempdir()).resolve()
        self.assertFalse(parent.is_relative_to(DIST.resolve()),
                         "system temp directory must be outside dist")
        temp = tempfile.TemporaryDirectory(prefix="chacha-key-usage-", dir=parent)
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.source = self.work / "source"
        (self.source / "nested").mkdir(parents=True)
        self.payload = bytes(range(256)) * 256
        (self.source / "nested" / "payload.bin").write_bytes(self.payload)
        (self.source / "empty.txt").write_bytes(b"")
        self.serial = 0

    def unique(self, prefix):
        self.serial += 1
        return self.work / "{}-{}".format(prefix, self.serial)

    def invoke(self, exe, *args):
        command = [str(exe)] + [str(arg) for arg in args]
        try:
            result = subprocess.run(command, cwd=self.work, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=TIMEOUT, check=False)
        except subprocess.TimeoutExpired as error:
            raise AssertionError("CLI timeout: " + repr(command)) from error
        output = (result.stdout + result.stderr).decode("utf-8", "replace")
        detail = "rc={} (0x{:08x}): {}\n{}".format(
            result.returncode, result.returncode & 0xffffffff, command, output[-2400:])
        self.assertIn(result.returncode, (0, 1, 2), detail)
        self.assertNotIn("panicked at", output.lower(), detail)
        return result.returncode, output, detail

    def encrypt(self, uses=None):
        package, key = self.unique("package"), self.unique("key")
        args = ["--encrypt", self.source, "--package", package, "--keyout", key]
        if uses is not None:
            args.extend(("--uses", uses))
        rc, _output, detail = self.invoke(self.enc, *args)
        self.assertEqual(rc, 0, detail)
        self.assertTrue(key.read_bytes().startswith(b"CHAKY002"),
                        "expected limited key envelope; rebuild binaries first")
        return package, key

    def output_dir(self):
        out = self.unique("restore")
        out.mkdir()
        return out

    def decrypt(self, package, key, out=None):
        if out is None:
            out = self.output_dir()
        return self.invoke(self.dec, "--decrypt", package, "--key", key, "--out", out), out

    def assert_success(self, package, key):
        (rc, _output, detail), out = self.decrypt(package, key)
        self.assertEqual(rc, 0, detail)
        target = out / self.source.name
        self.assertEqual((target / "nested" / "payload.bin").read_bytes(), self.payload)
        self.assertEqual((target / "empty.txt").read_bytes(), b"")
        self.assertEqual(list(out.iterdir()), [target], "success left staging output")

    def assert_rejected(self, package, key, exhausted=False):
        (rc, output, detail), out = self.decrypt(package, key)
        self.assertIn(rc, (1, 2), detail)
        if exhausted:
            self.assertEqual(output.strip(), EXHAUSTED, detail)
        else:
            self.assertNotIn(EXHAUSTED, output, "exhaustion masked the intended failure: " + detail)
        self.assertEqual(list(out.iterdir()), [], "rejected restore left output")
        return output

    def test_default_and_all_limits_persist_across_processes(self):
        for uses in (None, 1, 2, 3, 4, 5, 6, 7):
            with self.subTest(uses=uses):
                package, key = self.encrypt(uses)
                for _ in range(1 if uses is None else uses):
                    self.assert_success(package, key)
                exhausted_bytes = key.read_bytes()
                for _ in range(2):
                    self.assert_rejected(package, key, exhausted=True)
                    self.assertEqual(key.read_bytes(), exhausted_bytes)

    def test_zero_byte_package_still_consumes_single_use(self):
        (self.source / "nested" / "payload.bin").unlink()
        (self.source / "nested" / "empty.bin").write_bytes(b"")
        (self.source / "empty-directory").mkdir()
        expected = {path.relative_to(self.source).as_posix(): path.is_dir()
                    for path in self.source.rglob("*")}
        self.assertEqual(sum(path.stat().st_size for path in self.source.rglob("*")
                             if path.is_file()), 0)
        package, key = self.encrypt(1)
        original_key = key.read_bytes()
        (rc, _output, detail), out = self.decrypt(package, key)
        self.assertEqual(rc, 0, detail)
        target = out / self.source.name
        self.assertEqual(list(out.iterdir()), [target], "success left staging output")
        actual = {path.relative_to(target).as_posix(): path.is_dir()
                  for path in target.rglob("*")}
        self.assertEqual(actual, expected)
        for path in target.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), b"")
        self.assertNotEqual(key.read_bytes(), original_key, "zero-byte restore skipped debit")
        self.assert_rejected(package, key, exhausted=True)

    def test_invalid_and_missing_uses_leave_no_outputs(self):
        for value in ("0", "8", "-1", "nonnumeric", None):
            with self.subTest(value=value):
                package, key = self.unique("invalid-package"), self.unique("invalid-key")
                before = set(self.work.iterdir())
                args = ["--encrypt", self.source, "--package", package,
                        "--keyout", key, "--uses"]
                if value is not None:
                    args.append(value)
                rc, output, detail = self.invoke(self.enc, *args)
                self.assertEqual(rc, 2, detail)
                self.assertIn("--uses", output, detail)
                self.assertFalse(package.exists())
                self.assertFalse(key.exists())
                self.assertEqual(set(self.work.iterdir()), before, "invalid arguments left staging output")

    def test_imported_hex_envelope_preserves_remaining_count(self):
        package, key = self.encrypt(3)
        self.assert_success(package, key)
        imported = self.unique("imported-hex-key")
        imported.write_text(key.read_bytes().hex(), encoding="ascii")
        self.assert_success(package, imported)
        self.assert_success(package, imported)
        self.assert_rejected(package, imported, exhausted=True)

    def test_binary_corruption_and_truncation_are_rejected(self):
        package, key = self.encrypt(1)
        original = key.read_bytes()
        variants = {}
        # Cover magic, binding/AAD, wrapping material, ciphertext and tag.
        for offset in (0, 8, 24, 32, 64, 88, 120, len(original) - 1):
            corrupted = bytearray(original)
            corrupted[offset] ^= 0x80
            variants["flip-{}".format(offset)] = bytes(corrupted)
        for length in (0, 1, 7, 8, 24, 32, 64, 88, 121, len(original) - 1):
            variants["truncate-{}".format(length)] = original[:length]
        variants["trailing-byte"] = original + b"\0"
        for name, data in variants.items():
            with self.subTest(variant=name):
                broken = self.unique("broken-key")
                broken.write_bytes(data)
                self.assert_rejected(package, broken)
                self.assertEqual(broken.read_bytes(), data)
        self.assertEqual(key.read_bytes(), original)
        self.assert_success(package, key)

    def test_readonly_key_fails_without_changes_or_debit(self):
        package, key = self.encrypt(1)
        original = key.read_bytes()
        key.chmod(stat.S_IREAD)
        try:
            self.assert_rejected(package, key)
            self.assertEqual(key.read_bytes(), original)
        finally:
            key.chmod(stat.S_IREAD | stat.S_IWRITE)
        self.assert_success(package, key)
        self.assert_rejected(package, key, exhausted=True)

    def test_wrong_bound_key_does_not_debit(self):
        package, _key = self.encrypt(1)
        other_package, other_key = self.encrypt(1)
        original = other_key.read_bytes()
        self.assert_rejected(package, other_key)
        self.assertEqual(other_key.read_bytes(), original)
        self.assert_success(other_package, other_key)
        self.assert_rejected(other_package, other_key, exhausted=True)

    def test_existing_destination_does_not_debit(self):
        for kind in ("empty-directory", "nonempty-directory", "file"):
            with self.subTest(kind=kind):
                package, key = self.encrypt(1)
                original = key.read_bytes()
                out = self.output_dir()
                target = out / self.source.name
                sentinel = b"must remain untouched"
                if kind == "file":
                    target.write_bytes(sentinel)
                else:
                    target.mkdir()
                    if kind == "nonempty-directory":
                        (target / "sentinel").write_bytes(sentinel)
                (rc, output, detail), _ = self.decrypt(package, key, out)
                self.assertIn(rc, (1, 2), detail)
                self.assertNotIn(EXHAUSTED, output, detail)
                self.assertEqual(key.read_bytes(), original)
                self.assertEqual(list(out.iterdir()), [target])
                if kind == "file":
                    self.assertEqual(target.read_bytes(), sentinel)
                elif kind == "nonempty-directory":
                    self.assertEqual(list(target.iterdir()), [target / "sentinel"])
                    self.assertEqual((target / "sentinel").read_bytes(), sentinel)
                else:
                    self.assertEqual(list(target.iterdir()), [])
                self.assert_success(package, key)
                self.assert_rejected(package, key, exhausted=True)

    def test_concurrent_single_use_has_at_most_one_success(self):
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                package, key = self.encrypt(1)
                outputs = [self.output_dir() for _ in range(4)]
                gate = threading.Barrier(len(outputs))

                def restore(out):
                    gate.wait(timeout=TIMEOUT)
                    return self.decrypt(package, key, out)

                with concurrent.futures.ThreadPoolExecutor(max_workers=len(outputs)) as executor:
                    results = list(executor.map(restore, outputs))
                successes = 0
                for (rc, _output, detail), out in results:
                    if rc == 0:
                        successes += 1
                        target = out / self.source.name
                        self.assertEqual((target / "nested" / "payload.bin").read_bytes(), self.payload)
                        self.assertEqual(list(out.iterdir()), [target])
                    else:
                        self.assertIn(rc, (1, 2), detail)
                        self.assertEqual(list(out.iterdir()), [])
                self.assertLessEqual(successes, 1, "single-use key restored concurrently more than once")
                # Windows sharing contention can make all first attempts fail;
                # the unused key must still work once after contenders exit.
                if successes == 0:
                    self.assert_success(package, key)
                self.assert_rejected(package, key, exhausted=True)

    def test_post_debit_blob_authentication_failure_consumes_use(self):
        package, key = self.encrypt(1)
        original_key = key.read_bytes()
        blob = next(path for path in (package / "blobs").iterdir() if path.stat().st_size > 100)
        original_blob = blob.read_bytes()
        damaged = bytearray(original_blob)
        # Header + nonce + chunk length are intact; flip ciphertext, not structure.
        damaged[32 + 24 + 4] ^= 0x80
        blob.write_bytes(damaged)
        try:
            output = self.assert_rejected(package, key)
            self.assertIn("\u5b8c\u6574\u6027\u6821\u9a8c\u5931\u8d25", output)
            self.assertNotEqual(key.read_bytes(), original_key, "failure occurred before debit")
        finally:
            blob.write_bytes(original_blob)
        self.assert_rejected(package, key, exhausted=True)


def main():
    global TIMEOUT
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-process timeout in seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("--timeout must be greater than zero and at most 300 seconds")
    TIMEOUT = args.timeout
    if os.name == "nt":
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002)
    started = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(KeyUsageRegression)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    print("\nKey-use summary: {} test groups, {} failures, {} errors, {:.2f}s; {}".format(
        result.testsRun, len(result.failures), len(result.errors),
        time.monotonic() - started, "PASS" if result.wasSuccessful() else "FAIL"), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
