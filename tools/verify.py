"""端到端验收：加密 → 无密钥读清单 → 解密 → 逐字节比对 → 错密钥/篡改必须失败。"""
import os, shutil, subprocess, sys, random

ROOT = r"E:\chacha"
DIST = os.environ.get("CHACHA_TEST_DIST", os.path.join(ROOT, "dist"))
ENC = os.path.join(DIST, "enc", "chacha-enc.exe")
DEC = os.path.join(DIST, "dec", "chacha-dec.exe")
WORK = os.path.join(ROOT, "dist", "verify")

A = os.path.join(WORK, "A")
B = os.path.join(WORK, "B")
K = os.path.join(WORK, "A.chacha.key")
OUT = os.path.join(WORK, "out")
BAD = os.path.join(WORK, "bad.key")


def run(exe, args):
    p = subprocess.run([exe] + args, capture_output=True)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def build_fixture():
    random.seed(7)
    os.makedirs(os.path.join(A, "照片", "2024 夏"), exist_ok=True)
    os.makedirs(os.path.join(A, "空目录"), exist_ok=True)
    os.makedirs(os.path.join(A, "文档"), exist_ok=True)
    with open(os.path.join(A, "说明.txt"), "wb") as f:
        f.write("CHACHA 往返测试\n中文与 emoji 🎉\r\n".encode("utf-8"))
    open(os.path.join(A, "文档", "空文件.bin"), "wb").close()
    with open(os.path.join(A, "文档", "名字带 空格 和(括号).dat"), "wb") as f:
        f.write(bytes(random.randrange(256) for _ in range(4096)))
    # 一个跨多块的大文件，真正压到并行与 SIMD 路径
    big = os.path.join(A, "照片", "2024 夏", "大图.raw")
    with open(big, "wb") as f:
        for _ in range(40):
            f.write(bytes(random.randrange(256) for _ in range(1024 * 1024)))
    with open(os.path.join(A, "照片", "小图.jpg"), "wb") as f:
        f.write(b"\xff\xd8\xff" + bytes(random.randrange(256) for _ in range(700 * 1024)))
    total = 0
    for r, _, fs in os.walk(A):
        for x in fs:
            total += os.path.getsize(os.path.join(r, x))
    return total


def trees_equal(a, b):
    def snap(root):
        out = {}
        for r, ds, fs in os.walk(root):
            for x in fs:
                p = os.path.join(r, x)
                out[os.path.relpath(p, root)] = open(p, "rb").read()
            for d in ds:
                out[os.path.relpath(os.path.join(r, d), root) + os.sep] = None
        return out
    sa, sb = snap(a), snap(b)
    if set(sa) != set(sb):
        miss = set(sa) ^ set(sb)
        return False, "条目不一致: %s" % list(miss)[:5]
    for k in sa:
        if sa[k] is None:
            continue
        if sa[k] != sb[k]:
            return False, "内容不一致: %s" % k
    return True, "ok"


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)
    total = build_fixture()
    print("fixture: %.2f MB" % (total / 1048576.0))

    rc, so, se = run(ENC, ["--encrypt", A, "--package", B, "--keyout", K])
    print("[1] encrypt rc=%d" % rc)
    print("    " + so.strip().replace("\n", "\n    "))
    if se.strip():
        print("    STDERR " + se.strip())
    assert rc == 0, "加密失败"
    assert os.path.isfile(K), "缺少密钥文件"
    assert os.path.isfile(os.path.join(B, "package.chx")), "缺少清单"
    assert os.path.isdir(os.path.join(B, "blobs")), "缺少 blobs"

    # 清单必须无需密钥就能读出来
    rc, so, se = run(DEC, ["--info", B])
    print("[2] info-without-key rc=%d, 行数=%d" % (rc, so.count("\n")))
    assert rc == 0 and "大图.raw" in so and "名字带 空格 和(括号).dat" in so, "清单读取失败"

    rc, so, se = run(DEC, ["--decrypt", B, "--key", K, "--out", OUT])
    print("[3] decrypt rc=%d" % rc)
    print("    " + so.strip().replace("\n", "\n    "))
    assert rc == 0, "解密失败"
    ok, why = trees_equal(A, os.path.join(OUT, "A"))
    print("[4] byte-for-byte: %s (%s)" % (ok, why))
    assert ok, why

    # 错误密钥必须被拒绝
    data = bytearray(open(K, "rb").read())
    data[40] ^= 0x01
    open(BAD, "wb").write(bytes(data))
    rc, so, se = run(DEC, ["--decrypt", B, "--key", BAD, "--out", os.path.join(WORK, "out2")])
    print("[5] wrong-key rc=%d msg=%s" % (rc, (se or so).strip()))
    assert rc != 0, "错误密钥竟然成功了"

    # 篡改密文一个字节必须被完整性校验抓住
    blobs = os.path.join(B, "blobs")
    victim = os.path.join(blobs, sorted(os.listdir(blobs))[0])
    raw = bytearray(open(victim, "rb").read())
    raw[64] ^= 0x80
    open(victim, "wb").write(bytes(raw))
    rc, so, se = run(DEC, ["--decrypt", B, "--key", K, "--out", os.path.join(WORK, "out3")])
    print("[6] tampered rc=%d msg=%s" % (rc, (se or so).strip()[:160]))
    assert rc != 0, "篡改竟然没被发现"

    print("\nALL PASS")


if __name__ == "__main__":
    sys.exit(main())
