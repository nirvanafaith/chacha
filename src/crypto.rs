//! XChaCha20-Poly1305 (RFC 8439 + draft-irtf-cfrg-xchacha-03).
//! ChaCha20 uses SSE2 4-block SIMD when the CPU supports it, otherwise scalar.

use crate::util::{ct_eq, read_u32_le, TAG_LEN};

const CHACHA_CONST: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[inline(always)]
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl32(*d, 16);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl32(*b, 12);
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = rotl32(*d, 8);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = rotl32(*b, 7);
}

fn load_key_words(key: &[u8; 32]) -> [u32; 8] {
    [
        read_u32_le(&key[0..4]),
        read_u32_le(&key[4..8]),
        read_u32_le(&key[8..12]),
        read_u32_le(&key[12..16]),
        read_u32_le(&key[16..20]),
        read_u32_le(&key[20..24]),
        read_u32_le(&key[24..28]),
        read_u32_le(&key[28..32]),
    ]
}

fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let k = load_key_words(key);
    [
        CHACHA_CONST[0],
        CHACHA_CONST[1],
        CHACHA_CONST[2],
        CHACHA_CONST[3],
        k[0],
        k[1],
        k[2],
        k[3],
        k[4],
        k[5],
        k[6],
        k[7],
        counter,
        read_u32_le(&nonce[0..4]),
        read_u32_le(&nonce[4..8]),
        read_u32_le(&nonce[8..12]),
    ]
}

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let mut va = s[a];
    let mut vb = s[b];
    let mut vc = s[c];
    let mut vd = s[d];
    quarter_round(&mut va, &mut vb, &mut vc, &mut vd);
    s[a] = va;
    s[b] = vb;
    s[c] = vc;
    s[d] = vd;
}

fn rounds(s: &mut [u32; 16]) {
    let mut i = 0;
    while i < 10 {
        qr(s, 0, 4, 8, 12);
        qr(s, 1, 5, 9, 13);
        qr(s, 2, 6, 10, 14);
        qr(s, 3, 7, 11, 15);
        qr(s, 0, 5, 10, 15);
        qr(s, 1, 6, 11, 12);
        qr(s, 2, 7, 8, 13);
        qr(s, 3, 4, 9, 14);
        i += 1;
    }
}

pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = init_state(key, counter, nonce);
    let orig = s;
    rounds(&mut s);
    let mut out = [0u8; 64];
    for i in 0..16 {
        let w = s[i].wrapping_add(orig[i]);
        let b = w.to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&b);
    }
    out
}

/// HChaCha20: first/last rows of the un-summed state after 20 rounds.
pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let k = load_key_words(key);
    let mut s = [
        CHACHA_CONST[0],
        CHACHA_CONST[1],
        CHACHA_CONST[2],
        CHACHA_CONST[3],
        k[0],
        k[1],
        k[2],
        k[3],
        k[4],
        k[5],
        k[6],
        k[7],
        read_u32_le(&nonce16[0..4]),
        read_u32_le(&nonce16[4..8]),
        read_u32_le(&nonce16[8..12]),
        read_u32_le(&nonce16[12..16]),
    ];
    rounds(&mut s);
    let mut out = [0u8; 32];
    for (i, idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[*idx].to_le_bytes());
    }
    out
}

fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let n = dst.len();
    debug_assert_eq!(n, src.len());
    let mut i = 0;
    while i < n {
        dst[i] ^= src[i];
        i += 1;
    }
}

fn chacha20_xor_scalar(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    let mut off = 0;
    while off + 64 <= buf.len() {
        let ks = chacha20_block(key, counter, nonce);
        xor_bytes(&mut buf[off..off + 64], &ks);
        counter = counter.wrapping_add(1);
        off += 64;
    }
    if off < buf.len() {
        let ks = chacha20_block(key, counter, nonce);
        let n = buf.len() - off;
        let mut i = 0;
        while i < n {
            buf[off + i] ^= ks[i];
            i += 1;
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_sse2() -> bool {
    is_x86_feature_detected!("sse2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn has_sse2() -> bool {
    false
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_avx2() -> bool {
    // std 的检测包含 OSXSAVE / XCR0 判定：XP 未启用 YMM 状态时返回 false，
    // 因此在支持 AVX2 但系统不保存 YMM 的机器上也不会误用。
    is_x86_feature_detected!("avx2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn has_avx2() -> bool {
    false
}

/// AVX2：一次算 8 个块（512 字节）。硬件不支持时不会被调用。
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn chacha20_xor_avx2(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    macro_rules! qr_avx {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {{
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm256_xor_si256($x[$d], $x[$a]);
            $x[$d] = _mm256_or_si256(_mm256_slli_epi32($x[$d], 16), _mm256_srli_epi32($x[$d], 16));
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            $x[$b] = _mm256_xor_si256($x[$b], $x[$c]);
            $x[$b] = _mm256_or_si256(_mm256_slli_epi32($x[$b], 12), _mm256_srli_epi32($x[$b], 20));
            $x[$a] = _mm256_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm256_xor_si256($x[$d], $x[$a]);
            $x[$d] = _mm256_or_si256(_mm256_slli_epi32($x[$d], 8), _mm256_srli_epi32($x[$d], 24));
            $x[$c] = _mm256_add_epi32($x[$c], $x[$d]);
            $x[$b] = _mm256_xor_si256($x[$b], $x[$c]);
            $x[$b] = _mm256_or_si256(_mm256_slli_epi32($x[$b], 7), _mm256_srli_epi32($x[$b], 25));
        }};
    }

    let k = load_key_words(key);
    let n0 = read_u32_le(&nonce[0..4]);
    let n1 = read_u32_le(&nonce[4..8]);
    let n2 = read_u32_le(&nonce[8..12]);

    let mut off = 0usize;
    while off + 512 <= buf.len() {
        let mut x = [
            _mm256_set1_epi32(CHACHA_CONST[0] as i32),
            _mm256_set1_epi32(CHACHA_CONST[1] as i32),
            _mm256_set1_epi32(CHACHA_CONST[2] as i32),
            _mm256_set1_epi32(CHACHA_CONST[3] as i32),
            _mm256_set1_epi32(k[0] as i32),
            _mm256_set1_epi32(k[1] as i32),
            _mm256_set1_epi32(k[2] as i32),
            _mm256_set1_epi32(k[3] as i32),
            _mm256_set1_epi32(k[4] as i32),
            _mm256_set1_epi32(k[5] as i32),
            _mm256_set1_epi32(k[6] as i32),
            _mm256_set1_epi32(k[7] as i32),
            _mm256_setr_epi32(
                counter as i32,
                counter.wrapping_add(1) as i32,
                counter.wrapping_add(2) as i32,
                counter.wrapping_add(3) as i32,
                counter.wrapping_add(4) as i32,
                counter.wrapping_add(5) as i32,
                counter.wrapping_add(6) as i32,
                counter.wrapping_add(7) as i32,
            ),
            _mm256_set1_epi32(n0 as i32),
            _mm256_set1_epi32(n1 as i32),
            _mm256_set1_epi32(n2 as i32),
        ];
        let y = x;

        let mut r = 0;
        while r < 10 {
            qr_avx!(x, 0, 4, 8, 12);
            qr_avx!(x, 1, 5, 9, 13);
            qr_avx!(x, 2, 6, 10, 14);
            qr_avx!(x, 3, 7, 11, 15);
            qr_avx!(x, 0, 5, 10, 15);
            qr_avx!(x, 1, 6, 11, 12);
            qr_avx!(x, 2, 7, 8, 13);
            qr_avx!(x, 3, 4, 9, 14);
            r += 1;
        }

        for i in 0..16 {
            x[i] = _mm256_add_epi32(x[i], y[i]);
        }

        let mut lanes = [[0u32; 8]; 16];
        for i in 0..16 {
            _mm256_storeu_si256(lanes[i].as_mut_ptr() as *mut __m256i, x[i]);
        }
        let mut ks = [0u8; 512];
        for lane in 0..8 {
            for w in 0..16 {
                let dst = lane * 64 + w * 4;
                ks[dst..dst + 4].copy_from_slice(&lanes[w][lane].to_le_bytes());
            }
        }
        xor_bytes(&mut buf[off..off + 512], &ks);

        counter = counter.wrapping_add(8);
        off += 512;
    }

    if off < buf.len() {
        chacha20_xor_scalar(key, counter, nonce, &mut buf[off..]);
    }
}

pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if buf.len() >= 512 && has_avx2() {
            unsafe {
                chacha20_xor_avx2(key, counter, nonce, buf);
            }
            return;
        }
        if buf.len() >= 256 && has_sse2() {
            unsafe {
                chacha20_xor_sse2_xor(key, counter, nonce, buf);
            }
            return;
        }
    }
    chacha20_xor_scalar(key, counter, nonce, buf);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn chacha20_xor_sse2_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    macro_rules! qr_sse {
        ($x:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {{
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm_xor_si128($x[$d], $x[$a]);
            $x[$d] = _mm_or_si128(_mm_slli_epi32($x[$d], 16), _mm_srli_epi32($x[$d], 16));
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = _mm_xor_si128($x[$b], $x[$c]);
            $x[$b] = _mm_or_si128(_mm_slli_epi32($x[$b], 12), _mm_srli_epi32($x[$b], 20));
            $x[$a] = _mm_add_epi32($x[$a], $x[$b]);
            $x[$d] = _mm_xor_si128($x[$d], $x[$a]);
            $x[$d] = _mm_or_si128(_mm_slli_epi32($x[$d], 8), _mm_srli_epi32($x[$d], 24));
            $x[$c] = _mm_add_epi32($x[$c], $x[$d]);
            $x[$b] = _mm_xor_si128($x[$b], $x[$c]);
            $x[$b] = _mm_or_si128(_mm_slli_epi32($x[$b], 7), _mm_srli_epi32($x[$b], 25));
        }};
    }

    let k = load_key_words(key);
    let n0 = read_u32_le(&nonce[0..4]);
    let n1 = read_u32_le(&nonce[4..8]);
    let n2 = read_u32_le(&nonce[8..12]);

    let mut off = 0usize;
    while off + 256 <= buf.len() {
        let mut x = [
            _mm_set1_epi32(CHACHA_CONST[0] as i32),
            _mm_set1_epi32(CHACHA_CONST[1] as i32),
            _mm_set1_epi32(CHACHA_CONST[2] as i32),
            _mm_set1_epi32(CHACHA_CONST[3] as i32),
            _mm_set1_epi32(k[0] as i32),
            _mm_set1_epi32(k[1] as i32),
            _mm_set1_epi32(k[2] as i32),
            _mm_set1_epi32(k[3] as i32),
            _mm_set1_epi32(k[4] as i32),
            _mm_set1_epi32(k[5] as i32),
            _mm_set1_epi32(k[6] as i32),
            _mm_set1_epi32(k[7] as i32),
            _mm_setr_epi32(
                counter as i32,
                counter.wrapping_add(1) as i32,
                counter.wrapping_add(2) as i32,
                counter.wrapping_add(3) as i32,
            ),
            _mm_set1_epi32(n0 as i32),
            _mm_set1_epi32(n1 as i32),
            _mm_set1_epi32(n2 as i32),
        ];
        let y = x;

        let mut r = 0;
        while r < 10 {
            qr_sse!(x, 0, 4, 8, 12);
            qr_sse!(x, 1, 5, 9, 13);
            qr_sse!(x, 2, 6, 10, 14);
            qr_sse!(x, 3, 7, 11, 15);
            qr_sse!(x, 0, 5, 10, 15);
            qr_sse!(x, 1, 6, 11, 12);
            qr_sse!(x, 2, 7, 8, 13);
            qr_sse!(x, 3, 4, 9, 14);
            r += 1;
        }

        for i in 0..16 {
            x[i] = _mm_add_epi32(x[i], y[i]);
        }

        // Store keystream words and XOR into plaintext.
        let mut lanes = [[0u32; 4]; 16];
        for i in 0..16 {
            _mm_storeu_si128(lanes[i].as_mut_ptr() as *mut __m128i, x[i]);
        }
        for lane in 0..4 {
            for w in 0..16 {
                let val = lanes[w][lane].to_le_bytes();
                let dst = off + lane * 64 + w * 4;
                buf[dst] ^= val[0];
                buf[dst + 1] ^= val[1];
                buf[dst + 2] ^= val[2];
                buf[dst + 3] ^= val[3];
            }
        }

        counter = counter.wrapping_add(4);
        off += 256;
    }

    if off < buf.len() {
        chacha20_xor_scalar(key, counter, nonce, &mut buf[off..]);
    }
}

// -------------------- Poly1305 --------------------

struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let t0 = read_u32_le(&key[0..4]);
        let t1 = read_u32_le(&key[4..8]);
        let t2 = read_u32_le(&key[8..12]);
        let t3 = read_u32_le(&key[12..16]);
        Poly1305 {
            r: [
                t0 & 0x3ff_ffff,
                ((t0 >> 26) | (t1 << 6)) & 0x3ffff03,
                ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff,
                ((t2 >> 14) | (t3 << 18)) & 0x3f03fff,
                (t3 >> 8) & 0x00f_ffff,
            ],
            h: [0; 5],
            pad: [
                read_u32_le(&key[16..20]),
                read_u32_le(&key[20..24]),
                read_u32_le(&key[24..28]),
                read_u32_le(&key[28..32]),
            ],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    fn blocks(&mut self, data: &[u8], hibit: u32) {
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;
        let s1 = r1.wrapping_mul(5);
        let s2 = r2.wrapping_mul(5);
        let s3 = r3.wrapping_mul(5);
        let s4 = r4.wrapping_mul(5);

        let mut h0 = self.h[0] as u64;
        let mut h1 = self.h[1] as u64;
        let mut h2 = self.h[2] as u64;
        let mut h3 = self.h[3] as u64;
        let mut h4 = self.h[4] as u64;

        let mut off = 0;
        while off + 16 <= data.len() {
            let t0 = read_u32_le(&data[off..off + 4]) as u64;
            let t1 = read_u32_le(&data[off + 4..off + 8]) as u64;
            let t2 = read_u32_le(&data[off + 8..off + 12]) as u64;
            let t3 = read_u32_le(&data[off + 12..off + 16]) as u64;

            h0 += t0 & 0x3ff_ffff;
            h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff;
            h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff;
            h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff;
            h4 += (t3 >> 8) | (hibit as u64);

            let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            let mut c = d0 >> 26;
            h0 = d0 & 0x3ff_ffff;
            d1 += c;
            c = d1 >> 26;
            h1 = d1 & 0x3ff_ffff;
            d2 += c;
            c = d2 >> 26;
            h2 = d2 & 0x3ff_ffff;
            d3 += c;
            c = d3 >> 26;
            h3 = d3 & 0x3ff_ffff;
            d4 += c;
            c = d4 >> 26;
            h4 = d4 & 0x3ff_ffff;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= 0x3ff_ffff;
            h1 += c;

            off += 16;
        }

        self.h[0] = h0 as u32;
        self.h[1] = h1 as u32;
        self.h[2] = h2 as u32;
        self.h[3] = h3 as u32;
        self.h[4] = h4 as u32;
    }

    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        if self.buf_len > 0 {
            let take = core::cmp::min(16 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let buf = self.buf;
                self.blocks(&buf, 1 << 24);
                self.buf_len = 0;
            }
        }
        let n = data.len() & !15;
        if n > 0 {
            self.blocks(&data[..n], 1 << 24);
        }
        let rest = &data[n..];
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buf_len = rest.len();
        }
    }

    fn finish(mut self) -> [u8; 16] {
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1;
            let buf = block;
            self.blocks(&buf, 0);
        }

        let mut h0 = self.h[0] as u32;
        let mut h1 = self.h[1] as u32;
        let mut h2 = self.h[2] as u32;
        let mut h3 = self.h[3] as u32;
        let mut h4 = self.h[4] as u32;

        let mut c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 = h1.wrapping_add(c);

        let g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        let g0 = g0 & 0x3ff_ffff;
        let g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        let g1 = g1 & 0x3ff_ffff;
        let g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        let g2 = g2 & 0x3ff_ffff;
        let g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        let g3 = g3 & 0x3ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        let not_mask = !mask;
        h0 = (h0 & not_mask) | (g0 & mask);
        h1 = (h1 & not_mask) | (g1 & mask);
        h2 = (h2 & not_mask) | (g2 & mask);
        h3 = (h3 & not_mask) | (g3 & mask);
        h4 = (h4 & not_mask) | (g4 & mask);

        let f0 = ((h0 as u64) | ((h1 as u64) << 26)) & 0xffff_ffff;
        let f1 = (((h1 as u64) >> 6) | ((h2 as u64) << 20)) & 0xffff_ffff;
        let f2 = (((h2 as u64) >> 12) | ((h3 as u64) << 14)) & 0xffff_ffff;
        let f3 = (((h3 as u64) >> 18) | ((h4 as u64) << 8)) & 0xffff_ffff;

        let mut f = [0u64; 4];
        let mut carry: u64;
        let s0 = f0.wrapping_add(self.pad[0] as u64);
        f[0] = s0 & 0xffff_ffff;
        carry = s0 >> 32;
        let s1 = f1.wrapping_add(self.pad[1] as u64).wrapping_add(carry);
        f[1] = s1 & 0xffff_ffff;
        carry = s1 >> 32;
        let s2 = f2.wrapping_add(self.pad[2] as u64).wrapping_add(carry);
        f[2] = s2 & 0xffff_ffff;
        carry = s2 >> 32;
        let s3 = f3.wrapping_add(self.pad[3] as u64).wrapping_add(carry);
        f[3] = s3 & 0xffff_ffff;

        let mut tag = [0u8; 16];
        for i in 0..4 {
            tag[i * 4..i * 4 + 4].copy_from_slice(&(f[i] as u32).to_le_bytes());
        }
        tag
    }
}

fn pad16(len: usize) -> &'static [u8] {
    const Z: [u8; 16] = [0; 16];
    let n = (16 - (len % 16)) % 16;
    &Z[..n]
}

fn poly1305_aead_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut p = Poly1305::new(otk);
    p.update(aad);
    p.update(pad16(aad.len()));
    p.update(ciphertext);
    p.update(pad16(ciphertext.len()));
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    p.update(&lens);
    p.finish()
}

fn ietf_nonce_from_x(nonce24: &[u8; 24]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&nonce24[16..24]);
    n
}

/// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce12: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut otk_block = [0u8; 64];
    otk_block.copy_from_slice(&chacha20_block(key, 0, nonce12));
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);

    let mut ct = plaintext.to_vec();
    chacha20_xor(key, 1, nonce12, &mut ct);
    let tag = poly1305_aead_tag(&otk, aad, &ct);
    (ct, tag)
}

pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce12: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ()> {
    let mut otk_block = [0u8; 64];
    otk_block.copy_from_slice(&chacha20_block(key, 0, nonce12));
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);
    let expect = poly1305_aead_tag(&otk, aad, ciphertext);
    if !ct_eq(&expect, tag) {
        return Err(());
    }
    let mut pt = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce12, &mut pt);
    Ok(pt)
}

pub fn xchacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = hchacha20(key, &n16);
    let n12 = ietf_nonce_from_x(nonce24);
    chacha20_poly1305_encrypt(&subkey, &n12, aad, plaintext)
}

pub fn xchacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, ()> {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = hchacha20(key, &n16);
    let n12 = ietf_nonce_from_x(nonce24);
    chacha20_poly1305_decrypt(&subkey, &n12, aad, ciphertext, tag)
}

pub fn xchacha20_poly1305_encrypt_in_place(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = hchacha20(key, &n16);
    let n12 = ietf_nonce_from_x(nonce24);
    let mut otk_block = [0u8; 64];
    otk_block.copy_from_slice(&chacha20_block(&subkey, 0, &n12));
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);
    chacha20_xor(&subkey, 1, &n12, buf);
    poly1305_aead_tag(&otk, aad, buf)
}

pub fn xchacha20_poly1305_decrypt_in_place(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), ()> {
    let mut n16 = [0u8; 16];
    n16.copy_from_slice(&nonce24[..16]);
    let subkey = hchacha20(key, &n16);
    let n12 = ietf_nonce_from_x(nonce24);
    let mut otk_block = [0u8; 64];
    otk_block.copy_from_slice(&chacha20_block(&subkey, 0, &n12));
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);
    let expect = poly1305_aead_tag(&otk, aad, buf);
    if !ct_eq(&expect, tag) {
        return Err(());
    }
    chacha20_xor(&subkey, 1, &n12, buf);
    Ok(())
}

/// 硬件加速档位：优先 AVX2（8 块），其次 SSE2（4 块），否则纯软件标量。
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Tier {
    Avx2,
    Sse2,
    Scalar,
}

pub fn best_tier() -> Tier {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if has_avx2() {
            return Tier::Avx2;
        }
        if has_sse2() {
            return Tier::Sse2;
        }
    }
    Tier::Scalar
}

pub fn tier_name(t: Tier) -> &'static str {
    match t {
        Tier::Avx2 => "AVX2 x8",
        Tier::Sse2 => "SSE2 x4",
        Tier::Scalar => "软件标量",
    }
}

pub fn backend_name() -> &'static str {
    "XChaCha20-Poly1305"
}

/// 界面脚注：算法 + 当前加速档位。
pub fn backend_label() -> String {
    format!("XChaCha20-Poly1305 · {}", tier_name(best_tier()))
}

/// 用指定档位跑一遍密钥流，返回 MiB/s。用于 `--bench` 与界面自检。
pub fn throughput(tier: Tier, len: usize) -> f64 {
    use std::time::Instant;
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let mut buf = vec![0u8; len];
    let rounds = if len >= 8 * 1024 * 1024 { 1 } else { 8 };
    let mut best = 0.0f64;
    for _ in 0..3 {
        let t0 = Instant::now();
        for _ in 0..rounds {
            match tier {
                Tier::Scalar => chacha20_xor_scalar(&key, 1, &nonce, &mut buf),
                Tier::Sse2 => {
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    {
                        if has_sse2() {
                            unsafe { chacha20_xor_sse2_xor(&key, 1, &nonce, &mut buf) }
                        } else {
                            chacha20_xor_scalar(&key, 1, &nonce, &mut buf)
                        }
                    }
                    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                    {
                        chacha20_xor_scalar(&key, 1, &nonce, &mut buf)
                    }
                }
                Tier::Avx2 => {
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    {
                        if has_avx2() {
                            unsafe { chacha20_xor_avx2(&key, 1, &nonce, &mut buf) }
                        } else if has_sse2() {
                            unsafe { chacha20_xor_sse2_xor(&key, 1, &nonce, &mut buf) }
                        } else {
                            chacha20_xor_scalar(&key, 1, &nonce, &mut buf)
                        }
                    }
                    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                    {
                        chacha20_xor_scalar(&key, 1, &nonce, &mut buf)
                    }
                }
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        let mibs = (len as f64 * rounds as f64 / (1024.0 * 1024.0)) / secs.max(1e-9);
        if mibs > best {
            best = mibs;
        }
    }
    best
}

/// 强制用某个档位异或，供自测比对 SIMD 与标量是否一致。
fn xor_with(tier: Tier, key: &[u8; 32], counter: u32, nonce: &[u8; 12], buf: &mut [u8]) {
    match tier {
        Tier::Scalar => chacha20_xor_scalar(key, counter, nonce, buf),
        Tier::Sse2 => {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if has_sse2() {
                unsafe { chacha20_xor_sse2_xor(key, counter, nonce, buf) };
                return;
            }
            chacha20_xor_scalar(key, counter, nonce, buf);
        }
        Tier::Avx2 => {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            if has_avx2() {
                unsafe { chacha20_xor_avx2(key, counter, nonce, buf) };
                return;
            }
            chacha20_xor_scalar(key, counter, nonce, buf);
        }
    }
}


fn parse_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = bytes[i];
        if c == b' ' || c == b'\n' || c == b'\r' || c == b':' {
            i += 1;
            continue;
        }
        fn n(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            }
        }
        out.push((n(bytes[i]) << 4) | n(bytes[i + 1]));
        i += 2;
    }
    out
}

/// Run built-in RFC / draft test vectors. Returns Ok or an error string.
pub fn self_test() -> Result<(), String> {
    // RFC 8439 §2.3.2 ChaCha20 block
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let block = chacha20_block(&key, 1, &nonce);
    let expect = parse_hex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    );
    if block.to_vec() != expect {
        return Err("ChaCha20 block vector failed".into());
    }

    // HChaCha20 draft §2.2.1
    let hnonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];
    let sub = hchacha20(&key, &hnonce);
    let hexpect = parse_hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    if sub.to_vec() != hexpect {
        return Err("HChaCha20 vector failed".into());
    }

    // RFC 8439 §2.8.2 AEAD
    let mut aead_key = [0u8; 32];
    for i in 0..32 {
        aead_key[i] = 0x80 + i as u8;
    }
    let aead_nonce = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = parse_hex("50515253c0c1c2c3c4c5c6c7");
    let (ct, tag) = chacha20_poly1305_encrypt(&aead_key, &aead_nonce, &aad, pt);
    let ct_expect = parse_hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let tag_expect = parse_hex("1ae10b594f09e26a7e902ecbd0600691");
    if ct != ct_expect {
        return Err(format!(
            "ChaCha20-Poly1305 ciphertext mismatch\n got {}\n exp {}",
            crate::util::hex_encode(&ct),
            crate::util::hex_encode(&ct_expect)
        ));
    }
    if tag.to_vec() != tag_expect {
        return Err(format!(
            "ChaCha20-Poly1305 tag mismatch\n got {}\n exp {}",
            crate::util::hex_encode(&tag),
            crate::util::hex_encode(&tag_expect)
        ));
    }
    let dec = chacha20_poly1305_decrypt(&aead_key, &aead_nonce, &aad, &ct, &tag)
        .map_err(|_| "AEAD decrypt failed")?;
    if dec.as_slice() != pt.as_ref() {
        return Err("AEAD roundtrip failed".into());
    }

    // XChaCha20-Poly1305 draft appendix A.3.1
    let mut xn = [0u8; 24];
    let xv = parse_hex("404142434445464748494a4b4c4d4e4f5051525354555657");
    xn.copy_from_slice(&xv);
    let (xct, xtag) = xchacha20_poly1305_encrypt(&aead_key, &xn, &aad, pt);
    let xct_expect = parse_hex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
    );
    let xtag_expect = parse_hex("c0875924c1c7987947deafd8780acf49");
    if xct != xct_expect {
        return Err(format!(
            "XChaCha20-Poly1305 ciphertext mismatch\n got {}\n exp {}",
            crate::util::hex_encode(&xct),
            crate::util::hex_encode(&xct_expect)
        ));
    }
    if xtag.to_vec() != xtag_expect {
        return Err(format!(
            "XChaCha20-Poly1305 tag mismatch\n got {}\n exp {}",
            crate::util::hex_encode(&xtag),
            crate::util::hex_encode(&xtag_expect)
        ));
    }

    // SIMD 与标量必须逐字节一致（覆盖三种档位下实际会走到的路径）
    for &tier in [best_tier()].iter() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        for i in 0..4096 {
            a[i] = (i * 17 + 3) as u8;
            b[i] = a[i];
        }
        chacha20_xor_scalar(&aead_key, 1, &aead_nonce, &mut a);
        xor_with(tier, &aead_key, 1, &aead_nonce, &mut b);
        if a != b {
            return Err(format!("{} 与标量实现不一致", tier_name(tier)));
        }
    }
    // 非 64 对齐的尾巴也要一致
    for len in [513usize, 1022, 1000, 63, 1].iter() {
        let mut a = vec![0u8; *len];
        let mut b = vec![0u8; *len];
        for i in 0..*len {
            a[i] = (i * 31) as u8;
            b[i] = a[i];
        }
        chacha20_xor_scalar(&aead_key, 2, &aead_nonce, &mut a);
        chacha20_xor(&aead_key, 2, &aead_nonce, &mut b);
        if a != b {
            return Err(format!("ChaCha 尾部不一致 (len={})", len));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_and_draft_vectors() {
        self_test().unwrap();
    }
}
