#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ganti_url_apk.py — Ganti URL download .so NOROOT & ROOT di BackMod Injector 3.1.0
=================================================================================

Pemakaian:
  # Lihat URL yang sedang dipakai di APK:
  python3 ganti_url_apk.py --status --input APK

  # Ganti URL NOROOT saja (ROOT dipertahankan):
  python3 ganti_url_apk.py --input APK --noroot "https://raw.githubusercontent.com/user/repo/main/libbackmodcr.so"

  # Ganti keduanya:
  python3 ganti_url_apk.py --input APK \
      --noroot "https://contoh.com/cr.so" \
      --root   "https://contoh.com/cr-root.so"

  # Tanpa signing (hasil APK raw/unsigned):
  python3 ganti_url_apk.py --input APK --noroot URL --no-sign

Hasil default: <folder input>/<nama>_gantiurl.apk (signed debug, siap install).

Catatan nama file:
  * Nama file di URL (remote), mis. .../TheDanzPro.so atau .../libbackmodcr.so,
    BOLEH APA PUN — injector tinggal mengunduh isi URL.
  * Yang tetap (fixed) hanya nama file LOKAL tempat payload disimpan:
    "libbackmodcr.so" (string terenkripsi STR3 di lib, tidak perlu diubah).
  * Satu-satunya batasan: panjang URL NOROOT + ROOT <= 127 karakter.

--------------------------------------------------------------------------------
CARA KERJA (ringkas):

Config URL tersimpan terenkripsi keystream di libRevenyInjector.so (4 ABI):
    x = state; x ^= x>>13; x = (x*0x85EBCA77)&0xffffffff; x ^= x>>17
    out = enc ^ (x&0xff); state = (state + 0x9E37) & 0xffffffff
Seed  : NOROOT 0x9F80C83A, ROOT 0x1500857C, STR3 0xD67CB721 ("libbackmodcr.so").

Layout region config (A = offset config; total terpakai 127 byte, ditutup
string typeinfo "NSt6__ndk1..." yang tidak boleh tersentuh):
  * APK original     : [NOROOT 57 @A][ROOT 55 @B][STR3 15 @C]   (x86_64: B=A+64)
  * APK patch lama   : [ROOT   55 @A][NOROOT len @A+55][STR3 @Z]
Layout output script ini (uniform semua ABI):
  * [ROOT len_rt @A][NOROOT len_nr @A+len_rt], STR3 pindah ke zero-run dead @Z.
  * Syarat: len_rt + len_nr <= 127, keduanya >= 1, karakter ASCII printable.

Patch kode: 7 site per ABI (2 ctor size, 2 addr, 2 cmp size/state, 1 addr STR3).
  arm64 : mov w1,#imm (ctor), adr Xn (addr), cmp xn,#imm (cmp)
  arm32 : movs r1,#imm, literal-pool word (PC-rel), cmp r1,#imm
  x86   : push imm8, lea r,[ebx+disp32] (ebx=GOT 0x8726C), cmp esi,(seed+n*0x9E37)
  x64   : mov esi,imm32, lea r,[rip+disp32], cmp rcx,#imm8

Setelah patch: rebuild ZIP (buang signature lama) -> sign uber-apk-signer
(debug, zipalign v1/v2/v3) -> auto-fix cert-hash (string hex SHA256 cert di
lib) bila cert mesin ini berbeda -> verifikasi akhir dari APK signed.

Semua langkah fail-fast: verifikasi dulu, baru tulis, verifikasi ulang.
"""

import argparse
import glob
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

try:
    from capstone import (Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64,
                          CS_ARCH_X86, CS_MODE_32, CS_ARCH_ARM, CS_MODE_THUMB)
except ImportError:
    print("Modul 'capstone' belum terpasang. Install dulu:")
    print("  python3 -m pip install capstone")
    sys.exit(1)

# ============================== KONSTANTA INTI ==============================

SEED_NR = 0x9F80C83A   # seed keystream slot NOROOT
SEED_RT = 0x1500857C   # seed keystream slot ROOT
SEED_S3 = 0xD67CB721   # seed keystream STR3 (nama file lokal payload)
STR3 = "libbackmodcr.so"   # 15 byte, fixed (nama file lokal penyimpanan .so)

MAX_TOTAL = 127        # batas ruang config: len_root + len_noroot

GEO = {
    # A = pangkal region config, B = slot ROOT versi original, C = slot STR3
    # versi original, Z = rumah baru STR3 (zero-run dead, ref-checked Task 18).
    "arm64-v8a":   {"A": 0x15539, "B": 0x15572, "C": 0x155A9, "Z": 0x163B1, "arch": "a64"},
    "armeabi-v7a": {"A": 0x1193B, "B": 0x11974, "C": 0x119AB, "Z": 0x123F1, "arch": "a32"},
    "x86":         {"A": 0x0F184, "B": 0x0F1BD, "C": 0x0F1F4, "Z": 0x101E5, "arch": "x86"},
    "x86_64":      {"A": 0x18190, "B": 0x181D0, "C": 0x18207, "Z": 0x19461, "arch": "x64"},
}
# x86_64 punya 7 byte padding setelah NOROOT di layout original (B = A+64).

EBX_GOT = 0x8726C      # basis GOT untuk lea [ebx+disp] di x86 (terverifikasi Task 18)

LIBS = {
    "arm64-v8a":   "lib/arm64-v8a/libRevenyInjector.so",
    "armeabi-v7a": "lib/armeabi-v7a/libRevenyInjector.so",
    "x86":         "lib/x86/libRevenyInjector.so",
    "x86_64":      "lib/x86_64/libRevenyInjector.so",
}

# offset string hex cert-hash (64 char) di tiap lib (Task 17)
HASH_OFF = {
    "arm64-v8a": 0x1456E,
    "armeabi-v7a": 0x11790,
    "x86": 0x0E1CE,
    "x86_64": 0x17229,
}

# add-site (add rX, pc) untuk tiap literal pool arm32
ADD32 = {"NR": 0x1704E, "RT": 0x1712E, "S3": 0x1720E}

# 7 site per ABI: (slot, role, file_offset, kind, extra)
#   role: ctor=panjang di std::string ctor, addr=alamat slot, cmp=panjang/state
SITES = {
    "arm64-v8a": [
        ("NR", "ctor", 0x327EC, "a64_imm16", None),
        ("NR", "addr", 0x32810, "a64_adr",   None),
        ("NR", "cmp",  0x32850, "a64_imm12", None),
        ("RT", "ctor", 0x3292C, "a64_imm16", None),
        ("RT", "addr", 0x32950, "a64_adr",   None),
        ("RT", "cmp",  0x32990, "a64_imm12", None),
        ("S3", "addr", 0x32A90, "a64_adr",   None),
    ],
    "armeabi-v7a": [
        ("NR", "ctor", 0x17038, "t32_imm8", None),
        ("NR", "addr", 0x170F0, "t32_lit",  None),
        ("NR", "cmp",  0x17080, "t32_imm8", None),
        ("RT", "ctor", 0x17118, "t32_imm8", None),
        ("RT", "addr", 0x171D0, "t32_lit",  None),
        ("RT", "cmp",  0x17160, "t32_imm8", None),
        ("S3", "addr", 0x172B0, "t32_lit",  None),
    ],
    "x86": [
        ("NR", "ctor", 0x27C5C, "x86_push",     None),
        ("NR", "addr", 0x27C6E, "lea_disp",     None),
        ("NR", "cmp",  0x27C8B, "x86_cmpstate", {"seed": SEED_NR}),
        ("RT", "ctor", 0x27D9C, "x86_push",     None),
        ("RT", "addr", 0x27DAE, "lea_disp",     None),
        ("RT", "cmp",  0x27DCB, "x86_cmpstate", {"seed": SEED_RT}),
        ("S3", "addr", 0x27EEE, "lea_disp",     None),
    ],
    "x86_64": [
        ("NR", "ctor", 0x2E81C, "x64_movimm", None),
        ("NR", "addr", 0x2E833, "lea_disp",   None),
        ("NR", "cmp",  0x2E86B, "x64_cmpimm", None),
        ("RT", "ctor", 0x2E93C, "x64_movimm", None),
        ("RT", "addr", 0x2E953, "lea_disp",   None),
        ("RT", "cmp",  0x2E98B, "x64_cmpimm", None),
        ("S3", "addr", 0x2EA73, "lea_disp",   None),
    ],
}

# ============================== UTIL DASAR ==============================


def fail(msg):
    print(f"[GAGAL] {msg}")
    sys.exit(1)


def keystream(seed, n):
    out = bytearray()
    st = seed & 0xFFFFFFFF
    for _ in range(n):
        x = st
        x ^= x >> 13
        x = (x * 0x85EBCA77) & 0xFFFFFFFF
        x ^= x >> 17
        out.append(x & 0xFF)
        st = (st + 0x9E37) & 0xFFFFFFFF
    return bytes(out)


def xor_crypt(data, seed):
    ks = keystream(seed, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def dec_at(data, off, seed, n):
    return xor_crypt(bytes(data[off:off + n]), seed)


def md_for(arch):
    return {
        "a64": Cs(CS_ARCH_ARM64, CS_MODE_ARM),
        "a32": Cs(CS_ARCH_ARM, CS_MODE_THUMB),
        "x86": Cs(CS_ARCH_X86, CS_MODE_32),
        "x64": Cs(CS_ARCH_X86, CS_MODE_64),
    }[arch]


def disasm_one(data, off, arch):
    for ins in md_for(arch).disasm(bytes(data[off:off + 16]), off):
        return ins
    return None


def _imm_from_op(op_str):
    m = re.search(r"#?(0x[0-9a-fA-F]+|\d+)$", op_str.strip())
    return int(m.group(1), 0) if m else None


def lea_target(data, off, arch):
    """Decode lea [rip+disp] (x64) / [ebx+disp] (x86) -> alamat absolut."""
    ins = disasm_one(data, off, arch)
    if ins is None or ins.mnemonic != "lea":
        return None
    m64 = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", ins.op_str)
    m32 = re.search(r"\[ebx ([+-]) (0x[0-9a-f]+)\]", ins.op_str)
    if m64:
        d = int(m64.group(2), 16) * (1 if m64.group(1) == "+" else -1)
        return off + ins.size + d
    if m32:
        d = int(m32.group(2), 16) * (1 if m32.group(1) == "+" else -1)
        return (EBX_GOT + d) & 0xFFFFFFFF
    return None


# ======================= PEMBACA STATE SAAT INI =======================


def read_ctor_len(tag, data, off, kind):
    """Baca panjang dari immediate std::string ctor di site."""
    arch = GEO[tag]["arch"]
    if kind == "a64_imm16":
        ins = disasm_one(data, off, arch)
        if not (ins and ins.mnemonic == "mov" and ins.op_str.startswith("w") and "#0x" in ins.op_str):
            fail(f"{tag}: ctor @0x{off:x} bukan 'mov wN,#imm': {ins and (ins.mnemonic + ' ' + ins.op_str)}")
        return _imm_from_op(ins.op_str)
    if kind == "t32_imm8":
        ins = disasm_one(data, off, arch)
        if not (ins and ins.mnemonic in ("mov", "movs") and "#0x" in ins.op_str):
            fail(f"{tag}: ctor @0x{off:x} bukan 'movs rN,#imm': {ins and (ins.mnemonic + ' ' + ins.op_str)}")
        return _imm_from_op(ins.op_str)
    if kind == "x86_push":
        if data[off] != 0x6A:
            fail(f"{tag}: ctor @0x{off:x} bukan 'push imm8' (6A): {data[off:off+2].hex()}")
        return data[off + 1]
    if kind == "x64_movimm":
        if data[off] != 0xBE or data[off + 2:off + 5] != b"\x00\x00\x00":
            fail(f"{tag}: ctor @0x{off:x} bukan 'mov esi,imm32' (BE): {data[off:off+5].hex()}")
        return data[off + 1]
    fail(f"kind ctor tak dikenal: {kind}")


def read_cmp_len(tag, data, off, kind, extra):
    """Baca panjang dari site cmp. x86 memakai state-compare (seed+n*0x9E37)."""
    arch = GEO[tag]["arch"]
    if kind in ("a64_imm12", "t32_imm8"):
        ins = disasm_one(data, off, arch)
        if not (ins and ins.mnemonic == "cmp" and "#0x" in ins.op_str):
            fail(f"{tag}: cmp @0x{off:x} tak terbaca: {ins and (ins.mnemonic + ' ' + ins.op_str)}")
        return _imm_from_op(ins.op_str)
    if kind == "x64_cmpimm":
        if data[off:off + 3] != b"\x48\x83\xf9":
            fail(f"{tag}: cmp @0x{off:x} bukan 'cmp rcx,#imm8': {data[off:off+4].hex()}")
        return data[off + 3]
    if kind == "x86_cmpstate":
        if data[off:off + 2] != b"\x81\xfe":
            fail(f"{tag}: cmp @0x{off:x} bukan 'cmp esi,imm32' (81 FE): {data[off:off+2].hex()}")
        const = struct.unpack("<I", data[off + 2:off + 6])[0]
        seed = extra["seed"]
        diff = (const - seed) & 0xFFFFFFFF
        if diff % 0x9E37 != 0:
            fail(f"{tag}: state const @0x{off:x} = 0x{const:x} bukan seed+n*0x9E37")
        return diff // 0x9E37
    fail(f"kind cmp tak dikenal: {kind}")


def read_addr_target(tag, data, off, kind, slot):
    """Baca alamat slot yang ditunjuk site addr (adr/literal/lea)."""
    arch = GEO[tag]["arch"]
    if kind == "a64_adr":
        ins = disasm_one(data, off, arch)
        if not (ins and ins.mnemonic == "adr" and "#" in ins.op_str):
            fail(f"{tag}: addr @0x{off:x} bukan 'adr Xn,#imm': {ins and (ins.mnemonic + ' ' + ins.op_str)}")
        return int(ins.op_str.split("#")[1], 0)
    if kind == "t32_lit":
        v = struct.unpack("<i", data[off:off + 4])[0]
        return (ADD32[slot] + 4 + v) & 0xFFFFFFFF
    if kind == "lea_disp":
        t = lea_target(data, off, arch)
        if t is None:
            fail(f"{tag}: addr @0x{off:x} lea tak terparse")
        return t
    fail(f"kind addr tak dikenal: {kind}")


# ======================= DETEKSI LAYOUT INPUT =======================


def printable_http(buf):
    try:
        s = buf.decode("ascii")
    except UnicodeDecodeError:
        return None
    if s.startswith("http") and all(33 <= ord(c) <= 126 for c in s):
        return s
    return None


def _site_off(tag, slot, role, kind=False):
    for (s, r, off, k, ex) in SITES[tag]:
        if s == slot and r == role:
            return (off, k) if kind else off
    fail(f"{tag}: site {slot}/{role} tidak ditemukan")


def detect_layout(tag, data):
    """Deteksi layout APK input + baca URL saat ini (self-consistent dari kode)."""
    len_nr = read_ctor_len(tag, data, _site_off(tag, "NR", "ctor"),
                           _site_off(tag, "NR", "ctor", kind=True)[1])
    len_rt = read_ctor_len(tag, data, _site_off(tag, "RT", "ctor"),
                           _site_off(tag, "RT", "ctor", kind=True)[1])
    return _detect(tag, data, len_nr, len_rt)


def _detect(tag, data, len_nr, len_rt):
    g = GEO[tag]
    A, B, C, Z = g["A"], g["B"], g["C"], g["Z"]

    # verifikasi konsistensi ctor vs cmp
    cmp_nr = read_cmp_len(tag, data, _site_off(tag, "NR", "cmp"),
                          _site_off(tag, "NR", "cmp", kind=True)[1],
                          {"seed": SEED_NR})
    cmp_rt = read_cmp_len(tag, data, _site_off(tag, "RT", "cmp"),
                          _site_off(tag, "RT", "cmp", kind=True)[1],
                          {"seed": SEED_RT})
    if cmp_nr != len_nr:
        fail(f"{tag}: panjang NOROOT ctor({len_nr}) != cmp({cmp_nr})")
    if cmp_rt != len_rt:
        fail(f"{tag}: panjang ROOT ctor({len_rt}) != cmp({cmp_rt})")

    # layout original: NOROOT @A dulu, ROOT @B, STR3 @C
    nr_a = printable_http(dec_at(data, A, SEED_NR, len_nr))
    if nr_a:
        rt_off = B
        s3_off = C
        layout = "original"
    else:
        # layout patch lama: ROOT @A, NOROOT @A+len_rt, STR3 @Z
        rt_a = printable_http(dec_at(data, A, SEED_RT, len_rt))
        if not rt_a:
            fail(f"{tag}: layout tidak dikenali (bukan original maupun patch lama)")
        nr_a = printable_http(dec_at(data, A + len_rt, SEED_NR, len_nr))
        if not nr_a:
            fail(f"{tag}: slot NOROOT @A+{len_rt} tidak berisi URL valid")
        rt_off, s3_off, layout = A, Z, "patch-lama"
    nr_off = A if layout == "original" else A + len_rt

    url_rt = printable_http(dec_at(data, rt_off, SEED_RT, len_rt))
    if not url_rt:
        fail(f"{tag}: slot ROOT @0x{rt_off:x} tidak berisi URL valid")
    cur_s3 = dec_at(data, s3_off, SEED_S3, 15).decode("latin1")
    if cur_s3 != STR3:
        fail(f"{tag}: STR3 @0x{s3_off:x} tidak cocok: {cur_s3!r}")
    if data[C + 15:C + 17] != b"NS":
        fail(f"{tag}: typeinfo setelah region rusak: {data[C+15:C+17]!r}")

    # verifikasi alamat di kode menunjuk slot yang benar
    t_nr = read_addr_target(tag, data, _site_off(tag, "NR", "addr"),
                            _site_off(tag, "NR", "addr", kind=True)[1], "NR")
    t_rt = read_addr_target(tag, data, _site_off(tag, "RT", "addr"),
                            _site_off(tag, "RT", "addr", kind=True)[1], "RT")
    t_s3 = read_addr_target(tag, data, _site_off(tag, "S3", "addr"),
                            _site_off(tag, "S3", "addr", kind=True)[1], "S3")
    if t_nr != nr_off or t_rt != rt_off:
        fail(f"{tag}: alamat kode tidak sesuai layout: NR 0x{t_nr:x} (harap 0x{nr_off:x}), "
             f"RT 0x{t_rt:x} (harap 0x{rt_off:x})")
    if t_s3 not in (C, Z):
        fail(f"{tag}: alamat STR3 di kode menunjuk 0x{t_s3:x} (harap C=0x{C:x} atau Z=0x{Z:x})")
    if t_s3 != s3_off:
        fail(f"{tag}: alamat STR3 kode 0x{t_s3:x} != slot terdeteksi 0x{s3_off:x}")

    return {
        "layout": layout, "len_nr": len_nr, "len_rt": len_rt,
        "nr_off": nr_off, "rt_off": rt_off, "s3_off": s3_off,
        "url_nr": nr_a, "url_rt": url_rt,
    }

# ======================= PATCH INTI PER ABI =======================


def validate_url(slot, url):
    if not url:
        return url
    if not url.startswith("http"):
        fail(f"URL {slot} harus diawali http/https: {url!r}")
    if not all(33 <= ord(c) <= 126 for c in url):
        fail(f"URL {slot} mengandung karakter tidak valid (harus ASCII printable tanpa spasi)")
    if len(url) < 1 or len(url) > MAX_TOTAL - 1:
        fail(f"URL {slot} panjang {len(url)} di luar batas 1..{MAX_TOTAL - 1}")
    return url


def patch_lib(tag, data, url_nr_new, url_rt_new):
    """Patch satu lib: data config + 7 site kode. Return bytes_baru."""
    g = GEO[tag]
    A, C, Z = g["A"], g["C"], g["Z"]
    arch = g["arch"]
    len_rt_n = len(url_rt_new)
    len_nr_n = len(url_nr_new)
    out = bytearray(data)

    # ===== 1. tulis data config baru =====
    # [ROOT len_rt @A][NOROOT len_nr @A+len_rt] ... zero sampai akhir region (C+15)
    out[A:A + len_rt_n] = xor_crypt(url_rt_new.encode(), SEED_RT)
    out[A + len_rt_n:A + len_rt_n + len_nr_n] = xor_crypt(url_nr_new.encode(), SEED_NR)
    region_end = C + 15
    for i in range(A + len_rt_n + len_nr_n, region_end):
        out[i] = 0
    # STR3 ke rumah barunya (Z); posisi lama (C) sudah tertimpa/ter-zero di atas
    out[Z:Z + 15] = xor_crypt(STR3.encode(), SEED_S3)

    # ===== 2. patch 7 site kode =====
    targets = {"NR": A + len_rt_n, "RT": A, "S3": Z}
    sizes = {"NR": len_nr_n, "RT": len_rt_n}
    report = []
    for (slot, role, off, kind, extra) in SITES[tag]:
        if role == "ctor":
            new_len = sizes[slot]
            if kind == "a64_imm16":
                w = struct.unpack("<I", out[off:off + 4])[0]
                w = (w & ~0x1FFFE0) | (new_len << 5)
                out[off:off + 4] = struct.pack("<I", w)
            elif kind == "t32_imm8":
                h = struct.unpack("<H", out[off:off + 2])[0]
                out[off:off + 2] = struct.pack("<H", (h & 0xFF00) | new_len)
            elif kind == "x86_push":
                out[off + 1] = new_len
            elif kind == "x64_movimm":
                out[off + 1] = new_len
            report.append(f"ctor {slot}={new_len}")
        elif role == "cmp":
            new_len = sizes[slot]
            if kind == "a64_imm12":
                w = struct.unpack("<I", out[off:off + 4])[0]
                w = (w & ~0x3FFC00) | (new_len << 10)
                out[off:off + 4] = struct.pack("<I", w)
            elif kind == "t32_imm8":
                h = struct.unpack("<H", out[off:off + 2])[0]
                out[off:off + 2] = struct.pack("<H", (h & 0xFF00) | new_len)
            elif kind == "x64_cmpimm":
                out[off + 3] = new_len
            elif kind == "x86_cmpstate":
                seed = extra["seed"]
                out[off + 2:off + 6] = struct.pack("<I", (seed + new_len * 0x9E37) & 0xFFFFFFFF)
            report.append(f"cmp {slot}={new_len}")
        elif role == "addr":
            tgt = targets[slot]
            if kind == "a64_adr":
                pc = off
                delta = tgt - pc
                if not (-(1 << 20) <= delta < (1 << 20)):
                    fail(f"{tag}: adr delta out of range @0x{off:x}")
                w = struct.unpack("<I", out[off:off + 4])[0]
                rd = w & 0x1F
                w = 0x10000000 | ((delta & 0x3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | rd
                out[off:off + 4] = struct.pack("<I", w)
            elif kind == "t32_lit":
                add_site = ADD32[slot]
                out[off:off + 4] = struct.pack("<i", tgt - (add_site + 4))
            elif kind == "lea_disp":
                ins = disasm_one(out, off, arch)
                if ins is None or ins.mnemonic != "lea":
                    fail(f"{tag}: lea hilang @0x{off:x}")
                if "[rip" in ins.op_str:
                    out[off + ins.size - 4:off + ins.size] = struct.pack("<i", tgt - (off + ins.size))
                elif "[ebx" in ins.op_str:
                    out[off + ins.size - 4:off + ins.size] = struct.pack("<I", (tgt - EBX_GOT) & 0xFFFFFFFF)
                else:
                    fail(f"{tag}: lea @0x{off:x} tak terparse: {ins.op_str}")
            report.append(f"addr {slot}->0x{tgt:x}")

    # ===== 3. verifikasi hasil =====
    chk_rt = dec_at(out, A, SEED_RT, len_rt_n).decode("latin1")
    chk_nr = dec_at(out, A + len_rt_n, SEED_NR, len_nr_n).decode("latin1")
    chk_s3 = dec_at(out, Z, SEED_S3, 15).decode("latin1")
    if chk_rt != url_rt_new:
        fail(f"{tag}: ROOT hasil tak cocok: {chk_rt!r}")
    if chk_nr != url_nr_new:
        fail(f"{tag}: NOROOT hasil tak cocok: {chk_nr!r}")
    if chk_s3 != STR3:
        fail(f"{tag}: STR3 hasil tak cocok: {chk_s3!r}")
    if out[C + 15:C + 17] != b"NS":
        fail(f"{tag}: typeinfo setelah region rusak pasca-patch")
    # re-disasm semua site: nilai baru harus terbaca kembali dengan benar
    len_nr_v = read_ctor_len(tag, out, _site_off(tag, "NR", "ctor"), _site_off(tag, "NR", "ctor", kind=True)[1])
    len_rt_v = read_ctor_len(tag, out, _site_off(tag, "RT", "ctor"), _site_off(tag, "RT", "ctor", kind=True)[1])
    if (len_nr_v, len_rt_v) != (len_nr_n, len_rt_n):
        fail(f"{tag}: verifikasi ulang ctor gagal: NR={len_nr_v} RT={len_rt_v}")
    cmp_nr_v = read_cmp_len(tag, out, _site_off(tag, "NR", "cmp"), _site_off(tag, "NR", "cmp", kind=True)[1], {"seed": SEED_NR})
    cmp_rt_v = read_cmp_len(tag, out, _site_off(tag, "RT", "cmp"), _site_off(tag, "RT", "cmp", kind=True)[1], {"seed": SEED_RT})
    if (cmp_nr_v, cmp_rt_v) != (len_nr_n, len_rt_n):
        fail(f"{tag}: verifikasi ulang cmp gagal: NR={cmp_nr_v} RT={cmp_rt_v}")
    t_nr = read_addr_target(tag, out, _site_off(tag, "NR", "addr"), _site_off(tag, "NR", "addr", kind=True)[1], "NR")
    t_rt = read_addr_target(tag, out, _site_off(tag, "RT", "addr"), _site_off(tag, "RT", "addr", kind=True)[1], "RT")
    t_s3 = read_addr_target(tag, out, _site_off(tag, "S3", "addr"), _site_off(tag, "S3", "addr", kind=True)[1], "S3")
    if (t_nr, t_rt, t_s3) != (A + len_rt_n, A, Z):
        fail(f"{tag}: verifikasi ulang addr gagal: NR=0x{t_nr:x} RT=0x{t_rt:x} S3=0x{t_s3:x}")

    # diff region: pastikan tak ada byte lain yang berubah
    diffs = []
    i = 0
    while i < len(data):
        if data[i] != out[i]:
            j = i
            while j < len(data) and data[j] != out[j]:
                j += 1
            diffs.append((i, j))
            i = j
        else:
            i += 1
    merged = []
    for s, e in diffs:
        if merged and s - merged[-1][1] < 8:
            merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    expect_regions = [(A, C + 15), (Z, Z + 15)] + [(off, off + 8) for (_, _, off, _, _) in SITES[tag]]
    for s, e in merged:
        if not any(es - 8 <= s and e <= ee + 8 for (es, ee) in expect_regions):
            fail(f"{tag}: perubahan di luar region yang diharapkan: "
                 f"{[(hex(a), hex(b)) for a, b in merged]} vs {[(hex(a), hex(b)) for a, b in sorted(expect_regions)]}")

    print(f"  [{tag}] OK: {'; '.join(report)}")
    print(f"  [{tag}] region berubah: {[(hex(a), hex(b)) for a, b in merged]}")
    return bytes(out)

# ======================= REBUILD / SIGN / CERT-HASH =======================

SIG_DROP_RE = re.compile(r"^META-INF/.*\.(SF|RSA|DSA|EC|MF)$")


def rebuild_apk(zin, patched_libs, out_path):
    """Tulis ulang ZIP: ganti lib yang dipatch, buang file signature lama."""
    buf = io.BytesIO()
    zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    n_replaced = 0
    for info in zin.infolist():
        if SIG_DROP_RE.match(info.filename):
            continue
        payload = zin.read(info.filename)
        if info.filename in patched_libs:
            payload = patched_libs[info.filename]
            n_replaced += 1
        zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        zi.compress_type = info.compress_type
        zi.external_attr = info.external_attr
        zout.writestr(zi, payload)
    zout.close()
    with open(out_path, "wb") as f:
        f.write(buf.getvalue())
    if n_replaced != len(LIBS):
        fail(f"rebuild: lib yang diganti {n_replaced}, harap {len(LIBS)}")
    return len(buf.getvalue())


def find_signer_jar(explicit):
    if explicit:
        return explicit if os.path.isfile(explicit) else fail(f"jar tidak ditemukan: {explicit}")
    cands = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "uber-apk-signer.jar"),
        os.path.join(os.getcwd(), "tools", "uber-apk-signer.jar"),
        "/home/z/my-project/tools/uber-apk-signer.jar",
        "/home/z/my-project/download/tools/uber-apk-signer.jar",
        "/tmp/my-project/apkwork/tools/uber-apk-signer.jar",
    ]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def sign_apk(jar, apk_path, workdir):
    """Sign dgn uber-apk-signer (debug keystore). Return path APK signed."""
    if not shutil.which("java"):
        fail("java tidak ditemukan untuk signing. Install java, atau jalankan ulang dgn --no-sign.")
    os.makedirs(workdir, exist_ok=True)
    r = subprocess.run(
        ["java", "-jar", jar, "-a", apk_path, "--out", workdir],
        capture_output=True, text=True, timeout=300,
    )
    outs = glob.glob(os.path.join(workdir, "*-aligned-debugSigned.apk"))
    if r.returncode != 0 or not outs:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        fail("gagal sign dengan uber-apk-signer")
    return outs[0]


def cert_sha256_from_apk(apk_path):
    """SHA256 hex (64 char) dari sertifikat signing v1 (META-INF/*.RSA)."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
    except ImportError:
        print("Modul 'cryptography' belum terpasang (dibutuhkan untuk cek cert-hash).")
        print("  Install dulu: python3 -m pip install cryptography")
        print("  Atau jalankan dgn --no-sign untuk hasil unsigned.")
        sys.exit(1)
    z = zipfile.ZipFile(apk_path)
    sigs = [n for n in z.namelist()
            if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
    if not sigs:
        fail(f"tidak ada file signature v1 di {apk_path}")
    certs = pkcs7.load_der_pkcs7_certificates(z.read(sigs[0]))
    if not certs:
        fail(f"sertifikat tidak ditemukan di {sigs[0]}")
    der = certs[0].public_bytes(Encoding.DER)
    import hashlib
    return hashlib.sha256(der).hexdigest()


def fix_certhash_if_needed(signed_apk, patched_libs):
    """Pastikan string cert-hash di lib == SHA256 cert penandatangan saat ini.
    Return True bila ada patch tambahan (perlu rebuild+sign ulang)."""
    sha = cert_sha256_from_apk(signed_apk)
    need = {}
    for tag, entry in LIBS.items():
        data = bytearray(patched_libs[entry])
        off = HASH_OFF[tag]
        cur = bytes(data[off:off + 64]).decode("latin1")
        if cur != sha:
            need[entry] = (tag, data, off, cur)
    if not need:
        print(f"  cert-hash cocok: {sha[:16]}...")
        return False
    print(f"  cert-hash beda (mesin ini: {sha[:16]}...) -> patch {len(need)} lib + rebuild ulang")
    for entry, (tag, data, off, cur) in need.items():
        print(f"    [{tag}] hash lama {cur[:16]}... -> {sha[:16]}... @0x{HASH_OFF[tag]:x}")
        data[off:off + 64] = sha.encode()
        patched_libs[entry] = bytes(data)
    return True


# ======================= VERIFIKASI AKHIR =======================


def verify_apk(apk_path, url_nr, url_rt):
    """Verifikasi dari file APK final (signed/unsigned): decrypt semua slot."""
    z = zipfile.ZipFile(apk_path)
    ok = True
    print(f"\n=== VERIFIKASI AKHIR: {os.path.basename(apk_path)} ===")
    sha = None
    try:
        sha = cert_sha256_from_apk(apk_path)
    except SystemExit:
        pass
    for tag, entry in LIBS.items():
        data = z.read(entry)
        len_nr = read_ctor_len(tag, data, _site_off(tag, "NR", "ctor"), _site_off(tag, "NR", "ctor", kind=True)[1])
        len_rt = read_ctor_len(tag, data, _site_off(tag, "RT", "ctor"), _site_off(tag, "RT", "ctor", kind=True)[1])
        A, C, Z = GEO[tag]["A"], GEO[tag]["C"], GEO[tag]["Z"]
        got_rt = dec_at(data, A, SEED_RT, len_rt).decode("latin1")
        got_nr = dec_at(data, A + len_rt, SEED_NR, len_nr).decode("latin1")
        got_s3 = dec_at(data, Z, SEED_S3, 15).decode("latin1")
        hsh = bytes(data[HASH_OFF[tag]:HASH_OFF[tag] + 64]).decode("latin1")
        t_s3 = read_addr_target(tag, data, _site_off(tag, "S3", "addr"), _site_off(tag, "S3", "addr", kind=True)[1], "S3")
        checks = [
            ("ROOT", got_rt == url_rt),
            ("NOROOT", got_nr == url_nr),
            ("STR3", got_s3 == STR3),
            ("addr-S3->Z", t_s3 == Z),
            ("typeinfo", data[C + 15:C + 17] == b"NS"),
            ("certhash", sha is None or hsh == sha),
        ]
        stat = " ".join(f"{n}:{'PASS' if v else 'GAGAL'}" for n, v in checks)
        print(f"  [{tag}] len(RT)={len_rt} len(NR)={len_nr} | {stat}")
        if not all(v for _, v in checks):
            ok = False
    if sha:
        print(f"  cert signing: {sha[:32]}...")
    return ok


# ======================= MAIN =======================


def find_input_auto():
    cands = [
        "backmodinjector_3.1.0_noroot_github.apk",
        "backmodinjector_3.1.0_noroot_worker.apk",
        "/home/z/my-project/download/backmodinjector_3.1.0_noroot_github.apk",
        "/home/z/my-project/download/backmodinjector_3.1.0_noroot_worker.apk",
        "/tmp/my-project/apkwork/backmodinjector_310.apk",
    ]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Ganti URL download .so NOROOT/ROOT di BackMod Injector 3.1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--input", "-i", help="APK injector 3.1.0 (default: cari otomatis)")
    ap.add_argument("--noroot", "-n", help="URL .so NOROOT baru (kosongkan = pertahankan)")
    ap.add_argument("--root", "-r", help="URL .so ROOT baru (kosongkan = pertahankan)")
    ap.add_argument("--output", "-o", help="APK hasil (default: <input>_gantiurl.apk)")
    ap.add_argument("--status", action="store_true", help="hanya tampilkan URL saat ini, tanpa patch")
    ap.add_argument("--no-sign", action="store_true", help="jangan sign (hasil unsigned)")
    ap.add_argument("--tools-jar", help="lokasi uber-apk-signer.jar (default: cari otomatis)")
    args = ap.parse_args()

    apk_in = args.input or find_input_auto()
    if not apk_in or not os.path.isfile(apk_in):
        fail("APK input tidak ditemukan; pakai --input /path/ke/apk")
    print(f"APK input : {apk_in}")
    zin = zipfile.ZipFile(apk_in)
    for tag, entry in LIBS.items():
        if entry not in zin.namelist():
            fail(f"entry {entry} tidak ada di APK (bukan injector 3.1.0?)")

    # --- deteksi layout & URL saat ini ---
    infos, libs_cur = {}, {}
    for tag, entry in LIBS.items():
        data = zin.read(entry)
        libs_cur[tag] = data
        infos[tag] = detect_layout(tag, data)
    print("\n=== STATUS SAAT INI ===")
    for tag, info in infos.items():
        print(f"  [{tag}] layout={info['layout']} | NOROOT({info['len_nr']}): {info['url_nr']}")
        print(f"  [{' ' * len(tag)}] {'':{len(info['layout'])}} | ROOT({info['len_rt']})   : {info['url_rt']}")
    lay = {i["layout"] for i in infos.values()}
    if len(lay) != 1:
        fail(f"layout antar-ABI tidak konsisten: {lay}")
    url_nr_cur = {i["url_nr"] for i in infos.values()}
    url_rt_cur = {i["url_rt"] for i in infos.values()}
    if len(url_nr_cur) != 1 or len(url_rt_cur) != 1:
        fail("URL current antar-ABI berbeda — APK campuran, tidak didukung")
    url_nr_cur, url_rt_cur = url_nr_cur.pop(), url_rt_cur.pop()

    if args.status:
        return

    # --- tentukan URL baru ---
    url_nr_new = validate_url("NOROOT", args.noroot) if args.noroot else url_nr_cur
    url_rt_new = validate_url("ROOT", args.root) if args.root else url_rt_cur
    if len(url_nr_new) + len(url_rt_new) > MAX_TOTAL:
        fail(f"total panjang URL {len(url_nr_new)}+{len(url_rt_new)}={len(url_nr_new)+len(url_rt_new)} "
             f"> batas {MAX_TOTAL} byte. Persingkat salah satu URL.")
    if args.noroot is None and args.root is None:
        print("\nTidak ada URL baru yang diberikan — tidak ada yang perlu diubah.")
        return
    print("\n=== PATCH ===")
    print(f"  NOROOT baru ({len(url_nr_new)}): {url_nr_new}")
    print(f"  ROOT   baru ({len(url_rt_new)}): {url_rt_new}")

    # --- patch semua ABI ---
    patched = {}
    for tag, entry in LIBS.items():
        print(f"--- {tag} ---")
        patched[entry] = patch_lib(tag, libs_cur[tag], url_nr_new, url_rt_new)

    # --- output path ---
    if args.output:
        apk_out = args.output
    else:
        base = os.path.splitext(os.path.basename(apk_in))[0]
        base = re.sub(r"\.apk$", "", base, flags=re.I) + "_gantiurl"
        apk_out = os.path.join(os.path.dirname(os.path.abspath(apk_in)), base + ".apk")
    os.makedirs(os.path.dirname(os.path.abspath(apk_out)) or ".", exist_ok=True)

    # --- rebuild (+ sign + cert-hash loop) ---
    size = rebuild_apk(zin, patched, apk_out)
    print(f"\nAPK raw tertulis: {apk_out} ({size} bytes)")
    if args.no_sign:
        # tetap verifikasi isi slot (cek cert-hash dilewati otomatis utk unsigned)
        if not verify_apk(apk_out, url_nr_new, url_rt_new):
            fail("verifikasi akhir GAGAL")
        print("\nSelesai (tanpa sign sesuai permintaan) — slot URL terverifikasi.")
        return
    jar = find_signer_jar(args.tools_jar)
    if not jar:
        print("[PERINGATAN] uber-apk-signer.jar tidak ditemukan — hasil UNSIGNED.")
        print("  Taruh jar di tools/uber-apk-signer.jar di sebelah script ini, atau pakai --tools-jar.")
        print("  APK unsigned tidak bisa di-install sebelum ditandatangani.")
        return
    workdir = apk_out + ".work"
    try:
        for attempt in (1, 2):
            signed = sign_apk(jar, apk_out, workdir)
            if fix_certhash_if_needed(signed, patched):
                if attempt == 2:
                    fail("cert-hash masih belum cocok setelah 1 kali perbaikan")
                rebuild_apk(zipfile.ZipFile(apk_in), patched, apk_out)
                continue
            shutil.copyfile(signed, apk_out)
            break
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print(f"APK signed  : {apk_out}")

    # --- verifikasi akhir ---
    if not verify_apk(apk_out, url_nr_new, url_rt_new):
        fail("verifikasi akhir GAGAL")
    print("\nSEMUA CEK PASS — APK siap install.")
    print(f"  NOROOT ({len(url_nr_new)}): {url_nr_new}")
    print(f"  ROOT   ({len(url_rt_new)}): {url_rt_new}")


if __name__ == "__main__":
    main()
