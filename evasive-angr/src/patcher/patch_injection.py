#!/usr/bin/env python3
"""
patch_injection_lief.py
Usage:
  python3 src/patch_injection_lief.py --binary samples/injection_demo --addr 0x4011ec --size 8 --out samples/injection_demo_patched
CAUTION: This is a simple byte patcher. Use on copies only. Test in snapshots.
"""
import argparse, lief, sys, os

def patch_nops(binary_path, addr, size, out_path):
    b = lief.parse(binary_path)
    if b is None:
        raise SystemExit("Failed to parse binary (not ELF/PE or corrupt).")
    # Convert virtual address to file offset
    rva = addr - b.imagebase if b.imagebase is not None else addr
    # Find segment/section containing addr
    file_offset = None
    for seg in b.segments:
        start = seg.virtual_address
        end = start + seg.virtual_size
        if addr >= start and addr < end:
            offset_in_seg = addr - start
            file_offset = seg.file_offset + offset_in_seg
            break
    if file_offset is None:
        # fallback: for PE try section mapping
        for sec in b.sections:
            start = sec.virtual_address
            end = start + sec.size
            if addr >= start and addr < end:
                offset_in_sec = addr - start
                file_offset = sec.pointerto_raw_data + offset_in_sec
                break
    if file_offset is None:
        raise SystemExit(f"Could not map VA 0x{addr:x} to file offset.")
    print(f"[*] Patching file offset {file_offset} (VA 0x{addr:x}) length {size}")

    # Read file bytes, patch them
    data = bytearray(open(binary_path, "rb").read())
    nop_byte = b'\x90'  # x86 nop
    for i in range(size):
        data[file_offset + i] = nop_byte[0]
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"[+] Wrote patched binary to {out_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--addr", required=True, help="hex VA like 0x4011ec")
    ap.add_argument("--size", type=int, default=8)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    addr = int(args.addr, 0)
    patch_nops(args.binary, addr, args.size, args.out)
