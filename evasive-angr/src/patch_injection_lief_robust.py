#!/usr/bin/env python3
"""
Robust patcher using LIEF with diagnostics and fallback pattern search.

Usage example:
python3 src/patch_injection_lief_robust.py --binary samples/injection_demo \
    --addr 0x4011ec --size 8 --out samples/injection_demo_patched

Optional fallback pattern (escaped hex string, e.g. "\x48\x89\xe5") will be searched
if mapping VA->file offset fails.
"""
import argparse, lief, sys, os, binascii

def bytes_from_escaped(s: str):
    # e.g. "\\x90\\x90" or "\x90\x90"
    if s is None:
        return None
    # normalize string: allow both literal backslash escapes and direct bytes
    try:
        return s.encode('utf-8').decode('unicode_escape').encode('latin1')
    except Exception:
        # try interpreting as hex without \x
        try:
            return binascii.unhexlify(s)
        except Exception:
            return None

def map_va_to_offset_lief(b, addr):
    # try program segments first (ELF/PE segments)
    for seg in getattr(b, "segments", []):
        start = seg.virtual_address
        end = start + seg.virtual_size
        if addr >= start and addr < end:
            file_off = seg.file_offset + (addr - start)
            return file_off, f"segment {hex(start)}-{hex(end)} (file_offset {seg.file_offset})"
    # try sections next
    for sec in getattr(b, "sections", []):
        start = sec.virtual_address
        end = start + sec.size
        ptr = getattr(sec, "pointerto_raw_data", None)
        if ptr is None:
            ptr = getattr(sec, "offset", None)
        if ptr is None:
            continue
        if addr >= start and addr < end:
            file_off = ptr + (addr - start)
            return file_off, f"section {sec.name} {hex(start)}-{hex(end)} (raw {ptr})"
    # PE-specific: compute RVA = addr - imagebase and map to section raw
    ib = getattr(b, "imagebase", None)
    if ib:
        rva = addr - ib
        for sec in getattr(b, "sections", []):
            start = sec.virtual_address
            end = start + sec.size
            if rva >= start and rva < end:
                file_off = sec.pointerto_raw_data + (rva - start)
                return file_off, f"PE section {sec.name} via RVA {hex(rva)}"
    return None, None

def pattern_search_and_patch(file_bytes, pattern_bytes):
    idx = file_bytes.find(pattern_bytes)
    return idx

def patch_in_file(input_path, file_offset, size, nop_byte=b'\x90'):
    data = bytearray(open(input_path, "rb").read())
    if file_offset < 0 or file_offset+size > len(data):
        raise RuntimeError("computed file offset out of range")
    for i in range(size):
        data[file_offset + i] = nop_byte[0]
    return data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--addr", required=False, help="VA e.g. 0x4011ec (optional if using --pattern fallback)")
    ap.add_argument("--size", type=int, default=8)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pattern", required=False, help="fallback byte pattern (escaped) to search in file")
    args = ap.parse_args()

    binary_path = args.binary
    if not os.path.exists(binary_path):
        print("[!] Binary not found:", binary_path)
        sys.exit(1)

    print("[*] Parsing binary with LIEF...")
    b = lief.parse(binary_path)
    if b is None:
        print("[!] LIEF failed to parse the binary.")
        sys.exit(1)

    print("[*] Basic info:")
    try:
        print("  - format:", type(b).__name__)
        print("  - imagebase:", hex(b.imagebase) if getattr(b, "imagebase", None) else b.imagebase)
    except Exception as e:
        print("  - error reading imagebase:", e)

    print("\n[*] Segments (if any):")
    for seg in getattr(b, "segments", []):
        print(f"  - VA {hex(seg.virtual_address)} size {hex(seg.virtual_size)} file_offset {getattr(seg,'file_offset',None)}")

    print("\n[*] Sections (if any):")
    for sec in getattr(b, "sections", []):
        ptr = getattr(sec, "pointerto_raw_data", None)
        print(f"  - {sec.name} VA {hex(sec.virtual_address)} size {sec.size} raw {ptr}")

    file_offset = None
    reason = None
    if args.addr:
        try:
            addr = int(args.addr, 0)
            print(f"\n[*] Attempting to map VA {hex(addr)} -> file offset...")
            file_offset, reason = map_va_to_offset_lief(b, addr)
            if file_offset is not None:
                print(f"[+] Mapped VA {hex(addr)} -> file_offset {file_offset} via {reason}")
        except Exception as e:
            print("[!] Error parsing addr:", e)

    # Fallback: pattern search
    pattern_bytes = bytes_from_escaped(args.pattern) if args.pattern else None
    file_bytes = open(binary_path, "rb").read()

    if file_offset is None and pattern_bytes:
        print("[*] VA mapping failed. Trying pattern fallback search...")
        idx = pattern_search_and_patch(file_bytes, pattern_bytes)
        if idx >= 0:
            print(f"[+] Found pattern at file offset {idx}. Will patch there.")
            file_offset = idx
            reason = "pattern_search"
        else:
            print("[-] Pattern not found in file.")

    if file_offset is None:
        print("\n[!] Failed to compute a file offset for the requested VA and pattern.")
        print("Hints:")
        print(" - Are you sure the VA 0x... is a file VA and not a runtime relocated address (PIE/ASLR)?")
        print(" - Use readelf -h / readelf -l to check if the binary is ET_DYN (PIE).")
        print(" - Consider providing a short byte pattern to search for using --pattern \"\\x90\\x90\"")
        sys.exit(2)

    print(f"[*] Patching {args.size} bytes at file offset {file_offset} (reason: {reason})")
    patched = patch_in_file(binary_path, file_offset, args.size)
    out_dir = os.path.dirname(args.out)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(args.out, "wb") as f:
        f.write(patched)
    # Make executable
    try:
        os.chmod(args.out, 0o755)
    except Exception:
        pass

    print(f"[+] Wrote patched binary to {args.out}")
    print("[*] Done. TEST in an isolated VM snapshot.")

if __name__ == "__main__":
    main()
