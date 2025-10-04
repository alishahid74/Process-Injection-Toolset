#!/usr/bin/env python3
"""
list_imports.py - robust import listing for PE and ELF files

Usage:
  python3 scripts/list_imports.py <path-to-binary>
"""
import sys, os

def is_pe(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
            return head == b"MZ"
    except Exception:
        return False

def is_elf(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
            return head == b"\x7fELF"
    except Exception:
        return False

def list_pe_imports(path):
    try:
        import pefile
    except Exception:
        print("[!] pefile not installed. Install with: pip install pefile")
        return False
    try:
        p = pefile.PE(path, fast_load=True)
        p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        if not hasattr(p, "DIRECTORY_ENTRY_IMPORT") or not p.DIRECTORY_ENTRY_IMPORT:
            print("[*] No import directory found (maybe statically linked or stripped).")
            return True
        for entry in p.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
            print(f"DLL: {dll}")
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else ("<ordinal_%s>" % (getattr(imp, "ordinal", "?")))
                print(f"    {name}")
        return True
    except Exception as e:
        print("[!] PE parsing error:", e)
        return False

def list_elf_imports(path):
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        print("[!] pyelftools not installed. Install with: pip install pyelftools")
        return False
    try:
        with open(path, "rb") as fh:
            elff = ELFFile(fh)
            dyn = elff.get_section_by_name('.dynamic')
            if dyn:
                print("[*] DT_NEEDED entries (shared libs):")
                for tag in dyn.iter_tags():
                    if getattr(tag.entry, "d_tag", None) == "DT_NEEDED" or getattr(tag, "tag", None) == "DT_NEEDED":
                        # pyelftools may represent tags slightly differently; try both attrs
                        try:
                            print("   ", tag.needed)
                        except Exception:
                            try:
                                print("   ", tag['d_val'])
                            except Exception:
                                pass
            dynsym = elff.get_section_by_name('.dynsym')
            if dynsym:
                print("[*] dynamic symbols (.dynsym) — showing names:")
                cnt = 0
                for sym in dynsym.iter_symbols():
                    if sym.name:
                        print("   ", sym.name)
                        cnt += 1
                        if cnt >= 200:
                            print("   ... (truncated)")
                            break
            else:
                print("[*] No .dynsym section found (stripped or static binary)")
            return True
    except Exception as e:
        print("[!] ELF parsing error:", e)
        return False

def fallback_scan(path):
    suspects = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateSection", "NtMapViewOfSection", "GetProcAddress", "LoadLibrary",
                "mmap", "ptrace", "dlopen", "dlsym", "socket", "connect"]
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception as e:
        print("[!] cannot read file:", e)
        return
    found = False
    for s in suspects:
        if s.encode() in data:
            print(f"[+] Found string: {s}")
            found = True
    if not found:
        print("[*] No common API strings found in raw bytes (fallback).")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/list_imports.py <binary>")
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.exists(path):
        print("[!] path does not exist:", path); sys.exit(2)
    if os.path.isdir(path):
        print("[!] path is a directory; provide a single file (or iterate files)."); sys.exit(3)

    if is_pe(path):
        print("[*] detected file type: PE/PE32")
        ok = list_pe_imports(path)
        if not ok:
            print("[*] Falling back to raw string scan")
            fallback_scan(path)
        sys.exit(0)
    if is_elf(path):
        print("[*] detected file type: ELF")
        ok = list_elf_imports(path)
        if not ok:
            print("[*] Falling back to raw string scan")
            fallback_scan(path)
        sys.exit(0)

    print("[*] Unknown file type (not PE or ELF). Doing a raw string scan for common API names.")
    fallback_scan(path)

if __name__ == '__main__':
    main()
