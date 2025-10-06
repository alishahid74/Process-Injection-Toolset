#!/usr/bin/env python3
"""
angr_x86_detector.py

Simple 32-bit (x86) angr-based static detector focused on process-injection / evasion heuristics.

Usage:
  python3 scripts/angr_x86_detector.py <file-or-dir> --out findings_x86.csv --html findings_x86.html --yara yara_x86

Notes:
 - Designed for x86 (32-bit). Non-x86 targets are skipped.
 - Requires: pip install angr pefile (optional) capstone (angr supplies capstone)
 - Heuristics based on your project's advanced detector and v2 detector.
"""
import os, sys, argparse, csv, math, traceback
from collections import defaultdict

try:
    import angr
except Exception as e:
    print("[!] angr import failed:", e)
    sys.exit(2)

try:
    import pefile
except Exception:
    pefile = None

# --- heuristics (kept deliberately small & focused for 32-bit) ---
SUSPICIOUS_APIS = [
    # Windows (existing)
    "VirtualAlloc", "VirtualProtect", "VirtualAllocEx", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "OpenProcess", "GetProcAddress",
    "LoadLibrary", "NtCreateSection", "NtMapViewOfSection", "SetThreadContext",
    "GetThreadContext", "ResumeThread", "QueueUserAPC",

    # Linux / cross-platform strings to look for in ELF .rodata/.data
    # (mmap/mprotect/dlopen/dlsym/ptrace/process_vm_writev often used by loaders/injectors)
    "mmap", "mprotect", "munmap", "mremap", "ptrace", "process_vm_writev",
    "dlopen", "dlsym", "dlmopen", "memcpy", "madvise",

    # Generic suspicious substrings or helpers that might appear in embedded payloads
    "/proc/", "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocA",
    "VirtualProtectEx", "LoadLibraryA"
]


ENTROPY_WINDOW = 64
ENTROPY_THRESHOLD = 7.2
YARA_SNIP_LEN = 64

def shannon(b: bytes) -> float:
    if not b:
        return 0.0
    counts = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    ent = 0.0
    ln = len(b)
    for v in counts.values():
        p = v / ln
        ent -= p * math.log2(p)
    return ent

def collect_targets(path):
    path = os.path.expanduser(path)
    files = []
    if os.path.isdir(path):
        for root, _, fnames in os.walk(path):
            for fn in fnames:
                full = os.path.join(root, fn)
                try:
                    sz = os.path.getsize(full)
                except Exception:
                    sz = 0
                if sz > 200 * 1024 * 1024:
                    continue
                files.append(full)
    else:
        files = [path]
    return sorted(set(files))

def is_pe32(path):
    if not os.path.exists(path):
        return False
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(2)
            return hdr == b"MZ"
    except Exception:
        return False

def arch_with_pe(path):
    if pefile is None:
        return None
    try:
        p = pefile.PE(path, fast_load=True)
        magic = getattr(p.OPTIONAL_HEADER, "Magic", None)
        return 'x64' if magic == 0x20b else 'x86'
    except Exception:
        return None

def arch_with_angr(proj):
    try:
        mo = proj.loader.main_object
        arch = getattr(mo, "arch", None)
        if arch:
            an = str(arch).lower()
            if "i386" in an or "x86" in an:
                return "x86"
            if "amd64" in an or "x86_64" in an:
                return "x64"
        return None
    except Exception:
        return None

def scan_data_sections_for_blobs(proj):
    findings = []
    try:
        mo = proj.loader.main_object
        for sec in getattr(mo, "sections", []):
            name = (sec.name.decode() if isinstance(sec.name, bytes) else sec.name) if getattr(sec, "name", None) else ""
            lname = (name or "").lower()
            if not any(x in lname for x in (".data", ".rdata", ".rsrc", "data", "rdata", "rsrc")):
                continue
            try:
                data = getattr(sec, "content", None) or getattr(sec, "data", None) or proj.loader.memory.load(sec.vaddr, getattr(sec, "memsize", sec.size or 0))
            except Exception:
                data = b""
            if not data:
                continue
            for i in range(0, max(1, len(data)-ENTROPY_WINDOW+1), max(1, ENTROPY_WINDOW//2)):
                wnd = data[i:i+ENTROPY_WINDOW]
                e = shannon(wnd)
                if e >= ENTROPY_THRESHOLD:
                    findings.append(("high_entropy_blob", sec.vaddr + i, len(wnd), f"sec={name} ent={e:.2f} off=0x{sec.vaddr+i:x}"))
            # simple embedded PE check (MZ -> PE)
            idx = data.find(b"MZ")
            if idx != -1 and idx + 0x40 < len(data):
                try:
                    e_lfanew = int.from_bytes(data[idx+0x3c:idx+0x40], "little")
                    pe_off = idx + e_lfanew
                    if pe_off + 4 < len(data) and data[pe_off:pe_off+4] == b"PE\x00\x00":
                        findings.append(("pe_in_blob", sec.vaddr + idx, 0, f"sec={name} mzoff=0x{idx:x} elfanew=0x{e_lfanew:x}"))
                except Exception:
                    pass
    except Exception as e:
        print("[!] data-scan error:", e)
    return findings

def scan_sections_for_suspicious_strings(proj, path, rows, yara_dir, arch):
    """
    Scan loaded sections (.rodata, .data, .rdata, .rsrc) for suspicious API names or keywords.
    Adds rows directly to the results list.
    """
    try:
        mo = proj.loader.main_object
        if not mo:
            return
        for sec in getattr(mo, "sections", []):
            name = (sec.name.decode() if isinstance(sec.name, bytes) else sec.name) if getattr(sec, "name", None) else ""
            lname = (name or "").lower()
            if not any(x in lname for x in (".rodata", ".data", ".rdata", ".rsrc", "data", "rodata")):
                continue
            # attempt to read section bytes
            try:
                data = getattr(sec, "content", None) or getattr(sec, "data", None) or proj.loader.memory.load(sec.vaddr, getattr(sec, "memsize", sec.size or 0))
            except Exception:
                data = b""
            if not data:
                continue
            try:
                s = data.decode("latin-1", errors="ignore").lower()
            except Exception:
                s = ""
            for api in SUSPICIOUS_APIS:
                api_l = api.lower()
                if api_l in s:
                    # find first offset occurrence
                    off = s.find(api_l)
                    vaddr = sec.vaddr + off if getattr(sec, "vaddr", None) else None
                    detail = f"section={name} found={api} off=0x{vaddr:x}" if vaddr else f"section={name} found={api}"
                    rows.append([path, arch, "suspicious_string", "", hex(vaddr) if vaddr else "", detail, api_l[:64], 4])
    except Exception as e:
        # non-fatal
        print("[!] string-scan error:", e)

def inspect_block_for_heuristics(block):
    out = []
    try:
        text = getattr(block, "disassembly_text", "") or ""
        # PEB like access heuristics (fs: + offsets)
        if ("fs:" in text.lower() or "gs:" in text.lower()) and any(k in text for k in ("0x30","0x60","0x18")):
            out.append(("peb_access", block.addr, "PEB-like access"))
        # capstone insn scan
        insns = []
        try:
            insns = block.capstone.insns
        except Exception:
            insns = []
        for i, ins in enumerate(insns):
            m = (ins.mnemonic or "").lower()
            op = (ins.op_str or "")
            op_lower = op.lower()

            # syscall / sysenter detection (direct syscall instruction)
            if m in ("syscall", "sysenter"):
                # try to read previous mov eax, imm (common pattern)
                val = None
                if i > 0:
                    prev = insns[i-1]
                    if getattr(prev, "mnemonic", "").lower().startswith("mov") and "eax" in (prev.op_str or "").lower():
                        try:
                            val = int(prev.op_str.split(",")[-1].strip(), 0)
                        except Exception:
                            val = None
                out.append(("direct_syscall", ins.address, f"{m} at 0x{ins.address:x} imm={val}"))

            # int instructions: capture both 0x2e (win32) and 0x80 (linux i386) patterns
            if m == "int":
                # look for common encodings/representations
                is_2e = ("0x2e" in op_lower) or (op_lower.strip().endswith(" 2e")) or (op_lower.strip() == "2e")
                is_80 = ("0x80" in op_lower) or (op_lower.strip().endswith(" 80")) or (op_lower.strip() == "80")
                # fallback: if op contains '2e' or '80' anywhere (broad but useful)
                if not (is_2e or is_80):
                    if "2e" in op_lower:
                        is_2e = True
                    if "80" in op_lower:
                        is_80 = True

                if is_2e or is_80:
                    val = None
                    # attempt to capture imm from previous mov eax, imm
                    if i > 0:
                        prev = insns[i-1]
                        if getattr(prev, "mnemonic", "").lower().startswith("mov") and "eax" in (prev.op_str or "").lower():
                            try:
                                val = int(prev.op_str.split(",")[-1].strip(), 0)
                            except Exception:
                                val = None
                    tag = "int_0x2e" if is_2e else "int_0x80"
                    out.append((tag, ins.address, f"{op.strip()} at 0x{ins.address:x} val={val}"))

            # calls referencing suspicious APIs (operands often include strings or imports)
            if m.startswith("call"):
                opstr = ins.op_str or ""
                for api in SUSPICIOUS_APIS:
                    if api.lower() in opstr.lower():
                        out.append(("call_suspicious", block.addr, f"call {api} operand={opstr}"))
    except Exception:
        pass
    return out


def analyze_file(path, rows, yara_dir):
    """
    Load a target with angr (try normal loader, fallback to 'blob' backend).
    If blob backend is used we run only data/entropy/string heuristics (no CFG).
    """
    print("[*] loading", path)
    is_blob = False

    # try normal loader, fallback to blob backend if angr complains
    try:
        proj = angr.Project(path, auto_load_libs=False)
        loader_backend = 'auto'
    except Exception as e:
        print("[!] angr failed loading (normal):", e)
        # quick heuristic: skip obvious non-binary files early
        lower = path.lower()
        if lower.endswith(".c") or lower.endswith(".txt") or lower.endswith(".md") or lower.endswith(".py"):
            print(f"[*] skipping non-binary-like file: {path}")
            return

        # attempt blob fallback
        try:
            print("[*] trying blob loader fallback (treating file as raw bytes)")
            # sensible default base address for analysis; change if needed
            blob_base = 0x10000000
            # specify arch and use base_addr (avoid deprecation/custom_base_addr)
            proj = angr.Project(path, auto_load_libs=False, main_opts={'backend': 'blob', 'arch': 'x86', 'base_addr': blob_base})
            loader_backend = 'blob'
            is_blob = True
            print(f"[*] blob loader succeeded (base=0x{blob_base:x})")
        except Exception as e2:
            print("[!] blob loader also failed:", e2)
            return

    # determine architecture (PE/angr detection)
    try:
        arch = arch_with_pe(path) or arch_with_angr(proj) or "unknown"
    except Exception:
        arch = "unknown"
    print(f"[*] detected arch (pe/angr): {arch}")

    # If we used blob loader, we won't have reliable arch/sections/funcs — still continue but avoid CFG.
    if not is_blob and arch != "x86":
        print(f"[*] skipping (not x86): {path} (detected arch={arch})")
        return

    # --- Data-section + entropy + embedded-PE scanning (works for normal and blob) ---
    try:
        blobs = scan_data_sections_for_blobs(proj)
        for typ, vaddr, ln, det in blobs:
            snippet = b""
            try:
                snippet = proj.loader.memory.load(vaddr, min(YARA_SNIP_LEN, max(16, ln)))
            except Exception:
                snippet = b""
            hexs = snippet.hex() if snippet else ""
            conf = 7 if typ == "high_entropy_blob" else 8
            rows.append([path, arch, typ, "", hex(vaddr) if vaddr else "", det, hexs, conf])
            # write a tiny yara rule for the snippet
            if hexs and yara_dir:
                os.makedirs(yara_dir, exist_ok=True)
                rname = f"yar_{os.path.basename(path)}_{typ}_{vaddr:x}".replace(".", "_")
                try:
                    with open(os.path.join(yara_dir, rname + ".yar"), "w", encoding="utf-8") as fh:
                        pairs = " ".join(hex(int(hexs[i:i+2],16))[2:].zfill(2) for i in range(0, len(hexs), 2))
                        fh.write(f"rule {rname} {{\n  strings:\n    $a = {{ {pairs} }}\n  condition:\n    $a\n}}\n")
                except Exception:
                    pass
    except Exception as e:
        print("[!] data-scan error:", e)

    # scan for suspicious strings in sections (captures ELF .rodata/.data indicators)
    try:
        scan_sections_for_suspicious_strings(proj, path, rows, yara_dir, arch)
    except Exception:
        pass

    # If we loaded as a blob, don't attempt CFG/function analysis (not meaningful)
    if is_blob:
        print("[*] loaded as raw blob — skipping CFG/function analysis")
        return

    # --- build CFG and inspect functions (only for real binaries) ---
    try:
        cfg = proj.analyses.CFGFast()
    except Exception as e:
        print("[!] CFG build failed:", e)
        return

    mo = proj.loader.main_object

    # imports -> suspicious API scan
    try:
        imports = getattr(mo, "imports", {}) or {}
        for name, info in imports.items():
            nm = name.decode() if isinstance(name, bytes) else str(name)
            for api in SUSPICIOUS_APIS:
                if api.lower() in nm.lower():
                    rows.append([path, arch, "suspicious_import", "", "", nm, "", 3])
    except Exception:
        pass

    for func in cfg.kb.functions.values():
        faddr = func.addr
        # sequence or multi-api detection (simple): collect API mentions in all blocks
        api_mentions = []
        for block in func.blocks:
            text = (getattr(block, "disassembly_text", "") or "").lower()
            for api in SUSPICIOUS_APIS:
                if api.lower() in text:
                    api_mentions.append((api, block.addr))
            # per-block heuristics
            ins_hits = inspect_block_for_heuristics(block)
            for t, addr, detail in ins_hits:
                rows.append([path, arch, t, hex(faddr), hex(addr) if addr else "", detail, "", 6 if t == "peb_access" else 9])
        if api_mentions:
            # if more than 1 suspicious API in func, flag as potential sequence/higher confidence
            conf = 10 if len(api_mentions) >= 2 else 5
            detail = ";".join([f"{a}@0x{b:x}" for a,b in api_mentions[:6]])
            rows.append([path, arch, "api_matches", hex(faddr), "", detail, "", conf])

    print("[*] done", path)


def write_csv(out, rows):
    hdr = ["file","arch","detection","func_addr","block_addr","detail","snippet_or_hex","confidence"]
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(hdr)
        for r in rows:
            w.writerow(r)

def write_html(src, rows, out_html):
    byf = defaultdict(list)
    for r in rows:
        byf[r[0]].append(r)
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write("<html><head><meta charset='utf-8'><title>Angr x86 Detector</title></head><body>")
        fh.write(f"<h1>Detector results for {src}</h1>")
        for f, items in byf.items():
            fh.write(f"<h2>{f}</h2><table border='1' cellpadding='6'><tr><th>Arch</th><th>Detection</th><th>Func</th><th>Block</th><th>Detail</th><th>Conf</th></tr>")
            for it in items:
                fh.write("<tr>")
                fh.write(f"<td>{it[1]}</td><td>{it[2]}</td><td>{it[3]}</td><td>{it[4]}</td><td>{(it[5] or '')}</td><td>{it[7]}</td>")
                fh.write("</tr>")
            fh.write("</table>")
        fh.write("</body></html>")

def main():
    p = argparse.ArgumentParser(description="Small angr-based x86 (32-bit) detector")
    p.add_argument("target", help="file or directory")
    p.add_argument("--out", default="findings_x86.csv")
    p.add_argument("--html", default="findings_x86.html")
    p.add_argument("--yara", default="yara_x86")
    args = p.parse_args()

    targets = collect_targets(args.target)
    if not targets:
        print("[!] no targets found")
        return

    rows = []
    for t in targets:
        try:
            analyze_file(t, rows, args.yara)
        except Exception:
            traceback.print_exc()
            continue

    write_csv(args.out, rows)
    write_html(args.target, rows, args.html)
    print("[*] CSV written to", args.out, "rows:", len(rows))
    print("[*] HTML written to", args.html)
    print("[*] YARA dir:", args.yara)

if __name__ == "__main__":
    main()
