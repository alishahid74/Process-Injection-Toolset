#!/usr/bin/env python3
"""
extended_injection_detector_v2.py (patched with --use-advanced-angr)

This is the same extended detector but with a non-invasive option to call the
advanced angr analyzer (advanced_angr_detector.py). When enabled with
--use-advanced-angr, the script will attempt to import the advanced analyzer
and call it per-target instead of (or in addition to) the built-in analyze_binary
function. The advanced analyzer must expose a function:

    analyze_binary(path, out_rows, yara_outdir, cfg_fast=True, do_symbolic=False, explore_timeout=6)

which appends detection rows to `out_rows`.
"""
import os
import sys
import argparse
import csv
import math
import json
import traceback
from collections import defaultdict

try:
    import pefile
except Exception:
    pefile = None

import angr
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

# Try to import the advanced analyzer (non-fatal; fall back gracefully)
advanced_analyze_binary = None
try:
    # Try top-level import (if advanced_angr_detector.py is in repo root)
    import advanced_angr_detector as _a
    if hasattr(_a, "analyze_binary"):
        advanced_analyze_binary = _a.analyze_binary
except Exception:
    try:
        # Try import from scripts package (if you put advanced file under scripts/)
        from scripts.advanced_angr_detector import analyze_binary as _ab
        advanced_analyze_binary = _ab
    except Exception:
        advanced_analyze_binary = None

# ---- Config & heuristics (same as before) ----
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "RtlCreateUserThread", "NtCreateSection", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "MapViewOfFile", "OpenProcess", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread", "SuspendThread",
    "LoadLibrary", "GetProcAddress", "GetModuleHandle", "CreateProcess",
    "NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtCreateThreadEx",
    "CreateThread", "VirtualAllocEx", "ImageNtHeader",
]

SEQUENCE_PATTERNS = [
    ["CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],  # hollowing
    ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],  # classic remote injection
    ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],  # local alloc+write+thread
    ["NtCreateSection", "NtMapViewOfSection", "RtlCreateUserThread", "ResumeThread"],  # section mapping injection
    ["QueueUserAPC", "CreateRemoteThread"],  # APC + remote
    ["CreateFiber", "QueueUserAPC", "ConvertThreadToFiber"],  # fiber-ish
]

ENTROPY_WINDOW = 64
ENTROPY_THRESHOLD = 7.5
LARGE_BLOB_MIN = 64
DATA_NON_PRINTABLE_RATIO = 0.6
MAX_SNIPPET_INSN = 8
YARA_BYTES_FOR_RULE = 64

BASE_CONFIDENCE = {
    "direct_syscall": 9,
    "int_0x2e": 9,
    "syscall_number": 9,
    "peb_walk_access": 6,
    "peb_walk_sequence": 8,
    "call_to_suspicious_api": 5,
    "rwx_protect_immediate": 6,
    "high_entropy_blob": 7,
    "large_nonprint_blob": 6,
    "suspicious_import": 3,
    "text_api_match": 2,
    "pe_in_blob": 8,
    "api_sequence_match": 10,
    "entrypoint_write": 5,
    "indirect_getproc_call": 7,
    "rwx_write_to_mem": 7,
}

HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Injection Detector Report</title>
<style>
body{{font-family: Arial, Helvetica, sans-serif; margin: 14px;}}
table{{border-collapse: collapse; width: 100%; font-size: 13px;}}
th, td{{border: 1px solid #ddd; padding: 6px; text-align: left; vertical-align: top;}}
th{{background:#222; color:#fff; position: sticky; top: 0; z-index:2;}}
pre{{background:#f5f5f5; padding:8px; overflow:auto; max-height:240px;}}
.bad{{background:#ffdddd;}}
.mid{{background:#fff3cd;}}
.ok{{background:#ddffdd;}}
</style>
</head><body>
<h1>Injection Detector Report</h1>
<p>Source: {source}</p>
{body}
</body></html>
"""

# ---- helpers ----
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def is_mostly_non_printable(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b <= 126)
    ratio = printable / len(data)
    return ratio < (1.0 - DATA_NON_PRINTABLE_RATIO)

def detect_arch_with_pe(path):
    if pefile is None:
        return None
    try:
        p = pefile.PE(path, fast_load=True)
        magic = getattr(p.OPTIONAL_HEADER, "Magic", None)
        is_pe32plus = (magic == 0x20b)
        arch = "x64" if is_pe32plus else "x86"
        return arch
    except Exception:
        return None

def get_arch_with_angr(proj):
    try:
        mo = proj.loader.main_object
        arch = getattr(mo, "arch", None)
        if arch:
            n = str(arch).lower()
            if "amd64" in n or "x86_64" in n:
                return "x64"
            if "i386" in n or "x86" in n:
                return "x86"
            return n
        return None
    except Exception:
        return None

def safe_section_bytes(proj, sec):
    """Return bytes for a section using multiple fallbacks"""
    data = None
    try:
        if hasattr(sec, "content") and sec.content:
            data = sec.content
        elif hasattr(sec, "data") and sec.data:
            data = sec.data
        else:
            size = getattr(sec, "memsize", None) or getattr(sec, "size", None) or 0
            if size:
                try:
                    data = proj.loader.memory.load(sec.vaddr, size)
                except Exception:
                    raw = getattr(sec, "raw", None) or getattr(sec, "contents", None)
                    if raw:
                        data = raw
    except Exception:
        data = None
    return data or b""

def extract_bytes_from_section(proj, vaddr, length):
    try:
        return proj.loader.memory.load(vaddr, length)
    except Exception:
        try:
            mo = proj.loader.main_object
            for sec in mo.sections:
                s_v = getattr(sec, "vaddr", None)
                s_sz = getattr(sec, "memsize", None) or getattr(sec, "size", None) or 0
                if s_v is None:
                    continue
                if s_v <= vaddr < s_v + s_sz:
                    data = safe_section_bytes(proj, sec)
                    off = vaddr - s_v
                    return data[off:off+length]
        except Exception:
            pass
    return b""

def snippet_for_insn_block(block, insn_addr, max_insns=MAX_SNIPPET_INSN):
    try:
        insns = getattr(block.capstone, "insns", [])
        if not insns:
            return block.disassembly_text[:800]
        idx = 0
        for i, ins in enumerate(insns):
            if ins.address == insn_addr:
                idx = i
                break
        start = max(0, idx - (max_insns//2))
        end = min(len(insns), start + max_insns)
        lines = []
        for ins in insns[start:end]:
            lines.append(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
        return "\n".join(lines)
    except Exception:
        try:
            return block.disassembly_text[:800]
        except Exception:
            return ""

# ----- data section scanning -----
def scan_data_sections_for_blobs(proj):
    findings = []
    try:
        mo = proj.loader.main_object
        for sec in getattr(mo, "sections", []):
            name = (sec.name.decode() if isinstance(sec.name, bytes) else sec.name) if getattr(sec, "name", None) else ""
            name = name.lower() if name else ""
            if not any(x in name for x in (".data", ".rdata", ".rsrc", "data", "rdata", "rsrc")):
                continue
            data = safe_section_bytes(proj, sec)
            if not data:
                continue
            # entropy sliding window
            for i in range(0, max(1, len(data) - ENTROPY_WINDOW + 1), max(1, ENTROPY_WINDOW//2)):
                wnd = data[i:i+ENTROPY_WINDOW]
                ent = shannon_entropy(wnd)
                if ent >= ENTROPY_THRESHOLD:
                    findings.append(("high_entropy_blob", sec.vaddr + i, len(wnd),
                                     f"section={sec.name} ent={ent:.2f} offset=0x{sec.vaddr+i:x}"))
            # large nonprint runs
            run_start = None
            for idx, b in enumerate(data):
                if b == 0:
                    if run_start is not None:
                        run_len = idx - run_start
                        if run_len >= LARGE_BLOB_MIN:
                            chunk = data[run_start:idx]
                            if is_mostly_non_printable(chunk):
                                findings.append(("large_nonprint_blob", sec.vaddr + run_start, run_len,
                                                 f"section={sec.name} offset=0x{sec.vaddr+run_start:x} len={run_len}"))
                        run_start = None
                else:
                    if run_start is None:
                        run_start = idx
            if run_start is not None:
                run_len = len(data) - run_start
                if run_len >= LARGE_BLOB_MIN:
                    chunk = data[run_start:]
                    if is_mostly_non_printable(chunk):
                        findings.append(("large_nonprint_blob", sec.vaddr + run_start, run_len,
                                         f"section={sec.name} offset=0x{sec.vaddr+run_start:x} len={run_len}"))
    except Exception as e:
        print("[!] error scanning data sections:", e)
    return findings

def find_pe_headers_in_data_sections(proj, max_scan_bytes=0x200000):
    findings = []
    mo = proj.loader.main_object
    for sec in getattr(mo, "sections", []):
        try:
            data = safe_section_bytes(proj, sec)
            if not data:
                continue
            ptr = 0
            while True:
                idx = data.find(b"MZ", ptr)
                if idx == -1:
                    break
                # try reading e_lfanew at offset 0x3c if present
                if idx + 0x40 < len(data):
                    try:
                        e_lfanew_off = idx + 0x3c
                        e_lfanew = int.from_bytes(data[e_lfanew_off:e_lfanew_off+4], "little")
                        pe_off = idx + e_lfanew
                        if pe_off + 4 < len(data) and data[pe_off:pe_off+4] == b"PE\x00\x00":
                            findings.append((sec.vaddr + idx, f"PE_in_blob at offset 0x{idx:x} e_lfanew=0x{e_lfanew:x}", data[idx:idx+64].hex()))
                    except Exception:
                        pass
                ptr = idx + 2
        except Exception:
            continue
    return findings

# ----- sequence & syscall helpers -----
def find_api_sequences_in_func(func, proj, suspicious_sequence_patterns):
    entries = []
    try:
        for block in func.blocks:
            block_addr = block.addr
            block_text = getattr(block, "disassembly_text", "") or ""
            try:
                insns = block.capstone.insns
            except Exception:
                insns = []
            for ins in insns:
                opstr = (ins.op_str or "").lower()
                for api in SUSPICIOUS_APIS:
                    if api.lower() in opstr:
                        entries.append((api, block_addr, ins.address))
            for api in SUSPICIOUS_APIS:
                if api.lower() in block_text.lower():
                    entries.append((api, block_addr, block_addr))
    except Exception:
        pass

    matches = []
    apis_only = [e[0] for e in entries]
    for pattern in suspicious_sequence_patterns:
        pat = [p.lower() for p in pattern]
        i = 0
        idxs = []
        for p in pat:
            found = False
            while i < len(apis_only):
                if apis_only[i].lower().find(p) != -1:
                    idxs.append(i); found = True; i += 1; break
                i += 1
            if not found:
                idxs = []
                break
        if idxs:
            matched = []
            for ix in idxs:
                matched.append(entries[ix])
            matches.append((tuple(pattern), matched))
    return matches

def inspect_syscall_insn(insns, arch, syscall_map):
    """Return (found_flag, syscall_num_or_None, mapped_name_or_None, snippet_text)"""
    for i, ins in enumerate(insns):
        mnem = ins.mnemonic.lower()
        opstr = (ins.op_str or "")
        if mnem in ("syscall", "sysenter"):
            imm_val = None
            mapped = None
            # look back for mov rax/eax, imm
            if i > 0:
                prev = insns[i-1]
                if prev.mnemonic.lower().startswith("mov"):
                    ops = (prev.op_str or "").lower().split(",")
                    if len(ops) >= 2 and ("rax" in ops[0] or "eax" in ops[0]):
                        try:
                            imm_val = int(ops[1].strip(), 0)
                            mapped = syscall_map.get(imm_val)
                        except Exception:
                            imm_val = None
            snippet = "\n".join([f"0x{ins2.address:x}: {ins2.mnemonic} {ins2.op_str}" for ins2 in insns[max(0, i-4):i+3]])
            return True, imm_val, mapped, snippet
        if mnem == "int":
            if "0x2e" in opstr.lower() or "2e" in opstr.lower():
                imm_val = None
                mapped = None
                if i > 0:
                    prev = insns[i-1]
                    if prev.mnemonic.lower().startswith("mov") and "eax" in (prev.op_str or "").lower():
                        try:
                            imm_val = int(prev.op_str.split(",")[-1].strip(), 0)
                            mapped = syscall_map.get(imm_val)
                        except Exception:
                            imm_val = None
                snippet = "\n".join([f"0x{ins2.address:x}: {ins2.mnemonic} {ins2.op_str}" for ins2 in insns[max(0, i-4):i+3]])
                return True, imm_val, mapped, snippet
    return False, None, None, ""

def detect_peb_walk_sequences(func):
    depth = 0
    details = []
    try:
        for block in func.blocks:
            text = (getattr(block, "disassembly_text", "") or "").lower()
            if ("fs:" in text or "gs:" in text) and ("0x30" in text or "0x60" in text or "0x18" in text):
                depth += 1
                details.append(f"PEB access in block 0x{block.addr:x}")
            if any(x in text for x in ("inmemoryordermodulelist", "ldr", "inmemory")):
                depth += 1
                details.append(f"Ldr list mention in block 0x{block.addr:x}")
    except Exception:
        pass
    return (depth >= 2), "; ".join(details)

def detect_entrypoint_write(func, proj):
    mo = proj.loader.main_object
    image_base = getattr(mo, "mapped_base", None) or getattr(mo, "link_base", None) or getattr(mo, "min_addr", None)
    if not image_base:
        return False, ""
    try:
        for block in func.blocks:
            txt = (getattr(block, "disassembly_text", "") or "").lower()
            if "mov" in txt and ("[0x" in txt or "imagebase" in txt or "entrypoint" in txt):
                return True, f"possible_imagebase_write in block 0x{block.addr:x}"
    except Exception:
        pass
    return False, ""

# ---- analysis per-binary ----
def analyze_binary(path, out_rows, yara_outdir, syscall_map):
    """Legacy/an existing analyze_binary implementation kept for v2's internal heuristics"""
    print(f"[*] analyzing {path}")
    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as e:
        print(f"[!] angr failed to load {path}: {e}")
        return

    arch = detect_arch_with_pe(path) or get_arch_with_angr(proj) or "unknown"

    # imports
    try:
        mo = proj.loader.main_object
        imports = getattr(mo, "imports", {}) or {}
        for name, info in imports.items():
            try:
                nm = name.decode() if isinstance(name, bytes) else str(name)
            except Exception:
                nm = str(name)
            for api in SUSPICIOUS_APIS:
                if api.lower() in nm.lower():
                    conf = BASE_CONFIDENCE.get("suspicious_import", 3)
                    out_rows.append([path, arch, "suspicious_import", "", "", nm, "", conf])
    except Exception as e:
        print("[!] import scan error:", e)

    # data section blob heuristics
    data_findings = scan_data_sections_for_blobs(proj)
    for ftype, vaddr, length, detail in data_findings:
        bs = extract_bytes_from_section(proj, vaddr, min(YARA_BYTES_FOR_RULE, length))
        hexpat = bs.hex() if bs else ""
        conf = BASE_CONFIDENCE.get(ftype, 6)
        out_rows.append([path, arch, ftype, "", f"0x{vaddr:x}", detail, hexpat, conf])

    # PE-in-blob detection
    pe_blobs = find_pe_headers_in_data_sections(proj)
    for vaddr, detail, hex_snip in pe_blobs:
        conf = BASE_CONFIDENCE.get("pe_in_blob", 8)
        out_rows.append([path, arch, "pe_in_blob", "", f"0x{vaddr:x}", detail, hex_snip, conf])
        # generate yara rule
        if hex_snip:
            os.makedirs(yara_outdir, exist_ok=True)
            rule_name = f"yar_{os.path.basename(path)}_pe_{vaddr:x}".replace(".", "_")
            yara_path = os.path.join(yara_outdir, f"{rule_name}.yar")
            try:
                bs = bytes.fromhex(hex_snip)
                hex_pairs = " ".join([hex(bs[i])[2:].zfill(2) for i in range(len(bs))])
                with open(yara_path, "w") as fh:
                    fh.write("rule " + rule_name + " {\n")
                    fh.write("  meta:\n")
                    fh.write(f'    source_file = "{path}"\n')
                    fh.write(f'    comment = "{detail}"\n')
                    fh.write("  strings:\n")
                    fh.write(f'    $a1 = {{ {hex_pairs} }}\n')
                    fh.write("  condition:\n")
                    fh.write("    $a1\n")
                    fh.write("}\n")
            except Exception:
                pass

    # build CFG
    try:
        print("[*] building CFGFast (may take a bit)...")
        cfg = proj.analyses.CFGFast()
    except Exception as e:
        print("[!] CFGFast failed:", e)
        cfg = None

    if cfg is None:
        return

    # iterate functions
    for func in cfg.kb.functions.values():
        func_addr = func.addr
        # sequence matches
        seq_matches = find_api_sequences_in_func(func, proj, SEQUENCE_PATTERNS)
        for pat, matched in seq_matches:
            detail = "->".join([m[0] for m in matched])
            snippet = "\n".join([f"{m[0]} @0x{m[2]:x}" for m in matched])
            conf = BASE_CONFIDENCE.get("api_sequence_match", 10)
            out_rows.append([path, arch, "api_sequence_match", f"0x{func_addr:x}", f"0x{matched[0][1]:x}", f"pattern={'|'.join(pat)} detail={detail}", snippet, conf])

        # peb walk sequence detector
        peb_seq, peb_detail = detect_peb_walk_sequences(func)
        if peb_seq:
            conf = BASE_CONFIDENCE.get("peb_walk_sequence", 8)
            out_rows.append([path, arch, "peb_walk_sequence", f"0x{func_addr:x}", "", peb_detail, "", conf])

        # entrypoint write heuristic
        entry_w, entry_detail = detect_entrypoint_write(func, proj)
        if entry_w:
            conf = BASE_CONFIDENCE.get("entrypoint_write", 5)
            out_rows.append([path, arch, "entrypoint_write", f"0x{func_addr:x}", "", entry_detail, "", conf])

        # iterate blocks for instruction-level heuristics
        try:
            for block in func.blocks:
                block_addr = block.addr
                try:
                    cap = block.capstone
                    insns = cap.insns
                except Exception:
                    insns = []
                block_text = getattr(block, "disassembly_text", "") or ""

                # syscall / int detection
                found_syscall, val, mapped, snippet = inspect_syscall_insn(insns, arch, {})
                if found_syscall:
                    conf = BASE_CONFIDENCE.get("syscall_number", 9) if val is not None else BASE_CONFIDENCE.get("direct_syscall", 9)
                    detail = f"syscall_num={val} mapped={mapped}"
                    out_rows.append([path, arch, "syscall_number" if val is not None else "direct_syscall",
                                     f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])

                # instruction scanning for calls and other signs
                try:
                    for ins in insns:
                        mnem = ins.mnemonic.lower()
                        opstr = (ins.op_str or "").lower()

                        # calls referencing suspicious APIs
                        if mnem.startswith("call"):
                            for api in SUSPICIOUS_APIS:
                                if api.lower() in opstr:
                                    snippet = snippet_for_insn_block(block, ins.address)
                                    detail = f"call {api} operand={ins.op_str}"
                                    conf = BASE_CONFIDENCE.get("call_to_suspicious_api", 5)
                                    out_rows.append([path, arch, "call_to_suspicious_api", f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])

                        # int 0x2e explicit detection
                        if mnem == "int":
                            if "0x2e" in opstr or "2e" in opstr:
                                snippet = snippet_for_insn_block(block, ins.address)
                                detail = f"int 0x2e {ins.op_str}"
                                conf = BASE_CONFIDENCE.get("int_0x2e", 9)
                                out_rows.append([path, arch, "int_0x2e", f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])

                        # detect fs/gs peb-like operand in individual insns
                        if "fs:" in opstr or "gs:" in opstr or "fs[" in opstr or "gs[" in opstr:
                            if "0x30" in opstr or "0x60" in opstr or "0x18" in opstr:
                                snippet = snippet_for_insn_block(block, ins.address)
                                detail = f"PEB/TEB access candidate: {ins.mnemonic} {ins.op_str}"
                                conf = BASE_CONFIDENCE.get("peb_walk_access", 6)
                                out_rows.append([path, arch, "peb_walk_access", f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])

                        # immediate 0x40 near alloc/protect
                        if "0x40" in opstr or "0x00000040" in opstr:
                            lower_block_text = block_text.lower()
                            if any(a.lower() in lower_block_text for a in ("virtualalloc", "virtualprotect", "ntcreate", "mapview", "writeprocessmemory")):
                                snippet = snippet_for_insn_block(block, ins.address)
                                detail = f"PAGE_EXECUTE_READWRITE constant near alloc/protect (op:{ins.mnemonic} {ins.op_str})"
                                conf = BASE_CONFIDENCE.get("rwx_protect_immediate", 6)
                                out_rows.append([path, arch, "rwx_protect_immediate", f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])

                        # detect indirect GetProcAddress("Nt*") style (pointer resolution)
                        if mnem.startswith("call") or mnem.startswith("mov"):
                            txt = block_text.lower()
                            if "getproc" in txt and "nt" in txt:
                                snippet = block_text[:400]
                                detail = "possible indirect syscalls resolution via GetProcAddress('Nt*')"
                                conf = BASE_CONFIDENCE.get("indirect_getproc_call", 7)
                                out_rows.append([path, arch, "indirect_getproc_call", f"0x{func_addr:x}", f"0x{block_addr:x}", detail, snippet, conf])
                except Exception:
                    # fallback textual search
                    txt = block_text.lower()
                    for api in SUSPICIOUS_APIS:
                        if api.lower() in txt:
                            conf = BASE_CONFIDENCE.get("text_api_match", 2)
                            out_rows.append([path, arch, "text_api_match", f"0x{func_addr:x}", f"0x{block_addr:x}", f"api_text_match={api}", txt[:400], conf])
        except Exception:
            traceback.print_exc()
            continue

    print(f"[*] done analyzing {path}")

# ---- I/O & reporting ----
def collect_targets(path):
    files = []
    path = os.path.expanduser(path)
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for fn in filenames:
                full = os.path.join(root, fn)
                try:
                    # skip extremely large files
                    try:
                        if os.path.getsize(full) > 200 * 1024 * 1024:
                            continue
                    except Exception:
                        pass
                    # include based on extension
                    if fn.lower().endswith((".exe", ".dll", ".pe", ".bin", ".so")):
                        files.append(full)
                        continue
                    # read first bytes to detect magic/shebang
                    try:
                        with open(full, "rb") as fh:
                            head = fh.read(4)
                            if head.startswith(b"MZ") or head.startswith(b"\x7fELF") or head.startswith(b"#!"):
                                files.append(full)
                                continue
                    except Exception:
                        pass
                    # include if exec bit is set
                    if os.access(full, os.X_OK):
                        files.append(full)
                except Exception:
                    continue
    else:
        files.append(os.path.expanduser(path))
    return files

def filter_targets_by_arch(targets, arch_filter):
    if not arch_filter or arch_filter.lower() == "all":
        return targets
    filtered = []
    for t in targets:
        tstr = t
        a = None
        try:
            a = detect_arch_with_pe(tstr)
        except Exception:
            a = None
        if a is None:
            try:
                proj = angr.Project(tstr, auto_load_libs=False)
                a = get_arch_with_angr(proj)
            except Exception:
                a = None
        if a and arch_filter.lower() in a:
            filtered.append(tstr)
    return filtered

def write_csv(out_csv, rows):
    hdr = ["file","arch","detection_type","func_addr","block_addr","detail","dasm_snippet_or_hex","confidence"]
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(hdr)
        for r in rows:
            writer.writerow(r)

def write_html_report(source, csv_rows, out_html):
    by_file = defaultdict(list)
    for row in csv_rows:
        by_file[row[0]].append(row)
    body_parts = []
    for f, items in by_file.items():
        body_parts.append(f"<h2>{f}</h2>")
        body_parts.append("<table>")
        body_parts.append("<tr><th>Arch</th><th>Detection</th><th>Func</th><th>Block</th><th>Detail</th><th>Confidence</th><th>Snippet</th></tr>")
        for it in items:
            arch, det, func, block, detail, snippet, conf = it[1], it[2], it[3], it[4], (it[5] or ""), (it[6] or ""), it[7] if len(it) > 7 else it[-1]
            try:
                conf_val = int(conf)
            except Exception:
                conf_val = 0
            cls = "ok" if conf_val < 6 else "mid" if conf_val < 9 else "bad"
            snippet_html = f"<pre>{snippet}</pre>" if snippet else ""
            body_parts.append(f"<tr class='{cls}'><td>{arch}</td><td>{det}</td><td>{func}</td><td>{block}</td><td>{detail}</td><td>{conf_val}</td><td>{snippet_html}</td></tr>")
        body_parts.append("</table>")
    body = "\n".join(body_parts)
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(HTML_TEMPLATE.format(source=source, body=body))

def main():
    parser = argparse.ArgumentParser(description="Extended injection detector v2 (patched full)")
    parser.add_argument("target", help="file or directory to scan")
    parser.add_argument("--out", default="findings_v2.csv", help="output CSV file")
    parser.add_argument("--html", default="report_v2.html", help="output HTML report")
    parser.add_argument("--yaradir", default="yara_rules", help="where to save generated yara rules")
    parser.add_argument("--syscallmap", default=None, help="optional JSON file mapping syscall numbers to names")
    parser.add_argument("--arch-filter", default="all", choices=["all","x86","x64"], help="optional architecture filter for scanning")
    # NEW: flags to enable the advanced angr analyzer (non-invasive)
    parser.add_argument("--use-advanced-angr", action="store_true", help="use advanced angr analyzer (advanced_angr_detector.py) if available")
    parser.add_argument("--angr-cfg", choices=["fast","full"], default="fast", help="CFG mode to pass to advanced angr analyzer")
    parser.add_argument("--angr-advanced-symbolic", action="store_true", help="enable symbolic in advanced angr analyzer (slow)")
    parser.add_argument("--angr-explore-timeout", type=int, default=6, help="timeout in seconds for advanced angr explore calls")
    args = parser.parse_args()

    syscall_map = {}
    if args.syscallmap:
        try:
            with open(args.syscallmap, "r", encoding="utf-8") as fh:
                j = json.load(fh)
                for k, v in j.items():
                    try:
                        syscall_map[int(k, 0)] = v
                    except Exception:
                        try:
                            syscall_map[int(k)] = v
                        except Exception:
                            pass
            print(f"[*] loaded syscall map entries: {len(syscall_map)}")
        except Exception as e:
            print("[!] failed to load syscall map:", e)

    targets = collect_targets(args.target)
    if not targets:
        print("[!] no target files found. Provide a .exe/.dll or a directory containing them.")
        return

    # apply arch filter if requested
    targets = filter_targets_by_arch(targets, args.arch_filter)
    if not targets:
        print(f"[!] no files matched arch filter '{args.arch_filter}'.")
        return

    rows = []
    for t in targets:
        try:
            if args.use_advanced_angr and advanced_analyze_binary:
                # call the advanced analyzer; it will append rows to the provided rows list
                try:
                    print(f"[*] Using advanced angr analyzer for {t}")
                    advanced_analyze_binary(t, rows, args.yaradir, cfg_fast=(args.angr_cfg=='fast'),
                                            do_symbolic=args.angr_advanced_symbolic, explore_timeout=args.angr_explore_timeout)
                except TypeError:
                    # if signature differs, call with a reduced set of params
                    advanced_analyze_binary(t, rows, args.yaradir)
            else:
                analyze_binary(t, rows, args.yaradir, syscall_map)
        except Exception as e:
            print(f"[!] error analyzing {t}: {e}")
            traceback.print_exc()

    write_csv(args.out, rows)
    write_html_report(args.target, rows, args.html)
    print(f"[*] CSV written to {args.out} ({len(rows)} rows)")
    print(f"[*] HTML report written to {args.html}")
    print(f"[*] YARA rules (if any) saved to {args.yaradir}")

if __name__ == "__main__":
    main()
