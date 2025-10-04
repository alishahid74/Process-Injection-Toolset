#!/usr/bin/env python3
"""
extended_injection_detector.py

Extended heuristics for detecting Windows process-injection & evasive behaviors
using angr static analysis + disassembly heuristics.

Detections implemented:
 - suspicious imported APIs (same as previous scripts)
 - call sites referencing suspicious APIs (CFG)
 - direct syscall usage (syscall / int 0x2e / sysenter)
 - PEB-walk / manual import resolution indicators (fs:0x30 or gs:0x60 memory reads)
 - PAGE_EXECUTE_READWRITE / RWX heuristics (immediate 0x40 found near alloc/protect calls)
 - high-entropy data regions (may indicate shellcode / encrypted payload)
 - large inline byte arrays in data sections (non-printable heavy sequences)

Outputs:
 - CSV (default: findings.csv) with columns:
    file, detection_type, func_addr, block_addr, insn_addr, detail

Usage:
    python3 extended_injection_detector.py <file_or_dir> [--out findings.csv]

Notes:
 - Run in an isolated analysis VM.
 - Angr does static/symbolic analysis: confirm suspicious hits in a sandbox.
"""
import sys
import os
import argparse
import csv
import math
import traceback
from collections import defaultdict

import angr
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

# Heuristics / lists
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "RtlCreateUserThread", "NtCreateSection", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "MapViewOfFile", "OpenProcess", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread",
    "LoadLibrary", "GetProcAddress", "GetModuleHandle", "GetModuleHandleA",
    "GetModuleHandleW",
]

# thresholds
ENTROPY_WINDOW = 64
ENTROPY_THRESHOLD = 7.5  # 8 is maximum for bytes; high entropy suggests shellcode/encryption
LARGE_BLOB_MIN = 64      # minimum length to consider a blob suspicious
DATA_NON_PRINTABLE_RATIO = 0.6

# helpers
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

def scan_data_sections_for_blobs(proj):
    """Scan loaded object's data sections for high-entropy blobs or large non-printable blobs."""
    findings = []
    try:
        mo = proj.loader.main_object
        for sec in getattr(mo, "sections", []):
            # only look at initialized data sections commonly: .data, .rdata, .rsrc, etc.
            name = sec.name.lower()
            if not name:
                continue
            if not any(x in name for x in (".data", ".rdata", ".rsrc", "data", "rdata", "rsrc")):
                continue
            data = sec.content
            if not data:
                continue
            # sliding window entropy
            for i in range(0, max(1, len(data) - ENTROPY_WINDOW + 1), ENTROPY_WINDOW//2 or 1):
                wnd = data[i:i+ENTROPY_WINDOW]
                ent = shannon_entropy(wnd)
                if ent >= ENTROPY_THRESHOLD:
                    findings.append(("high_entropy_blob", sec.vaddr + i, len(wnd),
                                     f"section={sec.name} ent={ent:.2f} offset=0x{sec.vaddr+i:x}"))
            # large non-printable runs
            run_start = None
            for idx, b in enumerate(data):
                if b == 0:
                    # treat 0 as separator (often padding)
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
            # tail run
            if run_start is not None:
                run_len = len(data) - run_start
                if run_len >= LARGE_BLOB_MIN:
                    chunk = data[run_start:]
                    if is_mostly_non_printable(chunk):
                        findings.append(("large_nonprint_blob", sec.vaddr + run_start, run_len,
                                         f"section={sec.name} offset=0x{sec.vaddr+run_start:x} len={run_len}"))
    except Exception as e:
        # defensive: something went wrong reading sections
        print("[!] error scanning data sections:", e)
    return findings

def analyze_binary(path, out_rows):
    print(f"[*] analyzing {path}")
    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as e:
        print(f"[!] angr failed to load {path}: {e}")
        return

    # 1) imports
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
                    out_rows.append([path, "suspicious_import", "", "", "", nm])
    except Exception as e:
        print("[!] import scan error:", e)

    # 2) data section heuristics (entropy, blobs)
    data_findings = scan_data_sections_for_blobs(proj)
    for ftype, vaddr, length, detail in data_findings:
        out_rows.append([path, ftype, "", f"section_vaddr=0x{vaddr:x}", "", detail])

    # 3) CFG-based block analysis
    try:
        print("[*] building CFGFast (may take a bit)...")
        cfg = proj.analyses.CFGFast()
    except Exception as e:
        print("[!] CFGFast failed:", e)
        cfg = None

    if cfg is None:
        return

    for func in cfg.kb.functions.values():
        func_addr = func.addr
        found_in_func = []
        try:
            for block in func.blocks:
                block_addr = block.addr
                # disassembly text fallback
                try:
                    cap = block.capstone
                    insns = cap.insns
                except Exception:
                    insns = []
                # analyze each insn
                block_text = ""
                try:
                    block_text = getattr(block, "disassembly_text", "") or ""
                except Exception:
                    block_text = ""
                # 3a) calls referencing suspicious APIs
                try:
                    for insn in insns:
                        mnem = insn.mnemonic.lower()
                        opstr = (insn.op_str or "").lower()
                        # direct call operands containing API name (heuristic)
                        if mnem.startswith("call"):
                            for api in SUSPICIOUS_APIS:
                                if api.lower() in opstr:
                                    out_rows.append([path, "call_to_suspicious_api",
                                                     f"0x{func_addr:x}", f"0x{block_addr:x}", f"0x{insn.address:x}",
                                                     f"api={api} op={insn.op_str}"])
                                    found_in_func.append("call_api")
                        # syscall detection
                        if mnem in ("syscall", "sysenter"):
                            out_rows.append([path, "direct_syscall", f"0x{func_addr:x}", f"0x{block_addr:x}",
                                             f"0x{insn.address:x}", f"{mnem} {insn.op_str}"])
                            found_in_func.append("syscall")
                        if mnem == "int":
                            # check immediate interrupt value (common Windows int 0x2e)
                            if "0x2e" in opstr or "0x2e" in insn.op_str.lower() or "46" in opstr:
                                out_rows.append([path, "direct_int_0x2e", f"0x{func_addr:x}", f"0x{block_addr:x}",
                                                 f"0x{insn.address:x}", f"int {insn.op_str}"])
                                found_in_func.append("int2e")
                        # detect accesses to fs/gs referencing peb offsets -> manual import resolution
                        if "fs:" in opstr or "gs:" in opstr or "fs[" in opstr or "gs[" in opstr:
                            # look for common PEB offsets 0x30 (PEB) or 0x60 (x64 PEB)
                            if "0x30" in opstr or "0x60" in opstr or "0x18" in opstr:
                                out_rows.append([path, "peb_walk_access", f"0x{func_addr:x}", f"0x{block_addr:x}",
                                                 f"0x{insn.address:x}", f"{insn.mnemonic} {insn.op_str}"])
                                found_in_func.append("peb_walk")
                        # detect immediate 0x40 (PAGE_EXECUTE_READWRITE) near alloc/protect ops
                        if "0x40" in opstr or "0x00000040" in opstr:
                            # tie to proximity of alloc/protect by checking block text for alloc/protect API names
                            lower_block_text = block_text.lower()
                            if any(api.lower() in lower_block_text for api in ("virtualalloc", "virtualprotect", "ntcreate", "mapview")):
                                out_rows.append([path, "rwx_protect_immediate", f"0x{func_addr:x}", f"0x{block_addr:x}",
                                                 f"0x{insn.address:x}", f"contains 0x40 near alloc/protect (op:{insn.op_str})"])
                                found_in_func.append("rwx")
                except Exception:
                    # fallback: textual disasm scan (slower, but ok)
                    txt = block_text.lower()
                    for api in SUSPICIOUS_APIS:
                        if api.lower() in txt:
                            out_rows.append([path, "text_api_match", f"0x{func_addr:x}", f"0x{block_addr:x}", "", f"api_text_match={api}"])
                            found_in_func.append("text_api")
                    if "fs:" in txt or "gs:" in txt:
                        if "0x30" in txt or "0x60" in txt:
                            out_rows.append([path, "peb_walk_text", f"0x{func_addr:x}", f"0x{block_addr:x}", "", "fs/gs access with peb offset (text)"])
                            found_in_func.append("peb_walk_text")

                # 3b) fallback textual checks for immediates and constants
                try:
                    text = block_text.lower()
                    if "0x40" in text and any(x in text for x in ("virtualalloc", "virtualprotect", "ntcreate", "mapview", "writeprocessmemory")):
                        out_rows.append([path, "rwx_protect_text", f"0x{func_addr:x}", f"0x{block_addr:x}", "", "0x40 found near alloc/protect (text)"])
                        found_in_func.append("rwx_text")
                except Exception:
                    pass

        except Exception:
            # best-effort: don't fail entire binary for one function
            traceback.print_exc()
            continue

    print(f"[*] done analyzing {path}")
    return

def collect_targets(path):
    files = []
    if os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for fn in filenames:
                if fn.lower().endswith((".exe", ".dll", ".bin", ".pe")):
                    files.append(os.path.join(root, fn))
    else:
        files.append(path)
    return files

def main():
    parser = argparse.ArgumentParser(description="Extended injection detector (angr)")
    parser.add_argument("target", help="file or directory to scan")
    parser.add_argument("--out", help="output CSV file", default="findings.csv")
    args = parser.parse_args()

    targets = collect_targets(args.target)
    if not targets:
        print("[!] no target files found. Provide a .exe or a directory containing samples.")
        return

    out_rows = []
    # header: file, detection_type, func_addr, block_addr, insn_addr, detail
    for t in targets:
        try:
            analyze_binary(t, out_rows)
        except Exception as e:
            print(f"[!] error analyzing {t}: {e}")

    # write CSV
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "detection_type", "func_addr", "block_addr", "insn_addr", "detail"])
        for r in out_rows:
            writer.writerow(r)
    print(f"[*] findings written to {args.out} ({len(out_rows)} rows)")

if __name__ == "__main__":
    main()
