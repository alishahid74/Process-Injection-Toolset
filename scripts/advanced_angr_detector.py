
#!/usr/bin/env python3
"""
advanced_angr_detector.py

Advanced angr-based static detector for process-injection techniques.
Features:
 - Uses angr/CLE loader to inspect imports, sections, and embedded blobs
 - Builds CFG (CFGFast by default) and scans functions/blocks for suspicious APIs,
   API sequences, direct syscalls, and PEB access patterns.
 - Examines Capstone disassembly for immediate operands (PAGE_EXECUTE_READWRITE),
   GetProcAddress('Nt*') style heuristics, and RWX allocation patterns.
 - Optional light symbolic exploration to try to reach suspicious functions/addresses.
 - Generates YARA rules for high-entropy or PE-in-blob resources found in data sections.
 - Outputs CSV and an HTML report.

Usage:
    python3 /mnt/data/advanced_angr_detector.py <target-file-or-dir> --out findings.csv --html report.html --yaradir yara_rules

Notes:
 - Run in a Python 3 virtualenv with angr installed:
     pip install angr pefile
 - Symbolic exploration can be slow; enable it with --symbolic and tune --explore-timeout.
"""
import os, sys, argparse, csv, math, json, time, traceback
from collections import defaultdict

try:
    import pefile
except Exception:
    pefile = None

import angr
import logging
logging.getLogger("angr").setLevel(logging.ERROR)

# Heuristics and patterns
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "RtlCreateUserThread", "NtCreateSection", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "MapViewOfFile", "OpenProcess", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread", "SuspendThread",
    "LoadLibrary", "GetProcAddress", "GetModuleHandle", "CreateProcess",
    "NtWriteVirtualMemory", "NtCreateThreadEx", "CreateThread",
]

SEQUENCE_PATTERNS = [
    ["CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],  # process hollowing
    ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],  # classic remote injection
    ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
    ["NtCreateSection", "NtMapViewOfSection", "RtlCreateUserThread", "ResumeThread"],
    ["QueueUserAPC", "CreateRemoteThread"],
]

ENTROPY_WINDOW = 64
ENTROPY_THRESHOLD = 7.5
LARGE_BLOB_MIN = 64
YARA_SNIP_LEN = 64

BASE_CONF = {
    "suspicious_import": 3,
    "api_sequence_match": 10,
    "high_entropy_blob": 7,
    "pe_in_blob": 8,
    "direct_syscall": 9,
    "int_0x2e": 9,
    "peb_access": 6,
    "rwx_constant": 6,
    "call_suspicious": 5,
    "indirect_getproc": 6,
}

HTML_TMPL = """<!doctype html>
<html><head><meta charset="utf-8"><title>Angr Advanced Detector Report</title>
<style>body{{font-family:Arial,Helvetica,sans-serif}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:6px;text-align:left}}th{{background:#222;color:#fff}}</style>
</head><body><h1>Angr Advanced Detector Report</h1><p>Source: {src}</p>{body}</body></html>
"""

def shannon(data: bytes) -> float:
    if not data: return 0.0
    import math
    counts = {}
    for b in data:
        counts[b] = counts.get(b,0)+1
    ent = 0.0
    ln = len(data)
    for v in counts.values():
        p = v/ln
        ent -= p * math.log2(p)
    return ent

def collect_targets(path):
    path = os.path.expanduser(path)
    if os.path.isdir(path):
        res = []
        for root, _, files in os.walk(path):
            for fn in files:
                full = os.path.join(root, fn)
                try:
                    size = os.path.getsize(full)
                    if size > 200*1024*1024:
                        continue
                except Exception:
                    pass
                if fn.lower().endswith(('.exe','.dll','.pe','.bin','.so')):
                    res.append(full); continue
                try:
                    with open(full,'rb') as fh:
                        head = fh.read(4)
                        if head.startswith(b'MZ') or head.startswith(b'\x7fELF') or head.startswith(b'#!'):
                            res.append(full); continue
                except Exception:
                    pass
                if os.access(full, os.X_OK):
                    res.append(full)
        return sorted(set(res))
    else:
        return [path]

def build_cfg(proj, fast=True):
    if fast:
        return proj.analyses.CFGFast()
    else:
        return proj.analyses.CFG()

def scan_data_sections_for_blobs(proj):
    findings = []
    try:
        mo = proj.loader.main_object
        for sec in getattr(mo, 'sections', []):
            name = getattr(sec,'name',None)
            try:
                name = name.decode() if isinstance(name, bytes) else str(name)
            except Exception:
                name = str(name)
            if not any(k in (name or '').lower() for k in ('.data','.rdata','.rsrc','data','rdata','rsrc')):
                continue
            data = None
            try:
                if hasattr(sec,'content') and sec.content:
                    data = sec.content
                elif hasattr(sec,'data') and sec.data:
                    data = sec.data
                else:
                    data = proj.loader.memory.load(sec.vaddr, getattr(sec,'memsize',sec.size or 0))
            except Exception:
                pass
            if not data:
                continue
            # sliding window entropy
            for i in range(0, max(1,len(data)-ENTROPY_WINDOW+1), max(1,ENTROPY_WINDOW//2)):
                wnd = data[i:i+ENTROPY_WINDOW]
                e = shannon(wnd)
                if e >= ENTROPY_THRESHOLD:
                    findings.append(('high_entropy_blob', sec.vaddr+i, len(wnd), f"sec={name} ent={e:.2f} off=0x{sec.vaddr+i:x}"))
            # find MZ inside section
            idx = data.find(b'MZ')
            if idx!=-1:
                try:
                    elfanew_off = idx+0x3c
                    if elfanew_off+4 < len(data):
                        e_lfanew = int.from_bytes(data[elfanew_off:elfanew_off+4],'little')
                        pe_off = idx + e_lfanew
                        if pe_off+4 < len(data) and data[pe_off:pe_off+4]==b'PE\\x00\\x00':
                            findings.append(('pe_in_blob', sec.vaddr+idx, 0, f"sec={name} mzoff=0x{idx:x} elfanew=0x{e_lfanew:x}"))
                except Exception:
                    pass
    except Exception as e:
        print("[!] data-scan error:", e)
    return findings

def find_api_sequences_in_blocks(func, suspicious_patterns):
    entries = []
    try:
        for block in func.blocks:
            text = getattr(block,'disassembly_text','') or ''
            try:
                insns = block.capstone.insns
            except Exception:
                insns = []
            for api in SUSPICIOUS_APIS:
                if api.lower() in text.lower():
                    entries.append((api, block.addr, block.addr))
            for ins in insns:
                op = (ins.op_str or '').lower()
                for api in SUSPICIOUS_APIS:
                    if api.lower() in op:
                        entries.append((api, block.addr, ins.address))
    except Exception:
        pass
    # check for sequence patterns in api list
    apis = [a[0] for a in entries]
    matches = []
    for pat in suspicious_patterns:
        patl = [p.lower() for p in pat]
        i=0; idxs=[]
        for p in patl:
            found=False
            while i < len(apis):
                if apis[i].lower().find(p)!=-1:
                    idxs.append(i); found=True; i+=1; break
                i+=1
            if not found:
                idxs=[]
                break
        if idxs:
            matched = [entries[ix] for ix in idxs]
            matches.append((pat, matched))
    return matches

def inspect_insns_for_syscall_and_peb(block):
    findings = []
    try:
        insns = []
        try:
            insns = block.capstone.insns
        except Exception:
            pass
        text = getattr(block,'disassembly_text','') or ''
        # PEB access heuristics
        if ('fs:' in text.lower() or 'gs:' in text.lower()) and any(o in text for o in ('0x30','0x60','0x18')):
            findings.append(('peb_access', block.addr, f"PEB-like access in block 0x{block.addr:x}"))
        # scan insns
        for i,ins in enumerate(insns):
            m = ins.mnemonic.lower()
            op = (ins.op_str or '').lower()
            if m in ('syscall','sysenter'):
                # try looking back for mov rax/eax imm
                val=None
                if i>0:
                    prev=insns[i-1]
                    if prev.mnemonic.lower().startswith('mov') and ('rax' in (prev.op_str or '').lower() or 'eax' in (prev.op_str or '').lower()):
                        try:
                            val = int(prev.op_str.split(",")[-1].strip(),0)
                        except Exception:
                            val=None
                findings.append(('direct_syscall', ins.address, f"syscall at 0x{ins.address:x} moved_val={val}"))
            if m=='int' and ('0x2e' in op or '2e' in op):
                findings.append(('int_0x2e', ins.address, f"int 0x2e at 0x{ins.address:x}"))
            # detect RWX constant usage nearby
            if '0x40' in op or '0x00000040' in op:
                findings.append(('rwx_constant', block.addr, f"PAGE_EXECUTE_READWRITE constant near block 0x{block.addr:x}"))
            # detect getproc + nt pattern
            if 'getproc' in op or 'getproc' in text.lower():
                if 'nt' in op or 'nt' in text.lower():
                    findings.append(('indirect_getproc', block.addr, f"GetProcAddress('Nt*') style in block 0x{block.addr:x}"))
    except Exception:
        pass
    return findings

def analyze_binary(path, out_rows, yara_dir, cfg_fast=True, do_symbolic=False, explore_timeout=6):
    print("[*] loading", path)
    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as e:
        print("[!] angr failed to load:", e)
        return
    arch = None
    try:
        arch = None
        if pefile:
            try:
                pe = pefile.PE(path, fast_load=True)
                arch = 'x64' if getattr(pe.OPTIONAL_HEADER,'Magic',None)==0x20b else 'x86'
            except Exception:
                arch = None
    except Exception:
        arch=None

    mo = proj.loader.main_object
    # imports
    try:
        imports = getattr(mo,'imports',{}) or {}
        for name, info in imports.items():
            nm = name.decode() if isinstance(name, bytes) else str(name)
            for api in SUSPICIOUS_APIS:
                if api.lower() in nm.lower():
                    out_rows.append([path, arch or 'unknown', 'suspicious_import', '', '', nm, '', BASE_CONF['suspicious_import']])
    except Exception as e:
        print("[!] import scan error", e)
    # data section heuristics + yara gen
    blobs = scan_data_sections_for_blobs(proj)
    for typ, vaddr, length, detail in blobs:
        sample = b''
        try:
            sample = proj.loader.memory.load(vaddr, min(YARA_SNIP_LEN, max(16,length)))
        except Exception:
            try:
                # attempt section content
                for sec in mo.sections:
                    if getattr(sec,'vaddr',None) and sec.vaddr <= vaddr < sec.vaddr + (getattr(sec,'memsize',getattr(sec,'size',0) or 0)):
                        if hasattr(sec,'content'):
                            sample = sec.content[:YARA_SNIP_LEN]
            except Exception:
                pass
        hexs = sample.hex() if sample else ''
        conf = BASE_CONF.get('high_entropy_blob',7) if typ=='high_entropy_blob' else BASE_CONF.get('pe_in_blob',8)
        out_rows.append([path, arch or 'unknown', typ, '', hex(vaddr) if vaddr else '', detail, hexs, conf])
        # generate yara rule
        if hexs:
            os.makedirs(yara_dir, exist_ok=True)
            rulename = f"yar_{os.path.basename(path)}_{typ}_{vaddr:x}".replace('.','_')
            yara_f = os.path.join(yara_dir, rulename + '.yar')
            try:
                bs = bytes.fromhex(hexs)
                hexpairs = ' '.join([f"{b:02x}" for b in bs])
                with open(yara_f,'w') as fh:
                    fh.write(f"rule {rulename} {{\\n  meta:\\n    source = \"{path}\"\\n  strings:\\n    $a = {{ {hexpairs} }}\\n  condition:\\n    $a\\n}}\\n")
            except Exception:
                pass
    # build CFG
    try:
        print("[*] building CFG (fast=%s) ..." % cfg_fast)
        cfg = build_cfg(proj, fast=cfg_fast)
    except Exception as e:
        print("[!] CFG build failed:", e)
        cfg = None
    if cfg is None:
        return
    # analyze functions
    for func in cfg.kb.functions.values():
        try:
            faddr = func.addr
            # sequence matches
            seq_matches = find_api_sequences_in_blocks(func, SEQUENCE_PATTERNS)
            for pat, matched in seq_matches:
                detail = '->'.join([m[0] for m in matched])
                snippet = ';'.join([f"{m[0]}@0x{m[2]:x}" for m in matched])
                out_rows.append([path, arch or 'unknown', 'api_sequence_match', hex(faddr), '', f"pattern={'|'.join(pat)} detail={detail}", snippet, BASE_CONF['api_sequence_match']])
            # per-block inspection
            for block in func.blocks:
                # textual/capstone heuristics
                try:
                    insn_findings = inspect_insns_for_syscall_and_peb(block)
                    for t,a,det in insn_findings:
                        out_rows.append([path, arch or 'unknown', t, hex(faddr), hex(block.addr), det, getattr(block,'disassembly_text','')[:400], BASE_CONF.get(t,5)])
                    # calls to suspicious APIs within insns
                    try:
                        insns = block.capstone.insns
                    except Exception:
                        insns = []
                    for ins in insns:
                        m = ins.mnemonic.lower()
                        op = (ins.op_str or '').lower()
                        if m.startswith('call') or m.startswith('jmp'):
                            for api in SUSPICIOUS_APIS:
                                if api.lower() in op:
                                    out_rows.append([path, arch or 'unknown','call_suspicious', hex(faddr), hex(block.addr), f"call {api} operand={ins.op_str}", f"0x{ins.address:x} {ins.mnemonic} {ins.op_str}", BASE_CONF['call_suspicious']])
                        # immediates: RWX constant detection near alloc/protect textual matches
                        if '0x40' in (ins.op_str or '').lower():
                            txt = getattr(block,'disassembly_text','').lower()
                            if any(k.lower() in txt for k in ('virtualalloc','virtualprotect','ntcreate','mapview','writeprocessmemory')):
                                out_rows.append([path, arch or 'unknown','rwx_constant', hex(faddr), hex(block.addr), 'PAGE_EXECUTE_READWRITE constant near allocation/protect', txt[:400], BASE_CONF['rwx_constant']])
                        if 'getproc' in (ins.op_str or '').lower() or 'getproc' in getattr(block,'disassembly_text','').lower():
                            if 'nt' in (ins.op_str or '').lower() or 'nt' in getattr(block,'disassembly_text','').lower():
                                out_rows.append([path, arch or 'unknown','indirect_getproc', hex(faddr), hex(block.addr), 'GetProcAddress(nt*) pattern', getattr(block,'disassembly_text','')[:400], BASE_CONF['indirect_getproc']])
                except Exception as e:
                    # fallback textual
                    txt = getattr(block,'disassembly_text','') or ''
                    for api in SUSPICIOUS_APIS:
                        if api.lower() in txt.lower():
                            out_rows.append([path, arch or 'unknown','suspicious_text', hex(faddr), hex(block.addr), api, txt[:200], 2])
            # optionally attempt a light symbolic reachability check
            if do_symbolic:
                # find a representative "suspicious" address for this function: either the first matched API call or function addr
                target = faddr
                try:
                    st = proj.factory.entry_state()
                    simgr = proj.factory.simgr(st)
                    start_time = time.time()
                    # try to find function address reachable from entry
                    simgr.explore(find=lambda p: p.addr==target, n=1, timeout=explore_timeout)
                    if simgr.found:
                        out_rows.append([path, arch or 'unknown','symbolic_reachable', hex(faddr), '', f"Function 0x{faddr:x} reachable from entry", '', 9])
                except Exception as e:
                    # symbolic exploration failed/too slow -> skip
                    pass
        except Exception as e:
            # single-function error shouldn't break whole analysis
            traceback.print_exc()
            continue
    print("[*] done:", path)

def write_csv(path, rows):
    hdr = ['file','arch','detection','func_addr','block_addr','detail','snippet_or_hex','confidence']
    with open(path,'w',newline='',encoding='utf-8') as fh:
        import csv
        w = csv.writer(fh)
        w.writerow(hdr)
        for r in rows:
            w.writerow(r)

def write_html(src, rows, out_html):
    byf = defaultdict(list)
    for r in rows:
        byf[r[0]].append(r)
    parts = []
    for f, items in byf.items():
        parts.append(f"<h2>{f}</h2>")
        parts.append("<table><tr><th>Arch</th><th>Detection</th><th>Func</th><th>Block</th><th>Detail</th><th>Confidence</th></tr>")
        for it in items:
            arch, det, func, block, detail, snip, conf = it[1], it[2], it[3], it[4], it[5], it[6], it[7]
            parts.append(f"<tr><td>{arch}</td><td>{det}</td><td>{func}</td><td>{block}</td><td>{detail}</td><td>{conf}</td></tr>")
        parts.append("</table>")
    body = '\\n'.join(parts)
    with open(out_html,'w',encoding='utf-8') as fh:
        fh.write(HTML_TMPL.format(src=src, body=body))

def main():
    p = argparse.ArgumentParser(description="Advanced angr-based process-injection static detector")
    p.add_argument("target", help="file or directory to scan")
    p.add_argument("--out", default="angr_findings.csv", help="output CSV file")
    p.add_argument("--html", default="angr_report.html", help="output HTML report")
    p.add_argument("--yaradir", default="angr_yara", help="yara output directory")
    p.add_argument("--cfg", choices=['fast','full'], default='fast', help="CFG mode (fast or full)")
    p.add_argument("--symbolic", action='store_true', help="enable light symbolic reachability checks (slow)")
    p.add_argument("--explore-timeout", type=int, default=6, help="seconds to allow for each symbolic explore call")
    p.add_argument("--syscallmap", default=None, help="optional JSON mapping syscall numbers to names")
    args = p.parse_args()

    syscall_map = {}
    if args.syscallmap:
        try:
            with open(args.syscallmap,'r',encoding='utf-8') as fh:
                j = json.load(fh)
                for k,v in j.items():
                    try:
                        syscall_map[int(k,0)] = v
                    except Exception:
                        try:
                            syscall_map[int(k)] = v
                        except Exception:
                            pass
        except Exception:
            pass

    targets = collect_targets(args.target)
    if not targets:
        print("[!] no candidates found under", args.target)
        return
    rows = []
    for t in targets:
        try:
            analyze_binary(t, rows, args.yaradir, cfg_fast=(args.cfg=='fast'), do_symbolic=args.symbolic, explore_timeout=args.explore_timeout)
        except Exception as e:
            print("[!] error analyzing", t, e)
            traceback.print_exc()
    write_csv(args.out, rows)
    write_html(args.target, rows, args.html)
    print("[*] CSV written to", args.out, "rows:", len(rows))
    print("[*] HTML written to", args.html)
    print("[*] YARA rules (if any) in", args.yaradir)

if __name__ == '__main__':
    main()
