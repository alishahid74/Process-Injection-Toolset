#!/usr/bin/env python3
"""
syscall_heuristics.py - detect syscall patterns using angr and capstone
Usage:
  python3 scripts/syscall_heuristics.py target.bin --out syscalls.json
"""
import argparse, json
from pathlib import Path
import angr, capstone

def disasm_bytes(arch, bytes_, addr):
    if "x86" in arch and "64" in arch:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False
    outs = []
    for i in md.disasm(bytes_, addr):
        outs.append((i.address, i.mnemonic, i.op_str))
    return outs

def scan_for_syscalls(proj):
    arch = proj.arch.name
    results = {"syscalls": [], "ints": [], "nt_strings": []}
    for s in proj.loader.find_all_strings():
        try:
            st = s.decode(errors="ignore")
            if st.startswith("Nt") and len(st) > 2:
                results["nt_strings"].append(st)
        except Exception:
            continue
    cfg = proj.analyses.CFGFast()
    for f in cfg.kb.functions.values():
        for block in f.blocks:
            bs = block.bytes
            addr = block.addr
            try:
                insns = disasm_bytes(arch, bs, addr)
            except Exception:
                continue
            for (a,mnem,op) in insns:
                m = mnem.lower()
                if m == "syscall":
                    results["syscalls"].append({"addr": hex(a), "function": hex(f.addr)})
                if m == "int" and ("0x2e" in op or "0x80" in op):
                    results["ints"].append({"addr": hex(a), "function": hex(f.addr), "op": op})
    return results

def main():
    parser = argparse.ArgumentParser(description="Scan for direct syscall patterns")
    parser.add_argument("target")
    parser.add_argument("--out", default="syscalls.json")
    args = parser.parse_args()
    proj = angr.Project(args.target, auto_load_libs=False)
    print("[*] building CFGFast...")
    proj.analyses.CFGFast()
    res = scan_for_syscalls(proj)
    Path(args.out).write_text(json.dumps(res, indent=2))
    print("[*] written", args.out)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
