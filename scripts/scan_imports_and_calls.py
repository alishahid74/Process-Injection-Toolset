
---

# Script 1 — `scan_imports_and_calls.py` (fast heuristic)
Create a file named `scan_imports_and_calls.py` and paste:

```python
#!/usr/bin/env python3
# scan_imports_and_calls.py
# Quick scan: list suspicious imported API names and attempt to find call sites in CFG.

import sys
import angr
import logging

logging.getLogger("angr").setLevel(logging.ERROR)

SUSPICIOUS_APIS = {
    # common Windows injection APIs / syscalls
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "RtlCreateUserThread", "NtCreateSection", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "MapViewOfFile", "OpenProcess",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext", "ResumeThread",
}

def list_imports(proj):
    mo = proj.loader.main_object
    imports = getattr(mo, "imports", None)
    if not imports:
        print("[!] No imports found (file may be stripped)")
        return {}
    # imports is a dict mapping ordinal/name -> tuple(addr, libname?)
    found = {}
    for name, imp in imports.items():
        # CLE sometimes stores keys as names, sometimes symbols — normalize
        try:
            nm = name.decode() if isinstance(name, bytes) else name
        except Exception:
            nm = str(name)
        for api in SUSPICIOUS_APIS:
            if api.lower() in nm.lower():
                found.setdefault(api, []).append(nm)
    return found

def quick_cfg_search(proj):
    print("[*] building fast CFG (this can take a few seconds)...")
    cfg = proj.analyses.CFGFast()
    suspicious_matches = []
    for func in cfg.kb.functions.values():
        # iterate blocks in the function
        try:
            for block in func.blocks:
                try:
                    cap = block.capstone
                    for insn in cap.insns:
                        if insn.mnemonic.lower().startswith("call"):
                            op = insn.op_str
                            for api in SUSPICIOUS_APIS:
                                if api.lower() in op.lower():
                                    suspicious_matches.append((func.addr, block.addr, insn.address, api, op))
                except Exception:
                    # older angr versions may present capstone slightly different
                    text = block.disassembly_text
                    for api in SUSPICIOUS_APIS:
                        if api.lower() in text.lower():
                            suspicious_matches.append((func.addr, block.addr, block.addr, api, "<disasm match>"))
        except Exception:
            continue
    return suspicious_matches

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scan_imports_and_calls.py <binary.exe>")
        return
    target = sys.argv[1]
    proj = angr.Project(target, auto_load_libs=False)
    print("[*] loaded:", target)
    imports = list_imports(proj)
    if imports:
        print("\n== Suspicious imported APIs found ==")
        for k,v in imports.items():
            print(f"{k}: {v}")
    else:
        print("\n== No obvious suspicious imports detected ==")

    matches = quick_cfg_search(proj)
    if matches:
        print("\n== Candidate call sites found ==")
        for func_addr, block_addr, ins_addr, api, op in matches:
            print(f"func@0x{func_addr:x} block@0x{block_addr:x} ins@0x{ins_addr:x} api={api} op={op}")
    else:
        print("\n== No candidate call sites found via CFG search ==")

if __name__ == "__main__":
    main()
