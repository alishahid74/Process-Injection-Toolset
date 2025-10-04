#!/usr/bin/env python3
# cfg_injection_finder.py
# Stronger CFG-based detection: for each function, look for sequences or multiple suspicious API calls.
import sys
import angr
import logging
from collections import defaultdict

logging.getLogger("angr").setLevel(logging.ERROR)

SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "RtlCreateUserThread", "NtCreateSection", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "MapViewOfFile", "OpenProcess", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread",
]

def find_api_calls_in_block(block):
    calls = []
    try:
        cap = block.capstone
        for insn in cap.insns:
            if insn.mnemonic.lower().startswith("call"):
                op = insn.op_str
                for api in SUSPICIOUS_APIS:
                    if api.lower() in op.lower():
                        calls.append((insn.address, api, op))
    except Exception:
        # fallback textual search
        text = getattr(block, "disassembly_text", "")
        for api in SUSPICIOUS_APIS:
            if api.lower() in text.lower():
                calls.append((block.addr, api, "<text-match>"))
    return calls

def analyze(proj):
    print("[*] building CFGFast (may take a bit)...")
    cfg = proj.analyses.CFGFast()
    results = defaultdict(list)
    for func in cfg.kb.functions.values():
        api_calls = []
        for block in func.blocks:
            calls = find_api_calls_in_block(block)
            if calls:
                for c in calls:
                    api_calls.append((block.addr,) + c)
        if api_calls:
            results[func.addr] = api_calls
    return results

def dump_context(proj, results, max_blocks=5):
    for faddr, items in results.items():
        print(f"\n=== Function 0x{faddr:x} => {len(items)} suspicious calls ===")
        seen_blocks = set()
        for blk_addr, ins_addr, api, op in items[:max_blocks]:
            if blk_addr in seen_blocks:
                continue
            seen_blocks.add(blk_addr)
            block = proj.factory.block(blk_addr)
            print(f"\nBlock 0x{blk_addr:x} (ins @ 0x{ins_addr:x}) - api: {api}\n")
            print(block.capstone)  # prints capstone object / disasm
            # show bytes / hexdump for quick signature
            print("\nHexdump (first 64 bytes):", block.bytes[:64].hex())
    print("\n[+] Done. Review the printed call sites and disassembly for injection chains.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 cfg_injection_finder.py <binary.exe>")
        return
    target = sys.argv[1]
    proj = angr.Project(target, auto_load_libs=False)
    results = analyze(proj)
    if not results:
        print("[*] No suspicious API calls found in CFG.")
        return
    dump_context(proj, results)

if __name__ == "__main__":
    main()
