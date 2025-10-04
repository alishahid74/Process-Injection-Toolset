\
#!/usr/bin/env python3

"""

symbolic_arg_checker.py

Lightweight prototype that:
 - loads a binary with angr (auto_load_libs=False)
 - builds a CFG (CFGFast)
 - searches for call sites that reference a suspicious API (default: WriteProcessMemory)
 - for each found call site, performs a light symbolic exploration from entry to the block address (timeout configurable)
 - if reachable, inspects calling convention registers (x64) to determine if the buffer/argument is symbolic

Notes & limitations:
 - This prototype focuses on x64 Windows targets and attempts a best-effort for x86.
 - Symbolic exploration is limited by the --timeout per-search and may not find a path for complex binaries.

"""

import argparse, os, sys, time, traceback
try:
    import pefile
except Exception:
    pefile = None
import angr

def detect_arch(pe_path):
    if pefile:
        try:
            p = pefile.PE(pe_path, fast_load=True)
            magic = getattr(p.OPTIONAL_HEADER, 'Magic', None)
            return 'x64' if magic == 0x20b else 'x86'
        except Exception:
            pass
    # fallback: let angr detect
    try:
        proj = angr.Project(pe_path, auto_load_libs=False)
        mo = proj.loader.main_object
        arch = getattr(mo, 'arch', None)
        if arch:
            n = str(arch).lower()
            if 'amd64' in n or 'x86_64' in n:
                return 'x64'
            if 'i386' in n or 'x86' in n:
                return 'x86'
    except Exception:
        pass
    return 'unknown'

def find_call_sites(cfg, api_name):
    sites = []
    for func in cfg.kb.functions.values():
        for block in func.blocks:
            try:
                text = (getattr(block, 'disassembly_text', '') or '').lower()
                if api_name.lower() in text:
                    sites.append((func.addr, block.addr, text[:400]))
                else:
                    try:
                        insns = block.capstone.insns
                        for ins in insns:
                            if api_name.lower() in (ins.op_str or '').lower():
                                sites.append((func.addr, block.addr, f"ins@0x{ins.address:x} {ins.mnemonic} {ins.op_str}"))
                    except Exception:
                        pass
            except Exception:
                continue
    return sites

def is_expr_symbolic(ast):
    try:
        vars = getattr(ast, 'variables', None)
        if vars is None:
            try:
                vars = ast.variables
            except Exception:
                vars = set()
        return len(vars) > 0
    except Exception:
        try:
            s = str(ast)
            return 'BVS' in s or 'symbolic' in s.lower()
        except Exception:
            return False

def inspect_state_for_args(state, arch):
    result = {}
    try:
        if arch == 'x64':
            # Windows x64: rcx, rdx, r8, r9
            regs = ['rcx','rdx','r8','r9']
            for r in regs:
                try:
                    val = getattr(state.regs, r)
                    result[r] = {'symbolic': is_expr_symbolic(val), 'expr': str(val)[:200]}
                except Exception:
                    result[r] = {'symbolic': False, 'expr': 'N/A'}
        elif arch == 'x86':
            try:
                sp = state.regs.esp
                addr = state.solver.eval(sp)
                try:
                    arg0 = state.memory.load(addr + 4, 4)
                    result['arg0'] = {'symbolic': is_expr_symbolic(arg0), 'expr': str(arg0)[:200]}
                except Exception as e:
                    result['arg0'] = {'symbolic': True, 'expr': f"could_not_read:{e}"}
            except Exception:
                result['arg0'] = {'symbolic': True, 'expr': 'unknown'}
        else:
            for r in ['rdi','rsi','rcx','rdx']:
                try:
                    val = getattr(state.regs, r)
                    result[r] = {'symbolic': is_expr_symbolic(val), 'expr': str(val)[:200]}
                except Exception:
                    pass
    except Exception:
        pass
    return result

def main():
    p = argparse.ArgumentParser(description="Symbolic argument reachability checker for suspicious API calls")
    p.add_argument("target", help="file to analyze")
    p.add_argument("--api", default="WriteProcessMemory", help="API name to search for in disassembly")
    p.add_argument("--timeout", type=int, default=6, help="seconds per exploration attempt")
    p.add_argument("--max-sites", type=int, default=8, help="max call sites to attempt")
    args = p.parse_args()

    target = os.path.expanduser(args.target)
    if not os.path.exists(target):
        print("[!] target not found:", target); sys.exit(1)

    arch = detect_arch(target)
    print("[*] detected arch:", arch)

    try:
        proj = angr.Project(target, auto_load_libs=False)
    except Exception as e:
        print("[!] angr failed to load target:", e); sys.exit(1)

    try:
        cfg = proj.analyses.CFGFast()
    except Exception as e:
        print("[!] failed to build CFG:", e); cfg = None

    if cfg is None:
        sys.exit(1)

    sites = find_call_sites(cfg, args.api)
    if not sites:
        print("[*] no sites found referencing", args.api); sys.exit(0)

    print(f"[*] found {len(sites)} candidate sites; trying up to {args.max_sites}")
    for i,(faddr,baddr,ctx) in enumerate(sites[:args.max_sites]):
        print(f"\\n--- Site {i+1}/{min(len(sites),args.max_sites)} ---")
        print(f"function@0x{faddr:x} block@0x{baddr:x}")
        print("context snippet:", ctx)
        try:
            start = proj.factory.entry_state()
            simgr = proj.factory.simgr(start)
            start_time = time.time()
            simgr.explore(find=lambda p: p.addr == baddr, timeout=args.timeout)
            elapsed = time.time() - start_time
            if simgr.found:
                st = simgr.found[0]
                print(f"[+] reachable in {elapsed:.2f}s")
                args_info = inspect_state_for_args(st, arch)
                print("Argument inspection (symbolic? expr):")
                for k,v in args_info.items():
                    print(f"  {k}: symbolic={v.get('symbolic')} expr={v.get('expr')}")
            else:
                print(f"[-] not reachable within {args.timeout}s (elapsed {elapsed:.2f}s)")
        except Exception as e:
            print("[!] exploration error:", e)
            traceback.print_exc()

if __name__ == '__main__':
    main()
