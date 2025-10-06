#!/usr/bin/env python3
"""
angr_detect_injection.py
Usage:
  python3 src/angr_detect_injection.py --binary samples/injection_demo --out results/injection/found_input.txt
Optional:
  --target 0x4011ec   (hex address of injected call / target basic block)
"""
import argparse, os, logging
import angr, claripy

logging.getLogger('angr').setLevel('INFO')

def main(binary, out, target):
    if not os.path.exists(binary):
        raise SystemExit(f"Binary not found: {binary}")

    proj = angr.Project(binary, auto_load_libs=False)
    # 64 bytes symbolic for argv[1]
    arg_bv = claripy.BVS("user_input", 8 * 64)
    state = proj.factory.entry_state(args=[binary, arg_bv])

    simgr = proj.factory.simulation_manager(state)

    find_addr = None
    if target is not None:
        find_addr = int(target, 0)

    print(f"[*] Exploring binary: {binary}")
    try:
        if find_addr:
            simgr.explore(find=find_addr, num_find=1)
        else:
            # If no address provided: try finding functions that call WriteProcessMemory via CFG imports
            print("[*] No target address provided; running short CFG to find imports (may take a few seconds)")
            cfg = proj.analyses.CFGFast()
            # naive heuristic: see if WriteProcessMemory is imported
            for imp in proj.loader.main_object.imports:
                if 'WriteProcessMemory' in imp.name:
                    print("[*] Found import:", imp)
                    # find callers to the PLT entry if possible (simple)
            # fallback: try exploring for 'put' or 'strcmp' success message heuristics - skip for now
            raise SystemExit("Please pass --target <hex address> for reliable exploration.")
    except Exception as e:
        print("[!] Exploration failed:", e)
        return

    if simgr.found:
        found = simgr.found[0]
        try:
            concrete = found.solver.eval(arg_bv, cast_to=bytes)
        except Exception:
            # try eval as string with null termination
            concrete = found.solver.eval(arg_bv, cast_to=bytes)
        # Trim trailing nulls
        concrete = concrete.split(b'\x00', 1)[0]
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as f:
            f.write(concrete)
        print(f"[+] Found input written to {out}")
        print("[+] Input (repr):", repr(concrete))
    else:
        print("[-] No path found to target.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", default="found_input.txt")
    ap.add_argument("--target", default=None, help="hex or dec address to reach (e.g. 0x4011ec)")
    args = ap.parse_args()
    main(args.binary, args.out, args.target)
