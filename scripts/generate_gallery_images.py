#!/usr/bin/env python3
"""
generate_gallery_images.py
Auto-generate missing gallery images for adv_results candidates.

Usage:
  python3 scripts/generate_gallery_images.py --candidate antidebug_demo
  python3 scripts/generate_gallery_images.py --all

Requires: scripts/cfg_visualizer_enhanced.py (in repo)
"""
import argparse, subprocess, shlex, os, sys
from pathlib import Path

REPO = Path.cwd()
SCRIPTS = REPO / "scripts"
ADV = REPO / "adv_results"
CFGVIS = SCRIPTS / "cfg_visualizer_enhanced.py"  # uses this if present

def run_cmd(cmd):
    print("[*] Running:", " ".join(shlex.quote(str(x)) for x in cmd))
    rc = subprocess.run(cmd).returncode
    return rc

def candidate_dirs():
    if not ADV.exists():
        return []
    return [p for p in ADV.iterdir() if p.is_dir()]

def generate_for_candidate(name):
    cand_dir = ADV / name
    cand_dir.mkdir(parents=True, exist_ok=True)
    # try to find adv CSV (may be adv_results/<name>_v2.csv or merged CSV)
    csv_candidates = list(ADV.glob(f"{name}*.csv"))
    func_addrs = set()
    # first, try to find existing PNG names already present and extract addresses
    for p in cand_dir.glob("*.png"):
        s = p.stem
        # pattern: <name>_0x401000_blocks
        if "_0x" in s and s.endswith("_blocks"):
            try:
                part = s.split("_0x",1)[1].split("_",1)[0]
                func_addrs.add("0x"+part)
            except Exception:
                pass
    # If no addresses yet, attempt to derive via angr (quick CFGFast)
    if not func_addrs and csv_candidates:
        # try to parse CSV to get func addresses
        import csv
        for csvf in csv_candidates:
            try:
                with open(csvf, newline='', encoding='utf-8') as fh:
                    rdr = csv.DictReader(fh)
                    for r in rdr:
                        a = r.get("func_addr") or r.get("function_addr") or r.get("func") or r.get("funcaddr")
                        if a:
                            if isinstance(a, str) and not a.startswith("0x"):
                                try:
                                    a = hex(int(a))
                                except:
                                    pass
                            func_addrs.add(str(a))
            except Exception:
                continue
    # If still none, try to use angr to list functions from the original sample file (if present)
    # look for a sample binary in the cand_dir or REPO samples path
    if not func_addrs:
        # search for likely binary in repo samples or adv dir
        possible = list(cand_dir.glob("*")) + list(REPO.glob("samples/*"))
        binp = None
        for p in possible:
            if p.is_file():
                # probe with 'file' string, simple heuristic
                try:
                    out = subprocess.check_output(["file", str(p)], stderr=subprocess.DEVNULL).decode().lower()
                    if "elf" in out or "pe32" in out or "pe32+" in out:
                        binp = p
                        break
                except Exception:
                    continue
        if binp:
            print("[*] Using binary", binp, "to enumerate functions with angr (requires angr installed).")
            try:
                import angr
                proj = angr.Project(str(binp), auto_load_libs=False)
                cfg = proj.analyses.CFGFast()
                for f in cfg.kb.functions.values():
                    func_addrs.add(hex(f.addr))
            except Exception as e:
                print("[!] angr enumerate failed:", e)
    # now generate images for each function address
    if not func_addrs:
        print("[!] No function addresses found for candidate", name, "— skipping.")
        return
    for a in sorted(func_addrs):
        # strip 0x prefix for file naming
        short = a if a.startswith("0x") else f"0x{a}"
        basepng = f"{name}_{short}_blocks.png"
        outpng = cand_dir / basepng
        # call cfg_visualizer_enhanced.py to build block-level graph; fallback to cfg_visualizer.py if not found
        if CFGVIS.exists():
            cmd = [sys.executable, str(CFGVIS), str(binp) if 'binp' in locals() and binp else str(binp or ""), "--func", a, "--block-level", "--out", str(outpng), "--png", str(outpng)]
            # some versions accept --block-level; adapt if needed
        else:
            # fallback: try cfg_visualizer.py
            fallback = SCRIPTS / "cfg_visualizer.py"
            if fallback.exists():
                cmd = [sys.executable, str(fallback), str(binp) if 'binp' in locals() and binp else str(binp or ""), "--func", a, "--block-level", "--out", str(outpng), "--png", str(outpng)]
            else:
                print("[!] No cfg visualizer found to generate", outpng)
                continue
        # remove empty BINP placeholder values if binp unknown
        cmd = [x for x in cmd if x and x != ""] 
        rc = run_cmd(cmd)
        if rc != 0:
            print("[!] Generation failed for", a, "rc=", rc)
        else:
            print("[+] Wrote", outpng)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", help="Candidate name (folder under adv_results)")
    parser.add_argument("--all", action="store_true", help="Generate for all candidates")
    args = parser.parse_args()
    if args.candidate:
        generate_for_candidate(args.candidate)
    elif args.all:
        for p in candidate_dirs():
            generate_for_candidate(p.name)
    else:
        print("Usage: --candidate NAME OR --all")

if __name__ == "__main__":
    import argparse
    main()
