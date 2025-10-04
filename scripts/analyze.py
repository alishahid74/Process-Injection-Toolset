#!/usr/bin/env python3
"""
analyze.py

Light-weight angr script to detect calls to common anti-debug / injection APIs.
Saves findings to adv_results/<binary>_analysis_<timestamp>.json

Usage:
    python3 analyze.py /path/to/binary --timeout 30 --find 0x401166
"""

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone

import angr
import claripy

LOG = logging.getLogger("analyze")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

COMMON_API_NAMES = [
    # Anti-debug / process inspection
    "ptrace", "IsDebuggerPresent", "NtQueryInformationProcess", "CheckRemoteDebuggerPresent",
    # Timing / clocks
    "clock_gettime", "gettimeofday", "time", "QueryPerformanceCounter", "rdtsc",
    # Process manipulation (Windows names + linux libc)
    "OpenProcess", "WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "CreateProcessA", "CreateProcessW",
    # Memory / exec helpers
    "mmap", "munmap", "VirtualAlloc", "VirtualProtect",
]

def find_import_addrs(proj, names):
    """
    Try to locate imported symbol addresses for the main binary.
    Returns a mapping name -> address
    """
    res = {}
    main = proj.loader.main_object
    for n in names:
        try:
            sym = proj.loader.find_symbol(n)
        except Exception:
            sym = None
        if sym is not None and sym.rebased_addr is not None:
            res[n] = sym.rebased_addr
        else:
            for imp in getattr(main, "imports", []) or []:
                try:
                    imp_name = getattr(imp, "name", None) or (imp[0] if isinstance(imp, tuple) and len(imp) > 0 else None)
                except Exception:
                    imp_name = None
                if not imp_name:
                    continue
                if imp_name.lower() == n.lower():
                    addr = getattr(imp, "rebased_addr", None) or getattr(imp, "plt", None) or None
                    if addr:
                        res[n] = addr
                        break
    return res

def ensure_outdirs():
    if not os.path.isdir("adv_results"):
        os.makedirs("adv_results", exist_ok=True)

def get_stash(simgr, name):
    """
    Safely fetch a stash from the SimulationManager across angr versions.
    Never raises; always returns a list.
    """
    stashes = getattr(simgr, "stashes", None)
    if isinstance(stashes, dict):
        return stashes.get(name, []) or []
    return getattr(simgr, name, []) or []

def run_analysis(binary_path, find_addr=None, timeout=30, max_steps=2000, verbose=False):
    ensure_outdirs()
    # timezone-aware UTC (fixes deprecation warning)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_json = os.path.join("adv_results", f"{os.path.basename(binary_path)}_analysis_{ts}.json")

    LOG.info("Loading project: %s", binary_path)
    proj = angr.Project(binary_path, auto_load_libs=False)

    LOG.info("Building quick CFG (fast) - this helps locate plt/imports")
    try:
        proj.analyses.CFGFast()
    except Exception as e:
        LOG.warning("CFGFast failed: %s", e)

    LOG.info("Searching imports for common API names...")
    import_addrs = find_import_addrs(proj, COMMON_API_NAMES)
    LOG.info("Found %d candidate import symbols", len(import_addrs))
    if verbose:
        for k, v in import_addrs.items():
            LOG.info("  %s -> 0x%x", k, v)

    findings = []

    # Hook handler will get called when execution reaches the symbol's address
    def make_hook(name):
        def hook_fn(state):
            pc = state.addr
            LOG.info("Hook hit: %s at %#x", name, pc)
            try:
                constraints = [str(c) for c in state.solver.constraints[:10]]
                regs = {}
                for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi"):
                    if proj.arch.registers.get(r):
                        regs[r] = state.regs.__getattr__(r).__repr__()[:120]
            except Exception as e:
                constraints = [f"<error reading constraints: {e}>"]
                regs = {}

            findings.append({
                "api": name,
                "hit_addr": pc,
                "constraints_sample": constraints,
                "regs_sample": regs,
                "timestamp": time.time(),
            })
        return hook_fn

    # Install hooks for each import address we found
    for name, addr in import_addrs.items():
        try:
            proj.hook(addr, make_hook(name), length=0)
            LOG.info("Installed hook for %s at %s", name, hex(addr))
        except Exception as e:
            LOG.warning("Failed to hook %s at %s: %s", name, hex(addr) if addr else addr, e)

    # Start symbolic execution
    start_state = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(start_state)

    start_time = time.time()
    steps = 0
    LOG.info("Starting symbolic exploration (timeout=%ds, max_steps=%d)...", timeout, max_steps)
    try:
        while time.time() - start_time < timeout and steps < max_steps and len(simgr.active) > 0:
            steps += 1
            simgr.step()

            # Per-state checks
            for s in list(simgr.active):
                pc = s.addr
                # Hit import addresses (manual call to the hook if sitting right on the PLT)
                for name, addr in import_addrs.items():
                    if pc == addr:
                        LOG.info("Direct hit (active state) at %s for %s", hex(pc), name)
                        make_hook(name)(s)

                # Reachability of a user-specified address
                if find_addr and pc == find_addr:
                    LOG.info("Reached user requested address: %s", hex(pc))
                    findings.append({
                        "event": "found_target",
                        "target_addr": pc,
                        "timestamp": time.time()
                    })
                    simgr.move(from_stash='active', to_stash='found', filter_func=lambda st: st.addr == pc)

            # Safe check for 'found' stash (works across angr versions)
            if get_stash(simgr, "found"):
                LOG.info("Exploration found target state(s); stopping early.")
                break

    except KeyboardInterrupt:
        LOG.warning("Interrupted by user, continuing to dump findings.")
    except Exception as e:
        LOG.exception("Exception during exploration: %s", e)

    # Optional: show stashes that exist at the end
    try:
        stashes = getattr(simgr, "stashes", None)
        if isinstance(stashes, dict):
            LOG.info("Final stashes: %s", list(stashes.keys()))
    except Exception:
        pass

    # Summarize results
    summary = {
        "binary": os.path.abspath(binary_path),
        "timestamp_utc": ts,
        "found_count": len(findings),
        "findings": findings,
        "imported_candidates": {k: hex(v) for k, v in import_addrs.items()},
        "steps_run": steps,
    }

    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)

    LOG.info("Wrote results to %s", out_json)
    LOG.info("Done - %d findings", len(findings))
    return summary

def main():
    p = argparse.ArgumentParser(description="Simple angr analysis runner for anti-debug/injection detection")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--find", help="Address (hex) to attempt to reach (0x...)", default=None)
    p.add_argument("--timeout", type=int, default=30, help="Timeout seconds for exploration")
    p.add_argument("--max-steps", type=int, default=2000, help="Maximum simulation steps")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    find_addr = None
    if args.find:
        find_addr = int(args.find, 16) if args.find.startswith("0x") else int(args.find)

    run_analysis(args.binary, find_addr=find_addr, timeout=args.timeout, max_steps=args.max_steps, verbose=args.verbose)

if __name__ == "__main__":
    main()
