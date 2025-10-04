#!/usr/bin/env python3
"""
decompile_func.py

Usage:
  python3 scripts/decompile_func.py <target> --func <addr> --out <out.c> [--cfg {fast,full}] [--timeout SECS]

Attempts to decompile a single function using angr's decompiler.
Tries multiple angr API patterns for wider compatibility.
"""
import argparse
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format="[*] %(message)s")
log = logging.getLogger("decompile_func")

try:
    import angr
except Exception as e:
    log.error("angr import failed: %s", e)
    log.error("Install angr in your environment (e.g. pip install angr).")
    sys.exit(2)

def build_cfg(proj, cfg_mode):
    if cfg_mode == "fast":
        log.info("building CFGFast...")
        return proj.analyses.CFGFast()
    else:
        log.info("building CFGEmulated (may be slower)...")
        # CFGEmulated can be slow, but sometimes helps the decompiler
        try:
            return proj.analyses.CFGEmulated()
        except Exception:
            # fallback to CFGFast if CFGEmulated not available or fails
            log.warning("CFGEmulated failed — falling back to CFGFast")
            return proj.analyses.CFGFast()

def try_decompile_via_project_decompiler(proj, func_addr, cfg=None, timeout=None):
    """
    Try the modern pattern where Project exposes a decompiler instance or a Project.Decompiler helper.
    Return (success, ccode_str_or_error)
    """
    # pattern A: proj.decompiler.decompile_func(...)
    dec = None
    try:
        dec = getattr(proj, "decompiler", None)
        if dec is not None:
            log.info("Using proj.decompiler API")
            # some versions provide decompile_func or decompile
            if hasattr(dec, "decompile_func"):
                cfunc = dec.decompile_func(func_addr)
                return True, getattr(cfunc, "text", str(cfunc))
            if hasattr(dec, "decompile"):
                cfunc = dec.decompile(func_addr)
                # Decompiler.decompile sometimes returns a CFunction object
                return True, getattr(cfunc, "text", str(cfunc))
    except Exception as e:
        return False, f"proj.decompiler attempt failed: {e}"

    # pattern B: Project.Decompiler class bound on project
    try:
        DecompilerClass = getattr(proj, "Decompiler", None)
        if DecompilerClass is not None:
            log.info("Using proj.Decompiler(...) API")
            if cfg is None:
                cfg = build_cfg(proj, "fast")
            inst = DecompilerClass(proj, cfg=cfg)
            if hasattr(inst, "decompile_func"):
                cfunc = inst.decompile_func(func_addr)
                return True, getattr(cfunc, "text", str(cfunc))
            if hasattr(inst, "decompile"):
                cfunc = inst.decompile(func_addr)
                return True, getattr(cfunc, "text", str(cfunc))
    except Exception as e:
        return False, f"proj.Decompiler attempt failed: {e}"

    return False, "No project-level decompiler API available."

def try_decompiler_module(proj, func_addr, cfg=None):
    """
    Try importing angr.analyses.decompiler.* Decompiler classes and use them.
    """
    try:
        # try common module paths
        candidates = [
            "angr.analyses.decompiler.decompiler",
            "angr.analyses.decompiler",
            "angr.analyses.decompiler.decompile",
        ]
        for modname in candidates:
            try:
                module = __import__(modname, fromlist=["*"])
            except Exception:
                continue
            # try to find a Decompiler class inside
            for attr in ("Decompiler", "Decompilation", "DecompilerEngine", "DecompilationEngine"):
                DecompilerClass = getattr(module, attr, None)
                if DecompilerClass is None:
                    continue
                log.info("Using %s.%s", modname, attr)
                if cfg is None:
                    cfg = build_cfg(proj, "fast")
                try:
                    inst = DecompilerClass(proj, cfg=cfg)
                except TypeError:
                    # some constructors only take proj, or only cfg, try a couple variants
                    try:
                        inst = DecompilerClass(proj)
                    except Exception:
                        try:
                            inst = DecompilerClass(cfg=cfg)
                        except Exception as e:
                            log.debug("Could not instantiate %s: %s", DecompilerClass, e)
                            continue
                # attempt to decompile
                if hasattr(inst, "decompile_func"):
                    cfunc = inst.decompile_func(func_addr)
                    return True, getattr(cfunc, "text", str(cfunc))
                if hasattr(inst, "decompile"):
                    cfunc = inst.decompile(func_addr)
                    return True, getattr(cfunc, "text", str(cfunc))
        return False, "No usable Decompiler class found in angr.analyses.decompiler modules."
    except Exception as e:
        return False, f"decompiler module attempt failed: {e}"

def main():
    p = argparse.ArgumentParser(description="Decompile a function using angr-based decompiler (best-effort).")
    p.add_argument("target", help="binary file to analyze")
    p.add_argument("--func", required=True, help="function address (hex, e.g. 0x401166) or symbol name")
    p.add_argument("--out", required=True, help="output C filename")
    p.add_argument("--cfg", choices=("fast","full"), default="fast", help="CFG flavor for analysis (fast or full)")
    p.add_argument("--timeout", type=int, default=30, help="overall timeout (seconds) - best-effort, not strict")
    args = p.parse_args()

    target = args.target
    func_arg = args.func
    out_path = args.out

    if not os.path.exists(target):
        log.error("Target file not found: %s", target)
        sys.exit(2)

    # normalize function address if hex
    try:
        if func_arg.startswith("0x") or func_arg.isdigit():
            func_addr = int(func_arg, 0)
        else:
            # treat as a symbol name; will try to look up in project
            func_addr = func_arg
    except Exception:
        func_addr = func_arg

    log.info("loading project (this may take a few seconds)...")
    try:
        proj = angr.Project(target, auto_load_libs=False)
    except Exception as e:
        log.error("angr.Project() failed: %s", e)
        log.error("Make sure target is a real binary; try opening a single file path (not a dir).")
        sys.exit(2)

    cfg = None
    log.info("ensuring a CFG exists (some decompiler APIs require it)...")
    try:
        cfg = build_cfg(proj, args.cfg)
    except Exception as e:
        log.warning("CFG build encountered an error: %s", e)
        cfg = None

    # If function was provided as symbol name, try to resolve
    if isinstance(func_addr, str) and not func_addr.startswith("0x"):
        sym = proj.loader.find_symbol(func_addr)
        if sym is None:
            log.error("Could not resolve symbol name '%s' in binary.", func_addr)
            sys.exit(3)
        func_addr = sym.rebased_addr
        log.info("Resolved symbol '%s' -> 0x%x", func_arg, func_addr)

    # Try project-decompiler APIs first
    log.info("attempting decompilation using project-level helpers...")
    ok, res = try_decompile_via_project_decompiler(proj, func_addr, cfg=cfg, timeout=args.timeout)
    if not ok:
        log.info("project-level decompiler attempt failed or not present: %s", res)
        log.info("trying to import angr decompiler modules directly...")
        ok2, res2 = try_decompiler_module(proj, func_addr, cfg=cfg)
        if not ok2:
            log.error("All decompiler attempts failed.")
            log.error("Last error(s):")
            log.error(" - project-level: %s", res)
            log.error(" - module-level: %s", res2)
            log.error("")
            log.error("Notes / suggestions:")
            log.error("  * Make sure you have the decompiler dependencies installed (ailment, pyvex, angr's decompiler extras).")
            log.error("  * Newer angr versions may expose proj.decompiler or Project.Decompiler.")
            log.error("  * If you want, run `python3 -c \"import angr; print(dir(angr.Project('...')) )\"` to inspect available attributes.")
            sys.exit(4)
        else:
            csource = res2
    else:
        csource = res

    # Write the output file
    try:
        with open(out_path, "w") as f:
            f.write("// Decompiled by angr-based decompiler wrapper\n")
            f.write("// target: %s\n\n" % (os.path.abspath(target),))
            if isinstance(func_arg, int):
                f.write("// function: 0x%x\n\n" % func_arg)
            else:
                f.write("// function: %s\n\n" % func_arg)
            f.write(csource if csource is not None else "// (decompiler returned nothing)\n")
        log.info("Decompiled output written to %s", out_path)
    except Exception as e:
        log.error("Failed to write output file: %s", e)
        sys.exit(5)

if __name__ == "__main__":
    main()
