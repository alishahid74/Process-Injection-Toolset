#!/usr/bin/env python3
"""
slice_provenance.py

Backward-slicing / provenance helper using angr's BackwardSlice analysis.

What it does:
 - Builds an accurate CFG (CFGEmulated) required by BackwardSlice (configurable parameters).
 - Optionally computes CDG and DDG (DDG is slow) and uses them when building the slice.
 - Allows the user to specify a target as either:
     * a function address (hex or decimal) using --func
     * a basic block address (hex or decimal) using --block
     * the script will use statement ID -1 (meaning "beginning of the node") by default.
 - Produces:
     * Human-readable debug repr of the slice
     * A DOT file representing the sub-CFG in the slice (nodes=basic blocks/SimProcs)
     * Optional HTML report embedding DOT->PNG (requires Graphviz)
 - Use this to trace the provenance of values that reach a callsite (e.g., WriteProcessMemory) or any target block.

Usage examples:
  python3 slice_provenance.py target.exe --func 0x401000 --out slice.dot --png slice.png --use-ddg
  python3 slice_provenance.py target_bin --block 0x4006b0 --out slice.dot --control-only

Notes / caveats:
 - CFGEmulated and DDG can be slow for large binaries. Start with --control-only to get a CFG-only slice.
 - The script attempts reasonable fallbacks and will print progress and helpful errors.
"""

import argparse, os, sys, shutil, subprocess, textwrap
import logging

def write_dot_from_graph(nx_graph, out_path, title=None):
    try:
        import networkx as nx
    except Exception:
        print("[!] networkx is required to export graph; please install networkx")
        return False
    with open(out_path, "w", encoding='utf-8') as fh:
        fh.write("digraph slice {\n")
        fh.write("  rankdir=LR;\n")
        if title:
            fh.write('  label="%s"; labelloc=top; fontsize=14;\n' % title.replace('"', '\\"'))
        for n in nx_graph.nodes():
            label = str(n)
            # try to get addr attribute
            try:
                addr = getattr(n, "addr", None) or (n if isinstance(n, int) else None)
                if addr is not None:
                    label = "0x%x" % addr
            except Exception:
                pass
            fh.write('  n_%s [label="%s"];\n' % (str(abs(hash(n)))[:10], label.replace('"', '\\"')))
        fh.write("\n")
        for a,b in nx_graph.edges():
            fh.write("  n_%s -> n_%s;\n" % (str(abs(hash(a)))[:10], str(abs(hash(b)))[:10]))
        fh.write("}\n")
    return True

def render_dot(dot_path, out_png):
    dot = shutil.which("dot")
    if not dot:
        print("[!] Graphviz 'dot' not found in PATH; cannot render PNG. Install graphviz package.")
        return False
    cmd = [dot, "-Tpng", dot_path, "-o", out_png]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print("[!] dot failed:", e)
        return False

def main():
    p = argparse.ArgumentParser(description="Backward slice / provenance helper using angr.BackwardSlice")
    p.add_argument("target", help="binary to analyze")
    p.add_argument("--func", help="function address (hex like 0x401000) to slice to")
    p.add_argument("--block", help="basic block address (hex like 0x401234) to slice to (alternative to --func)")
    p.add_argument("--out", help="output DOT file for the slice (recommended)", default="slice.dot")
    p.add_argument("--png", help="optional PNG render of DOT (requires Graphviz)")
    p.add_argument("--use-ddg", action="store_true", help="compute DDG (data-dependence graph) to improve slice precision (can be slow)")
    p.add_argument("--control-only", action="store_true", help="build CFG-only slice (faster, does not compute DDG)")
    p.add_argument("--context-sensitivity", type=int, default=0, help="context sensitivity level for CFGEmulated (0..2)")
    p.add_argument("--keep-state", action="store_true", help="keep states during CFGEmulated (required for DDG)")
    p.add_argument("--state-refs", action="store_true", help="add angr.sim_options.refs to CFGEmulated state options (recommended when using DDG)")
    p.add_argument("--auto-load-libs", action="store_true", help="let angr auto-load libs (may be slower)")
    p.add_argument("--log", help="log level (DEBUG/INFO/WARNING)", default="INFO")
    args = p.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    target = os.path.expanduser(args.target)
    if not os.path.exists(target):
        print("[!] target not found:", target); sys.exit(1)

    if not (args.func or args.block):
        print("[!] either --func or --block is required. Use --func to provide a function address to slice to, or --block for a basic block address.")
        sys.exit(1)

    try:
        import angr
    except Exception as e:
        print("[!] angr is required but failed to import:", e); sys.exit(1)

    print("[*] loading project (this may take a few seconds)...")
    proj = angr.Project(target, auto_load_libs=args.auto_load_libs)

    # Build accurate CFG
    cfg_kwargs = {}
    if args.keep_state:
        cfg_kwargs['keep_state'] = True
    if args.state_refs:
        cfg_kwargs['state_add_options'] = angr.sim_options.refs
    if args.context_sensitivity and args.context_sensitivity > 0:
        cfg_kwargs['context_sensitivity_level'] = args.context_sensitivity

    print("[*] building CFGEmulated (this may be slow for big binaries)...")
    try:
        cfg = proj.analyses.CFGEmulated(**cfg_kwargs)
    except Exception as e:
        print("[!] CFGEmulated failed:", e)
        print("[*] you may try again with --control-only to build a CFG-only slice (no DDG)")
        sys.exit(1)

    # resolve target node
    target_addr = None
    if args.func:
        try:
            if args.func.lower().startswith("0x"):
                target_addr = int(args.func, 16)
            else:
                target_addr = int(args.func)
        except Exception as e:
            print("[!] cannot parse --func value:", e); sys.exit(1)
    else:
        try:
            if args.block.lower().startswith("0x"):
                target_addr = int(args.block, 16)
            else:
                target_addr = int(args.block)
        except Exception as e:
            print("[!] cannot parse --block value:", e); sys.exit(1)

    # try to obtain a CFGNode instance for the address
    target_node = None
    try:
        target_node = cfg.model.get_any_node(target_addr)
    except Exception:
        target_node = None

    if target_node is None:
        # try to find node by iterating model
        try:
            for n in cfg.model.nodes():
                addr = getattr(n, "addr", None) or (n if isinstance(n, int) else None)
                if addr == target_addr:
                    target_node = n
                    break
        except Exception:
            target_node = None

    if target_node is None:
        print("[!] unable to find a CFG node for 0x%x in the generated CFG." % target_addr)
        print("[*] available functions (first 20):")
        for f in list(cfg.kb.functions.values())[:20]:
            print("  0x%x %s" % (f.addr, getattr(f, 'name', '')))
        sys.exit(1)

    print("[*] target CFG node acquired:", target_node)

    # compute optional CDG / DDG if requested
    cdg = None
    ddg = None
    if args.use_ddg and not args.control_only:
        print("[*] computing CDG (control-dependence graph)...")
        try:
            cdg = proj.analyses.CDG(cfg)
            print("[*] CDG computed")
        except Exception as e:
            print("[!] CDG failed:", e)
            cdg = None
        print("[*] computing DDG (data-dependence graph); this can be slow...")
        try:
            ddg = proj.analyses.DDG(cfg)
            print("[*] DDG computed")
        except Exception as e:
            print("[!] DDG failed:", e)
            ddg = None
    else:
        if args.control_only:
            print("[*] building a CFG-only backward slice (control-flow slice)")

    # build targets list for BackwardSlice: (CFGNode, stmt_id) tuples. Use -1 to indicate whole node start.
    targets = [(target_node, -1)]
    print("[*] building BackwardSlice (this may take a little while)...")
    try:
        if cdg is not None or ddg is not None:
            bs = proj.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=targets)
        else:
            # control_flow_slice True tells it to compute based solely on CFG
            bs = proj.analyses.BackwardSlice(cfg, control_flow_slice=True, targets=targets)
    except Exception as e:
        print("[!] BackwardSlice analysis failed:", e)
        sys.exit(1)

    print("[*] BackwardSlice constructed:")
    try:
        print(bs.dbg_repr())
    except Exception:
        print(str(bs))

    # export slice graphs
    if hasattr(bs, "cfg_nodes_in_slice") and bs.cfg_nodes_in_slice is not None:
        dot_file = args.out
        print("[*] exporting slice CFG nodes graph to DOT:", dot_file)
        ok = write_dot_from_graph(bs.cfg_nodes_in_slice, dot_file, title="Slice for 0x%x" % target_addr)
        if ok and args.png:
            if render_dot(dot_file, args.png):
                print("[*] PNG written to", args.png)
    elif hasattr(bs, "runs_in_slice") and bs.runs_in_slice is not None:
        dot_file = args.out
        print("[*] exporting runs_in_slice to DOT:", dot_file)
        ok = write_dot_from_graph(bs.runs_in_slice, dot_file, title="Slice for 0x%x" % target_addr)
        if ok and args.png:
            if render_dot(dot_file, args.png):
                print("[*] PNG written to", args.png)
    else:
        print("[!] BackwardSlice does not contain exportable graphs. Printing repr instead.")
        print(bs)

    print("[*] done.")

if __name__ == '__main__':
    main()
