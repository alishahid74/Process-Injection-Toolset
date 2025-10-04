#!/usr/bin/env python3
"""
cfg_visualizer.py

Produces a function-level call graph DOT file (and optional PNG) for a binary using angr.

Features:
- Build CFGFast and extract call instructions from blocks (via capstone).
- Build a directed graph where nodes = functions (addr + optional name) and edges = direct calls to immediate addresses.
- Optionally focus on a single function (show only its outgoing calls) with --func <addr|name>.
- Optionally filter by regex on function name/address.
- Output: DOT file (required). Optionally render to PNG using Graphviz 'dot' if installed.

Usage examples:
  python3 cfg_visualizer.py /path/to/binary --out graph.dot
  python3 cfg_visualizer.py /path/to/binary --out graph.dot --png graph.png
  python3 cfg_visualizer.py /path/to/binary --out graph.dot --func 0x401000
  python3 cfg_visualizer.py /path/to/binary --out graph.dot --filter "inject|hollowing" --limit 200

Notes/limitations:
- This is a function-level call graph derived from direct 'call' instructions only (indirect calls via registers/PLT may not resolve to concrete targets).
- For better results, run on stripped/unstripped binaries and ensure capstone is available (angr usually provides Capstone).
"""
import argparse, os, sys, shutil, subprocess, re

def build_call_graph(proj, cfg, func_filter=None, max_nodes=None):
    """
    Build a simple call graph based on scanning capstone disassembly for 'call' instructions
    and extracting immediate operands (direct calls).
    Returns: nodes: dict(addr -> label), edges: set((caller_addr, callee_addr))
    """
    nodes = {}
    edges = set()
    funcs = list(cfg.kb.functions.values())
    addr_to_func = {f.addr: f for f in funcs}

    def label_for(faddr):
        f = addr_to_func.get(faddr)
        if f is None:
            return "0x%x" % faddr
        name = getattr(f, "name", None) or ""
        if name and not name.startswith("sub_"):
            return "0x%x\\n%s" % (faddr, name)
        return "0x%x" % faddr

    count = 0
    for f in funcs:
        if max_nodes and count >= max_nodes:
            break
        faddr = f.addr
        fname = getattr(f, "name", "") or ""
        if func_filter:
            # func_filter may match name or addr string
            if not re.search(func_filter, fname, re.IGNORECASE) and not re.search(func_filter, "0x%x" % faddr, re.IGNORECASE):
                continue
        nodes[faddr] = label_for(faddr)
        count += 1
        # iterate blocks and inspect capstone insns for call mnemonics
        for block in getattr(f, "blocks", []):
            try:
                insns = getattr(block.capstone, "insns", [])
                for ins in insns:
                    m = (ins.mnemonic or "").lower()
                    if not m.startswith("call"):
                        continue
                    op = (ins.op_str or "").strip()
                    # try to parse immediate address like 0x401020 or 401020h
                    match = None
                    m1 = re.search(r"0x[0-9a-fA-F]+", op)
                    if m1:
                        match = m1.group(0)
                    else:
                        m2 = re.search(r"([0-9a-fA-F]+)h\\b", op)
                        if m2:
                            match = "0x" + m2.group(1)
                        else:
                            m3 = re.search(r"\\b([0-9]{5,})\\b", op)
                            if m3:
                                try:
                                    match = hex(int(m3.group(1)))
                                except Exception:
                                    match = None
                    if match:
                        try:
                            callee = int(match, 16)
                            edges.add((faddr, callee))
                            if callee not in nodes:
                                nodes[callee] = label_for(callee)
                        except Exception:
                            pass
            except Exception:
                continue

    return nodes, edges

def write_dot(nodes, edges, out_path, title=None):
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("digraph callgraph {\n")
        fh.write("  rankdir=LR;\n")
        fh.write("  node [shape=box, fontname=\"Helvetica\"];\n")
        if title:
            fh.write('  label=\"%s\"; labelloc=top; fontsize=20;\n' % title.replace('"', '\\"'))
        for addr, label in nodes.items():
            name = "f_%x" % addr
            safe_label = label.replace('"', '\\"')
            fh.write('  %s [label=\"%s\"];\n' % (name, safe_label))
        fh.write("\n")
        for a,b in sorted(edges):
            fa = "f_%x" % a
            fb = "f_%x" % b
            fh.write("  %s -> %s;\n" % (fa, fb))
        fh.write("}\n")

def render_dot_to_png(dot_path, png_path):
    dot = shutil.which("dot")
    if not dot:
        print("[!] Graphviz 'dot' not found in PATH; cannot render PNG. Install graphviz package.")
        return False
    cmd = [dot, "-Tpng", dot_path, "-o", png_path]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print("[!] dot failed:", e)
        return False

def main():
    p = argparse.ArgumentParser(description="CFG / Call-graph visualizer (function-level)")
    p.add_argument("target", help="binary to analyze")
    p.add_argument("--out", required=True, help="output DOT filepath")
    p.add_argument("--png", help="optional path to render PNG (requires Graphviz 'dot')")
    p.add_argument("--func", help="optional: focus on function address or name (regex); shows nodes matching filter and their outgoing calls")
    p.add_argument("--filter", help="regex to filter which functions to include (by name or addr)", default=None)
    p.add_argument("--limit", type=int, default=0, help="limit number of functions scanned (0 = unlimited)")
    p.add_argument("--auto-load-libs", action="store_true", help="let angr auto-load libs (may be slower)")
    args = p.parse_args()

    target = os.path.expanduser(args.target)
    if not os.path.exists(target):
        print("[!] target not found:", target); sys.exit(1)

    try:
        import angr
    except Exception as e:
        print("[!] angr is required but failed to import:", e); sys.exit(1)

    print("[*] loading project (this may take a few seconds)...")
    proj = angr.Project(target, auto_load_libs=args.auto_load_libs)
    print("[*] building CFGFast (may take some time)...")
    cfg = proj.analyses.CFGFast()

    func_filter = args.func or args.filter
    max_nodes = args.limit if args.limit and args.limit > 0 else None

    print("[*] extracting call graph...")
    nodes, edges = build_call_graph(proj, cfg, func_filter=func_filter, max_nodes=max_nodes)

    print(f"[*] nodes: {len(nodes)} edges: {len(edges)}. Writing DOT -> {args.out}")
    write_dot(nodes, edges, args.out, title=os.path.basename(target))

    if args.png:
        ok = render_dot_to_png(args.out, args.png)
        if ok:
            print("[*] PNG rendered to", args.png)
        else:
            print("[!] PNG render failed. DOT still written.")

if __name__ == '__main__':
    main()
