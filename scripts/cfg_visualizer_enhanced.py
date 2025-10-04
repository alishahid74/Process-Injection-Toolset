#!/usr/bin/env python3
"""
cfg_visualizer_enhanced.py (annotated with detector findings)

Enhanced CFG visualizer that:
 - builds function-level or block-level graphs
 - annotates nodes & edges using results from detectors CSV (colors, labels)
 - outputs DOT, optional PNG, and optional small HTML report that embeds PNGs

Usage (examples):
  python3 scripts/cfg_visualizer_enhanced.py target_bin --out callgraph.dot --png callgraph.png --findings merged_findings.csv
  python3 scripts/cfg_visualizer_enhanced.py target_bin --func 0x401000 --block-level --out blocks.dot --png blocks.png --findings merged_findings.csv --html vis_report.html
"""
import argparse, os, sys, csv, re, shutil, subprocess
from typing import Dict, List, Tuple

SUSPICIOUS_COLOR = "#ff6666"
WEAK_COLOR = "#ffcc66"
NORMAL_COLOR = "#a0c0ff"
EDGE_SUSPICIOUS_COLOR = "#ff0000"

def extract_hex_addrs(text: str) -> List[int]:
    """Find hex addresses like 0x401000 in a text blob and return ints."""
    if not text:
        return []
    matches = re.findall(r"0x[0-9a-fA-F]+", text)
    addrs = []
    for m in matches:
        try:
            addrs.append(int(m, 16))
        except Exception:
            pass
    return addrs

def parse_findings_csv(csv_path: str, target_file: str = None):
    """
    Parse findings CSV; return mapping:
      func_map: { func_addr(int) : [ {row, detection, confidence, block_addr (opt), details} ] }
    Also keep a list of all findings rows for fallback.
    """
    func_map = {}
    rows = []
    if not csv_path or not os.path.exists(csv_path):
        return func_map, rows
    with open(csv_path, newline='', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            rows.append(row)
            f = row.get("file", "") or row.get("filename", "") or ""
            if target_file and os.path.basename(f) != os.path.basename(target_file) and f != target_file:
                continue
            # parse function address
            fa = row.get("func_addr") or row.get("function_addr") or row.get("func") or row.get("funcaddr") or row.get("function")
            try:
                a = None
                if fa:
                    if isinstance(fa, str) and fa.lower().startswith("0x"):
                        a = int(fa, 16)
                    else:
                        a = int(fa)
                else:
                    a = None
            except Exception:
                a = None
            # parse block addr, if any
            ba = row.get("block_addr") or row.get("block") or row.get("block_addr_hex")
            try:
                b = None
                if ba:
                    if isinstance(ba, str) and ba.lower().startswith("0x"):
                        b = int(ba, 16)
                    else:
                        b = int(ba)
                else:
                    b = None
            except Exception:
                b = None
            det = row.get("detection_type") or row.get("type") or row.get("detail") or row.get("detection") or ""
            conf = 0.0
            try:
                conf = float(row.get("confidence") or 0.0)
            except Exception:
                conf = 0.0
            details = row.get("dasm_snippet_or_hex") or row.get("detail") or row.get("dasm") or row.get("description") or ""
            callee_addrs = extract_hex_addrs(details)
            entry = {"row": row, "detection": det, "confidence": conf, "block_addr": b, "details": details, "callees": callee_addrs}
            if a is not None:
                func_map.setdefault(a, []).append(entry)
    return func_map, rows

def write_dot(nodes: Dict[int,str], edges: List[Tuple[int,int]], out_path: str, node_attrs: Dict[int, Dict]=None, edge_attrs: Dict[Tuple[int,int], Dict]=None, title: str=None):
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("digraph cfg {\n")
        fh.write("  rankdir=LR;\n")
        fh.write("  node [shape=box,fontname=\"Helvetica\"];\n")
        if title:
            fh.write('  label="%s"; labelloc=top; fontsize=18;\n' % title.replace('"', '\\"'))
        # nodes
        for nid, label in nodes.items():
            node_name = "n_%x" % nid
            safe_label = label.replace('"', '\\"')
            attrs = ""
            if node_attrs and nid in node_attrs:
                a = node_attrs[nid]
                styles = []
                if a.get("color"):
                    styles.append('style=filled fillcolor="%s"' % a["color"])
                if a.get("shape"):
                    styles.append("shape=%s" % a["shape"])
                if a.get("xlabel"):
                    # Graphviz does not have xlabel for nodes; append to label instead
                    safe_label = safe_label + "\\n" + a["xlabel"].replace('"', '\\"')
                if styles:
                    attrs = " " + " ".join(styles)
            fh.write('  %s [label="%s"%s];\n' % (node_name, safe_label, attrs))
        fh.write("\n")
        # edges
        for a,b in sorted(edges):
            ename = (a,b)
            fa = "n_%x" % a
            fb = "n_%x" % b
            attr_str = ""
            if edge_attrs and ename in edge_attrs:
                ea = edge_attrs[ename]
                parts = []
                if ea.get("color"):
                    parts.append('color="%s"' % ea["color"])
                if ea.get("label"):
                    parts.append('label="%s"' % ea["label"].replace('"','\\"'))
                if parts:
                    attr_str = " [" + ", ".join(parts) + "]"
            fh.write("  %s -> %s%s;\n" % (fa, fb, attr_str))
        fh.write("}\n")

def render_dot_to_png(dot_path: str, png_path: str) -> bool:
    dot = shutil.which("dot")
    if not dot:
        print("[!] Graphviz 'dot' not found in PATH; cannot render PNG.")
        return False
    cmd = [dot, "-Tpng", dot_path, "-o", png_path]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print("[!] dot failed:", e)
        return False

# Reuse build/transition functions from earlier visualizer code:
def build_function_call_graph(proj, cfg, func_filter=None, max_nodes=None):
    nodes = {}
    edges = set()
    funcs = list(cfg.kb.functions.values())
    count = 0
    for f in funcs:
        if max_nodes and count >= max_nodes:
            break
        faddr = f.addr
        fname = getattr(f, "name", "") or ""
        if func_filter:
            if not re.search(func_filter, fname, re.IGNORECASE) and not re.search(func_filter, "0x%x" % faddr, re.IGNORECASE):
                continue
        label = ("0x%x\\n%s" % (faddr, fname)) if fname else ("0x%x" % faddr)
        nodes[faddr] = label
        count += 1
        for block in getattr(f, "blocks", []):
            try:
                insns = getattr(block.capstone, "insns", [])
                for ins in insns:
                    m = (ins.mnemonic or "").lower()
                    if not m.startswith("call"):
                        continue
                    op = (ins.op_str or "").strip()
                    m1 = re.search(r"0x[0-9a-fA-F]+", op)
                    if m1:
                        match = m1.group(0)
                    else:
                        m2 = re.search(r"([0-9a-fA-F]+)h\\b", op)
                        match = ("0x" + m2.group(1)) if m2 else None
                    if match:
                        try:
                            callee = int(match, 16)
                            edges.add((faddr, callee))
                            if callee not in nodes:
                                nodes[callee] = "0x%x" % callee
                        except Exception:
                            pass
            except Exception:
                continue
    return nodes, sorted(list(edges))

def short_disasm_of_block(proj, addr, size=128):
    try:
        b = proj.factory.block(addr, size=size)
        insns = []
        for ins in getattr(b.capstone, "insns", []):
            insns.append("%s %s" % (ins.mnemonic, ins.op_str or ""))
        s = "\\n".join(insns[:6])
        return s
    except Exception:
        return "block_0x%x" % addr

def build_block_graph_for_function(proj, cfg, faddr):
    func = cfg.kb.functions.get(faddr)
    if func is None:
        raise ValueError("function 0x%x not found in CFG" % faddr)
    tg = getattr(func, "transition_graph", None)
    nodes = {}
    edges = set()
    if tg is None:
        for b in getattr(func, "blocks", []):
            nodes[b.addr] = short_disasm_of_block(proj, b.addr)
        return nodes, sorted(list(edges))
    try:
        for n in tg.nodes():
            addr = getattr(n, "addr", None) or (n if isinstance(n, int) else None)
            if addr is None:
                continue
            nodes[addr] = short_disasm_of_block(proj, addr)
        for a,b in tg.edges():
            a_addr = getattr(a, "addr", None) or (a if isinstance(a, int) else None)
            b_addr = getattr(b, "addr", None) or (b if isinstance(b, int) else None)
            if a_addr is None or b_addr is None:
                continue
            edges.add((a_addr, b_addr))
    except Exception:
        try:
            for n in tg.nodes():
                addr = int(n)
                nodes[addr] = short_disasm_of_block(proj, addr)
            for (a,b) in tg.edges():
                edges.add((int(a), int(b)))
        except Exception as e:
            raise RuntimeError("unable to extract transition_graph nodes/edges: %s" % e)
    return nodes, sorted(list(edges))

def generate_html_report(html_path, title, images, summary_rows):
    html = ["<html><head><meta charset='utf-8'><title>%s</title></head><body>" % title]
    html.append("<h1>%s</h1>" % title)
    for img, caption in images:
        html.append("<h2>%s</h2>" % caption)
        html.append('<img src="%s" style="max-width:100%%;border:1px solid #666"><br>' % os.path.basename(img))
    if summary_rows:
        html.append("<h2>Summary</h2>")
        html.append("<table border='1' cellpadding='4'><tr><th>Function</th><th>Detection</th><th>Confidence</th><th>Details</th></tr>")
        for r in summary_rows:
            html.append("<tr><td>%s</td><td>%s</td><td>%.2f</td><td>%s</td></tr>" % (r.get("func"), r.get("detection"), r.get("confidence",0.0), r.get("detail","")))
        html.append("</table>")
    html.append("</body></html>")
    with open(html_path, "w", encoding='utf-8') as fh:
        fh.write("\\n".join(html))

def main():
    p = argparse.ArgumentParser(description="Enhanced CFG visualizer & annotator (with detector findings)")
    p.add_argument("target", help="binary to analyze")
    p.add_argument("--out", required=True, help="output DOT file")
    p.add_argument("--png", help="optional PNG output (requires Graphviz)")
    p.add_argument("--block-level", action="store_true", help="produce block-level CFG for the function given by --func")
    p.add_argument("--func", help="function address (hex like 0x401000) or name regex (required for --block-level)")
    p.add_argument("--filter", help="regex to filter functions included in function-level graph", default=None)
    p.add_argument("--limit", type=int, default=0, help="limit number of functions scanned (0=all)")
    p.add_argument("--auto-load-libs", action="store_true", help="let angr auto-load libs (may be slower)")
    p.add_argument("--findings", help="optional findings CSV (from detectors) to annotate nodes/edges")
    p.add_argument("--html", help="optional HTML report filename to generate")
    args = p.parse_args()

    target = os.path.expanduser(args.target)
    if not os.path.exists(target):
        print("[!] target not found:", target); sys.exit(1)

    try:
        import angr
    except Exception as e:
        print("[!] angr is required but failed to import:", e); sys.exit(1)

    print("[*] loading project...")
    proj = angr.Project(target, auto_load_libs=args.auto_load_libs)
    print("[*] building CFGFast...")
    cfg = proj.analyses.CFGFast()

    findings_map, all_rows = parse_findings_csv(args.findings, target_file=target) if args.findings else ({}, [])

    images = []
    summary_rows = []

    if args.block_level:
        if not args.func:
            print("[!] --func required for --block-level"); sys.exit(1)
        # resolve function address if name regex provided
        faddr = None
        if re.match(r"^0x[0-9a-fA-F]+$", args.func):
            faddr = int(args.func, 16)
        else:
            for f in cfg.kb.functions.values():
                if re.search(args.func, getattr(f, "name", "") or "", re.IGNORECASE):
                    faddr = f.addr; break
        if faddr is None:
            print("[!] function not found for", args.func); sys.exit(2)
        print("[*] building block-level graph for function 0x%x" % faddr)
        nodes, edges = build_block_graph_for_function(proj, cfg, faddr)
        node_attrs = {}
        # color blocks that appear in findings for this function
        if faddr in findings_map:
            for ent in findings_map[faddr]:
                if ent.get("block_addr"):
                    b = ent["block_addr"]
                    node_attrs[b] = {"color": SUSPICIOUS_COLOR, "xlabel": "%s (%.1f)" % (ent.get("detection",""), ent.get("confidence",0.0))}
                    summary_rows.append({"func": "0x%x" % faddr, "detection": ent.get("detection"), "confidence": ent.get("confidence",0.0), "detail": ent.get("details","")})
                else:
                    # if no block, color all blocks for that function
                    for n in nodes.keys():
                        node_attrs[n] = {"color": WEAK_COLOR}
                    summary_rows.append({"func": "0x%x" % faddr, "detection": ent.get("detection"), "confidence": ent.get("confidence",0.0), "detail": ent.get("details","")})
        out_dot = args.out
        write_dot(nodes, edges, out_dot, node_attrs=node_attrs, title="Function 0x%x blocks" % faddr)
        if args.png:
            if render_dot_to_png(out_dot, args.png):
                images.append((args.png, "Block-level CFG for 0x%x" % faddr))
    else:
        nodes, edges = build_function_call_graph(proj, cfg, func_filter=args.filter, max_nodes=(args.limit or None))
        node_attrs = {}
        edge_attrs = {}
        # annotate nodes and edges using findings_map
        for faddr in list(nodes.keys()):
            if faddr in findings_map:
                best = max(findings_map[faddr], key=lambda x: x.get("confidence",0.0))
                color = SUSPICIOUS_COLOR if best.get("confidence",0) >= 8.0 else WEAK_COLOR
                node_attrs[faddr] = {"color": color, "xlabel": "%s (%.1f)" % (best.get("detection",""), best.get("confidence",0.0))}
                summary_rows.append({"func": "0x%x" % faddr, "detection": best.get("detection"), "confidence": best.get("confidence",0.0), "detail": best.get("details","")})
                # annotate edges if we can find callee addresses mentioned in details
                for ent in findings_map[faddr]:
                    for callee in ent.get("callees", []):
                        if (faddr, callee) in edges:
                            edge_attrs[(faddr, callee)] = {"color": EDGE_SUSPICIOUS_COLOR, "label": ent.get("detection","")}
                        else:
                            # edge not present (e.g., indirect or external). Add a synthetic node + edge to show relation.
                            if callee not in nodes:
                                nodes[callee] = "0x%x" % callee
                            edge_attrs[(faddr, callee)] = {"color": EDGE_SUSPICIOUS_COLOR, "label": ent.get("detection"," (suspected)")}
        out_dot = args.out
        write_dot(nodes, edges, out_dot, node_attrs=node_attrs, edge_attrs=edge_attrs, title=os.path.basename(target))
        if args.png:
            if render_dot_to_png(out_dot, args.png):
                images.append((args.png, "Function-level call graph"))

    if args.html:
        html_path = args.html
        generate_html_report(html_path, "CFG Visualizer Report for %s" % os.path.basename(target), images, summary_rows)
        # copy images to same dir as html
        html_dir = os.path.dirname(html_path) or "."
        for img, _ in images:
            try:
                shutil.copy(img, os.path.join(html_dir, os.path.basename(img)))
            except Exception:
                pass
        print("[*] HTML report written to", html_path)

    print("[*] done. DOT written to", out_dot)
    if images:
        for img,_ in images:
            print("[*] image:", img)

if __name__ == '__main__':
    main()


#chmod +x scripts/cfg_visualizer_enhanced.py
