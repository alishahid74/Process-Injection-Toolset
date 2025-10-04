#!/usr/bin/env python3
"""
orchestrator.py (with thumbnail generation & nicer gallery CSS)

Usage example:
  python3 scripts/orchestrator.py ./samples \
    --v2-out v2_findings.csv --threshold 7.0 --workers 3 \
    --symbolic --explore-timeout 8 --merge-out merged_findings.csv \
    --gallery-html visuals_gallery.html --thumbnail-size 240

Flags:
  --no-slice        skip running slice_provenance.py
  --no-decompile    skip running decompile_func.py
  --thumbnail-size  maximum pixel dimension for thumbnails (default 240)
  --skip-thumbnails do not create thumbnails (faster)
"""
import argparse, os, sys, csv, subprocess, shutil, multiprocessing, time, textwrap
from typing import List, Tuple

# try to import PIL for thumbnails
try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

def is_candidate_file(path):
    try:
        if path.lower().endswith((".exe", ".dll", ".pe", ".bin", ".so")):
            return True
        with open(path, "rb") as fh:
            head = fh.read(4)
            if head.startswith(b"MZ") or head.startswith(b"\x7fELF") or head.startswith(b"#!"):
                return True
    except Exception:
        pass
    return False

def enumerate_targets(path:str) -> List[str]:
    path = os.path.expanduser(path)
    if os.path.isdir(path):
        out=[]
        for root, _, files in os.walk(path):
            for fn in files:
                full = os.path.join(root, fn)
                if is_candidate_file(full):
                    out.append(full)
        return sorted(set(out))
    else:
        return [os.path.expanduser(path)]

def run_v2_on_file(py_exec, file_path, out_csv, out_html, yaradir):
    cmd = [py_exec, "scripts/extended_injection_detector_v2.py", file_path, "--out", out_csv, "--html", out_html, "--yaradir", yaradir]
    print("[*] v2:", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.stdout: print(p.stdout)
    if p.stderr: print(p.stderr)
    return p.returncode == 0

def run_advanced_on_file(py_exec, file_path, adv_csv, adv_html, yara_dir, cfg_mode="fast", symbolic=False, timeout=6):
    cmd = [py_exec, "scripts/advanced_angr_detector.py", file_path, "--out", adv_csv, "--html", adv_html, "--yaradir", yara_dir, "--cfg", cfg_mode]
    if symbolic:
        cmd.append("--symbolic")
        cmd += ["--explore-timeout", str(timeout)]
    print("[*] advanced:", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.stdout: print(p.stdout)
    if p.stderr: print(p.stderr)
    return p.returncode

def extract_func_addrs_from_csv(csv_path):
    addrs = []
    if not os.path.exists(csv_path):
        return addrs
    with open(csv_path, newline='', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            fa = row.get("func_addr") or row.get("function_addr") or row.get("func") or row.get("funcaddr")
            if not fa: continue
            try:
                if isinstance(fa, str) and fa.lower().startswith("0x"):
                    addrs.append(int(fa, 16))
                else:
                    addrs.append(int(fa))
            except Exception:
                continue
    return sorted(set(addrs))

def generate_visuals_for_candidate(py_exec, target_file, adv_csv, adv_dir, do_slice=True, do_decompile=True, visualizer="scripts/cfg_visualizer_enhanced.py", slicer="scripts/slice_provenance.py", decompiler="scripts/decompile_func.py"):
    images = []
    base = os.path.splitext(os.path.basename(target_file))[0]
    out_dir = os.path.join(adv_dir, base)
    os.makedirs(out_dir, exist_ok=True)

    # function-level annotated
    func_dot = os.path.join(out_dir, f"{base}_func.dot")
    func_png = os.path.join(out_dir, f"{base}_func.png")
    cmd = [py_exec, visualizer, target_file, "--out", func_dot, "--png", func_png, "--findings", adv_csv]
    print("[*] func-level vis:", " ".join(cmd))
    subprocess.run(cmd)
    if os.path.exists(func_png): images.append(func_png)

    # block-level + slices + decomp for each func reported
    func_addrs = extract_func_addrs_from_csv(adv_csv)
    for addr in func_addrs:
        dot = os.path.join(out_dir, f"{base}_0x{addr:x}_blocks.dot")
        png = os.path.join(out_dir, f"{base}_0x{addr:x}_blocks.png")
        cmd2 = [py_exec, visualizer, target_file, "--func", hex(addr), "--block-level", "--out", dot, "--png", png, "--findings", adv_csv]
        print("[*] block-level vis:", " ".join(cmd2))
        subprocess.run(cmd2)
        if os.path.exists(png): images.append(png)

        # run slice_provenance if requested
        if do_slice:
            slice_dot = os.path.join(out_dir, f"{base}_0x{addr:x}_slice.dot")
            slice_png = os.path.join(out_dir, f"{base}_0x{addr:x}_slice.png")
            slicecmd = [py_exec, slicer, target_file, "--func", hex(addr), "--out", slice_dot, "--png", slice_png, "--use-ddg", "--keep-state", "--state-refs"]
            print("[*] slicing:", " ".join(slicecmd))
            subprocess.run(slicecmd)
            if os.path.exists(slice_png):
                images.append(slice_png)

        # run decompiler if requested
        if do_decompile:
            dec_out = os.path.join(out_dir, f"{base}_0x{addr:x}.c")
            decmd = [py_exec, decompiler, target_file, "--func", hex(addr), "--out", dec_out]
            print("[*] decompiling:", " ".join(decmd))
            subprocess.run(decmd)

    # copy adv csv next to outputs
    try:
        shutil.copy(adv_csv, os.path.join(out_dir, os.path.basename(adv_csv)))
    except Exception:
        pass
    return images, out_dir

def create_thumbnail(src_path, dst_path, max_dim):
    """Create a thumbnail using PIL if available; otherwise return False."""
    if not PIL_AVAILABLE:
        return False
    try:
        with Image.open(src_path) as im:
            # convert to RGB for consistent PNG/JPEG saving
            if im.mode not in ("RGB", "RGBA"):
                im = im.convert("RGB")
            im.thumbnail((max_dim, max_dim))
            # ensure directory exists
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            im.save(dst_path, format="PNG")
        return True
    except Exception as e:
        print("[!] thumbnail creation failed for", src_path, ":", e)
        return False

GALLERY_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial; margin: 10px; background:#f4f6f8; color:#222; }
.container { max-width:1200px; margin:0 auto; }
.header { display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; }
h1 { font-weight:600; }
.grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap:12px; }
.card { background:white; border-radius:8px; padding:8px; border:1px solid #e1e4e8; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
.card img { width:100%; height:auto; border-radius:6px; display:block; }
.meta { font-size:13px; color:#555; margin-top:6px; }
.code { background:#0f1720; color:#e6fffb; padding:10px; border-radius:6px; overflow:auto; font-family: monospace; white-space:pre-wrap; max-height: 360px;}
.summary { font-size:14px; color:#333; margin-top:8px; }
a.button { display:inline-block; padding:6px 10px; background:#0b5cff; color:white; border-radius:6px; text-decoration:none; font-size:13px; }
.details summary { cursor:pointer; padding:6px; background:#eef2ff; border-radius:6px; }
"""

def make_gallery_html(out_html, candidate_entries, thumb_size=240, skip_thumbs=False):
    # out_html: path to write. candidate_entries = list of (name, images_list, out_dir, adv_csv)
    gallery_dir = os.path.dirname(out_html) or "."
    os.makedirs(gallery_dir, exist_ok=True)
    css_name = "gallery_styles.css"
    css_path = os.path.join(gallery_dir, css_name)
    with open(css_path, "w", encoding="utf-8") as fh:
        fh.write(GALLERY_CSS)

    lines = ['<!doctype html><html><head><meta charset="utf-8"><title>Orchestrator Visuals</title>']
    lines.append(f'<link rel="stylesheet" href="{css_name}">')
    lines.append('</head><body><div class="container">')
    lines.append('<div class="header"><h1>Orchestrator Visuals</h1><div><a class="button" href="#" onclick="window.location.reload();">Refresh</a></div></div>')

    for name, imgs, out_dir, csvpath in candidate_entries:
        lines.append(f'<h2>{name}</h2>')
        if csvpath and os.path.exists(csvpath):
            # copy csv to gallery_dir for linking if not already there
            try:
                shutil.copy(csvpath, os.path.join(gallery_dir, os.path.basename(csvpath)))
            except Exception:
                pass
            lines.append(f'<p class="meta"><a href="{os.path.basename(csvpath)}">Advanced CSV</a></p>')
        # display files from out_dir as cards using thumbnails
        if out_dir and os.path.isdir(out_dir):
            files = sorted(os.listdir(out_dir))
            lines.append('<div class="grid">')
            for fn in files:
                ext = fn.lower().split('.')[-1]
                full_src = os.path.join(out_dir, fn)
                if ext in ("png","jpg","jpeg","gif"):
                    # create thumbnail in gallery dir (if not skipping)
                    thumb_name = f"thumb_{fn}.png"
                    dest_full = os.path.join(gallery_dir, fn)
                    dest_thumb = os.path.join(gallery_dir, thumb_name)
                    # copy full image if not already present
                    try:
                        if not os.path.exists(dest_full):
                            shutil.copy(full_src, dest_full)
                    except Exception:
                        pass
                    # create thumbnail
                    made_thumb = False
                    if not skip_thumbs and PIL_AVAILABLE:
                        if not os.path.exists(dest_thumb):
                            made_thumb = create_thumbnail(dest_full, dest_thumb, thumb_size)
                        else:
                            made_thumb = True
                    if made_thumb:
                        thumb_ref = thumb_name
                    else:
                        thumb_ref = fn
                    lines.append('<div class="card">')
                    lines.append(f'<a href="{fn}" target="_blank"><img src="{thumb_ref}" alt="{fn}"></a>')
                    lines.append(f'<div class="meta">{fn}</div>')
                    lines.append('</div>')
                elif ext in ("c","txt"):
                    # copy code file to gallery dir
                    try:
                        if not os.path.exists(os.path.join(gallery_dir, fn)):
                            shutil.copy(os.path.join(out_dir, fn), os.path.join(gallery_dir, fn))
                    except Exception:
                        pass
                    # embed content as collapsible
                    lines.append('<div class="card">')
                    lines.append(f'<div class="summary"><strong>{fn}</strong></div>')
                    try:
                        with open(os.path.join(out_dir, fn), 'r', encoding='utf-8') as fh:
                            content = fh.read()
                        # escape HTML
                        esc = content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                        lines.append(f'<details class="details"><summary>Show code</summary><pre class="code">{esc}</pre></details>')
                    except Exception:
                        lines.append(f'<p><a href="{fn}">{fn}</a></p>')
                    lines.append('</div>')
                elif ext == "dot":
                    # copy .dot to gallery_dir
                    try:
                        if not os.path.exists(os.path.join(gallery_dir, fn)):
                            shutil.copy(os.path.join(out_dir, fn), os.path.join(gallery_dir, fn))
                    except Exception:
                        pass
                    lines.append('<div class="card">')
                    lines.append(f'<div class="meta">DOT: <a href="{fn}">{fn}</a></div>')
                    lines.append('</div>')
                else:
                    # copy other files
                    try:
                        if not os.path.exists(os.path.join(gallery_dir, fn)):
                            shutil.copy(os.path.join(out_dir, fn), os.path.join(gallery_dir, fn))
                    except Exception:
                        pass
                    lines.append('<div class="card">')
                    lines.append(f'<div class="meta"><a href="{fn}">{fn}</a></div>')
                    lines.append('</div>')
            lines.append('</div>')  # grid
        else:
            lines.append(f'<p class="meta">No artifacts for {name}</p>')

    lines.append('</div></body></html>')
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("[*] gallery written to", out_html)
    return out_html

def merge_csvs(base_csv, adv_csvs, merged_out):
    hdr=None; rows=[]
    def read_csv(p):
        nonlocal hdr, rows
        if not os.path.exists(p): return
        with open(p, newline='', encoding='utf-8') as fh:
            rdr = list(csv.reader(fh))
            if not rdr: return
            if hdr is None: hdr = rdr[0]
            for r in rdr[1:]: rows.append(r)
    read_csv(base_csv)
    for c in adv_csvs: read_csv(c)
    if hdr is None:
        print("[!] no rows to merge"); return False
    with open(merged_out, "w", newline='', encoding='utf-8') as fh:
        w=csv.writer(fh); w.writerow(hdr)
        for r in rows: w.writerow(r)
    return True

def parse_candidates_from_csv(csv_path, conf_threshold):
    files=set()
    if not os.path.exists(csv_path): return files
    with open(csv_path, newline='', encoding='utf-8') as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            try:
                conf = float(row.get("confidence") or 0.0)
            except Exception:
                conf=0.0
            if conf >= conf_threshold:
                files.add(row.get("file") or row.get("filename") or "")
    return set([f for f in files if f])

def run_advanced_job(job_tuple):
    try:
        rc = run_advanced_on_file(*job_tuple)
        return (job_tuple[1], rc)
    except Exception as e:
        return (job_tuple[1], 1)

def main():
    parser = argparse.ArgumentParser(description="Orchestrator w/ thumbnails & nicer gallery")
    parser.add_argument("target")
    parser.add_argument("--v2-out", default="v2_findings.csv")
    parser.add_argument("--v2-html", default="v2_report.html")
    parser.add_argument("--v2-yara", default="yara_rules")
    parser.add_argument("--adv-dir", default="adv_results")
    parser.add_argument("--threshold", type=float, default=7.0)
    parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count()-1))
    parser.add_argument("--symbolic", action="store_true")
    parser.add_argument("--explore-timeout", type=int, default=6)
    parser.add_argument("--cfg-mode", choices=["fast","full"], default="fast")
    parser.add_argument("--merge-out", default="merged_findings.csv")
    parser.add_argument("--gallery-html", default="visuals_gallery.html")
    parser.add_argument("--no-slice", action="store_true", help="skip running slice_provenance.py")
    parser.add_argument("--no-decompile", action="store_true", help="skip running decompile_func.py")
    parser.add_argument("--thumbnail-size", type=int, default=240, help="max thumbnail dimension")
    parser.add_argument("--skip-thumbnails", action="store_true", help="do not create thumbnails (faster)")
    args = parser.parse_args()

    os.makedirs(args.adv_dir, exist_ok=True)
    py_exec = sys.executable

    targets = enumerate_targets(args.target)
    if not targets:
        print("[!] no candidate files found"); return

    temp_csvs=[]
    for i,t in enumerate(targets):
        base=os.path.join(args.adv_dir, f"v2_{i}")
        out_csv = base + ".csv"
        out_html = base + ".html"
        yara = os.path.join(args.adv_dir, "yara")
        ok = run_v2_on_file(py_exec, t, out_csv, out_html, yara)
        if ok and os.path.exists(out_csv):
            temp_csvs.append(out_csv)

    # merge v2 csvs
    hdr=None; merged_rows=[]
    for p in temp_csvs:
        with open(p, newline='', encoding='utf-8') as fh:
            rdr=list(csv.reader(fh))
            if not rdr: continue
            if hdr is None: hdr=rdr[0]
            for row in rdr[1:]: merged_rows.append(row)
    if hdr:
        with open(args.v2_out, "w", newline='', encoding='utf-8') as fh:
            w=csv.writer(fh); w.writerow(hdr)
            for r in merged_rows: w.writerow(r)
        print("[*] merged v2 CSV written to", args.v2_out)
    else:
        with open(args.v2_out, "w", newline='', encoding='utf-8') as fh:
            w=csv.writer(fh); w.writerow(["file","arch","detection_type","func_addr","block_addr","detail","dasm_snippet_or_hex","confidence"])

    # promote candidates
    candidates = parse_candidates_from_csv(args.v2_out, args.threshold)
    for f in targets:
        try:
            with open(f, "rb") as fh:
                data = fh.read()
            if b"ptrace" in data.lower() or b"mmap" in data.lower():
                candidates.add(f)
        except Exception:
            pass

    if not candidates:
        print("[*] no candidates promoted"); return
    print("[*] promoted candidates:", len(candidates))

    # run advanced detector in parallel
    jobs=[]
    for f in sorted(candidates):
        base = os.path.join(args.adv_dir, os.path.basename(f).replace('/', '_'))
        adv_csv = base + "_adv.csv"
        adv_html = base + "_adv.html"
        yara_dir = os.path.join(args.adv_dir, "adv_yara")
        job = (py_exec, f, adv_csv, adv_html, yara_dir, args.cfg_mode, args.symbolic, args.explore_timeout)
        jobs.append(job)

    pool = multiprocessing.Pool(processes=args.workers)
    try:
        results = pool.map(run_advanced_job, jobs)
    finally:
        pool.close(); pool.join()

    candidate_entries=[]
    adv_csvs=[]
    for f in sorted(candidates):
        base = os.path.join(args.adv_dir, os.path.basename(f).replace('/', '_'))
        adv_csv = base + "_adv.csv"
        if not os.path.exists(adv_csv):
            for p in os.listdir(args.adv_dir):
                if p.endswith("_adv.csv") and os.path.basename(f) in p:
                    adv_csv = os.path.join(args.adv_dir, p); break
        images, out_dir = generate_visuals_for_candidate(py_exec, f, adv_csv, args.adv_dir, do_slice=(not args.no_slice), do_decompile=(not args.no_decompile))
        adv_csvs.append(adv_csv if os.path.exists(adv_csv) else "")
        candidate_entries.append((os.path.basename(f), images, out_dir, adv_csv if os.path.exists(adv_csv) else ""))

    # create gallery html with thumbnails
    gallery_path = make_gallery_html(args.gallery_html, candidate_entries, thumb_size=args.thumbnail_size, skip_thumbs=args.skip_thumbnails)

    # copy assets (images, thumbs, csvs) into gallery dir already done by make_gallery_html
    # merge advanced CSVs
    adv_existing = [p for p in adv_csvs if p]
    merged_ok = merge_csvs(args.v2_out, adv_existing, args.merge_out)
    if merged_ok:
        print("[*] merged CSV written to", args.merge_out)
    else:
        print("[!] merged CSV failed")
    print("[*] done. gallery:", gallery_path)

if __name__ == '__main__':
    main()
