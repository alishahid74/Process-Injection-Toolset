#!/usr/bin/env python3
"""
pi_menu.py - Interactive menu for the ProcessInjectionTechniques toolset (extended)

Place this file in the repo root and run:
  python3 pi_menu.py

This extended menu includes helpers:
 - selective_ddg_slicer.py
 - blob_extractor_and_yara.py
 - syscall_heuristics.py
 - flask_gallery.py
 - orchestrator.py
 - cfg_visualizer.py / cfg_visualizer_enhanced.py
"""
from pathlib import Path
import subprocess, shlex, sys, webbrowser, shutil, os, time

# ASCII tool logos for Process Injection Toolset
# Usage: print_tool_logo(size="medium", color=True)
_TOOL_LOGOS = {
    "medium": r"""
   _____                  _           _   _ _       _   
  |  __ \                | |         | | (_) |     | |  
  | |__) |__ _ _ __   ___| |_ ___  __| |  _| |_ ___| |_ 
  |  ___/ _ \ '_ \ / _ \ __/ _ \/ _` | | | __/ __| __|
  | |  |  __/ | | |  __/ ||  __/ (_| | | | |_\__ \ |_ 
  |_|   \___|_| |_|\___|\__\___|\__,_| |_|_\__|___/\__|
    Process Injection Toolset
""",
}

# Optional ANSI color wrapper (green title)
def _colorize(s, color_code=32):
    return f"\033[{color_code}m{s}\033[0m"

def print_tool_logo(size="medium", color=False):
    """
    Print the ASCII tool logo.
    size: "small" | "medium" | "large"
    color: True to enable ANSI green color for whole block (best in terminals)
    """
    s = _TOOL_LOGOS.get(size, _TOOL_LOGOS["medium"])
    if color:
        print(_colorize(s, 32))
    else:
        print(s)

# Example: call at program start
if __name__ == "__main__":
    print_tool_logo(size="medium", color=True)


REPO_ROOT = Path.cwd()
SCRIPTS_DIR = REPO_ROOT / "scripts"

# core scripts (defaults)
DETECTOR = SCRIPTS_DIR / "extended_injection_detector_v2.py"
ANALYZER = SCRIPTS_DIR / "report_analyzer.py"
SELECTIVE = SCRIPTS_DIR / "selective_ddg_slicer.py"
BLOB = SCRIPTS_DIR / "blob_extractor_and_yara.py"
SYSCALL = SCRIPTS_DIR / "syscall_heuristics.py"
FLASK = SCRIPTS_DIR / "flask_gallery.py"
ORCH = SCRIPTS_DIR / "orchestrator.py"
CFGVIS = SCRIPTS_DIR / "cfg_visualizer.py"
CFGVIS_ENH = SCRIPTS_DIR / "cfg_visualizer_enhanced.py"
SLICE = SCRIPTS_DIR / "slice_provenance.py"

KNOWN_BINARY_EXTS = {".exe", ".dll", ".pe", ".bin", ".so", ""}

def run_cmd(cmd, cwd=None, background=False):
    """Echo command and run it. If background True, spawn and return Popen."""
    if isinstance(cmd, (list,tuple)):
        printable = " ".join(shlex.quote(str(x)) for x in cmd)
    else:
        printable = str(cmd)
    print("\n[+] Running:", printable)
    try:
        if background:
            p = subprocess.Popen(cmd, cwd=cwd)
            print("[+] Launched background PID", p.pid)
            return p
        else:
            rc = subprocess.run(cmd, cwd=cwd).returncode
            print("[+] Return code:", rc)
            return rc
    except KeyboardInterrupt:
        print("[!] Interrupted by user")
        return 130
    except Exception as e:
        print("[!] Error running command:", e)
        return 1

def has_file_util():
    return shutil.which("file") is not None

def detect_arch_using_file(path: Path):
    if not has_file_util():
        return "unknown"
    try:
        out = subprocess.check_output(["file", str(path)], stderr=subprocess.DEVNULL).decode(errors="ignore").lower()
        if any(x in out for x in ("x86-64","64-bit","amd64","x86_64","pe32+")):
            return "x64"
        if any(x in out for x in ("32-bit","i386","i686","pe32")):
            return "x86"
    except Exception:
        pass
    return "unknown"

def find_binaries(root: Path):
    candidates = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in KNOWN_BINARY_EXTS:
            candidates.append(p)
            continue
        if has_file_util():
            try:
                out = subprocess.check_output(["file", str(p)], stderr=subprocess.DEVNULL).decode(errors="ignore").lower()
                if any(k in out for k in ("elf","pe32","pe32+","executable","shared object")):
                    candidates.append(p)
            except Exception:
                continue
    return sorted(set(candidates))

def echo_and_confirm(cmd):
    print("\nWill run:", " ".join(shlex.quote(str(x)) for x in cmd))
    ans = input("Proceed? [Y/n]: ").strip().lower()
    return ans in ("", "y", "yes")

# --- Wrappers for the helpers ---

def run_detector_on_target(target, out_csv=None, out_html=None, yaradir=None, extra_args=None):
    if not DETECTOR.exists():
        print("[!] Detector not found:", DETECTOR)
        return 1
    cmd = [sys.executable, str(DETECTOR), str(target)]
    if out_csv: cmd += ["--out", str(out_csv)]
    if out_html: cmd += ["--html", str(out_html)]
    if yaradir: cmd += ["--yaradir", str(yaradir)]
    if extra_args: cmd += extra_args
    if echo_and_confirm(cmd):
        return run_cmd(cmd)
    return 0

def run_selective_slicer():
    if not SELECTIVE.exists():
        print("[!] Selective slicer not found:", SELECTIVE)
        return
    adv_csv = input("Path to advanced CSV (adv_results/foo_adv.csv): ").strip() or "adv_results/foo_adv.csv"
    target = input("Target binary (absolute path): ").strip()
    if not Path(adv_csv).exists():
        print("[!] adv CSV not found:", adv_csv); return
    if not Path(target).exists():
        print("[!] target binary not found:", target); return
    out_dir = input("Output dir for slices (default adv_slices): ").strip() or "adv_slices"
    topk = input("Top-K (default 3): ").strip() or "3"
    extra = ["--adv-csv", adv_csv, "--target", target, "--slicer", str(SLICE), "--out-dir", out_dir, "--top-k", topk, "--control-only-for-rest"]
    cmd = [sys.executable, str(SELECTIVE)] + extra
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def run_blob_extractor():
    if not BLOB.exists():
        print("[!] Blob extractor not found:", BLOB); return
    target = input("Target binary: ").strip()
    if not Path(target).exists():
        print("[!] target not found"); return
    outdir = input("Out dir (default extracted_blobs): ").strip() or "extracted_blobs"
    minent = input("Min entropy (default 7.5): ").strip() or "7.5"
    minsize = input("Min size bytes (default 256): ").strip() or "256"
    yara_out = input("YARA output filename (default blobs.yar): ").strip() or "blobs.yar"
    cmd = [sys.executable, str(BLOB), target, "--out-dir", outdir, "--min-entropy", minent, "--min-size", minsize, "--yara-out", yara_out]
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def run_syscall_scan():
    if not SYSCALL.exists():
        print("[!] Syscall scanner not found:", SYSCALL); return
    target = input("Target binary: ").strip()
    if not Path(target).exists(): print("[!] target not found"); return
    out = input("Output JSON (default syscalls.json): ").strip() or "syscalls.json"
    cmd = [sys.executable, str(SYSCALL), target, "--out", out]
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def start_flask_gallery():
    if not FLASK.exists():
        print("[!] Flask gallery not found:", FLASK); return
    gallery_dir = input("Gallery dir (default adv_results): ").strip() or "adv_results"
    os.environ["GALLERY_DIR"] = gallery_dir
    bg = input("Run in background? [y/N]: ").strip().lower() == "y"
    cmd = [sys.executable, str(FLASK)]
    if echo_and_confirm(cmd):
        if bg:
            run_cmd(cmd, background=True)
        else:
            run_cmd(cmd)

def run_orchestrator():
    if not ORCH.exists():
        print("[!] orchestrator.py not found:", ORCH); return
    target = input("Target path (dir or file) (default ./samples): ").strip() or "./samples"
    v2_out = input("v2-out CSV (default v2_findings.csv): ").strip() or "v2_findings.csv"
    threshold = input("threshold (default 7.0): ").strip() or "7.0"
    workers = input("workers (default 3): ").strip() or "3"
    symbolic = input("symbolic? [y/N]: ").strip().lower() == "y"
    explore = input("explore-timeout (default 8): ").strip() or "8"
    merge_out = input("merge-out (default merged_findings.csv): ").strip() or "merged_findings.csv"
    cmd = [sys.executable, str(ORCH), target, "--v2-out", v2_out, "--threshold", threshold, "--workers", workers, "--explore-timeout", explore, "--merge-out", merge_out]
    if symbolic: cmd.insert(-1, "--symbolic")  # insert symbolic before last arg
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def run_cfg_visualizer():
    # convenience wrapper prompting for common args
    chosen = input("Use enhanced visualizer? [y/N]: ").strip().lower() == "y"
    script = CFGVIS_ENH if chosen and CFGVIS_ENH.exists() else CFGVIS
    if not script.exists():
        print("[!] cfg visualizer not found:", script); return
    target = input("Target binary (path): ").strip()
    func = input("Function addr (hex, e.g., 0x401000) or leave blank: ").strip()
    filter_s = input("Filter regex (e.g., write|ptrace) or leave blank: ").strip()
    out_dot = input("Output DOT (default callgraph.dot): ").strip() or "callgraph.dot"
    out_png = input("Output PNG (default callgraph.png): ").strip() or "callgraph.png"
    cmd = [sys.executable, str(script), target]
    if func: cmd += ["--func", func]
    if filter_s: cmd += ["--filter", filter_s]
    cmd += ["--out", out_dot, "--png", out_png]
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def list_scripts():
    print("scripts/ contents:")
    for p in sorted(SCRIPTS_DIR.iterdir()):
        print("  ", p.name)

# --- UI --- #

def list_discovered_binaries():
    print("Scanning repo for binaries (this may take a moment)...")
    bins = find_binaries(REPO_ROOT)
    if not bins:
        print("No binaries found.")
        return
    for b in bins:
        arch = detect_arch_using_file(b)
        print(f" {b}  (arch: {arch})")

def scan_single_file():
    t = input("Enter full path to file to scan: ").strip()
    if not t:
        return
    target = Path(t).expanduser()
    if not target.exists():
        print("Path does not exist.")
        return
    arch = detect_arch_using_file(target)
    print("[*] Detected arch:", arch)
    out_csv = input("Output CSV name (default findings_v2.csv): ").strip() or "findings_v2.csv"
    out_html = input("Output HTML name (default report_v2.html): ").strip() or "report_v2.html"
    yaradir = input("YARA dir (default yara_rules): ").strip() or "yara_rules"
    run_detector_on_target(target, out_csv=out_csv, out_html=out_html, yaradir=yaradir)

def scan_directory(arch_filter="all"):
    d = input("Enter directory path to scan (default current folder): ").strip() or str(REPO_ROOT)
    dirpath = Path(d).expanduser()
    if not dirpath.exists() or not dirpath.is_dir():
        print("Not a directory.")
        return
    out_csv = input("Output CSV name (default findings_v2.csv): ").strip() or "findings_v2.csv"
    out_html = input("Output HTML name (default report_v2.html): ").strip() or "report_v2.html"
    yaradir = input("YARA dir (default yara_rules): ").strip() or "yara_rules"
    # if detector supports --arch-filter, use it
    supports = False
    try:
        helpout = subprocess.check_output([sys.executable, str(DETECTOR), "--help"], stderr=subprocess.STDOUT)
        supports = b"--arch-filter" in helpout
    except Exception:
        supports = False
    if arch_filter != "all" and supports:
        cmd = [sys.executable, str(DETECTOR), str(dirpath), "--out", out_csv, "--html", out_html, "--yaradir", yaradir, "--arch-filter", arch_filter]
        if echo_and_confirm(cmd):
            run_cmd(cmd)
        return
    bins = find_binaries(dirpath)
    if arch_filter != "all":
        bins = [b for b in bins if detect_arch_using_file(b) == arch_filter]
    if not bins:
        print("No matching files for that architecture.")
        return
    for idx,b in enumerate(bins):
        print(f"\n[*] analyzing {b} ({idx+1}/{len(bins)})")
        prefix = b.stem
        out_csv_per = Path(out_csv).with_name(f"{prefix}_{out_csv}")
        out_html_per = Path(out_html).with_name(f"{prefix}_{out_html}")
        yaradir_per = Path(yaradir) / prefix
        run_detector_on_target(b, out_csv=out_csv_per, out_html=out_html_per, yaradir=yaradir_per)

def run_analyzer_option():
    csv_path = input("Enter findings CSV path (default findings_v2.csv): ").strip() or "findings_v2.csv"
    if not Path(csv_path).exists():
        print("CSV not found:", csv_path); return
    cmd = [sys.executable, str(ANALYZER), csv_path]
    if echo_and_confirm(cmd):
        run_cmd(cmd)

def open_html_option():
    html_path = input("Enter HTML report path (default report_v2.html): ").strip() or "report_v2.html"
    p = Path(html_path)
    if not p.exists():
        print("HTML not found:", p); return
    url = p.resolve().as_uri()
    print("Opening:", url)
    webbrowser.open_new_tab(url)

def main_menu():
    while True:
        print("\n" + "="*72)
        print("Process Injection Toolset Menu")
        print(f"Repo root: {REPO_ROOT}")
        print(f"Scripts dir: {SCRIPTS_DIR}")
        print("="*72)
        print("  1) List discovered binaries")
        print("  2) Scan a single file")
        print("  3) Scan a directory (recursively)")
        print("  4) Scan directory but only x64 or only x86 (arch filter)")
        print("  5) Run analyzer on findings CSV")
        print("  6) Open HTML report in browser")
        print("  7) Run selective DDG slicer (selective_ddg_slicer.py)")
        print("  8) Extract high-entropy blobs & generate YARA (blob_extractor_and_yara.py)")
        print("  9) Run syscall heuristics scanner (syscall_heuristics.py)")
        print(" 10) Start Flask gallery (flask_gallery.py)")
        print(" 11) Run orchestrator pipeline (orchestrator.py)")
        print(" 12) Run CFG visualizer")
        print(" 13) List scripts/ contents")
        print(" 14) Quit")
        choice = input("Choose an option [1-14] (or paste a path to scan): ").strip()
        if not choice: continue
        if choice.startswith("/") or choice.startswith("~"):
            p = Path(choice).expanduser()
            if p.exists():
                if p.is_dir():
                    scan_directory()
                else:
                    run_detector_on_target(p, out_csv="findings_v2.csv", out_html="report_v2.html", yaradir="yara_rules")
            else:
                print("Path does not exist.")
            continue
        if choice == "1": list_discovered_binaries()
        elif choice == "2": scan_single_file()
        elif choice == "3": scan_directory()
        elif choice == "4":
            arch = input("Filter by arch? [x64/x86/all]: ").strip().lower() or "all"
            if arch not in ("x64","x86","all"): arch = "all"
            scan_directory(arch_filter=arch)
        elif choice == "5": run_analyzer_option()
        elif choice == "6": open_html_option()
        elif choice == "7": run_selective_slicer()
        elif choice == "8": run_blob_extractor()
        elif choice == "9": run_syscall_scan()
        elif choice == "10": start_flask_gallery()
        elif choice == "11": run_orchestrator()
        elif choice == "12": run_cfg_visualizer()
        elif choice == "13": list_scripts()
        elif choice == "14": print("Bye."); break
        else:
            print("Unknown option. Choose 1-14.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
