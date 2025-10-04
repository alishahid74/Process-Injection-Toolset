
ProcessInjectionTechniques — Comprehensive Project Report & User Guide
=====================================================================

Version: 1.0
Date: 2025-10-03
Prepared for: Research

Table of contents
-----------------
1. Executive summary
2. Environment & prerequisites
3. Project timeline — what we did
4. Script catalog (what each script does + example commands)
5. End-to-end workflows (commands & expected outputs)
6. Internals & technical notes (angr specifics)
7. Gallery, visualization & artifacts
8. Troubleshooting & tips
9. Next steps / future work
10. Appendix: quick command cheat-sheet

1) Executive summary
--------------------
This guide documents the ProcessInjectionTechniques toolset — a modular pipeline that detects process injection techniques in binaries (PE and ELF) using static inspection and angr-based analyses. The pipeline includes triage-level detectors, deeper symbolic/concolic checks, backward slicing for provenance, automatic decompilation, and a gallery-based triage UI.

2) Environment & prerequisites
------------------------------
Recommended minimal environment setup (Ubuntu/Kali):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install angr cle capstone pefile networkx pillow python-docx graphviz yara-python
sudo apt-get install -y graphviz
```
Notes:
- angr is the core analysis engine; installation may require extra packages and time.
- Pillow is optional but recommended for thumbnail creation in the gallery.
- python-docx is optional (used to generate Word documents).

3) Project timeline — what we did
---------------------------------
- Added a fast detector (extended_injection_detector_v2.py) that uses CFGFast to search for common injection API sequences and heuristics.
- Identified binaries in the repo and wrote helpers to scan imports and list dynamic symbols.
- Built advanced angr detector (advanced_angr_detector.py) for deeper symbolic checks and syscall detection.
- Wrote slice_provenance.py to compute backward slices and export DOT/PNG representations.
- Created decompile_func.py to attempt function-level decompilation using angr's Decompiler (fallback to disassembly on failure).
- Built cfg_visualizer_enhanced.py to generate annotated call-graphs and block graphs.
- Implemented orchestrator(s) to run v2 -> promote -> advanced -> visuals -> slice -> decompile -> gallery pipeline, with thumbnail support and CSS gallery.
- Produced README, handouts, and Word document exports for student labs.

4) Script catalog (what each script does + examples)
----------------------------------------------------
- extended_injection_detector_v2.py
  - Purpose: Fast scan for injection-like patterns using CFGFast and heuristics.
  - Example:
    ```bash
    python3 scripts/extended_injection_detector_v2.py /path/to/sample.exe --out findings_v2.csv --html report_v2.html --yaradir yara_rules --arch-filter x64
    ```
  - Outputs: findings CSV, HTML report, yara rules directory (if any).

- advanced_angr_detector.py
  - Purpose: Deeper analysis per candidate (CFGEmulated, symbolic exploration, syscall heuristics).
  - Example:
    ```bash
    python3 scripts/advanced_angr_detector.py sample.exe --out adv.csv --html adv.html --yaradir adv_yara --cfg full --symbolic --angr-explore-timeout 8
    ```
  - Outputs: per-candidate advanced CSV + HTML.

- cfg_injection_finder.py
  - Purpose: Heuristic CFG-based scanner for canonical injection sequences.
  - Example:
    ```bash
    python3 scripts/cfg_injection_finder.py sample.exe --out cfg_hits.csv
    ```

- list_imports.py / scan_imports_and_calls.py
  - Purpose: List imports/dynamic symbols for quick triage.
  - Example:
    ```bash
    python3 scripts/list_imports.py samples/injection_demo
    ```

- symbolic_arg_checker.py
  - Purpose: Light symbolic checks for API call arguments to decide whether arguments can be symbolic/controlled.
  - Example:
    ```bash
    python3 scripts/symbolic_arg_checker.py sample.bin --api WriteProcessMemory --timeout 8 --max-sites 4
    ```

- cfg_visualizer_enhanced.py
  - Purpose: produce DOT/PNG callgraphs and block graphs; annotate nodes from findings CSV.
  - Example:
    ```bash
    python3 scripts/cfg_visualizer_enhanced.py target.bin --out callgraph.dot --png callgraph.png --findings merged_findings.csv
    ```

- slice_provenance.py
  - Purpose: backward slicing with angr; supports control-only and DDG-based slicing.
  - Example:
    ```bash
    python3 scripts/slice_provenance.py target.bin --func 0x401166 --out slice.dot --png slice.png --use-ddg --keep-state --state-refs
    ```

- decompile_func.py
  - Purpose: attempt angr-based decompilation for a single function; fallback to disassembly.
  - Example:
    ```bash
    python3 scripts/decompile_func.py target.bin --func 0x401166 --out func_0x401166.c
    ```

- orchestrator.py / orchestrator_with_threshold.py
  - Purpose: drive full pipeline end-to-end. orchestrator_with_threshold adds --slice-threshold and --max-decompile.
  - Example:
    ```bash
    python3 scripts/orchestrator.py ./samples --v2-out v2_findings.csv --threshold 7.0 --workers 3 --symbolic --explore-timeout 8 --merge-out merged_findings.csv --gallery-html visuals_gallery.html --thumbnail-size 240
    ```

- report_analyzer.py
  - Purpose: summarize and rank findings CSVs for triage.
  - Example:
    ```bash
    python3 scripts/report_analyzer.py merged_findings.csv --out summary.csv --top 20
    ```

5) End-to-end workflows & practical examples
-------------------------------------------
A. Fast triage (single binary):
```
python3 scripts/extended_injection_detector_v2.py sample.exe --out findings_v2.csv --html v2_report.html --yaradir yara_rules
```
Inspect findings_v2.csv and run deeper analysis on selected candidates.

B. Full pipeline (recommended for lab/class):
```
python3 scripts/orchestrator.py ./samples --v2-out v2_findings.csv --threshold 7.0 --workers 3 --symbolic --explore-timeout 8 --merge-out merged_findings.csv --gallery-html visuals_gallery.html --thumbnail-size 240
```
Outputs: adv_results/, merged_findings.csv, visuals_gallery.html, per-candidate artifacts.

C. Investigate a function manually:
1. Build block-level graph and view it:
```
python3 scripts/cfg_visualizer_enhanced.py candidate.exe --func 0x401200 --block-level --out blocks.dot --png blocks.png --findings adv.csv
```
2. Compute a slice for provenance:
```
python3 scripts/slice_provenance.py candidate.exe --func 0x401200 --out slice.dot --png slice.png --use-ddg --keep-state --state-refs
```
3. Decompile the function:
```
python3 scripts/decompile_func.py candidate.exe --func 0x401200 --out decomp_0x401200.c
```

6) Internals & technical notes (angr specifics)
-----------------------------------------------
- **CFGFast vs CFGEmulated**: CFGFast is quicker and suitable for triage; CFGEmulated + state-tracing is needed for precise control-flow, DDG and slicing.
- **Slicing and DDG**: Data dependence graph (DDG) yields accurate backward slices but requires keeping state and is computationally expensive.
- **Symbolic argument checks**: Light symbolic exploration can help decide whether function arguments are derived from user-controllable sources; use conservatively — symbolic execution is expensive.
- **Decompiler**: Best-effort; success depends on angr decompiler availability and binary complexity. Always include fallback disassembly output.

7) Gallery, visualization & artifacts
-------------------------------------
- Artifacts for a candidate: PNGs (callgraph, blocks, slice), DOT files, decompiled .c, adv CSV.
- Gallery lives at the location specified (``visuals_gallery.html`` by default); thumbnails are created if Pillow is installed.
- Use browser to navigate gallery and click thumbnails to view full-size images and embedded decompiled source blocks.

8) Troubleshooting & tips
-------------------------
- If a script complains about invalid binary, ensure you're passing a file, not a directory.
- Use the helper to list angr-discovered functions for address confirmation (for PIE / ASLR):
```
python3 - <<'PY'
import angr
proj = angr.Project("target.bin", auto_load_libs=False)
cfg = proj.analyses.CFGFast()
for f in sorted(cfg.kb.functions.values(), key=lambda x:x.addr):
    print("0x%08x\t%s" % (f.addr, getattr(f,'name','')))
PY
```
- Speed up runs by: using CFGFast, disabling slicing/decompilation, increasing thresholds, or limiting max-decompile functions.

9) Next steps / future work
---------------------------
- Automate selective DDG slicing for top-k candidates only.
- Extract high-entropy data blobs and auto-generate YARA rules for PE-in-blob cases.
- Provide a small web UI (Flask) to serve galleries and allow annotation/feedback for supervised improvements.
- Expand syscall-level heuristics and anti-analysis detection capabilities.

10) Appendix: Quick command cheat-sheet
---------------------------------------
(Short reference of the most-used commands and the outputs they produce)
- Run v2 detector:
  - `extended_injection_detector_v2.py target --out findings_v2.csv --html v2_report.html`
- Run orchestrator (full):
  - `orchestrator.py ./samples --v2-out v2_findings.csv --threshold 7.0 --workers 3 --symbolic --explore-timeout 8 --merge-out merged_findings.csv --gallery-html visuals_gallery.html`
- Slice a function (DDG):
  - `slice_provenance.py target --func 0x401166 --out slice.dot --png slice.png --use-ddg --keep-state --state-refs`
- Decompile a function:
  - `decompile_func.py target --func 0x401166 --out func_0x401166.c`

End of report.
