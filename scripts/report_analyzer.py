#!/usr/bin/env python3
"""
report_analyzer.py (updated)

Reads the findings CSV (extended v2), computes a combined confidence score per (file, func),
and prints a prioritized list with recommended next steps.

Usage:
    python3 scripts/report_analyzer.py findings_v2.csv
"""
import csv
import argparse
from collections import defaultdict, Counter

# simple thresholds for recommendations
HIGH_THRESHOLD = 15
MED_THRESHOLD = 8

def load_csv(path):
    with open(path, newline='', encoding='utf-8') as fh:
        r = csv.DictReader(fh)
        return list(r)

def score_rows(rows):
    grouped = defaultdict(list)
    for row in rows:
        # group by file and function (func_addr may be empty)
        key = (row['file'], row.get('func_addr') or "")
        grouped[key].append(row)
    scored = []
    for key, items in grouped.items():
        file, func = key
        score = 0
        det_types = Counter(i['detection_type'] for i in items)
        # confidences sum
        for i in items:
            try:
                score += int(float(i.get('confidence') or 0))
            except Exception:
                score += 0
        scored.append((score, file, func, det_types, items))
    scored.sort(reverse=True, key=lambda x: x[0])
    return scored

def print_recommendations(scored):
    print("="*120)
    print("Top prioritized findings (score, file, func):")
    print("="*120)
    for score, file, func, det_types, items in scored[:40]:
        print(f"\nScore: {score}   File: {file}   Func: {func or '<no-func>'}")
        print("Detections summary:", dict(det_types))
        print("Top detail lines:")
        for it in items[:6]:
            d = it.get('detail') or it.get('dasm_snippet_or_hex', '')
            print(" -", (d[:240] + ("..." if len(d) > 240 else "")))
        # recommendations depending on score
        print("\nRecommended next steps:")
        if score >= HIGH_THRESHOLD:
            print("  * HIGH PRIORITY: Run in isolated Windows VM snapshot immediately. Capture Procmon + API tracer and a full memory image (winpmem).")
            print("  * After execution, run Volatility/YARA against memory image and look for RWX regions, injected PE blobs, remote threads.")
            print("  * Use the generated YARA rules in yara_rules/ to match memory and file.")
        elif score >= MED_THRESHOLD:
            print("  * MEDIUM PRIORITY: Consider dynamic confirmation in sandbox, or deeper static inspection of the function with cfg_injection_finder.py.")
            print("  * Check for overlapping heuristics (e.g., syscall + pe_in_blob) before dynamic run.")
        else:
            print("  * LOW PRIORITY: likely benign or low-confidence; manual triage recommended (look for false positives like compressed resources).")
        print("-"*80)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", help="findings CSV from detector v2")
    args = parser.parse_args()
    rows = load_csv(args.csv)
    scored = score_rows(rows)
    print_recommendations(scored)

if __name__ == "__main__":
    main()
