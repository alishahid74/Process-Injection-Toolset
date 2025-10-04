#!/usr/bin/env python3
"""
blob_extractor_and_yara.py
Extracts high-entropy blobs and generates simple YARA rules.
Usage:
  python3 blob_extractor_and_yara.py target.bin --out-dir extracted_blobs --min-entropy 7.5 --min-size 256 --yara-out blobs.yar
"""
import argparse, os, math, struct
from pathlib import Path

def entropy(data):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    ln = len(data)
    for v in freq.values():
        p = v / ln
        ent -= p * math.log2(p)
    return ent

def scan_file_for_blobs(path, out_dir, min_entropy, min_size):
    with open(path, "rb") as fh:
        data = fh.read()
    candidates = []
    window = 512
    i = 0
    n = len(data)
    while i < n - window:
        chunk = data[i:i+window]
        ent = entropy(chunk)
        if ent >= min_entropy:
            start = i
            end = i+window
            while start > 0 and entropy(data[max(0,start-256):start]) >= min_entropy:
                start = max(0, start-256)
            while end < n and entropy(data[end:end+256]) >= min_entropy:
                end = min(n, end+256)
            size = end - start
            if size >= min_size:
                candidates.append((start, end, size))
            i = end
        else:
            i += window // 4
    merged = []
    for s,e,size in candidates:
        if not merged or s > merged[-1][1]:
            merged.append([s,e,size])
        else:
            merged[-1][1] = max(merged[-1][1], e)
            merged[-1][2] = merged[-1][1] - merged[-1][0]
    os.makedirs(out_dir, exist_ok=True)
    rules = []
    for idx,(s,e,size) in enumerate(merged):
        blob = data[s:e]
        filename = os.path.join(out_dir, f"blob_{idx}_0x{s:x}_len{size}.bin")
        with open(filename, "wb") as outfh:
            outfh.write(blob)
        print("[*] extracted blob to", filename, "entropy:", entropy(blob))
        if blob[:2] == b"MZ":
            if len(blob) >= 0x40:
                e_lfanew = struct.unpack_from("<I", blob, 0x3c)[0]
                if 0 <= e_lfanew < len(blob) and blob[e_lfanew:e_lfanew+2] == b"PE":
                    print("[*] found embedded PE at offset", hex(e_lfanew))
        sample = blob[:64]
        hex_bytes = " ".join(f"\\x{b:02x}" for b in sample)
        rule_name = f"embedded_blob_{idx}_0x{s:x}"
        rule = f'rule {rule_name} {{\n  meta:\n    source = "{os.path.basename(path)}"\n    offset = "{hex(s)}"\n  strings:\n    $a = {{{hex_bytes}}}\n  condition:\n    $a at 0\n}}\n'
        rules.append(rule)
    return rules

def main():
    parser = argparse.ArgumentParser(description="Extract high-entropy blobs and generate YARA rules")
    parser.add_argument("target", help="Binary to scan")
    parser.add_argument("--out-dir", default="extracted_blobs", help="Directory to write blobs")
    parser.add_argument("--min-entropy", type=float, default=7.5, help="Minimum entropy to consider a blob suspicious")
    parser.add_argument("--min-size", type=int, default=256, help="Minimum blob size in bytes")
    parser.add_argument("--yara-out", default="blobs.yar", help="YARA file to write")
    args = parser.parse_args()

    rules = scan_file_for_blobs(args.target, args.out_dir, args.min_entropy, args.min_size)
    if rules:
        with open(args.yara_out, "w", encoding="utf-8") as fh:
            fh.write("// Auto-generated YARA rules for extracted blobs\n\n")
            for r in rules:
                fh.write(r + "\n")
        print("[*] wrote yara rules to", args.yara_out)
    else:
        print("[*] no high-entropy blobs found")

if __name__ == "__main__":
    main()
