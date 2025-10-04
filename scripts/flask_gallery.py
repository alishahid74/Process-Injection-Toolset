#!/usr/bin/env python3
"""
flask_gallery.py - simple gallery server for adv_results
Install: pip install flask
Run:
  export GALLERY_DIR=adv_results
  python3 scripts/flask_gallery.py
"""
from flask import Flask, send_from_directory, render_template_string, request, redirect, url_for, jsonify
import os, json
from pathlib import Path

GALLERY_DIR = os.environ.get("GALLERY_DIR", "adv_results")
ANNOTATIONS_FILE = "annotations.json"

app = Flask(__name__)

TEMPLATE = '''<!doctype html>
<html>
<head><meta charset="utf-8"><title>Gallery</title>
<style>
body{font-family:Arial;margin:12px;background:#f7fafc;color:#111} .thumb{width:200px;height:auto;border-radius:6px;border:1px solid #ddd;padding:6px;margin:6px;background:white;display:inline-block;vertical-align:top}
.card{display:inline-block;width:220px}
.form{margin-top:6px}
</style>
</head>
<body>
<h1>Gallery: {{gallery_dir}}</h1>
{% for candidate in candidates %}
  <h2>{{candidate}}</h2>
  <div>
    {% for fn in files[candidate] %}
      <div class="card">
        {% if fn.endswith(('.png','.jpg','.jpeg')) %}
          <img src="/artifact/{{candidate}}/{{fn}}" class="thumb"><br>
        {% endif %}
        <div>{{fn}}</div>
        <form action="/annotate" method="post" class="form">
          <input type="hidden" name="candidate" value="{{candidate}}">
          <input type="hidden" name="file" value="{{fn}}">
          <input type="text" name="label" placeholder="label"><br>
          <textarea name="note" rows="3" cols="22" placeholder="note"></textarea><br>
          <button type="submit">Save</button>
        </form>
      </div>
    {% endfor %}
  </div>
{% endfor %}
</body>
</html>'''

def load_gallery(gallery_dir):
    gallery_dir = Path(gallery_dir)
    candidates = []
    files = {}
    if not gallery_dir.exists():
        return candidates, files
    for candidate in sorted([p for p in gallery_dir.iterdir() if p.is_dir()]):
        names = sorted([f.name for f in candidate.iterdir() if f.is_file()])
        candidates.append(candidate.name)
        files[candidate.name] = names
    return candidates, files

@app.route("/")
def index():
    candidates, files = load_gallery(GALLERY_DIR)
    return render_template_string(TEMPLATE, gallery_dir=GALLERY_DIR, candidates=candidates, files=files)

@app.route("/artifact/<candidate>/<path:fname>")
def artifact(candidate, fname):
    base = Path(GALLERY_DIR) / candidate
    return send_from_directory(str(base), fname)

@app.route("/annotate", methods=["POST"])
def annotate():
    candidate = request.form.get("candidate")
    fname = request.form.get("file")
    label = request.form.get("label")
    note = request.form.get("note")
    ann_path = Path(GALLERY_DIR) / ANNOTATIONS_FILE
    anns = {}
    if ann_path.exists():
        anns = json.loads(ann_path.read_text())
    anns.setdefault(candidate, {}).setdefault(fname, []).append({"label": label, "note": note})
    ann_path.write_text(json.dumps(anns, indent=2))
    return redirect(url_for('index'))

@app.route("/annotations.json")
def annotations_json():
    ann_path = Path(GALLERY_DIR) / ANNOTATIONS_FILE
    if ann_path.exists():
        return jsonify(json.loads(ann_path.read_text()))
    return jsonify({})

if __name__ == "__main__":
    print("Serving gallery from", GALLERY_DIR)
    app.run(host="0.0.0.0", port=5000, debug=True)
