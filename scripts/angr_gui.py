from markupsafe import Markup
#!/usr/bin/env python3
"""
Simple local web GUI for the angr tools in this repo.

Features:
- Lists Python scripts from ./scripts directory
- Lets user run a script with arbitrary args (run with the same venv python)
- Shows stdout/stderr and saves logs to adv_results/logs
- Shows generated files in adv_results and serves PNGs/images for quick preview

Security note: This runs arbitrary local scripts as the user who runs the Flask server. Do NOT run on an open network. Intended for local use only.

Run:
    pip install flask
    python3 angr_gui.py

Open: http://127.0.0.1:5000/
"""

import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from flask import (
    
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    send_from_directory,
    abort,
    
)

HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = (HERE / "scripts").resolve()
RESULTS_DIR = (HERE / "adv_results").resolve()
LOGS_DIR = RESULTS_DIR / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # just in case

INDEX_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>angr tools GUI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-light">
    <div class="container py-4">
      <h1 class="mb-3">angr tools — Local GUI</h1>
      <p class="text-muted">Running as: <code>{{ user }}</code> — project: <code>{{ here }}</code></p>

      <div class="row">
        <div class="col-md-6">
          <h4>Available scripts</h4>
          <ul class="list-group mb-3">
            {% for s in scripts %}
            <li class="list-group-item">
              <form method="post" action="{{ url_for('run_script') }}" class="d-flex gap-2 align-items-center">
                <div class="flex-grow-1">
                  <strong>{{ s.name }}</strong>
                  <div class="small text-muted">{{ s.path }}</div>
                </div>
                <input type="hidden" name="script" value="{{ s.name }}">
                <input name="args" class="form-control form-control-sm" placeholder="arguments (e.g. --out adv.csv)" style="max-width:420px">
                <input name="timeout" class="form-control form-control-sm" placeholder="timeout sec" value="300" style="width:110px">
                <button class="btn btn-primary btn-sm" type="submit">Run</button>
              </form>
            </li>
            {% endfor %}
          </ul>

          <h4>Recent logs</h4>
          <ul class="list-group mb-3">
            {% for l in logs %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
              <a href="{{ url_for('view_file') }}?path={{ l.relpath }}">{{ l.name }}</a>
              <small class="text-muted">{{ l.mtime }}</small>
            </li>
            {% else %}
            <li class="list-group-item">No logs yet</li>
            {% endfor %}
          </ul>
        </div>

        <div class="col-md-6">
          <h4>adv_results (preview)</h4>
          <div class="mb-2">
            <a class="btn btn-outline-secondary btn-sm" href="{{ url_for('browse_results') }}">Browse adv_results</a>
          </div>
          <h5>Image gallery</h5>
          <div class="row">
            {% for img in images %}
            <div class="col-6 col-md-4 mb-3">
              <a href="{{ url_for('serve_image', filename=img.relpath) }}" target="_blank">
                <img src="{{ url_for('serve_image', filename=img.relpath) }}" class="img-fluid img-thumbnail">
              </a>
            </div>
            {% else %}
            <div class="col-12">No images found in adv_results</div>
            {% endfor %}
          </div>
        </div>
      </div>

      <footer class="pt-4">
        <small class="text-muted">Warning: this GUI executes local scripts. Only run trusted scripts. Not exposed to public networks.</small>
      </footer>
    </div>
  </body>
</html>
"""

VIEW_FILE_HTML = """
<!doctype html>
<html><head><meta charset="utf-8"><title>{{ name }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="p-3 bg-light">
<div class="container">
  <h3>{{ name }}</h3>
  <div class="mb-2">
    <a class="btn btn-sm btn-secondary" href="/">Back</a>
    {% if downloadable %}
    <a class="btn btn-sm btn-primary" href="{{ url_for('download', filename=relpath) }}">Download</a>
    {% endif %}
  </div>
  <pre style="white-space:pre-wrap; background:#0f172a; color:#e6eef8; padding:12px; border-radius:6px;">{{ content }}</pre>
</div>
</body></html>
"""


@app.route('/')
def index():
    # list scripts
    scripts = []
    if SCRIPTS_DIR.exists():
        for p in sorted(SCRIPTS_DIR.glob('*.py')):
            scripts.append({'name': p.name, 'path': str(p.relative_to(HERE))})
    # recent logs
    logs = []
    for p in sorted(LOGS_DIR.glob('*'), key=os.path.getmtime, reverse=True)[:20]:
        logs.append({'name': p.name, 'relpath': str(p.relative_to(HERE)), 'mtime': time.ctime(p.stat().st_mtime)})

    # images in adv_results
    imgs = []
    if RESULTS_DIR.exists():
        for p in sorted(RESULTS_DIR.rglob('*.png'))[:12]:
            imgs.append({'relpath': str(p.relative_to(HERE)), 'name': p.name})

    return render_template_string(INDEX_HTML, scripts=scripts, logs=logs, images=imgs, user=os.getlogin(), here=str(HERE))


def safe_join(base: Path, rel: str) -> Path:
    """Resolve a path and ensure it's under base."""
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise ValueError('Unsafe path')
    return target


@app.route('/run', methods=['POST'])
def run_script():
    script = request.form.get('script')
    args = request.form.get('args', '')
    timeout = int(request.form.get('timeout') or 300)

    if not script:
        abort(400, 'No script')
    script_path = SCRIPTS_DIR / script
    if not script_path.exists():
        abort(404, 'Script not found')

    cmd = [sys.executable, str(script_path)]
    if args:
        try:
            cmd += shlex.split(args)
        except Exception:
            # fallback: naive split
            cmd += args.split()

    ts = int(time.time())
    logname = f"{ts}_{script}__.log"
    logpath = LOGS_DIR / logname

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        output = proc.stdout
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or '') + "\n\n[PROCESS TIMEOUT]"
        rc = -1
    except Exception as e:
        output = f"[ERROR running script]\n{e}\n"
        rc = -2

    # save log
    with open(logpath, 'w') as f:
        f.write(f"# CMD: {' '.join(cmd)}\n# RC: {rc}\n\n")
        f.write(output)

    # show results page
    return redirect(url_for('view_file') + '?path=' + str(logpath.relative_to(HERE)))


@app.route('/view')
def view_file():
    rel = request.args.get('path')
    if not rel:
        abort(400, 'path required')
    try:
        p = safe_join(HERE, rel)
    except ValueError:
        abort(400, 'unsafe path')
    if not p.exists():
        abort(404)
    # if it's an image, redirect to image serving
    if p.suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif']:
        return redirect(url_for('serve_image', filename=str(p.relative_to(HERE))))
    try:
        text = p.read_text(errors='replace')
    except Exception as e:
        text = f"Could not read file: {e}"
    return render_template_string(VIEW_FILE_HTML, name=p.name, content=text, downloadable=True, relpath=str(p.relative_to(HERE)))


@app.route('/results/')
def browse_results():
    # show top-level adv_results listing
    if not RESULTS_DIR.exists():
        return "No adv_results directory"
    entries = []
    for p in sorted(RESULTS_DIR.iterdir(), key=lambda x: x.is_file(), reverse=False):
        entries.append({'name': p.name, 'is_dir': p.is_dir()})
    out = ['<h3>adv_results</h3><ul>']
    for e in entries:
        if e['is_dir']:
            out.append(f"<li><a href='{url_for('browse_dir', subpath=e['name'])}'>{e['name']}/</a></li>")
        else:
            out.append(f"<li><a href='{url_for('view_file') + '?path=' + 'adv_results/' + e['name']}'>{e['name']}</a></li>")
    out.append('</ul><a href="/">Back</a>')
    return '\n'.join(out)


@app.route('/results/<path:subpath>')
def browse_dir(subpath):
    try:
        p = safe_join(RESULTS_DIR, subpath)
    except ValueError:
        abort(400)
    if not p.exists():
        abort(404)
    if p.is_file():
        return redirect(url_for('view_file') + '?path=' + str(p.relative_to(HERE)))
    items = []
    for c in sorted(p.iterdir()):
        rel = str(c.relative_to(HERE))
        if c.is_dir():
            items.append(f"<li>[dir] <a href='{url_for('browse_dir', subpath=str((subpath + '/' + c.name).lstrip('/')))}'>{c.name}/</a></li>")
        else:
            items.append(f"<li><a href='{url_for('view_file') + '?path=' + rel}'>{c.name}</a></li>")
    return f"<h3>{p}</h3><ul>" + '\n'.join(items) + f"</ul><a href='/'>&larr; Back</a>"


@app.route('/image/<path:filename>')
def serve_image(filename):
    try:
        p = safe_join(HERE, filename)
    except ValueError:
        abort(400)
    if not p.exists():
        abort(404)
    # send file from the repo root
    return send_from_directory(HERE, str(p.relative_to(HERE)))


@app.route('/download/<path:filename>')
def download(filename):
    try:
        p = safe_join(HERE, filename)
    except ValueError:
        abort(400)
    if not p.exists() or not p.is_file():
        abort(404)
    return send_from_directory(HERE, str(p.relative_to(HERE)), as_attachment=True)


if __name__ == '__main__':
    # simply run in debug by default for local usage
    print(f"Starting GUI on http://127.0.0.1:5000 — scripts: {SCRIPTS_DIR} adv_results: {RESULTS_DIR}")
    app.run(debug=True, host='127.0.0.1', port=5000)
