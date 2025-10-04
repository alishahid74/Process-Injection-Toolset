#!/usr/bin/env python3
"""
Interactive Angr GUI - single-file Flask app

Place this file at scripts/angr_gui_interactive.py in your project root
and run: python3 scripts/angr_gui_interactive.py

It will:
 - list .py scripts under ./scripts (excluding itself)
 - start chosen script as subprocess, record logs under gui_results/jobs/<job_id>.log
 - expose endpoints for jobs, logs, cancelling
 - provide an interactive single-page UI that polls for logs
"""

from flask import Flask, jsonify, request, send_file, Response, render_template_string, abort
import os
import subprocess
import uuid
import threading
import time
from pathlib import Path
from markupsafe import escape

APPROOT = Path(__file__).resolve().parents[1]  # repo root
SCRIPTS_DIR = APPROOT / "scripts"
RESULTS_DIR = APPROOT / "gui_results" / "jobs"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False

# In-memory job store
jobs = {}
jobs_lock = threading.Lock()
# Each job: {id, script, cmdline, proc (Popen), log_path, start_time, end_time (or None), status}

def list_scripts():
    """Return list of runnable python script filenames +/- docstring summary."""
    out = []
    if not SCRIPTS_DIR.exists():
        return out
    for p in sorted(SCRIPTS_DIR.glob("*.py")):
        if p.name == Path(__file__).name:
            continue
        # read first lines to try to get a short docstring or comment
        summary = ""
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for _ in range(30):
                    line = fh.readline()
                    if not line:
                        break
                    s = line.strip()
                    if s.startswith('"""') or s.startswith("'''"):
                        # docstring block start
                        ds = s.strip('"""').strip("'''").strip()
                        if ds:
                            summary = ds
                        else:
                            # read next non-empty line
                            ds2 = fh.readline().strip()
                            summary = ds2[:200]
                        break
                    elif s.startswith("#"):
                        # accumulate comment lines until we hit non-comment
                        if summary:
                            summary += " " + s.lstrip("# ").strip()
                        else:
                            summary = s.lstrip("# ").strip()
                    elif s:
                        # first non-empty non-comment line: stop
                        break
        except Exception:
            summary = ""
        out.append({"name": p.name, "path": str(p), "summary": summary})
    return out

def start_job(script_name, target=None, args_text=""):
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        raise FileNotFoundError(script_name)
    job_id = str(uuid.uuid4())[:8]
    log_path = RESULTS_DIR / f"{job_id}.log"
    # Build command: run with the repo venv python if available or system python3
    python_exe = os.environ.get("VIRTUAL_ENV_PYTHON") or "python3"
    cmd = [python_exe, str(script_path)]
    if target:
        cmd.append(str(target))
    # split args_text by shell-like whitespace but don't use shell=True
    if args_text:
        # naive split respecting quoted segments
        import shlex
        try:
            extra = shlex.split(args_text)
        except Exception:
            extra = args_text.split()
        cmd += extra

    logfile = open(log_path, "w", encoding="utf-8", errors="ignore")
    proc = subprocess.Popen(cmd, stdout=logfile, stderr=subprocess.STDOUT, cwd=str(APPROOT))
    job = {
        "id": job_id,
        "script": script_name,
        "cmdline": " ".join(escape(x) for x in cmd),
        "proc": proc,
        "log_path": str(log_path),
        "start_time": time.time(),
        "end_time": None,
        "status": "running",
    }
    with jobs_lock:
        jobs[job_id] = job

    # Monitor thread to update status on exit
    def monitor(jobid, p, logfile):
        p.wait()
        logfile.close()
        with jobs_lock:
            j = jobs.get(jobid)
            if j:
                j["end_time"] = time.time()
                j["status"] = "done" if p.returncode == 0 else f"exited({p.returncode})"

    t = threading.Thread(target=monitor, args=(job_id, proc, logfile), daemon=True)
    t.start()
    return job

@app.route("/scripts_list")
def scripts_list():
    return jsonify(list_scripts())

@app.route("/run", methods=["POST"])
def run_script():
    data = request.get_json() or {}
    script = data.get("script")
    if not script:
        return jsonify({"error": "no script specified"}), 400
    target = data.get("target")
    args_text = data.get("args", "")
    try:
        job = start_job(script, target=target, args_text=args_text)
    except FileNotFoundError:
        return jsonify({"error": "script not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({
        "id": job["id"],
        "script": job["script"],
        "log_path": job["log_path"],
        "status": job["status"],
        "cmdline": job["cmdline"],
    })

@app.route("/jobs")
def get_jobs():
    with jobs_lock:
        js = []
        for jid, j in jobs.items():
            js.append({
                "id": j["id"],
                "script": j["script"],
                "status": j["status"],
                "start_time": j["start_time"],
                "end_time": j.get("end_time"),
                "log_path": j["log_path"],
                "cmdline": j["cmdline"],
            })
    # order by start_time desc
    js = sorted(js, key=lambda x: x["start_time"], reverse=True)
    return jsonify(js)

@app.route("/job/<job_id>/log")
def job_log(job_id):
    tail_lines = int(request.args.get("tail", "200"))
    with jobs_lock:
        j = jobs.get(job_id)
    if not j:
        return jsonify({"error": "job not found"}), 404
    p = Path(j["log_path"])
    if not p.exists():
        return jsonify({"log": ""})
    # return last tail_lines lines
    try:
        with p.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            filesize = fh.tell()
            size = 8192
            data = b""
            while tail_lines > 0 and filesize > 0:
                read_size = min(size, filesize)
                fh.seek(filesize - read_size)
                chunk = fh.read(read_size) + data
                lines = chunk.splitlines()
                if len(lines) > tail_lines:
                    data = b"\n".join(lines[-tail_lines:])
                    break
                else:
                    data = chunk
                filesize -= read_size
                size *= 2
            else:
                # file small
                pass
        text = data.decode("utf-8", errors="ignore")
    except Exception as e:
        text = f"Error reading log: {e}\n"
    return jsonify({"log": text})

@app.route("/job/<job_id>/cancel", methods=["POST"])
def cancel_job(job_id):
    with jobs_lock:
        j = jobs.get(job_id)
    if not j:
        return jsonify({"error": "job not found"}), 404
    proc = j.get("proc")
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            time.sleep(0.5)
            if proc.poll() is None:
                proc.kill()
            with jobs_lock:
                j["status"] = "killed"
                j["end_time"] = time.time()
            return jsonify({"ok": True, "status": j["status"]})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "process not running", "status": j.get("status")})

# Single-page UI (embedded template)
INDEX_HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>angr tools — Interactive GUI</title>
  <style>
    body { font-family: Inter, system-ui, Arial; margin: 28px; background:#0f1720; color:#e6eef8; }
    .wrap { display:flex; gap:40px; max-width:1200px; margin:auto; }
    .left { width:380px; }
    .panel { background:#15232b; padding:18px; border-radius:8px; box-shadow: 0 6px 20px rgba(0,0,0,0.6); }
    label{display:block; font-size:0.95rem; margin-top:10px; color:#cfe6ff}
    select,input,textarea{width:100%; padding:10px; margin-top:6px; border-radius:6px; background:#0b1418; border:1px solid #0f2940; color:#dfeefe}
    button{padding:10px 14px; margin-top:12px; border-radius:6px; cursor:pointer; background:#0a6; color:#012; border:none}
    button.secondary{background:#133240; color:#cfe6ff}
    #logbox { width:600px; height:480px; background:#060606; border:1px solid #222; padding:12px; overflow:auto; white-space:pre-wrap; color:#cfe6ff; }
    .job { padding:8px; border-bottom:1px solid #0b2430; }
    .small { font-size:0.85rem; color:#9fb2c8 }
  </style>
</head>
<body>
  <h1>angr tools — Interactive GUI</h1>
  <div class="small">Project: <code>{{project}}</code></div>
  <div class="wrap">
    <div class="left">
      <div class="panel">
        <h3>Run a script</h3>
        <label>Script</label>
        <select id="script-select"></select>
        <label>Target path (optional)</label>
        <input id="target" placeholder="/path/to/binary or leave blank"/>
        <label>Arguments (free-form)</label>
        <input id="args" placeholder="--out findings.csv --html report.html --yaradir yara_rules"/>
        <div style="display:flex; gap:8px;">
          <button id="start-btn">Start run</button>
          <button id="refresh-btn" class="secondary">Refresh scripts</button>
        </div>
      </div>

      <div style="height:18px"></div>
      <div class="panel">
        <h4>Current jobs</h4>
        <div id="jobs-list"></div>
      </div>
    </div>

    <div>
      <div class="panel">
        <h3>Live logs</h3>
        <div id="live-job-info" class="small">No job selected</div>
        <div id="logbox">Select a job to view its log.</div>
        <div style="margin-top:8px;">
          <button id="cancel-btn" class="secondary">Cancel selected job</button>
          <button id="tail-btn" class="secondary">Refresh log</button>
        </div>
      </div>
    </div>
  </div>

<script>
async function fetchScripts(){
  const r = await fetch("/scripts_list");
  const s = await r.json();
  const sel = document.getElementById("script-select");
  sel.innerHTML = "";
  s.forEach(x => {
    const opt = document.createElement("option");
    opt.value = x.name;
    opt.text = x.name + (x.summary ? " — "+x.summary.slice(0,80) : "");
    sel.appendChild(opt);
  });
}
async function fetchJobs(){
  const r = await fetch("/jobs");
  const js = await r.json();
  const container = document.getElementById("jobs-list");
  container.innerHTML = "";
  js.forEach(j => {
    const d = document.createElement("div");
    d.className = "job";
    d.innerHTML = `<strong>${j.script}</strong> <span class="small">[${j.status}]</span><br/><div class="small">${j.cmdline||''}</div>`;
    d.onclick = () => selectJob(j.id);
    container.appendChild(d);
  });
  window.all_jobs = js;
}
let current_job = null;
function selectJob(job_id){
  current_job = job_id;
  document.getElementById("live-job-info").innerText = "Selected: " + job_id;
  tailLog();
}
async function tailLog(){
  if(!current_job){ return; }
  try{
    const r = await fetch(`/job/${current_job}/log?tail=400`);
    const j = await r.json();
    document.getElementById("logbox").innerText = j.log || "";
    // scroll to bottom
    const lb = document.getElementById("logbox");
    lb.scrollTop = lb.scrollHeight;
  }catch(e){
    document.getElementById("logbox").innerText = "Error fetching log: " + e;
  }
}
document.getElementById("start-btn").onclick = async () => {
  const script = document.getElementById("script-select").value;
  const target = document.getElementById("target").value;
  const args = document.getElementById("args").value;
  if(!script){ alert("Choose a script"); return; }
  const r = await fetch("/run", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({script, target, args})
  });
  const j = await r.json();
  if(j.error){ alert("Error: "+j.error); return; }
  await fetchJobs();
  selectJob(j.id);
  // poll log periodically while running
  const poll = setInterval(async ()=>{
    await tailLog();
    // update job statuses, stop if job done
    const rj = await fetch("/jobs");
    const arr = await rj.json();
    const me = arr.find(x => x.id === j.id);
    if(me && me.status !== "running"){
      clearInterval(poll);
      await fetchJobs();
      await tailLog();
    }
  }, 1500);
};

document.getElementById("refresh-btn").onclick = fetchScripts;
document.getElementById("tail-btn").onclick = tailLog;
document.getElementById("cancel-btn").onclick = async () => {
  if(!current_job){ alert("Select a job first"); return; }
  const r = await fetch(`/job/${current_job}/cancel`, {method: "POST"});
  const j = await r.json();
  if(j.error) alert("Cancel error: "+j.error);
  else {
    await fetchJobs();
    await tailLog();
  }
};

(async function init(){
  await fetchScripts();
  await fetchJobs();
  setInterval(fetchJobs, 3000);
})();
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML, project=str(APPROOT))

if __name__ == "__main__":
    print(f"Starting interactive GUI on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
