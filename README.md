# 🧩 Process-Injection-Toolset

**Process-Injection-Toolset** is a research-driven framework for analyzing evasive malware using angr (https://docs.angr.io/en/latest/) symbolic execution engine.
It automates detection of **process injection, hollowing, anti-debugging, and evasive logic**.

---

## 🚀 Features
- Extended injection detectors (`v2`, `v3`)
- Advanced angr-based symbolic exploration
- CFG & DDG visualization
- High-entropy blob extraction → auto YARA rule generation
- Report analyzer (CSV + HTML outputs)
- Flask gallery to visualize results interactively
- Menu + GUI frontends for easy use

---

## 📦 Installation

```bash
git clone https://github.com/alishahid74/Process-Injection-Toolset.git
cd Process-Injection-Toolset
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Process-Injection-Toolset
