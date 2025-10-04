alias avbin='~/lab/evasive-angr/samples/antidebug_demo'

angr_cfg_inj () { python3 scripts/cfg_injection_finder.py "${1:-$(avbin)}" | tee "adv_results/cfg_injection_$(basename ${1:-$(avbin)}).log"; }

angr_adv_det () { python3 scripts/advanced_angr_detector.py "${1:-$(avbin)}" 2>&1 | tee "adv_results/advanced_detector_$(basename ${1:-$(avbin)}).log"; }

angr_imports () { python3 scripts/list_imports.py "${1:-$(avbin)}" | tee "adv_results/imports_$(basename ${1:-$(avbin)}).log"; }
