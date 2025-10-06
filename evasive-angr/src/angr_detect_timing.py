#!/usr/bin/env python3
"""
Neutralize timing anti-debug checks by stubbing clock_gettime/gettimeofday.

Usage:
  python3 src/angr_detect_timing.py --binary samples/antidebug_timing --out results/timing/input.txt
"""
import argparse, os, logging
import angr, claripy

logging.getLogger("angr").setLevel("INFO")

class FakeClockGettime(angr.SimProcedure):
    # int clock_gettime(clockid_t clk_id, struct timespec *tp)
    def run(self, clk_id, tp_ptr):
        # write a fixed timespec so delta will be small
        try:
            addr = self.state.solver.eval(tp_ptr)
        except Exception:
            return claripy.BVV(0, self.state.arch.bits)
        sec = 1000000  # arbitrary constant seconds
        nsec = 0
        # timespec: tv_sec (long), tv_nsec (long). Use 8 bytes each on x86_64
        sec_bytes = int(sec).to_bytes(8, 'little', signed=True)
        nsec_bytes = int(nsec).to_bytes(8, 'little', signed=True)
        self.state.memory.store(addr, sec_bytes)
        self.state.memory.store(addr + 8, nsec_bytes)
        return claripy.BVV(0, self.state.arch.bits)

class FakeGettimeofday(angr.SimProcedure):
    # int gettimeofday(struct timeval *tv, struct timezone *tz)
    def run(self, tv_ptr, tz):
        try:
            addr = self.state.solver.eval(tv_ptr)
        except Exception:
            return claripy.BVV(0, self.state.arch.bits)
        sec = 1000000
        usec = 0
        sec_bytes = int(sec).to_bytes(8, 'little', signed=True)  # store as 8 bytes so consistent
        usec_bytes = int(usec).to_bytes(8, 'little', signed=True)
        self.state.memory.store(addr, sec_bytes)
        self.state.memory.store(addr + 8, usec_bytes)
        return claripy.BVV(0, self.state.arch.bits)

def main(binary, out_path, success_text="[ok] timing check passed; continuing."):
    if not os.path.exists(binary):
        raise SystemExit("Binary not found: " + binary)

    proj = angr.Project(binary, auto_load_libs=False)

    # Hook clock_gettime/gettimeofday if available
    try:
        sym = proj.loader.find_symbol('clock_gettime')
        if sym is not None and sym.rebased_addr is not None:
            proj.hook_symbol('clock_gettime', FakeClockGettime())
            print("[*] Hooked clock_gettime")
    except Exception:
        pass

    try:
        sym2 = proj.loader.find_symbol('gettimeofday')
        if sym2 is not None and sym2.rebased_addr is not None:
            proj.hook_symbol('gettimeofday', FakeGettimeofday())
            print("[*] Hooked gettimeofday")
    except Exception:
        pass

    # symbolic argv[1]
    arg_bv = claripy.BVS("arg", 8*32)
    state = proj.factory.entry_state(args=[binary, arg_bv])
    simgr = proj.factory.simulation_manager(state)

    target_bytes = success_text.encode('utf-8')

    def reached_success(s):
        try:
            return target_bytes in s.posix.dumps(1)
        except Exception:
            return False

    print("[*] Exploring with timing hooks ...")
    simgr.explore(find=reached_success, num_find=1)

    if simgr.found:
        st = simgr.found[0]
        concrete = st.solver.eval(arg_bv, cast_to=bytes).split(b"\x00", 1)[0]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(concrete or b"OK")
        print("[+] Reached success; wrote", out_path)
        print("[+] Sample argv[1]:", repr(concrete))
    else:
        print("[-] Did not reach success; check which timing API is used.")
    
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", default="results/timing/input.txt")
    args = ap.parse_args()
    main(args.binary, args.out)
