#!/usr/bin/env python3
import argparse, os, logging
import angr, claripy

logging.getLogger("angr").setLevel("INFO")

# --- SimProcedures ---

class FakePtrace(angr.SimProcedure):
    # long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    def run(self, request, pid, addr, data):
        bits = self.state.arch.bits
        return claripy.BVV(0, bits)  # success

class FakeGetppid(angr.SimProcedure):
    def run(self):
        return claripy.BVV(1234, self.state.arch.bits)  # non-1 parent

class FakeOpenProcStatus(angr.SimProcedure):
    def run(self, pathname, flags, mode=0):
        # Resolve pathname best-effort
        try:
            path_str = self.state.mem[pathname].string.concrete.decode(errors="ignore")
        except Exception:
            path_str = ""
        if "/proc/self/status" in path_str:
            # mark a fake FD and preload content
            self.state.globals['fd_123_is_status'] = True
            self.state.globals['status_bytes'] = b"Name:\tfoo\nTracerPid:\t0\n"
            return claripy.BVV(123, self.state.arch.bits)  # fake fd
        return claripy.BVV(4, self.state.arch.bits)

class FakeRead(angr.SimProcedure):
    def run(self, fd, buf, count):
        bits = self.state.arch.bits
        try:
            fd_val = self.state.solver.eval(fd)
            n_req  = self.state.solver.eval(count)
        except Exception:
            return claripy.BVV(0, bits)
        if fd_val == 123 and self.state.globals.get('fd_123_is_status'):
            data = self.state.globals.get('status_bytes', b"")
            n = min(len(data), n_req)
            if n > 0:
                self.state.memory.store(buf, data[:n])
            return claripy.BVV(n, bits)
        return claripy.BVV(0, bits)

def main(binary, out_path, success_text, hook_getppid=False, hook_proc_status=False):
    if not os.path.exists(binary):
        raise SystemExit(f"Binary not found: {binary}")

    proj = angr.Project(binary, auto_load_libs=False)

    # Hook libc ptrace if dynamically linked
    sym = None
    try:
        sym = proj.loader.find_symbol('ptrace')
    except Exception:
        pass
    if sym is not None and sym.rebased_addr is not None:
        proj.hook_symbol('ptrace', FakePtrace())
        print(f"[*] Hooked 'ptrace' at {hex(sym.rebased_addr)}")
    else:
        print("[!] 'ptrace' import not found; if statically linked, consider addr hook or pattern hook.")

    if hook_getppid:
        try:
            proj.hook_symbol('getppid', FakeGetppid())
            print("[*] Hooked 'getppid'")
        except Exception:
            pass
    if hook_proc_status:
        try:
            proj.hook_symbol('open', FakeOpenProcStatus())
            proj.hook_symbol('read', FakeRead())
            print("[*] Hooked 'open' and 'read' for /proc/self/status")
        except Exception:
            print("[!] Could not hook open/read; libc symbol names may differ")

    # Symbolic argv[1]
    arg_bv = claripy.BVS("arg", 8*32)
    state = proj.factory.entry_state(args=[binary, arg_bv])
    simgr = proj.factory.simulation_manager(state)

    target_bytes = success_text.encode('utf-8')

    def reached_success(s):
        try:
            return target_bytes in s.posix.dumps(1)
        except Exception:
            return False

    print("[*] Exploring with anti-debug hooks …")
    simgr.explore(find=reached_success, num_find=1)

    if simgr.found:
        st = simgr.found[0]
        concrete = st.solver.eval(arg_bv, cast_to=bytes).split(b"\x00", 1)[0]
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(concrete or b"OK")
        print(f"[+] Reached success output; wrote {out_path}")
        print("[+] Sample argv[1]:", repr(concrete))
    else:
        print("[-] Did not reach success; check which anti-debug API the binary uses.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", default="results/antidebug/input.txt")
    ap.add_argument("--success-text", default="[ok] no debugger detected; continuing.")
    ap.add_argument("--hook-getppid", action="store_true")
    ap.add_argument("--hook-proc-status", action="store_true")
    args = ap.parse_args()
    main(args.binary, args.out, args.success_text, args.hook_getppid, args.hook_proc_status)
