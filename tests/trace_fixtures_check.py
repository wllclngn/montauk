#!/usr/bin/env python3
"""Live BPF captures of small known programs, each held to what it did.

Each fixture is a C program compiled here, exec'd after montauk attaches and
traced by its own name, so the capture is that program and nothing else. Every
verdict is read from `montauk --analyze --json`:

  ntsync    a thread in timed WAIT_ANY waits on an event nobody sets while a
            second thread loops on timed futex waits, both pinned to one CPU.
            Every wait completes once under the waiter's tid at its timeout;
            no ntsync event carries the futex thread's tid.
  aligned   a block freed and taken back by posix_memalign, then freed again,
            plus one block from each other aligned allocator: no double free,
            each allocator named. A real double free, two
            frees of one malloc block, is still flagged.
  narrowed  a capture of fork,exec,exit,comm,ntsync attaches no libc probe;
            one with heap attaches every one it asks for.
  parked    a --trace-classes ntsync capture of a thread entering an INFINITE
            wait keeps its wait-site stack.
  deadlock  two threads each holding one glibc mutex and waiting on the other's,
            killed after three seconds: endstate names both killed while parked
            on a futex word, each on the word of the mutex the other holds, with
            the site of the wait.
  pattern   a 40-odd-byte, three-name --trace pattern reads back whole.
  anonsys   a static program with no libc maps an anonymous executable page,
            fills it with two stubs and calls readlink and readlinkat on
            /proc/self/exe through it: Each call is recorded with its result, the
            path it returned and the page it came from; the filter by origin
            keeps those two and nothing else; the exec record carries a filename
            past 64 bytes and the arguments, and the exit its time.
  destroy   a program renames, unlinks and rmdirs known paths: Each call is
            recorded with the paths it named, whatever its libc calls it.
  catch     a program that ignores SIGINT and catches SIGTERM is sent each by a
            second process: One row apiece, ignored and caught, each carrying
            the sending process's pid, and no other signal row.
  abortsite abort() two calls below main in code built with no frame pointer:
            The signals report's site is walked by .eh_frame and names both
            callers and main, in order.
  firstfree a new thread freeing a block as its first heap call, as is and in
            two variants (its stack touched first; another heap call first):
            glibc enters free twice for a thread's first free, setting up the
            tcache and tail-calling free again, and each free must still be
            recorded once and no double free reported.

Needs root for BPF; reports SKIP without it.
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import harness
from harness import MONTAUK

note = harness.logger("trace-fixtures")
fails = 0
STOP_TIMEOUT = 15.0


def check(ok, label):
    global fails
    note(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        fails += 1
    return ok


NTSYNC = r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/ntsync.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static volatile int done;
static void pin(void) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(0, &s); sched_setaffinity(0, sizeof s, &s); }
static void *futexer(void *a) {
  pin(); printf("futex %ld\n", (long)gettid()); fflush(stdout);
  int w = 0; struct timespec t = {0, 2000000};
  while (!done) syscall(SYS_futex, &w, FUTEX_WAIT_PRIVATE, 0, &t, NULL, 0);
  return a;
}
int main(void) {
  pin();
  int dev = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
  struct ntsync_event_args ea = {0};
  int ev = ioctl(dev, NTSYNC_IOC_CREATE_EVENT, &ea);
  if (dev < 0 || ev < 0) return 3;
  printf("waiter %ld\n", (long)gettid()); fflush(stdout);
  pthread_t t; pthread_create(&t, NULL, futexer, NULL);
  for (int i = 0; i < 5; i++) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    __u32 objs[1] = {(__u32)ev};
    struct ntsync_wait_args wa = {0};
    wa.timeout = (__u64)now.tv_sec * 1000000000ull + (__u64)now.tv_nsec + 50000000ull;
    wa.objs = (uintptr_t)objs; wa.count = 1; wa.owner = (__u32)gettid();
    ioctl(dev, NTSYNC_IOC_WAIT_ANY, &wa);
  }
  done = 1; pthread_join(t, NULL);
  return 0;
}
"""

PARKED = r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <linux/ntsync.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/ioctl.h>
static int dev, ev;
static void *waiter(void *a) {
  __u32 objs[1] = {(__u32)ev};
  struct ntsync_wait_args wa = {0};
  wa.timeout = ~0ull; wa.objs = (uintptr_t)objs; wa.count = 1; wa.owner = (__u32)gettid();
  ioctl(dev, NTSYNC_IOC_WAIT_ANY, &wa);
  return a;
}
int main(void) {
  dev = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
  struct ntsync_event_args ea = {0};
  ev = ioctl(dev, NTSYNC_IOC_CREATE_EVENT, &ea);
  if (dev < 0 || ev < 0) return 3;
  pthread_t t; pthread_create(&t, NULL, waiter, NULL);
  __u32 prev; ioctl(ev, NTSYNC_IOC_EVENT_SET, &prev);   /* releases it, before or after it enters */
  pthread_join(t, NULL);
  return 0;
}
"""

ALIGNED = r"""
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
int main(void) {
  void *b[16] = {0}, *hit = 0;
  for (int i = 0; i < 16 && !hit; i++) { b[i] = malloc(40); if (((uintptr_t)b[i] & 63) == 0) hit = b[i]; }
  if (!hit) return 3;
  free(hit);
  void *p = 0;
  if (posix_memalign(&p, 64, 40)) return 4;
  printf("reused %d\n", p == hit); fflush(stdout);
  free(p);
  for (int i = 0; i < 16; i++) if (b[i] && b[i] != hit) free(b[i]);
  void *a = aligned_alloc(64, 64), *m = memalign(64, 40), *v = valloc(100), *pv = pvalloc(100);
  free(a); free(m); free(v); free(pv);
  return 0;
}
"""

DOUBLE = r"""
#include <stdlib.h>
int main(void) { void *volatile p = malloc(24); free(p); free(p); return 0; }
"""

FIRSTFREE = r"""
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
static void *thr(void *blk) {
#if VARIANT == 1
  volatile char touch[65536]; memset((char *)touch, 1, sizeof touch);
#elif VARIANT == 2
  free(malloc(1));
#endif
  free(blk);
  return 0;
}
int main(void) {
  for (int i = 0; i < 3; i++) {
    void *b = malloc(24);
    pthread_t t; pthread_create(&t, 0, thr, b); pthread_join(t, 0);
  }
  return 0;
}
"""


DEADLOCK = r"""
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
static pthread_mutex_t a = PTHREAD_MUTEX_INITIALIZER, b = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t both;
static void *take(pthread_mutex_t *mine, pthread_mutex_t *theirs, const char *who) {
  pthread_mutex_lock(mine);
  printf("%s %ld %p\n", who, (long)syscall(SYS_gettid), (void *)mine);
  fflush(stdout);
  pthread_barrier_wait(&both);
  pthread_mutex_lock(theirs);
  return 0;
}
static void *first(void *x) { return take(&a, &b, "first"); }
static void *second(void *x) { return take(&b, &a, "second"); }
int main(void) {
  pthread_barrier_init(&both, 0, 2);
  pthread_t t1, t2;
  pthread_create(&t1, 0, first, 0);
  pthread_create(&t2, 0, second, 0);
  pthread_join(t1, 0);
  return 0;
}
"""


# No libc at all: Every syscall is an instruction in this file, or in the
# anonymous executable page it fills with two stubs -- the call's number into
# eax, the syscall instruction, ret -- and calls readlink and readlinkat on
# /proc/self/exe through, as a module mapped by hand does. It prints the page's
# address in hex for the check.
ANONSYS = r"""
static long sys(long n, long a, long b, long c, long d, long e, long f) {
  long r;
  register long r10 __asm__("r10") = d, r8 __asm__("r8") = e, r9 __asm__("r9") = f;
  __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return r;
}
static const unsigned char rl[] = {0xb8, 89, 0, 0, 0, 0x0f, 0x05, 0xc3};
static const unsigned char rla[] = {0x49, 0x89, 0xca, 0xb8, 0x0b, 0x01, 0, 0, 0x0f, 0x05, 0xc3};
void _start(void) {
  char buf[256], out[32];
  unsigned char *m = (unsigned char *)sys(9, 0, 4096, 7, 0x22, -1, 0);
  for (unsigned i = 0; i < sizeof rl; i++) m[i] = rl[i];
  for (unsigned i = 0; i < sizeof rla; i++) m[64 + i] = rla[i];
  long (*f)(const char *, char *, long) = (long (*)(const char *, char *, long))m;
  long (*g)(long, const char *, char *, long) = (long (*)(long, const char *, char *, long))(m + 64);
  f("/proc/self/exe", buf, sizeof buf);
  g(-100, "/proc/self/exe", buf, sizeof buf);
  unsigned long v = (unsigned long)m;
  int n = 0;
  for (int s = 60; s >= 0; s -= 4) out[n++] = "0123456789abcdef"[(v >> s) & 15];
  out[n++] = '\n';
  sys(1, 1, (long)out, n, 0, 0, 0);
  sys(231, 0, 0, 0, 0, 0, 0);
}
"""


# Known paths removed and renamed under the directory given as its argument.
DESTROY = r"""
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
  char a[512], b[512], d[512];
  snprintf(a, sizeof a, "%s/doomed", argv[1]);
  snprintf(b, sizeof b, "%s/renamed", argv[1]);
  snprintf(d, sizeof d, "%s/subdir", argv[1]);
  close(open(a, O_CREAT | O_WRONLY, 0600));
  rename(a, b);
  unlink(b);
  mkdir(d, 0700);
  rmdir(d);
  return 0;
}
"""


# SIGINT ignored, SIGTERM caught: It prints its pid once both are in place and
# waits until the handler runs.
CATCH = r"""
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
static volatile sig_atomic_t got;
static void on_term(int s) { got = s; }
int main(void) {
  signal(SIGINT, SIG_IGN);
  struct sigaction sa = {0};
  sa.sa_handler = on_term;
  sigaction(SIGTERM, &sa, 0);
  printf("%d\n", getpid());
  fflush(stdout);
  while (!got) pause();
  return 0;
}
"""


# abort() two calls below main, in code built with no frame pointer. The
# printf takes stdout's buffer from malloc, whose record has montauk read the
# process's maps, and the pause holds the process until it has.
ABORTSITE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((noinline)) void site_f2(void) { abort(); }
__attribute__((noinline)) void site_f1(void) { site_f2(); __asm__ volatile(""); }
int main(void) {
  printf("%d\n", getpid());
  fflush(stdout);
  usleep(500000);
  site_f1();
  return 0;
}
"""


def build(td, name, src, *defs, libs=()):
    c, exe = td / f"{name}.c", td / name
    c.write_text(src)
    r = subprocess.run(["cc", "-O0", "-w", *defs, "-o", str(exe), str(c), "-pthread", *libs],
                       capture_output=True, text=True)
    return exe if r.returncode == 0 else None


def capture(td, exe, pattern, classes=None, hold=None, flags=(), args=(), drive=None):
    """Trace one run of `exe` by `pattern`, exec'd after attach. Returns the
    capture path, montauk's log and the program's stdout and status. With
    `hold`, the program is killed that many seconds after it starts; with
    `drive`, it is called with the running program, which then runs to its
    end; `flags` go to montauk and `args` to the program."""
    out = td / f"{exe.name}-{len(list(td.glob('*.bin')))}.bin"
    cmd = [str(MONTAUK), "--trace", pattern, "--trace-out", str(out), *flags]
    if classes:
        cmd += ["--trace-classes", classes]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log = []
    reader = threading.Thread(target=lambda: log.extend(proc.stdout), daemon=True)
    reader.start()
    end = time.monotonic() + STOP_TIMEOUT
    while time.monotonic() < end and not any("eBPF trace attached" in l for l in list(log)):
        time.sleep(0.05)
    if drive is not None:
        prog = subprocess.Popen([str(exe), *args], stdout=subprocess.PIPE, text=True)
        first = drive(prog)
        try:
            stdout, _ = prog.communicate(timeout=STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            prog.kill()
            stdout, _ = prog.communicate()
        r = subprocess.CompletedProcess(prog.args, prog.returncode, first + stdout, "")
    elif hold is None:
        r = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=STOP_TIMEOUT)
    else:
        prog = subprocess.Popen([str(exe), *args], stdout=subprocess.PIPE, text=True)
        time.sleep(hold)
        prog.kill()
        stdout, _ = prog.communicate()
        r = subprocess.CompletedProcess(prog.args, prog.returncode, stdout, "")
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=STOP_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    reader.join(timeout=STOP_TIMEOUT)
    return out, "".join(log), r.stdout, r.returncode


def query(cap, *q):
    r = harness.run_text([str(MONTAUK), "--analyze", str(cap), "--select", *q, "--json"])
    return json.loads(r.stdout)["rows"] if r.returncode == 0 else []


def report(cap, name):
    r = harness.run_text([str(MONTAUK), "--analyze", str(cap), "--json"])
    d = json.loads(r.stdout) if r.returncode == 0 else {"reports": []}
    return next((x for x in d["reports"] if x["name"] == name), {}), d.get("trace", {})


def main():
    if os.geteuid() != 0:
        note("SKIP: needs root for BPF -- run: sudo python3 tests/trace_fixtures_check.py")
        return 0
    if harness.missing_bins(MONTAUK):
        note("FAIL: montauk not built")
        return 1
    keep = Path("/tmp/montauk/trace_fixtures")
    with tempfile.TemporaryDirectory() as tdn:
        td = Path(tdn)

        # ntsync: each wait is its own thread's.
        exe = build(td, "mtkfx_ntsync", NTSYNC)
        if not Path("/dev/ntsync").exists() or not exe:
            note("SKIP ntsync: no /dev/ntsync or the fixture does not build")
        else:
            cap, log, out, rc = capture(td, exe, exe.name)
            tids = {k: int(v) for k, v in (l.split() for l in out.splitlines())}
            rows = query(cap, "ntsync.wait_any", "--by", "tid,result", "--count")
            futex_rows = [r for r in rows if r[0] == tids.get("futex")]
            done = sum(r[2] for r in rows if r[0] == tids.get("waiter") and r[1] == -110)
            entered = sum(r[2] for r in rows if r[0] == tids.get("waiter") and r[1] == -999)
            check(rc == 0 and not futex_rows,
                  f"ntsync: no wait under the futex thread's tid ({futex_rows})")
            check(done == 5 and entered == 5,
                  f"ntsync: the waiter's 5 waits enter and complete at their timeout under its own tid "
                  f"({entered} entered, {done} timed out; rows {rows})")

        # parked: a narrowed ntsync capture keeps the wait-site stack.
        exe = build(td, "mtkfx_park", PARKED)
        if Path("/dev/ntsync").exists() and exe:
            cap, log, out, rc = capture(td, exe, exe.name, "ntsync")
            stacks = query(cap, "waitstack", "--count")
            check(rc == 0 and stacks and stacks[0][0] >= 1,
                  f"classes: --trace-classes ntsync keeps the INFINITE wait's stack ({stacks})")

        # deadlock: endstate names each thread on the futex word the other holds.
        exe = build(td, "mtkfx_dlock", DEADLOCK)
        if exe:
            cap, log, out, rc = capture(td, exe, exe.name, "futex,signal,exit", hold=3.0)
            held = {who: (int(tid), int(addr, 16)) for who, tid, addr in (l.split() for l in out.splitlines())}
            es, _ = report(cap, "endstate")
            on = {t["tid"]: (t.get("wait"), t.get("status"), int(t.get("uaddr", "0"), 16), t.get("parked_at"))
                  for t in es.get("parked", [])}
            ok = len(held) == 2
            for who, other in (("first", "second"), ("second", "first")):
                tid = held.get(who, (0, 0))[0]
                ok = ok and on.get(tid, (None,))[:3] == ("futex", "KILLED-PARKED", held[other][1])
            check(ok, f"deadlock: endstate names both threads parked on the word the other holds "
                      f"(held {held}; parked {on}; {es.get('verdict')})")
            check(ok and all(on[held[w][0]][3] for w in held),
                  f"deadlock: each with the site of its wait ({on})")

        # aligned: an aligned allocation is an allocation.
        exe = build(td, "mtkfx_align", ALIGNED)
        if exe:
            cap, log, out, rc = capture(td, exe, exe.name)
            df, _ = report(cap, "doublefree")
            want = ("posix_memalign", "aligned_alloc", "memalign", "valloc", "pvalloc")
            seen = {op: (query(cap, f"heap.{op}", "--count") or [[0]])[0][0] for op in want}
            check(rc == 0 and "reused 1" in out, f"aligned: posix_memalign took back the freed block ({out.strip()})")
            check(df.get("class") == "CLEAN", f"aligned: no double free ({df.get('verdict')})")
            check(all(seen.values()), f"aligned: each allocator named ({seen})")
        exe = build(td, "mtkfx_dfree", DOUBLE)
        if exe:
            cap, log, out, rc = capture(td, exe, exe.name)
            df, _ = report(cap, "doublefree")
            check(df.get("class") in ("LOGIC", "RACE"), f"aligned: a real double free still flagged ({df.get('verdict')})")

        # narrowed: probes attach only for the classes captured.
        exe = build(td, "mtkfx_quiet", "int main(void) { return 0; }\n")
        if exe:
            _, log, _, _ = capture(td, exe, exe.name, "fork,exec,exit,comm,ntsync")
            check("libc uprobes: none attached" in log,
                  f"narrowed: no libc probe attaches without heap or abort "
                  f"({[l for l in log.splitlines() if 'libc uprobes' in l]})")
            _, log, _, _ = capture(td, exe, exe.name, "heap")
            line = next((l for l in log.splitlines() if "libc uprobes attached" in l), "")
            got = line.split("attached: ")[-1].split(" ")[0] if line else "?/?"
            a, _, b = got.partition("/")
            check(a == b and a.isdigit() and int(a) > 0, f"narrowed: heap attaches every heap probe ({line.strip()})")

        # pattern: the whole --trace pattern survives the header.
        if exe:
            pattern = f"{exe.name},second_name_here,third_name_there"
            cap, _, _, _ = capture(td, exe, pattern)
            _, trace = report(cap, "doublefree")
            check(trace.get("pattern") == pattern,
                  f"pattern: a {len(pattern)}-byte pattern reads back whole ({trace.get('pattern')!r})")

        # firstfree: a repeated delivery is not a second free.
        for v, label in ((0, "as is"), (1, "stack touched first"), (2, "another heap call first")):
            exe = build(td, f"mtkfx_ff{v}", FIRSTFREE, f"-DVARIANT={v}")
            if not exe:
                continue
            cap, _, _, _ = capture(td, exe, exe.name)
            df, _ = report(cap, "doublefree")
            frees = query(cap, "heap.free", "--by", "tid,addr", "--count")
            repeats = [r for r in frees if r[1] and r[2] > 1]
            check(df.get("class") == "CLEAN" and not repeats,
                  f"firstfree ({label}): each free once ({df.get('verdict')}; repeated {repeats})")

        # anonsys: a syscall made from a page mapped by hand is recorded with
        # its arguments, its result, the path it returned and the mapping it
        # came from; the filter by origin keeps it and nothing else; the exec
        # record carries a filename past 64 bytes and the arguments.
        deep = td / ("a_directory_whose_name_alone_runs_past_the_sixty_four_bytes_exec_once_kept")
        deep.mkdir()
        c = deep / "mtkfx_anonsys.c"
        c.write_text(ANONSYS)
        exe = deep / "mtkfx_anonsys"
        built = subprocess.run(["cc", "-O0", "-w", "-static", "-nostdlib", "-fno-pie", "-no-pie",
                                "-fno-stack-protector", "-fno-builtin", "-o", str(exe), str(c)],
                               capture_output=True, text=True).returncode == 0
        if not built:
            note("SKIP anonsys: the fixture does not build")
        else:
            cap, log, out, rc = capture(td, exe, exe.name, flags=("--trace-syscalls", "mmap,readlink,readlinkat"),
                                        args=("one", "two"))
            page = int(out.strip() or "0", 16)
            calls = query(cap, "syscall.readlink,readlinkat", "--by", "nr,result,anon,vma_start,path,path2", "--count")
            want = [[89, len(str(exe)), 1, page, "/proc/self/exe", str(exe), 1],
                    [267, len(str(exe)), 1, page, "/proc/self/exe", str(exe), 1]]
            check(rc == 0 and page and calls == want,
                  f"anonsys: both calls from the page mapped by hand, with the path each returned ({calls}; page {page:#x})")
            maps = query(cap, "syscall.mmap", "--by", "result,anon", "--count")
            check(maps == [[page, 0, 1]], f"anonsys: the mmap that made the page, from file-backed code ({maps})")
            anonmap = query(cap, "mmap", "--where", "fd=-1", "--by", "addr,prot", "--count")
            check([page, 7, 1] in anonmap, f"anonsys: the mmap class keeps the anonymous executable page ({anonmap})")
            ex = query(cap, "exec", "--by", "path,argv", "--count")
            check([str(exe), f"{exe} one two", 1] in ex,
                  f"anonsys: exec's whole {len(str(exe))}-byte filename and its arguments ({ex})")
            ends = query(cap, "exit", "--by", "pid", "--first")
            check(len(ends) == 1 and ends[0][1] > 0, f"anonsys: the exit record carries its time ({ends})")
            cap, log, out, rc = capture(td, exe, exe.name, flags=("--trace-syscalls-from", "anon"))
            fromanon = query(cap, "syscall", "--by", "nr", "--count")
            check(fromanon == [[89, 1], [267, 1]],
                  f"anonsys: --trace-syscalls-from anon keeps the page's two calls and nothing else ({fromanon})")

        # destroy: each removal and rename names its paths.
        exe = build(td, "mtkfx_destroy", DESTROY)
        if exe:
            work = td / "destroy-work"
            work.mkdir()
            cap, log, out, rc = capture(td, exe, exe.name, args=(str(work),),
                                        flags=("--trace-syscalls", "rename,renameat,renameat2,unlink,unlinkat,rmdir"))
            seen = query(cap, "syscall", "--by", "nr,path,path2,result", "--count")
            named = {(r[1], r[2]) for r in seen if r[3] == 0}
            check(rc == 0 and (f"{work}/doomed", f"{work}/renamed") in named and (f"{work}/renamed", "") in named
                  and (f"{work}/subdir", "") in named,
                  f"destroy: the rename, the unlink and the rmdir each with the paths they removed ({seen})")

        # catch: a signal the program handles is a row, with its disposition and
        # the pid of the process that sent it; one it ignores is a row too.
        exe = build(td, "mtkfx_catch", CATCH)
        if exe:
            senders = {}

            def send(prog):
                first = prog.stdout.readline()
                for sig, nr in (("INT", 2), ("TERM", 15)):
                    k = subprocess.Popen(["kill", f"-{sig}", str(prog.pid)])
                    k.wait()
                    senders[nr] = k.pid
                    time.sleep(0.2)
                return first

            cap, log, out, rc = capture(td, exe, exe.name, "fork,exec,exit,signal", drive=send)
            rows = query(cap, "signal", "--by", "signal_nr,disposition,sender_pid", "--count")
            check(rc == 0 and [15, 3, senders.get(15), 1] in rows,
                  f"catch: one delivery row for the caught SIGTERM with the sender's pid "
                  f"(senders {senders}; rows {rows})")
            check([2, 2, senders.get(2), 1] in rows and len(rows) == 2,
                  f"catch: the ignored SIGINT is a row with its sender, and nothing else is ({rows})")

        # abortsite: the abort's site reaches through code with no frame pointer.
        c = td / "mtkfx_abort.c"
        c.write_text(ABORTSITE)
        exe = td / "mtkfx_abort"
        built = subprocess.run(["cc", "-O2", "-w", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
                                "-o", str(exe), str(c)], capture_output=True, text=True).returncode == 0
        if not built:
            note("SKIP abortsite: the fixture does not build")
        else:
            cap, log, out, rc = capture(td, exe, exe.name)
            sg, _ = report(cap, "signals")
            ab = next((e for e in sg.get("events", []) if e.get("kind") == "DELIVER" and e.get("signal") == "SIGABRT"), {})
            funcs = harness.elf_functions(exe, {"site_f2", "site_f1", "main"})
            named = harness.site_callers(ab.get("site", ""), exe.name, funcs)
            check(ab.get("site_by") == "eh_frame" and named == ["site_f2", "site_f1", "main"],
                  f"abortsite: the site walks .eh_frame to both callers and main "
                  f"({ab.get('site_by')}: {ab.get('site')}; named {named})")
            check(ab.get("disposition") == "default", f"abortsite: the abort's disposition is the default ({ab})")

        if fails:
            keep.mkdir(parents=True, exist_ok=True)
            # The captures and their maps sidecars, which name every site in them.
            for f in [*td.glob("*.bin"), *td.glob("*.maps")]:
                (keep / f.name).write_bytes(f.read_bytes())
            note(f"evidence kept in {keep}")
    note("OK" if not fails else f"{fails} check(s) FAILED")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
