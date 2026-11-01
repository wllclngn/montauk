#!/usr/bin/env python3
"""A stopped process reads no GPU; a running one is still attributed.

A process stopped by SIGSTOP keeps its GPU context and memory, and montauk once
read it at 3.5 to 10% for its whole stop: A one-shot snapshot asked NVML from
the start of time and took the last sample NVML keeps for the process, frozen
at the stop, and a read NVML answered with "nothing newer" was taken as a
failure, which let the memory-share fallback hand every context holder a share.
This builds a small headless GLES load, waits for montauk to attribute it and
stops it. The first snapshots after the stop may still cover running time; once
one reads 0, every snapshot after it must, since each is then wholly inside the
stop. Then it resumes the load and requires it attributed again. It needs an NVIDIA GPU montauk reads through
NVML and the EGL and GLES headers; without them it reports SKIP.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import harness

note = harness.logger("gpu-stop")

LOAD = r"""
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <stdio.h>
static const char *vs = "attribute vec2 p; void main(){ gl_Position = vec4(p,0.0,1.0); }";
static const char *fs = "precision highp float; uniform float t; void main(){ float a = 0.0;"
  " for (int i = 0; i < 400; i++) a += sin(gl_FragCoord.x * 0.01 + float(i) + t) * cos(gl_FragCoord.y * 0.01 - t);"
  " gl_FragColor = vec4(a, a * 0.5, 0.25, 1.0); }";
static GLuint sh(GLenum k, const char *src) { GLuint s = glCreateShader(k); glShaderSource(s, 1, &src, 0); glCompileShader(s); return s; }
int main(void) {
  EGLDisplay d = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (!eglInitialize(d, 0, 0)) return 1;
  EGLint ca[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
  EGLConfig c; EGLint n; eglChooseConfig(d, ca, &c, 1, &n);
  EGLint pa[] = {EGL_WIDTH, 1024, EGL_HEIGHT, 1024, EGL_NONE};
  EGLSurface s = eglCreatePbufferSurface(d, c, pa);
  eglBindAPI(EGL_OPENGL_ES_API);
  EGLint xa[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
  EGLContext x = eglCreateContext(d, c, EGL_NO_CONTEXT, xa);
  if (!eglMakeCurrent(d, s, s, x)) return 1;
  GLuint pr = glCreateProgram(); glAttachShader(pr, sh(GL_VERTEX_SHADER, vs)); glAttachShader(pr, sh(GL_FRAGMENT_SHADER, fs));
  glBindAttribLocation(pr, 0, "p"); glLinkProgram(pr); glUseProgram(pr);
  GLfloat tri[] = {-1, -1, 3, -1, -1, 3};
  glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, tri); glEnableVertexAttribArray(0);
  GLint tl = glGetUniformLocation(pr, "t");
  printf("ready\n"); fflush(stdout);
  for (float t = 0;; t += 0.01f) { glUniform1f(tl, t); glDrawArrays(GL_TRIANGLES, 0, 3); glFinish(); }
}
"""

STOPPED_SNAPSHOTS = 8


def snapshot():
    r = harness.run_text([str(harness.MONTAUK), "--json"])
    return json.loads(r.stdout) if r.returncode == 0 else None


def gpu_of(snap, pid):
    for row in snap["processes"]["anomaly_features"]:
        if row["pid"] == pid:
            return row["gpu_util_pct"]
    return None


def until_attributed(pid, deadline):
    while time.monotonic() < deadline:
        s = snapshot()
        if s and (gpu_of(s, pid) or 0) > 0:
            return True
    return False


def main():
    if harness.missing_bins(harness.MONTAUK):
        note("FAIL: montauk not built")
        return 1
    first = snapshot()
    if not first or "NVIDIA" not in first.get("gpu", {}).get("name", "") or not shutil.which("cc") \
            or not Path("/usr/include/EGL/egl.h").exists():
        note("SKIP: needs an NVIDIA GPU read through NVML, cc and the EGL/GLES headers")
        return 0
    with tempfile.TemporaryDirectory() as td:
        src, exe = Path(td) / "load.c", Path(td) / "mtkgpuload"
        src.write_text(LOAD)
        cc = subprocess.run(["cc", "-O2", "-o", str(exe), str(src), "-lEGL", "-lGLESv2"],
                            capture_output=True, text=True)
        if cc.returncode != 0:
            note(f"SKIP: the GLES load does not build ({cc.stderr.strip()[:120]})")
            return 0
        # EGL_DEFAULT_DISPLAY takes its platform from the session: Under a
        # desktop's WAYLAND_DISPLAY or DISPLAY the load lands where NVML may
        # never see it, so it runs with no window system, on the device.
        bare = {k: v for k, v in os.environ.items() if k not in ("WAYLAND_DISPLAY", "WAYLAND_SOCKET", "DISPLAY")}
        load = subprocess.Popen([str(exe)], stdout=subprocess.PIPE, text=True, env=bare)
        fails = 0
        try:
            if load.stdout.readline().strip() != "ready":
                note("SKIP: the GLES load found no EGL display")
                return 0
            limit = time.monotonic() + 30
            if not until_attributed(load.pid, limit):
                note("FAIL: the running load was never attributed any GPU")
                return 1
            note("PASS the running load is attributed")
            os.kill(load.pid, signal.SIGSTOP)
            limit = time.monotonic() + 30
            while time.monotonic() < limit and gpu_of(snapshot(), load.pid):
                pass
            readings = [gpu_of(snapshot(), load.pid) for _ in range(STOPPED_SNAPSHOTS)]
            if time.monotonic() >= limit or any(v for v in readings):
                fails += 1
                note(f"FAIL: stopped, it read {readings}")
            else:
                note(f"PASS stopped, {STOPPED_SNAPSHOTS} snapshots in a row read 0")
            os.kill(load.pid, signal.SIGCONT)
            if until_attributed(load.pid, time.monotonic() + 30):
                note("PASS resumed, it is attributed again")
            else:
                fails += 1
                note("FAIL: resumed, it was not attributed again")
        finally:
            os.kill(load.pid, signal.SIGCONT)
            load.kill()
            load.wait()
    note("GATE PASSED" if not fails else f"GATE FAILED: {fails} check(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
