"""
builder.py — compile a generated project with x86_64-w64-mingw32-gcc.

Detects the cross-compiler, runs the build, captures errors clearly. The
tool never executes the produced binary — compilation only.
"""

import os
import shutil
import subprocess

CC = "x86_64-w64-mingw32-gcc"
I686_CC = "i686-w64-mingw32-gcc"


class BuildError(Exception):
    pass


def compiler_available() -> bool:
    return shutil.which(CC) is not None


def build(project_dir: str, fmt: str = "exe") -> dict:
    """Compile main.c (+ syscalls.S if present) inside project_dir. Returns metadata."""
    if not compiler_available():
        raise BuildError(
            "%s not found. Install with: sudo apt install mingw-w64" % CC
        )

    main_c = os.path.join(project_dir, "main.c")
    if not os.path.isfile(main_c):
        raise BuildError("no main.c in %s" % project_dir)

    asm = os.path.join(project_dir, "syscalls.S")
    sources = [main_c] + ([asm] if os.path.isfile(asm) else [])

    out_ext = "exe" if fmt == "exe" else "dll"
    out_name = os.path.basename(os.path.normpath(project_dir)) + "." + out_ext
    out_path = os.path.join(project_dir, out_name)

    cmd = [CC, "-Wall", "-O2", "-s", "-std=gnu11"]
    if fmt == "dll":
        cmd.append("-shared")
    cmd += sources
    cmd += ["-o", out_path, "-lkernel32"]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    result = {
        "ok": proc.returncode == 0,
        "cmd": " ".join(cmd),
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "output": out_path if proc.returncode == 0 else None,
        "size": (os.path.getsize(out_path) if proc.returncode == 0 and os.path.exists(out_path) else 0),
    }
    if proc.returncode != 0:
        raise BuildError(
            "build failed.\n--- command ---\n%s\n--- stderr ---\n%s"
            % (result["cmd"], result["stderr"])
        )
    return result
