"""
Offline tests for the ./wbs launcher's project-venv dispatch.

The launcher must always run under <project>/.venv/bin/python:
  * started by any other interpreter it re-execs (os.execv) into the venv
    python before importing third-party modules, preserving argv and keeping
    the launcher path (contains "wbs") in the cmdline for pidfile checks;
  * with no usable .venv it exits 1 and prints the bootstrap commands;
  * a re-exec that does not land in the venv is detected (no exec loop).
No bot is started and no IRC connection is made.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "wbs"
REEXEC_ENV = "_WBS_VENV_REEXEC"


def _base_python() -> str:
    """A non-venv interpreter (the venv's base python)."""
    exe = Path(sys.base_prefix) / "bin" / f"python{sys.version_info[0]}.{sys.version_info[1]}"
    if not exe.exists():
        pytest.skip(f"base interpreter not found at {exe}")
    return str(exe)


def _env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in (REEXEC_ENV, "VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME")}
    env.update(extra)
    return env


def _run(argv, cwd, **env) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(cwd), env=_env(**env), check=False,
                          capture_output=True, text=True, timeout=60)


def _require_exec_tmp(tmp_path: Path) -> None:
    """Skip when scripts under tmp_path cannot be executed (noexec mount)."""
    probe = tmp_path / "exec_probe.sh"
    probe.write_text("#!/bin/sh\nexit 0\n")
    probe.chmod(0o755)
    try:
        ok = subprocess.run([str(probe)], check=False, capture_output=True,
                            timeout=30).returncode == 0
    except OSError:
        ok = False
    finally:
        probe.unlink()
    if not ok:
        pytest.skip(f"pytest tmp dir {tmp_path} is on a noexec mount: "
                    "the fake venv interpreter cannot be executed")


def _fake_project(tmp_path: Path, venv_python_body: str | None) -> Path:
    """Copy the launcher into tmp_path; optionally add .venv/bin/python script."""
    proj = tmp_path / "proj"
    proj.mkdir()
    shutil.copy2(LAUNCHER, proj / "wbs")
    if venv_python_body is not None:
        bindir = proj / ".venv" / "bin"
        bindir.mkdir(parents=True)
        py = bindir / "python"
        py.write_text(venv_python_body)
        py.chmod(0o755)
    return proj


# ------------------------------------------------------------- real project

def test_help_under_base_python_reexecs_into_project_venv():
    venv_py = ROOT / ".venv" / "bin" / "python"
    if not venv_py.exists():
        pytest.skip("project .venv not bootstrapped")
    base = _base_python()
    probe = _run([base, "-c", "import sys; print(sys.prefix == sys.base_prefix)"], ROOT)
    assert probe.stdout.strip() == "True", "base interpreter must not be a venv"
    res = _run([base, str(LAUNCHER), "--help"], ROOT)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith("usage: wbs ")
    for flag in ("--config", "--db-path", "--foreground", "--mkpasswd", "--seed",
                 "--update", "--pidfile", "--logfile"):
        assert flag in res.stdout


def test_help_under_venv_python_runs_directly():
    venv_py = ROOT / ".venv" / "bin" / "python"
    if not venv_py.exists():
        pytest.skip("project .venv not bootstrapped")
    res = _run([str(venv_py), str(LAUNCHER), "--help"], ROOT)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith("usage: wbs ")


# ------------------------------------------------------------- fake projects

def test_reexec_preserves_argv_and_wbs_cmdline(tmp_path):
    _require_exec_tmp(tmp_path)
    # Fake venv python: report the argv it was exec'd with, then exit.
    proj = _fake_project(tmp_path, '#!/bin/sh\necho "ARGV:$0|$*"\necho "ENV:$' +
                         REEXEC_ENV + '"\n')
    res = _run([_base_python(), str(proj / "wbs"), "-f", "-c", "my.json",
                "--pidfile", "x.pid"], proj)
    assert res.returncode == 0, res.stderr
    argv_line, env_line = res.stdout.strip().splitlines()
    exe, args = argv_line[len("ARGV:"):].split("|", 1)
    assert exe == str(proj / ".venv" / "bin" / "python")
    assert args == f"{proj / 'wbs'} -f -c my.json --pidfile x.pid"
    assert "wbs" in args.split()[0]          # check_already_running() match
    assert env_line == f"ENV:{proj / '.venv'}"


def test_missing_venv_exits_1_with_bootstrap_commands(tmp_path):
    proj = _fake_project(tmp_path, None)
    res = _run([_base_python(), str(proj / "wbs"), "--help"], proj)
    assert res.returncode == 1
    assert res.stdout == ""
    for line in ("python3.13 -m venv .venv",
                 ".venv/bin/pip install --require-hashes -r requirements.lock",
                 ".venv/bin/pip install --no-deps ."):
        assert line in res.stderr
    assert "Traceback" not in res.stderr


def test_non_executable_venv_python_exits_1(tmp_path):
    proj = _fake_project(tmp_path, "#!/bin/sh\nexit 0\n")
    (proj / ".venv" / "bin" / "python").chmod(0o644)
    res = _run([_base_python(), str(proj / "wbs"), "--help"], proj)
    assert res.returncode == 1
    assert "project venv missing or broken" in res.stderr


def test_reexec_that_does_not_activate_venv_is_not_a_loop(tmp_path):
    # Broken venv python that just runs the base interpreter again: the
    # launcher must notice it is still not in the venv and stop.
    _require_exec_tmp(tmp_path)
    base = _base_python()
    proj = _fake_project(tmp_path, f'#!/bin/sh\nexec {base} "$@"\n')
    res = _run([base, str(proj / "wbs"), "--help"], proj)
    assert res.returncode == 1
    assert "did not activate the venv" in res.stderr
    assert "usage:" not in res.stdout


def test_launcher_reexec_happens_before_third_party_imports():
    src = LAUNCHER.read_text()
    guard = src.index("    _ensure_project_venv()")
    # SAST-018: the supervisor (argparse/psutil/IRC imports) lives in
    # src/main.py; the launcher's only project import is the delegate.
    for mod in ("from src.main import main",):
        assert src.index(mod) > guard, f"{mod!r} imported before venv re-exec"
    import ast
    for node in ast.parse(src).body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node.col_offset == 0:
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""])
            line_off = sum(len(l) + 1 for l in src.splitlines()[:node.lineno - 1])
            if line_off < guard:
                assert all(n.split(".")[0] in sys.stdlib_module_names for n in names), \
                    f"non-stdlib import {names} before venv re-exec"
