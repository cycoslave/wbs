"""
SAST-018: the installed ``wbs`` console script must resolve to a packaged module.

pyproject used to declare ``wbs = "main:main"`` while no ``main.py`` existed and
the wheel ships only the ``src`` package, so an installed ``wbs`` died with
ModuleNotFoundError. The supervisor now lives in ``src/main.py`` and both the
console script (``src.main:main``) and the repository ``./wbs`` launcher run it.

Covered here (all offline; no bot start, no IRC connection):
  * pyproject's console script names a module/function shipped in the wheel;
  * ``src.main`` imports and answers ``--help`` using only the standard library
    (no IRC/Core/psutil import), and the ./wbs launcher delegates to it;
  * a wheel built from a scratch copy of the project installs into a throwaway
    venv whose ``wbs --help`` succeeds from outside the checkout, importing
    ``src`` from site-packages, never from the checkout, and without IRC startup.
"""
from __future__ import annotations

import ast
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
PYPROJECT = ROOT / "pyproject.toml"
LAUNCHER = ROOT / "wbs"

HELP_FLAGS = ("--config", "--db-path", "--foreground", "--mkpasswd", "--seed",
              "--update", "--pidfile", "--logfile")
# Modules whose import would mean the bot runtime (IRC/Core) was being started.
RUNTIME_MODULES = ("src.irc", "src.core", "src.net", "src.botnet", "irc", "psutil")


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _entrypoint() -> tuple[str, str]:
    target = _pyproject()["project"]["scripts"]["wbs"]
    module, _, func = target.partition(":")
    return module.strip(), func.strip()


def _clean_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k not in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                        "UV_PROJECT_ENVIRONMENT", "_WBS_VENV_REEXEC")}
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# static: pyproject <-> packaged module
# ---------------------------------------------------------------------------

def test_console_script_targets_packaged_module():
    module, func = _entrypoint()
    assert (module, func) == ("src.main", "main")
    packages = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    top = module.split(".")[0]
    assert top in packages, f"{module} is not inside a packaged wheel directory {packages}"
    path = ROOT.joinpath(*module.split(".")).with_suffix(".py")
    assert path.is_file(), f"console script module missing: {path}"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert func in funcs


def test_no_stale_root_main_module_reference():
    # The old target: a top-level "main" module that never shipped.
    assert not (ROOT / "main.py").exists()
    assert _pyproject()["project"]["scripts"]["wbs"] != "main:main"


def test_main_module_has_no_eager_runtime_imports():
    """Top-level imports of src.main must stay stdlib + src/__init__ only."""
    tree = ast.parse((SRC / "main.py").read_text(encoding="utf-8"))
    eager = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            eager += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            eager.append("." * node.level + (node.module or ""))
    allowed_rel = {"."}
    for name in eager:
        if name.startswith("."):
            assert name in allowed_rel, f"eager relative import {name!r} in src/main.py"
        else:
            assert name.split(".")[0] in sys.stdlib_module_names, \
                f"eager third-party import {name!r} in src/main.py"


# ---------------------------------------------------------------------------
# in-process / checkout behaviour
# ---------------------------------------------------------------------------

def test_entrypoint_callable_resolves_and_parses_args():
    module, func = _entrypoint()
    main = getattr(importlib.import_module(module), func)
    assert callable(main)
    mod = importlib.import_module(module)
    args = mod.parse_args(["-f", "-c", "x.json", "--pidfile", "p.pid"])
    assert args.foreground and args.config == "x.json" and args.pidfile == "p.pid"


def test_help_imports_no_runtime_modules(tmp_path):
    probe = (
        "import json, sys\n"
        "from src.main import main\n"
        "try:\n"
        "    main(['--help'])\n"
        "except SystemExit as e:\n"
        "    code = e.code\n"
        "else:\n"
        "    code = 'no-exit'\n"
        f"bad = [m for m in {RUNTIME_MODULES!r} if m in sys.modules]\n"
        "print(json.dumps({'code': code, 'bad': bad}))\n"
    )
    res = subprocess.run([sys.executable, "-c", probe], cwd=str(ROOT), env=_clean_env(),
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    out = res.stdout.strip().splitlines()
    assert out[0].startswith("usage: wbs ")
    report = json.loads(out[-1])
    assert report == {"code": 0, "bad": []}


def test_missing_config_exits_before_runtime(tmp_path):
    """Startup path stops at config validation without touching IRC/Core."""
    probe = (
        "import json, sys\n"
        "from src.main import main\n"
        "try:\n"
        "    main(['-c', sys.argv[1]])\n"
        "except SystemExit as e:\n"
        "    code = e.code\n"
        f"bad = [m for m in {RUNTIME_MODULES!r} if m in sys.modules]\n"
        "print(json.dumps({'code': code, 'bad': bad}))\n"
    )
    res = subprocess.run([sys.executable, "-c", probe, str(tmp_path / "nope.json")],
                         cwd=str(ROOT), env=_clean_env(), capture_output=True, text=True,
                         timeout=60)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout.strip().splitlines()[-1]) == {"code": 1, "bad": []}
    assert "config file not found" in res.stderr


def test_launcher_delegates_to_packaged_main():
    """./wbs keeps its venv dispatch and runs src.main.main (no duplicate copy)."""
    tree = ast.parse(LAUNCHER.read_text(encoding="utf-8"))
    defs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert "_ensure_project_venv" in defs
    assert "main" not in defs and "parse_args" not in defs
    imports = [(n.module, [a.name for a in n.names]) for n in tree.body
               if isinstance(n, ast.ImportFrom)]
    assert ("src.main", ["main"]) in imports
    assert os.access(LAUNCHER, os.X_OK)


def _norm(text: str) -> str:
    return " ".join(text.split())


def _option_set(text: str) -> set[str]:
    return set(re.findall(r"(?<![\w-])--?[A-Za-z][\w-]*", text))


def test_launcher_help_matches_console_script_help():
    venv_py = ROOT / ".venv" / "bin" / "python"
    if not venv_py.exists():
        pytest.skip("project .venv not bootstrapped")
    # argparse formats option strings differently between Python versions
    # (3.12: "-c CONFIG, --config CONFIG"; 3.13: "-c, --config CONFIG"). The
    # launcher always re-execs into the project .venv, so run the module side
    # under that same interpreter instead of whatever pytest runs under.
    # NOTE: README/.python-version say 3.13 while pyproject says >=3.12
    # (supervisor decides separately); this test must pass under either.
    via_launcher = subprocess.run([str(venv_py), str(LAUNCHER), "--help"], cwd=str(ROOT),
                                  env=_clean_env(), capture_output=True, text=True, timeout=60)
    via_module = subprocess.run([str(venv_py), "-m", "src.main", "--help"], cwd=str(ROOT),
                                env=_clean_env(), capture_output=True, text=True, timeout=60)
    assert via_launcher.returncode == 0, via_launcher.stderr
    assert via_module.returncode == 0, via_module.stderr
    # Same interpreter on both sides: only whitespace/wrapping may differ.
    assert _norm(via_launcher.stdout) == _norm(via_module.stdout)
    assert _option_set(via_launcher.stdout) == _option_set(via_module.stdout)
    for flag in HELP_FLAGS:
        assert flag in via_launcher.stdout


# ---------------------------------------------------------------------------
# scratch wheel build + throwaway venv install (offline)
# ---------------------------------------------------------------------------

INSTALLED_PROBE = r"""
import json, sys
import src, src.main
print(json.dumps({
    "prefix": sys.prefix,
    "src_file": src.__file__,
    "main_file": src.main.__file__,
    "path": sys.path,
}))
"""


@pytest.fixture(scope="module")
def installed_wbs(tmp_path_factory):
    """Build a wheel from a scratch copy of the project and install it.

    The copy contains only what the build needs (pyproject.toml, README.md,
    src/), so the build cannot read or write anything in the checkout. The
    wheel is installed with --no-deps: --help must not need third-party
    packages, and no network or package index is used.
    """
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not available for the offline wheel build")
    base = tmp_path_factory.mktemp("sast018")
    # The installed console script and the throwaway venv's python must be
    # executable: skip (don't fail) when pytest's tmp dir is on a noexec mount.
    probe = base / "exec_probe.sh"
    probe.write_text("#!/bin/sh\nexit 0\n")
    probe.chmod(0o755)
    try:
        can_exec = subprocess.run([str(probe)], capture_output=True, timeout=30).returncode == 0
    except OSError:
        can_exec = False
    probe.unlink()
    if not can_exec:
        pytest.skip(f"pytest tmp dir {base} is on a noexec mount: installed scripts cannot run")
    proj = base / "proj"
    proj.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, proj / name)
    shutil.copytree(SRC, proj / "src",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.new", "*.old"))
    env = _clean_env()
    dist = base / "dist"
    build = subprocess.run([uv, "build", "--wheel", "--offline", "--no-config", "-q",
                            "-o", str(dist), str(proj)],
                           cwd=str(base), env=env, capture_output=True, text=True, timeout=300)
    if build.returncode != 0 and re.search(r"offline|not found in the cache|network",
                                           build.stderr, re.I):
        pytest.skip(f"build backend not in the local uv cache (offline run): {build.stderr[-300:]}")
    assert build.returncode == 0, build.stderr
    (wheel,) = dist.glob("wbs-*.whl")

    venv = base / "venv"
    subprocess.run([uv, "venv", "--no-config", "--offline", "-q", "-p", sys.executable, str(venv)],
                   cwd=str(base), env=env, check=True, capture_output=True, text=True,
                   timeout=120)
    py = venv / "bin" / "python"
    inst = subprocess.run([uv, "pip", "install", "--no-config", "--offline", "--no-deps",
                           "-p", str(py), str(wheel)],
                          cwd=str(base), env=env, capture_output=True, text=True, timeout=300)
    assert inst.returncode == 0, inst.stderr
    # A cwd with nothing importable in it, far from the checkout.
    run_dir = base / "run"
    run_dir.mkdir()
    return {"wheel": wheel, "venv": venv, "py": py, "script": venv / "bin" / "wbs",
            "run_dir": run_dir, "env": env}


def test_wheel_contains_entrypoint_module_and_metadata(installed_wbs):
    with zipfile.ZipFile(installed_wbs["wheel"]) as zf:
        names = set(zf.namelist())
        assert "src/main.py" in names
        assert "src/__init__.py" in names
        (ep,) = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
        text = zf.read(ep).decode()
    assert re.search(r"^wbs = src\.main:main$", text, re.M), text
    assert not any(n == "main.py" or n.startswith("tests/") for n in names)


def test_installed_console_script_help(installed_wbs):
    script = installed_wbs["script"]
    assert script.is_file() and os.access(script, os.X_OK)
    res = subprocess.run([str(script), "--help"], cwd=str(installed_wbs["run_dir"]),
                         env=installed_wbs["env"], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert res.stdout.startswith("usage: wbs ")
    for flag in HELP_FLAGS:
        assert flag in res.stdout
    assert "Traceback" not in res.stderr
    # --help must not create runtime artefacts (pidfile, logs, db) anywhere.
    assert list(installed_wbs["run_dir"].iterdir()) == []


def _root_on_path_via_pth(path_entries) -> bool:
    """True if a .pth file in one of the sys.path dirs names the checkout root."""
    if not any(p and Path(p).resolve() == ROOT for p in path_entries):
        return False
    for entry in path_entries:
        d = Path(entry) if entry else None
        if d is None or not d.is_dir():
            continue
        for pth in d.glob("*.pth"):
            try:
                text = pth.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if any(line.strip() and Path(line.strip()).resolve() == ROOT
                   for line in text.splitlines() if not line.startswith("import")):
                return True
    return False


def test_installed_package_imports_from_site_packages_not_checkout(installed_wbs):
    res = subprocess.run([str(installed_wbs["py"]), "-I", "-c", INSTALLED_PROBE],
                         cwd=str(installed_wbs["run_dir"]), env=installed_wbs["env"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    report = json.loads(res.stdout.strip().splitlines()[-1])
    venv = installed_wbs["venv"].resolve()
    # An editable install of the checkout (an ``_editable_impl_wbs.pth`` or
    # ``__editable__`` finder in a site dir the throwaway venv inherits, e.g.
    # when the test interpreter is itself a venv with such an install) puts
    # ROOT on sys.path, so the installed ``src`` legitimately resolves into
    # the checkout. That is an environment artefact, not a packaging bug.
    if _root_on_path_via_pth(report["path"]):
        pytest.skip("the checkout is on sys.path through an editable-install "
                    ".pth file in this environment")
    for key in ("src_file", "main_file"):
        p = Path(report[key]).resolve()
        assert p.is_relative_to(venv), report
        assert not p.is_relative_to(ROOT), report
    assert not any(p and Path(p).resolve() == ROOT for p in report["path"]), report


def test_installed_console_script_runtime_path_without_irc(installed_wbs, tmp_path):
    """A missing config stops the installed command before any IRC/Core import."""
    res = subprocess.run([str(installed_wbs["script"]), "-c", str(tmp_path / "nope.json")],
                         cwd=str(installed_wbs["run_dir"]), env=installed_wbs["env"],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 1
    assert "config file not found" in res.stderr
    assert "Traceback" not in res.stderr and "ModuleNotFoundError" not in res.stderr
