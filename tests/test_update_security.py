"""
Offline regression tests for SAST-013: authenticated updates, fail closed.

No external network and no production endpoint is ever contacted:
  * the "update server" is an aiohttp server bound to 127.0.0.1 in this
    process, serving HTTPS with a throw-away self-signed certificate that is
    generated per test session (the client trusts it only through an
    explicit ssl_context passed to UpdateManager);
  * a second loopback server speaks plain HTTP and exists only so tests can
    prove that insecure URLs / redirect targets are never requested
    (its hit counter must stay 0);
  * every filesystem path the updater touches (src/, .backup, .tmp,
    .update_state.json, root installables) is redirected into tmp_path;
  * backup/install/pip/subprocess entry points are wrapped with recorders so
    each rejection case asserts that none of them ran.
No bot is started and no IRC connection is made.
"""
import asyncio
import base64
import datetime
import hashlib
import inspect
import io
import ipaddress
import json
import ssl
import tarfile

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from src import __version__ as RUNNING_VERSION
from src import update as upd
from src.update import (
    InsecureUpdateURLError,
    UpdateManager,
    UpdateVerificationError,
    manifest_signing_payload,
    require_https_url,
)

NEW_VERSION = "6.0.0"
LOCK_CONTENT = (b"aiohttp==3.14.3 \\\n"
                b"    --hash=sha256:" + b"0" * 64 + b"\n")


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------- crypto

@pytest.fixture(scope="session")
def tls_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wbs-update-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(
            [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture(scope="session")
def signing_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def other_key():
    return Ed25519PrivateKey.generate()


def pub_b64(priv) -> str:
    return base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def sign(priv, raw: bytes) -> bytes:
    return base64.b64encode(priv.sign(manifest_signing_payload(raw)))


# ------------------------------------------------------------------ packaging

def make_tarball(version: str = NEW_VERSION, *, init_version: str | None = None,
                 extra=None, root: str | None = None, with_lock: bool = True) -> bytes:
    """Build a gzip tarball laid out like a release: wbs<ver>/src/..."""
    root = root or f"wbs{version}"
    init_version = init_version or version
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        def add(name, data: bytes):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
        add(f"{root}/src/__init__.py",
            f'__version__ = "{init_version}"\n'.encode())
        add(f"{root}/src/marker.py", f"VERSION = {version!r}\n".encode())
        add(f"{root}/pyproject.toml", b"[project]\nname = 'wbs'\n")
        if with_lock:
            add(f"{root}/requirements.lock", LOCK_CONTENT)
        for item in extra or ():
            item(tf)
    return buf.getvalue()


def make_manifest(url: str, pkg: bytes | None = None, *, version=NEW_VERSION,
                  sha256=None, size=None, fullupgrade="no", drop=(),
                  fmt=upd.MANIFEST_FORMAT, platform="python", prereq="none") -> bytes:
    major, sub, patch = version.split(".")
    fields = {
        "format": fmt,
        "version": major, "versionsub": sub, "versionpatch": patch,
        "fullupgrade": fullupgrade,
        "author": "test", "date": "30092026",
        "url": url,
        "size": str(len(pkg) if size is None and pkg is not None else size),
        "sha256": sha256 if sha256 is not None else hashlib.sha256(pkg or b"").hexdigest(),
        "prereq": prereq, "platform": platform,
    }
    lines = ["# WBS release manifest (test)"]
    lines += [f"{k} {v}" for k, v in fields.items() if k not in drop]
    return ("\n".join(lines) + "\n").encode()


# --------------------------------------------------------------------- server

class Env:
    """Loopback HTTPS + plain HTTP servers and a sandboxed updater."""

    def __init__(self, tls_files):
        self.cert, self.key = tls_files
        self.routes: dict[str, object] = {}
        self.hits: list[str] = []
        self.http_hits: list[str] = []
        self._runners = []

    async def __aenter__(self):
        async def https_handler(request):
            self.hits.append(request.path_qs)
            spec = self.routes.get(request.path)
            if spec is None:
                return web.Response(status=404)
            if inspect.iscoroutinefunction(spec):
                return await spec(request)
            if callable(spec):
                return spec(request)
            return web.Response(body=spec)

        async def http_handler(request):
            self.http_hits.append(request.path_qs)
            return web.Response(body=b"attacker controlled")

        server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_ctx.load_cert_chain(self.cert, self.key)

        for handler, ctx, attr in ((https_handler, server_ctx, "https_base"),
                                   (http_handler, None, "http_base")):
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", handler)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ctx)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            scheme = "https" if ctx else "http"
            setattr(self, attr, f"{scheme}://127.0.0.1:{port}")
            self._runners.append(runner)
        self.client_ctx = ssl.create_default_context(cafile=str(self.cert))
        return self

    async def __aexit__(self, *exc):
        for r in self._runners:
            await r.cleanup()

    def publish(self, manifest: bytes, sig: bytes | None, pkg: bytes | None = None,
                pkg_path: str = "/pkg/wbs.tgz"):
        self.routes["/RELEASE"] = manifest
        if sig is not None:
            self.routes["/RELEASE.sig"] = sig
        if pkg is not None:
            self.routes[pkg_path] = pkg

    def manager(self, keys, host=None, ssl_context="default") -> UpdateManager:
        cfg = {"update": {"host": host or self.https_base, "signing_keys": keys}}
        ctx = self.client_ctx if ssl_context == "default" else ssl_context
        return UpdateManager(cfg, ssl_context=ctx)


def redirect(location: str, status: int = 302):
    return lambda request: web.Response(status=status, headers={"Location": location})


# ------------------------------------------------------------------- sandbox

@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Redirect every updater path into tmp_path and record side effects."""
    root = tmp_path / "root"
    pkg_dir = root / "src"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text(f'__version__ = "{RUNNING_VERSION}"\n')
    (pkg_dir / "marker.py").write_text("VERSION = 'old'\n")
    monkeypatch.setattr(upd, "_PKG_DIR", pkg_dir)
    monkeypatch.setattr(upd, "_ROOT_DIR", root)
    monkeypatch.setattr(upd, "_TMP_DIR", root / ".tmp" / "update")
    monkeypatch.setattr(upd, "_BACKUP_DIR", root / ".backup")
    monkeypatch.setattr(upd, "_STATE_FILE", root / ".update_state.json")

    events: list[str] = []
    orig_backup = UpdateManager._create_backup
    orig_install = UpdateManager._install_files
    orig_extract = UpdateManager._safe_extract

    def rec_backup(self):
        events.append("backup")
        return orig_backup(self)

    def rec_install(self, wbs_root):
        events.append("install")
        return orig_install(self, wbs_root)

    def rec_extract(tarball, dest):
        events.append("extract")
        return orig_extract(tarball, dest)

    commands: list[tuple[list[str], dict | None]] = []
    pip_rc: list[int] = []   # per-call return codes; default 0

    class FakeProc:
        def __init__(self, rc):
            self.returncode = rc

        async def communicate(self):
            return b"", b"simulated pip failure" if self.returncode else b""

    async def fake_exec(*cmd, **kw):
        events.append("subprocess")
        commands.append((list(cmd), kw.get("env")))
        return FakeProc(pip_rc.pop(0) if pip_rc else 0)

    monkeypatch.setattr(UpdateManager, "_create_backup", rec_backup)
    monkeypatch.setattr(UpdateManager, "_install_files", rec_install)
    monkeypatch.setattr(UpdateManager, "_safe_extract", staticmethod(rec_extract))
    monkeypatch.setattr(upd.asyncio, "create_subprocess_exec", fake_exec)

    class S:
        pass
    s = S()
    s.root, s.pkg_dir, s.events = root, pkg_dir, events
    s.commands, s.pip_rc = commands, pip_rc
    s.marker = lambda: (pkg_dir / "marker.py").read_text()
    return s


def assert_untouched(sb):
    assert not {"backup", "install", "subprocess"} & set(sb.events), sb.events
    assert sb.marker() == "VERSION = 'old'\n"
    assert not (sb.root / ".backup").exists()
    assert not (sb.root / ".update_state.json").exists()


# ---------------------------------------------------------------- happy path

def test_valid_signed_package_installs_only_after_verification(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, fullupgrade="yes")
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert m is not None and m.version_str == NEW_VERSION
            sandbox.events.append("checked")
            ok = await mgr.perform_update(m)
            assert ok, mgr.last_error
            assert env.hits == ["/RELEASE", "/RELEASE.sig", "/pkg/wbs.tgz"]
            assert env.http_hits == []
            # replaying the same (validly signed) manifest is now refused
            again = await mgr.perform_update(m)
            assert again is False and "not newer" in mgr.last_error
    run(go())
    assert sandbox.events == ["checked", "extract", "backup", "install",
                              "subprocess", "subprocess"]
    assert sandbox.marker() == f"VERSION = {NEW_VERSION!r}\n"
    state = json.loads((sandbox.root / ".update_state.json").read_text())
    assert state == {"highest_installed": NEW_VERSION}
    # the package's hash-pinned lock was installed into the project root too
    assert (sandbox.root / "requirements.lock").read_bytes() == LOCK_CONTENT


# ------------------------------------------------------- venv-targeted pip

def _full_upgrade(tls_files, signing_key, **tar_kwargs):
    """Run one signed fullupgrade=yes update; return (ok, last_error, hits)."""
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball(**tar_kwargs)
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, fullupgrade="yes")
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert m is not None, mgr.last_error
            ok = await mgr.perform_update(m)
            return ok, mgr.last_error, list(env.hits)
    return run(go())


def test_pip_targets_running_venv_with_hash_locked_then_no_deps(tls_files, signing_key,
                                                                 sandbox):
    assert upd.sys.prefix != upd.sys.base_prefix, "test suite must run inside the venv"
    ok, err, _ = _full_upgrade(tls_files, signing_key)
    assert ok, err
    assert len(sandbox.commands) == 2
    (deps, deps_env), (proj, proj_env) = sandbox.commands
    exe = upd.sys.executable
    lock = deps[deps.index("-r") + 1]
    assert deps[:4] == [exe, "-m", "pip", "install"]
    assert "--require-hashes" in deps and lock.endswith("/requirements.lock")
    assert "--no-deps" not in deps
    assert proj[:4] == [exe, "-m", "pip", "install"]
    assert "--no-deps" in proj and "--require-hashes" not in proj
    assert "-r" not in proj and proj[-1].endswith(f"wbs{NEW_VERSION}")
    for env in (deps_env, proj_env):
        assert env["VIRTUAL_ENV"] == upd.sys.prefix
        assert not {"PYTHONPATH", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL",
                    "PIP_REQUIRE_HASHES", "PIP_CONFIG_FILE"} & set(env)


def test_venv_python_returns_running_venv_interpreter():
    assert upd.venv_python() == upd.sys.executable


def test_venv_python_refuses_base_interpreter(monkeypatch):
    monkeypatch.setattr(upd.sys, "base_prefix", upd.sys.prefix)
    with pytest.raises(upd.UpdateEnvironmentError, match="not running inside a virtual"):
        upd.venv_python()


def test_venv_python_refuses_foreign_executable(monkeypatch):
    monkeypatch.setattr(upd.sys, "executable", "/usr/bin/python3")
    with pytest.raises(upd.UpdateEnvironmentError, match="not inside the running venv"):
        upd.venv_python()


def test_full_upgrade_outside_venv_is_refused_before_download(tls_files, signing_key,
                                                             sandbox, monkeypatch):
    monkeypatch.setattr(upd.sys, "base_prefix", upd.sys.prefix)
    ok, err, hits = _full_upgrade(tls_files, signing_key)
    assert ok is False
    assert "virtual environment" in err
    assert "/pkg/wbs.tgz" not in hits
    assert_untouched(sandbox)


def test_full_upgrade_without_lock_rolls_back_and_runs_no_pip(tls_files, signing_key,
                                                              sandbox):
    ok, err, _ = _full_upgrade(tls_files, signing_key, with_lock=False)
    assert ok is False
    assert "requirements.lock is missing" in err
    assert sandbox.commands == []
    assert sandbox.marker() == "VERSION = 'old'\n"          # rolled back
    assert not (sandbox.root / ".update_state.json").exists()


def test_failed_hash_locked_install_rolls_back_and_skips_project_install(
        tls_files, signing_key, sandbox):
    sandbox.pip_rc.append(1)          # first pip step (--require-hashes) fails
    ok, err, _ = _full_upgrade(tls_files, signing_key)
    assert ok is False
    assert "hash-verified" in err and "exit 1" in err
    assert len(sandbox.commands) == 1
    assert sandbox.marker() == "VERSION = 'old'\n"
    assert not (sandbox.root / ".update_state.json").exists()


def test_https_to_https_redirect_is_followed(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            env.routes["/pkg/wbs.tgz"] = redirect("/cdn/wbs.tgz", 301)
            env.routes["/cdn/wbs.tgz"] = pkg
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man))
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert await mgr.perform_update(m), mgr.last_error
            assert "/cdn/wbs.tgz" in env.hits
    run(go())
    assert sandbox.events == ["extract", "backup", "install"]


# ------------------------------------------------------------- insecure URLs

@pytest.mark.parametrize("url", [
    "http://wbsupdate.example/RELEASE",
    "ftp://wbsupdate.example/RELEASE",
    "file:///etc/passwd",
    "//wbsupdate.example/RELEASE",
    "https://user:pw@wbsupdate.example/RELEASE",
    "https:///RELEASE",
    "https://h.example:bad/RELEASE",
])
def test_require_https_url_rejects(url):
    with pytest.raises(InsecureUpdateURLError):
        require_https_url(url)


def test_http_update_host_is_refused_without_any_request(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            mgr = env.manager([pub_b64(signing_key)], host=env.http_base)
            assert await mgr.check_update() is None
            assert "https" in mgr.last_error
            assert env.http_hits == [] and env.hits == []
    run(go())
    assert_untouched(sandbox)


def test_signed_manifest_with_http_package_url_is_refused(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.http_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man))
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "https" in mgr.last_error
            assert env.http_hits == []
    run(go())
    assert_untouched(sandbox)


def test_manifest_redirect_to_http_is_not_followed(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            env.routes["/RELEASE"] = redirect(env.http_base + "/RELEASE")
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "https" in mgr.last_error
            assert env.http_hits == []
    run(go())
    assert_untouched(sandbox)


def test_package_redirect_to_http_aborts_before_install(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man))
            env.routes["/pkg/wbs.tgz"] = redirect(env.http_base + "/evil.tgz", 307)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert m is not None
            assert await mgr.perform_update(m) is False
            assert "https" in mgr.last_error
            assert env.http_hits == []
    run(go())
    assert_untouched(sandbox)
    assert "extract" not in sandbox.events


def test_redirect_loop_is_bounded(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            env.routes["/RELEASE"] = redirect("/RELEASE")
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "too many redirects" in mgr.last_error
            assert len(env.hits) == upd.MAX_REDIRECTS + 1
    run(go())
    assert_untouched(sandbox)


def test_untrusted_tls_certificate_is_rejected(tls_files, signing_key, sandbox):
    """Default TLS context verifies certificates; a self-signed server fails."""
    async def go():
        async with Env(tls_files) as env:
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", b"x")
            env.publish(man, sign(signing_key, man))
            cfg = {"update": {"host": env.https_base,
                              "signing_keys": [pub_b64(signing_key)]}}
            mgr = UpdateManager(cfg)          # no test CA override
            assert await mgr.check_update() is None
            assert mgr.last_error
            assert env.hits == []             # handshake failed, no request served
    run(go())
    assert_untouched(sandbox)


# ------------------------------------------------------------------ signature

def test_no_pinned_key_fails_closed_without_network(tls_files, sandbox):
    async def go():
        async with Env(tls_files) as env:
            mgr = env.manager([])
            assert await mgr.check_update() is None
            assert "signing key" in mgr.last_error
            assert env.hits == []
    run(go())
    assert_untouched(sandbox)


def test_invalid_pinned_key_entries_are_ignored(tls_files, sandbox):
    mgr = UpdateManager({"update": {"host": "https://x.example",
                                    "signing_keys": ["not base64!!", "AAAA", 5]}})
    assert mgr._trusted_keys == []


@pytest.mark.parametrize("case", [
    "wrong_key", "missing_sig", "garbage_sig", "short_sig",
    "tampered_manifest", "no_domain_separation",
])
def test_invalid_signature_aborts(tls_files, signing_key, other_key, sandbox, case):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            good = sign(signing_key, man)
            served, sig = man, good
            if case == "wrong_key":
                sig = sign(other_key, man)
            elif case == "missing_sig":
                sig = None
            elif case == "garbage_sig":
                sig = b"this is not base64 !!!"
            elif case == "short_sig":
                sig = base64.b64encode(b"\x00" * 32)
            elif case == "tampered_manifest":
                served = man.replace(b"fullupgrade no", b"fullupgrade yes")
            elif case == "no_domain_separation":
                sig = base64.b64encode(signing_key.sign(man))
            env.publish(served, sig, pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert mgr.last_error
            assert "/pkg/wbs.tgz" not in env.hits
    run(go())
    assert_untouched(sandbox)


def test_second_pinned_key_allows_rotation(tls_files, signing_key, other_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(other_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key), pub_b64(other_key)])
            m = await mgr.check_update()
            assert m is not None
            assert await mgr.perform_update(m), mgr.last_error
    run(go())
    assert "install" in sandbox.events


@pytest.mark.parametrize("field,value", [
    ("url", "https://evil.example/wbs.tgz"),
    ("sha256", "0" * 64),
    ("size", 1),
    ("full_upgrade", True),
    ("version", "7"),
])
def test_perform_update_rejects_field_substitution(tls_files, signing_key, sandbox,
                                                   field, value):
    """Fields of a verified manifest cannot be swapped before perform_update."""
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            forged = m._replace(**{field: value})
            assert await mgr.perform_update(forged) is False
            assert "signed manifest" in mgr.last_error
            assert "/pkg/wbs.tgz" not in env.hits
    run(go())
    assert_untouched(sandbox)


def test_perform_update_rejects_unsigned_manifest_object(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            env.routes["/pkg/wbs.tgz"] = pkg
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            unsigned = UpdateManager._parse_manifest(man)   # raw/signature empty
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.perform_update(unsigned) is False
            assert env.hits == []
    run(go())
    assert_untouched(sandbox)


# ------------------------------------------------------------------ integrity

@pytest.mark.parametrize("kwargs", [
    {"drop": ("sha256",)},
    {"sha256": "none"},
    {"sha256": "abc123"},
    {"drop": ("size",)},
    {"size": 0},
    {"size": upd.MAX_PACKAGE_BYTES + 1},
    {"drop": ("format",)},
    {"fmt": "wbs-update-0"},
    {"drop": ("url",)},
])
def test_signed_manifest_missing_integrity_fields_is_refused(tls_files, signing_key,
                                                             sandbox, kwargs):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, **kwargs)
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert mgr.last_error
            assert "/pkg/wbs.tgz" not in env.hits
    run(go())
    assert_untouched(sandbox)


def test_duplicate_manifest_field_is_refused():
    raw = make_manifest("https://h.example/p.tgz", b"x") + b"url https://evil.example/p.tgz\n"
    with pytest.raises(UpdateVerificationError, match="repeats"):
        UpdateManager._parse_manifest(raw)


@pytest.mark.parametrize("case", ["hash_mismatch", "oversize", "undersize",
                                  "gzip_encoding"])
def test_package_integrity_failure_aborts_before_extract(tls_files, signing_key,
                                                         sandbox, case):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            served = pkg
            if case == "hash_mismatch":
                tampered = bytearray(pkg)              # same size, one bit flipped
                tampered[len(pkg) // 2] ^= 0x01
                served = bytes(tampered)
            elif case == "oversize":
                served = pkg + b"\0" * 4096
            elif case == "undersize":
                served = pkg[:-10]
            env.publish(man, sign(signing_key, man))
            if case == "gzip_encoding":
                env.routes["/pkg/wbs.tgz"] = lambda r: web.Response(
                    body=pkg, headers={"Content-Encoding": "gzip"})
            else:
                env.routes["/pkg/wbs.tgz"] = served
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert m is not None
            assert await mgr.perform_update(m) is False
            assert mgr.last_error
    run(go())
    assert "extract" not in sandbox.events
    assert_untouched(sandbox)


def test_manifest_download_is_size_bounded(tls_files, signing_key, sandbox, monkeypatch):
    monkeypatch.setattr(upd, "MAX_MANIFEST_BYTES", 256)

    async def go():
        async with Env(tls_files) as env:
            env.routes["/RELEASE"] = b"# pad\n" * 1000
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "too large" in mgr.last_error
            assert "/RELEASE.sig" not in env.hits
    run(go())
    assert_untouched(sandbox)


def test_chunked_package_without_length_is_capped_at_signed_size(tls_files, signing_key,
                                                                 sandbox):
    """No Content-Length: the stream is cut at the signed size, not the server's."""
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man))

            async def streamer(request):
                resp = web.StreamResponse()          # chunked transfer encoding
                await resp.prepare(request)
                try:
                    for _ in range(64):
                        await resp.write(b"\0" * 65536)
                    await resp.write_eof()
                except (ConnectionResetError, RuntimeError):
                    pass
                return resp
            env.routes["/pkg/wbs.tgz"] = streamer
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert m is not None and m.size == len(pkg)
            assert await mgr.perform_update(m) is False
            assert "exceeded size limit" in mgr.last_error
            assert not (upd._TMP_DIR / "wbs_update.tar.gz").exists()
    run(go())
    assert_untouched(sandbox)


# ---------------------------------------------------- version / rollback policy

@pytest.mark.parametrize("version", ["5.9.6", "5.9.0", "4.2.0"])
def test_downgrade_is_refused(tls_files, signing_key, sandbox, version):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball(version)
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, version=version)
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert mgr.last_error
            # even if a caller passes the signed stale manifest straight in:
            m = UpdateManager._parse_manifest(man)._replace(
                raw=man, signature=base64.b64decode(sign(signing_key, man)))
            assert await mgr.perform_update(m) is False
            assert "/pkg/wbs.tgz" not in env.hits
    run(go())
    assert_untouched(sandbox)


def test_same_version_is_up_to_date_not_error(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball(RUNNING_VERSION)
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg,
                                version=RUNNING_VERSION)
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert mgr.last_error is None
    run(go())
    assert_untouched(sandbox)


def test_stale_version_below_recorded_install_is_refused(tls_files, signing_key, sandbox):
    """Replay of an older signed release after a newer one was installed."""
    (sandbox.root / ".update_state.json").write_text(
        json.dumps({"highest_installed": "6.1.0"}))

    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)  # 6.0.0
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "6.1.0" in mgr.last_error
    run(go())
    assert not {"backup", "install", "subprocess"} & set(sandbox.events)
    assert sandbox.marker() == "VERSION = 'old'\n"


def test_corrupt_state_file_fails_closed(tls_files, signing_key, sandbox):
    (sandbox.root / ".update_state.json").write_text("{not json")

    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            assert await mgr.check_update() is None
            assert "rollback protection" in mgr.last_error
    run(go())
    assert not {"backup", "install", "subprocess"} & set(sandbox.events)


def test_package_version_must_match_signed_version(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball(init_version="5.0.0")
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, fullupgrade="yes")
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert await mgr.perform_update(m) is False
            assert "does not match signed" in mgr.last_error
    run(go())
    assert_untouched(sandbox)


def test_unsatisfied_prereq_aborts(tls_files, signing_key, sandbox):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, prereq="5.99.0")
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert await mgr.perform_update(m) is False
            assert "prerequisite" in mgr.last_error
            assert "/pkg/wbs.tgz" not in env.hits
    run(go())
    assert_untouched(sandbox)


# -------------------------------------------------------------------- archive

def _sym(tf):
    ti = tarfile.TarInfo(f"wbs{NEW_VERSION}/src/evil")
    ti.type = tarfile.SYMTYPE
    ti.linkname = "/etc/passwd"
    tf.addfile(ti)


def _traversal(tf):
    data = b"x"
    ti = tarfile.TarInfo(f"wbs{NEW_VERSION}/../../escape.py")
    ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))


def _hardlink(tf):
    ti = tarfile.TarInfo(f"wbs{NEW_VERSION}/src/hl")
    ti.type = tarfile.LNKTYPE
    ti.linkname = f"wbs{NEW_VERSION}/src/marker.py"
    tf.addfile(ti)


@pytest.mark.parametrize("extra,kwargs", [
    ([_sym], {}),
    ([_traversal], {}),
    ([_hardlink], {}),
    ([], {"root": "wbs9.9.9"}),        # layout does not match the signed version
])
def test_malicious_archive_aborts_before_install(tls_files, signing_key, sandbox,
                                                 extra, kwargs):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball(extra=extra, **kwargs)
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg, fullupgrade="yes")
            env.publish(man, sign(signing_key, man), pkg)
            mgr = env.manager([pub_b64(signing_key)])
            m = await mgr.check_update()
            assert await mgr.perform_update(m) is False
            assert mgr.last_error
    run(go())
    assert_untouched(sandbox)
    assert not (sandbox.root / "escape.py").exists()


def test_archive_member_count_and_unpacked_size_are_bounded(tmp_path, monkeypatch):
    many = make_tarball(extra=[
        lambda tf: [tf.addfile(_ti(f"wbs{NEW_VERSION}/f{i}", 1), io.BytesIO(b"x"))
                    for i in range(20)]])
    p = tmp_path / "many.tgz"
    p.write_bytes(many)
    monkeypatch.setattr(upd, "MAX_ARCHIVE_MEMBERS", 10)
    with pytest.raises(ValueError, match="too many members"):
        UpdateManager._safe_extract(p, tmp_path / "out1")

    monkeypatch.setattr(upd, "MAX_ARCHIVE_MEMBERS", 5000)
    bomb = make_tarball(extra=[
        lambda tf: tf.addfile(_ti(f"wbs{NEW_VERSION}/zeros", 4096),
                              io.BytesIO(b"\0" * 4096))])
    p2 = tmp_path / "bomb.tgz"
    p2.write_bytes(bomb)
    monkeypatch.setattr(upd, "MAX_ARCHIVE_UNPACKED_BYTES", 1024)
    with pytest.raises(ValueError, match="unpacked size"):
        UpdateManager._safe_extract(p2, tmp_path / "out2")
    assert not (tmp_path / "out2" / f"wbs{NEW_VERSION}" / "zeros").exists()


def _ti(name, size):
    ti = tarfile.TarInfo(name)
    ti.size = size
    return ti


# ------------------------------------------------------------ CLI / commands

def test_standalone_update_requires_pinned_key(capsys):
    rc = run(upd.run_standalone_update({"update": {"host": "https://x.example"}}))
    assert rc == 2
    assert "signing key" in capsys.readouterr().err


def test_standalone_update_reports_verification_failure(tls_files, signing_key,
                                                        other_key, sandbox, capsys):
    async def go():
        async with Env(tls_files) as env:
            pkg = make_tarball()
            man = make_manifest(env.https_base + "/pkg/wbs.tgz", pkg)
            env.publish(man, sign(other_key, man), pkg)
            orig_init = UpdateManager.__init__

            def init(self, config, ssl_context=None):
                orig_init(self, config, ssl_context=env.client_ctx)
            UpdateManager.__init__ = init
            try:
                return await upd.run_standalone_update(
                    {"update": {"host": env.https_base,
                                "signing_keys": [pub_b64(signing_key)]}})
            finally:
                UpdateManager.__init__ = orig_init
    assert run(go()) == 1
    assert "signature" in capsys.readouterr().err
    assert_untouched(sandbox)
