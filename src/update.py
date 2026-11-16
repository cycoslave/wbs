# src/update.py
"""
WBS Update Manager
==================
Handles self-update from a remote release endpoint.

Flow:
  1. check_update()   -- fetch the RELEASE manifest and its detached
                         RELEASE.sig, verify the Ed25519 signature against a
                         pinned key, parse it strictly, check platform
                         compatibility and version/rollback policy.
  2. perform_update() -- re-verify the signed manifest, download the package
                         (bounded), verify size + SHA-256 from the *signed*
                         manifest, pre-scan and extract it, check that the
                         package version matches the signed version, then
                         (and only then) back up, install src/ and optionally
                         run pip install into the project venv
                         (``--require-hashes -r requirements.lock`` then
                         ``--no-deps .``).
  3. rollback()       -- restore the backup if anything fails post-install.

Security model (SAST-013):
  - Authenticity: the manifest is signed with Ed25519. The signature covers
    ``SIGNATURE_CONTEXT + <exact manifest bytes>``, so version, package URL,
    size and SHA-256 are all bound by the signature. Trusted public keys are
    pinned locally (TRUSTED_UPDATE_KEYS below and/or config
    ``update.signing_keys``); they are never fetched from the network.
    With no pinned key, updating is refused (fail closed; no unsigned mode).
  - Integrity: ``sha256`` and ``size`` are mandatory manifest fields. The
    downloaded package must match both before anything is extracted.
  - Transport: HTTPS with certificate verification for the manifest, the
    signature and the package, and for *every* redirect hop (redirects are
    followed manually, at most MAX_REDIRECTS). No proxies from the
    environment, no transparent decompression.
  - Rollback prevention: the signed version must be strictly newer than both
    the running version and the highest version previously installed by this
    updater (recorded in .update_state.json). The package's own
    src/__init__.py __version__ must equal the signed version.
  - Bounds: manifest, signature and package downloads are size-capped; the
    archive's member count and total unpacked size are capped; only regular
    files and directories are allowed, all under a single wbs<version>/ root;
    extraction uses tarfile's "data" filter (Python >= 3.12).
  - Nothing is backed up, installed or executed until all of the above pass.
    Subprocess uses the running venv's sys.executable (refused outside a
    venv), a minimal env and a timeout. Dependencies are installed only from
    the package's hash-pinned requirements.lock (``--require-hashes``); the
    project itself is installed with ``--no-deps`` so pip never resolves
    unpinned versions.

Release signing (release tooling, not run by the bot)::

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from src.update import manifest_signing_payload
    sig = private_key.sign(manifest_signing_payload(manifest_bytes))
    # publish base64(sig) as RELEASE.sig next to RELEASE

    # the operator pins base64(raw 32-byte public key) in
    # config.json -> update.signing_keys (or TRUSTED_UPDATE_KEYS)

Manifest format (UTF-8, one ``key value`` per line, ``#`` comments)::

    format wbs-update-1
    version 6
    versionsub 1
    versionpatch 0
    fullupgrade no
    author cyco
    date 30052026
    url https://wbsupdate.wcksoft.com/6.1/wbs6.1.0.tgz
    size 1234567
    sha256 <64-char hex>
    prereq none
    platform python

TODOs:
  - Wire check_update() into a scheduled asyncio task in core.py
  - Implement restart signal (SIGUSR1 or process-manager message) after install
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import ssl
import sys
import tarfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Callable, NamedTuple, Optional

import aiohttp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging import version as pkg_version

from . import __version__

log = logging.getLogger("wbs.update")
_RUNTIME_PLATFORM = "python"
_MIN_PYTHON_MAJOR_STABLE = 6
_MIN_PYTHON_MAJOR_TESTING = 5
_MIN_PYTHON_SUB_TESTING = 9
_PKG_DIR    = Path(__file__).resolve().parent
_ROOT_DIR   = _PKG_DIR.parent
_TMP_DIR    = _ROOT_DIR / ".tmp" / "update"
_BACKUP_DIR = _ROOT_DIR / ".backup"
_STATE_FILE = _ROOT_DIR / ".update_state.json"
_ROOT_INSTALLABLE = ["main.py", "pyproject.toml", "requirements.lock", "db/schema.sql"]
_LOCK_FILE = "requirements.lock"
_PIP_TIMEOUT = 300.0

# --- signing / format ---------------------------------------------------------
MANIFEST_FORMAT = "wbs-update-1"
SIGNATURE_CONTEXT = b"WBS-UPDATE-MANIFEST-V1\n"
SIGNATURE_SUFFIX = ".sig"
# Release builds may embed base64 raw Ed25519 public keys here. Operators can
# additionally pin keys via config["update"]["signing_keys"].
TRUSTED_UPDATE_KEYS: tuple[str, ...] = ()

# --- bounds -------------------------------------------------------------------
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_REDIRECTS = 3
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_CHUNK = 65_536

_REQUIRED_FIELDS = ("format", "version", "versionsub", "versionpatch",
                    "url", "size", "sha256")
_KNOWN_FIELDS = frozenset(_REQUIRED_FIELDS + (
    "fullupgrade", "eggupg", "author", "date", "prereq", "platform",
))


class IncompatiblePlatformError(RuntimeError):
    """
    Raised when a remote update manifest targets a different runtime platform
    (e.g., an Eggdrop/Tcl manifest delivered to a Python bot, or a manifest
    whose major version predates the Python rewrite boundary).
    """


class UpdateVerificationError(RuntimeError):
    """The update failed authentication, integrity or policy verification."""


class InsecureUpdateURLError(UpdateVerificationError):
    """An update URL (or redirect hop) is not a plain https:// URL."""


class StaleUpdateError(UpdateVerificationError):
    """The signed version is not newer than the running/installed version."""


class UpdateDownloadError(RuntimeError):
    """Transport-level failure (status, size bound, encoding, redirects)."""


class UpdateEnvironmentError(RuntimeError):
    """The running interpreter cannot safely receive a dependency install."""


def venv_python() -> str:
    """
    Return the interpreter of the virtual environment WBS is running in.

    Dependency installs must only ever target the project venv, never a
    system/base interpreter. Raises UpdateEnvironmentError when not running
    inside a venv (sys.prefix == sys.base_prefix) or when sys.executable does
    not belong to that venv.
    """
    prefix = os.path.realpath(sys.prefix)
    base = os.path.realpath(getattr(sys, "base_prefix", sys.prefix))
    if prefix == base:
        raise UpdateEnvironmentError(
            f"not running inside a virtual environment (sys.prefix={sys.prefix}); "
            "refusing to pip install into the base interpreter. "
            "Start WBS via ./wbs from the project .venv (see README)."
        )
    exe = sys.executable or ""
    # Venv interpreters are symlinks to the base python: compare the *unresolved*
    # bin/ parent so <venv>/bin/python maps to <venv>.
    exe_prefix = (os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(exe))))
                  if exe else "")
    if exe_prefix != prefix:
        raise UpdateEnvironmentError(
            f"sys.executable {exe!r} is not inside the running venv {sys.prefix}; "
            "refusing to pip install."
        )
    return exe


class UpdateManifest(NamedTuple):
    """Parsed fields from the remote (signed) RELEASE manifest."""
    version:      str
    versionsub:   str
    versionpatch: str
    full_upgrade: bool    # run `pip install` after extract
    author:       str
    date:         str
    url:          str     # https tarball download URL
    prereq:       str     # minimum current version required, or "none"
    sha256:       str     # lowercase hex digest of tarball (mandatory)
    platform:     str     # "python" | "any"
    size:         int = 0         # exact tarball size in bytes (mandatory)
    raw:          bytes = b""     # exact signed manifest bytes
    signature:    bytes = b""     # detached Ed25519 signature over raw

    @property
    def version_str(self) -> str:
        return f"{self.version}.{self.versionsub}.{self.versionpatch}"

    @property
    def parsed_version(self) -> pkg_version.Version:
        return pkg_version.parse(self.version_str)


def manifest_signing_payload(raw: bytes) -> bytes:
    """Bytes that a release signer signs (domain-separated manifest bytes)."""
    return SIGNATURE_CONTEXT + raw


def require_https_url(url: str, what: str = "update URL") -> str:
    """
    Return *url* if it is an absolute https:// URL with a host and without
    embedded credentials; raise InsecureUpdateURLError otherwise.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 -- raises ValueError on a malformed port
    except ValueError as exc:
        raise InsecureUpdateURLError(f"{what} is malformed: {exc}") from None
    if parts.scheme.lower() != "https":
        raise InsecureUpdateURLError(
            f"{what} must use https:// (got scheme {parts.scheme or 'none'!r}); "
            "refusing insecure update transport"
        )
    if not host:
        raise InsecureUpdateURLError(f"{what} has no host")
    if parts.username is not None or parts.password is not None:
        raise InsecureUpdateURLError(f"{what} must not embed credentials")
    if any(c.isspace() or ord(c) < 0x20 for c in url):
        raise InsecureUpdateURLError(f"{what} contains whitespace/control characters")
    return url


def _load_public_key(entry: Any) -> Ed25519PublicKey:
    if not isinstance(entry, str):
        raise ValueError("signing key must be a base64 string")
    try:
        raw = base64.b64decode(entry.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signing key is not valid base64") from None
    if len(raw) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def _decode_signature(blob: bytes) -> bytes:
    try:
        sig = base64.b64decode(blob.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise UpdateVerificationError("manifest signature is not valid base64") from None
    if len(sig) != 64:
        raise UpdateVerificationError(
            f"manifest signature has wrong length ({len(sig)} bytes, expected 64)"
        )
    return sig


class UpdateManager:
    """
    Manages WBS self-updates from a signed remote manifest + tarball.

    All public methods are async-safe. Only one update may run at a time;
    concurrent callers block on the internal asyncio.Lock.

    Args:
        config: Bot config. Uses config["update"]["host"] (https:// base URL)
                and config["update"]["signing_keys"] (list of base64 raw
                Ed25519 public keys, pinned locally).
        ssl_context: Optional TLS context override (tests only). Default is
                ssl.create_default_context(), i.e. verified certificates.
    """

    def __init__(self, config: dict[str, Any],
                 ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self._config = config
        self._lock = asyncio.Lock()
        _update_cfg: dict[str, Any] = config.get("update", {}) or {}
        self._auhost: str = str(_update_cfg.get("host", "") or "").strip().rstrip("/")
        self._auto_updates: bool = bool(_update_cfg.get("auto_updates", False))
        self._auremotefile: str = "/RELEASE"
        self._useragent: str = f"WBS/{__version__}"
        self._timeout: int = 30
        self._current: pkg_version.Version = pkg_version.parse(__version__)
        self._ssl_context = ssl_context
        self.last_error: Optional[str] = None

        configured = _update_cfg.get("signing_keys", []) or []
        if isinstance(configured, str):
            configured = [configured]
        self._trusted_keys: list[Ed25519PublicKey] = []
        for idx, entry in enumerate(list(TRUSTED_UPDATE_KEYS) + list(configured)):
            try:
                self._trusted_keys.append(_load_public_key(entry))
            except ValueError as exc:
                log.error("Ignoring invalid update signing key #%d: %s", idx, exc)

    # ------------------------------------------------------------------ public

    NOT_CONFIGURED = "Updates are not configured (update.host missing)"

    @property
    def configured(self) -> bool:
        """True when update.host is set (SYS-8)."""
        return bool(self._auhost)

    async def check_update(self) -> Optional[UpdateManifest]:
        """
        Fetch and verify the signed remote manifest and return it if it
        describes a newer, compatible version -- otherwise None.

        Raises nothing -- all errors are logged, recorded in ``last_error``
        and None is returned.
        """
        self.last_error = None
        if not self._auhost:
            log.warning("update.check_update: update.host not configured, skipping.")
            return None

        log.info("Checking for WBS updates...")
        try:
            manifest = await self._fetch_verified_manifest()
            self._check_platform_compatibility(manifest)
            self._check_version_policy(manifest)
        except StaleUpdateError as exc:
            if manifest.parsed_version == self._current:
                log.info("WBS is up to date (current=%s).", self._current)
            else:
                self._fail("Refusing update: %s", exc)
            return None
        except IncompatiblePlatformError as exc:
            self._fail("Platform incompatibility detected: %s", exc)
            return None
        except (UpdateVerificationError, UpdateDownloadError) as exc:
            self._fail("Update manifest rejected: %s", exc)
            return None
        except Exception as exc:
            self._fail("Failed to fetch update manifest: %s", exc)
            return None

        log.info("Update available: %s -> %s", self._current, manifest.version_str)
        return manifest

    async def perform_update(self, manifest: UpdateManifest) -> bool:
        """
        Verify, download, extract and install the update described by the
        signed *manifest*.

        Returns True on success, False on failure. If a failure happens after
        the install step began, the previous installation is restored from
        backup; failures before that leave the installation untouched.
        """
        async with self._lock:
            return await self._run_update(manifest)

    async def rollback(self) -> bool:
        """
        Manually restore the last backup created by perform_update().

        Returns True on success, False if no backup exists or restore failed.
        """
        async with self._lock:
            return self._restore_backup()

    # ------------------------------------------------------------ verification

    def _fail(self, fmt: str, exc: BaseException) -> None:
        self.last_error = str(exc)
        log.error(fmt, exc)

    async def _fetch_verified_manifest(self) -> UpdateManifest:
        if not self._trusted_keys:
            raise UpdateVerificationError(
                "no pinned update signing key configured (update.signing_keys); "
                "refusing to install unauthenticated updates"
            )
        manifest_url = require_https_url(
            f"{self._auhost}{self._auremotefile}", "update.host"
        )
        raw = await self._fetch_bytes(manifest_url, MAX_MANIFEST_BYTES, "manifest")
        sig_blob = await self._fetch_bytes(
            manifest_url + SIGNATURE_SUFFIX, MAX_SIGNATURE_BYTES, "manifest signature"
        )
        signature = _decode_signature(sig_blob)
        self._verify_signature(raw, signature)
        return self._parse_manifest(raw)._replace(raw=raw, signature=signature)

    def _verify_signature(self, raw: bytes, signature: bytes) -> None:
        if not self._trusted_keys:
            raise UpdateVerificationError("no pinned update signing key configured")
        if not isinstance(raw, bytes) or not raw:
            raise UpdateVerificationError("manifest is not a signed manifest")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise UpdateVerificationError("manifest signature missing or malformed")
        payload = manifest_signing_payload(raw)
        for key in self._trusted_keys:
            try:
                key.verify(signature, payload)
                return
            except InvalidSignature:
                continue
        raise UpdateVerificationError(
            "manifest signature does not verify against any pinned signing key"
        )

    def _reverify(self, manifest: UpdateManifest) -> UpdateManifest:
        """
        Re-authenticate a manifest handed to perform_update(): the signature
        must verify over the embedded raw bytes and every parsed field must
        equal what those signed bytes say (no field substitution).
        """
        if not isinstance(manifest, UpdateManifest):
            raise UpdateVerificationError("not an UpdateManifest")
        self._verify_signature(manifest.raw, manifest.signature)
        fresh = self._parse_manifest(manifest.raw)._replace(
            raw=manifest.raw, signature=manifest.signature
        )
        if fresh != manifest:
            raise UpdateVerificationError(
                "manifest fields do not match the signed manifest bytes"
            )
        return fresh

    def _read_state(self) -> Optional[pkg_version.Version]:
        try:
            data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise UpdateVerificationError(
                f"update state file {_STATE_FILE} unreadable ({exc}); refusing "
                "to update without rollback protection"
            ) from None
        try:
            return pkg_version.parse(str(data["highest_installed"]))
        except (KeyError, TypeError, pkg_version.InvalidVersion):
            raise UpdateVerificationError(
                f"update state file {_STATE_FILE} is malformed; refusing to "
                "update without rollback protection"
            ) from None

    def _record_installed(self, ver: pkg_version.Version) -> None:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATE_FILE.with_name(_STATE_FILE.name + ".tmp")
        tmp.write_text(json.dumps({"highest_installed": str(ver)}), encoding="utf-8")
        os.replace(tmp, _STATE_FILE)

    def _check_version_policy(self, manifest: UpdateManifest) -> None:
        """Rollback prevention: signed version must beat running + recorded."""
        try:
            remote = manifest.parsed_version
        except pkg_version.InvalidVersion:
            raise UpdateVerificationError(
                f"manifest version {manifest.version_str!r} is not a valid version"
            ) from None
        floor = self._current
        recorded = self._read_state()
        if recorded is not None and recorded > floor:
            floor = recorded
        if remote <= floor:
            raise StaleUpdateError(
                f"signed version {remote} is not newer than {floor} "
                f"(running {self._current}; downgrade/replay refused)"
            )

    def _check_prereq(self, manifest: UpdateManifest) -> None:
        if manifest.prereq.lower() == "none":
            return
        try:
            prereq = pkg_version.parse(manifest.prereq)
        except pkg_version.InvalidVersion:
            raise UpdateVerificationError(
                f"manifest prereq {manifest.prereq!r} is not a valid version"
            ) from None
        if self._current < prereq:
            raise UpdateVerificationError(
                f"prerequisite {prereq} not satisfied (current={self._current}); "
                "install the intermediate release first"
            )

    def _check_platform_compatibility(self, manifest: UpdateManifest) -> None:
        """
        Reject manifests that are incompatible with this Python runtime.

        Accepts:
        - Any manifest with major >= _MIN_PYTHON_MAJOR_STABLE (6+)
        - The 5.9.x test track (major == _MIN_PYTHON_MAJOR_TESTING
            and versionsub >= _MIN_PYTHON_SUB_TESTING)

        Rejects:
        - Non-integer major version
        - Eggdrop/Tcl era releases (major < 5, or major == 5 and sub < 9)
        - Manifests declaring an incompatible platform field
        """
        try:
            remote_major = int(manifest.version)
        except ValueError:
            raise IncompatiblePlatformError(
                f"Remote manifest has non-integer major version: {manifest.version!r}. "
                "Cannot determine platform compatibility. "
                "Verify your update.host configuration."
            )

        if remote_major < _MIN_PYTHON_MAJOR_TESTING:
            raise IncompatiblePlatformError(
                f"Remote manifest is for WBS {manifest.version_str}, which is an "
                f"Eggdrop/Tcl release (major version < {_MIN_PYTHON_MAJOR_TESTING}). "
                "This Python bot cannot install Eggdrop-era updates. "
                "Verify your update.host configuration points to a "
                "WBS 5.9+ release endpoint."
            )

        if remote_major == _MIN_PYTHON_MAJOR_TESTING:
            try:
                remote_sub = int(manifest.versionsub)
            except ValueError:
                raise IncompatiblePlatformError(
                    f"Remote manifest has non-integer versionsub: {manifest.versionsub!r}. "
                    "Cannot determine test track compatibility."
                )
            if remote_sub < _MIN_PYTHON_SUB_TESTING:
                raise IncompatiblePlatformError(
                    f"Remote manifest is for WBS {manifest.version_str}. "
                    "This Python bot only accepts the 5.9.x test track or newer. "
                    "Verify your update host configuration."
                )

        declared = manifest.platform.lower().strip()
        if declared not in ("python", "any", ""):
            raise IncompatiblePlatformError(
                f"Remote manifest declares platform={manifest.platform!r}, "
                f"which is incompatible with this runtime ({_RUNTIME_PLATFORM!r}). "
                "Update aborted. Check your update server configuration."
            )

    # ---------------------------------------------------------------- pipeline

    async def _run_update(self, manifest: UpdateManifest) -> bool:
        """Orchestrates the full update pipeline (fail closed at every step)."""
        self.last_error = None
        try:
            manifest = self._reverify(manifest)
            self._check_platform_compatibility(manifest)
            self._check_version_policy(manifest)
            self._check_prereq(manifest)
            require_https_url(manifest.url, "package URL")
            if manifest.full_upgrade:
                venv_python()  # fail before download if pip has no venv to target
        except (UpdateVerificationError, IncompatiblePlatformError,
                UpdateEnvironmentError) as exc:
            self._fail("Update rejected before download: %s", exc)
            return False

        install_started = False
        try:
            _TMP_DIR.mkdir(parents=True, exist_ok=True)
            tarball = _TMP_DIR / "wbs_update.tar.gz"

            log.info("Downloading update package...")
            digest, size = await self._download_file(manifest.url, tarball, manifest.size)
            if size != manifest.size:
                raise UpdateVerificationError(
                    f"package size mismatch (signed={manifest.size}, got={size})"
                )
            if not hmac.compare_digest(digest, manifest.sha256):
                raise UpdateVerificationError(
                    f"package SHA-256 mismatch (signed={manifest.sha256}, got={digest})"
                )
            log.info("Package verified against signed manifest (sha256=%s).", digest)

            extract_root = _TMP_DIR / "extracted"
            self._safe_extract(tarball, extract_root)
            wbs_root = self._find_wbs_root(extract_root, manifest.version_str)
            self._check_package_version(wbs_root, manifest)

            self._create_backup()
            install_started = True
            self._install_files(wbs_root)

            if manifest.full_upgrade:
                await self._pip_install(wbs_root)

            self._record_installed(manifest.parsed_version)
            log.info(
                "Successfully updated WBS %s -> %s. "
                "Restart the bot to load the new code.",
                self._current,
                manifest.version_str,
            )
            return True

        except Exception as exc:
            self.last_error = str(exc)
            if not install_started:
                log.error("Update aborted before install (nothing changed): %s", exc)
                return False
            log.error("Update failed: %s. Attempting rollback...", exc)
            if not self._restore_backup():
                log.critical(
                    "Rollback also failed. Manual intervention required. "
                    "Backup is at: %s",
                    _BACKUP_DIR,
                )
            return False

        finally:
            # Always clean the temp dir; keep backup until next successful update
            if _TMP_DIR.exists():
                shutil.rmtree(_TMP_DIR, ignore_errors=True)

    # --------------------------------------------------------------- transport

    def _make_headers(self) -> dict[str, str]:
        return {"User-Agent": self._useragent, "Accept-Encoding": "identity"}

    def _make_timeout(self, total: int) -> aiohttp.ClientTimeout:
        return aiohttp.ClientTimeout(total=total, connect=10)

    def _tls_context(self) -> ssl.SSLContext:
        return self._ssl_context or ssl.create_default_context()

    async def _get(self, url: str, *, limit: int, what: str, total_timeout: int,
                   sink: Callable[[bytes], None]) -> None:
        """
        GET *url* over verified HTTPS, following at most MAX_REDIRECTS
        redirects manually (each hop must be https), streaming at most
        *limit* body bytes into *sink*.
        """
        current = require_https_url(url, what)
        connector = aiohttp.TCPConnector(ssl=self._tls_context())
        async with aiohttp.ClientSession(
            headers=self._make_headers(),
            connector=connector,
            timeout=self._make_timeout(total_timeout),
            trust_env=False,
            auto_decompress=False,
        ) as session:
            for _hop in range(MAX_REDIRECTS + 1):
                require_https_url(current, f"{what} (redirect hop)" if _hop else what)
                async with session.get(current, allow_redirects=False) as resp:
                    if resp.status in _REDIRECT_STATUSES:
                        location = resp.headers.get("Location", "")
                        if not location:
                            raise UpdateDownloadError(
                                f"HTTP {resp.status} without Location fetching {what}"
                            )
                        current = urllib.parse.urljoin(current, location)
                        continue
                    if resp.status != 200:
                        raise UpdateDownloadError(f"HTTP {resp.status} fetching {what}")
                    encoding = resp.headers.get("Content-Encoding", "identity").strip().lower()
                    if encoding not in ("", "identity"):
                        raise UpdateDownloadError(
                            f"{what} served with Content-Encoding {encoding!r}; refusing"
                        )
                    if resp.content_length is not None and resp.content_length > limit:
                        raise UpdateDownloadError(
                            f"{what} too large ({resp.content_length} > {limit} bytes)"
                        )
                    received = 0
                    async for chunk in resp.content.iter_chunked(_CHUNK):
                        received += len(chunk)
                        if received > limit:
                            raise UpdateDownloadError(
                                f"{what} exceeded size limit of {limit} bytes"
                            )
                        sink(chunk)
                    return
            raise UpdateDownloadError(
                f"too many redirects fetching {what} (max {MAX_REDIRECTS})"
            )

    async def _fetch_bytes(self, url: str, limit: int, what: str) -> bytes:
        buf = bytearray()
        await self._get(url, limit=limit, what=what,
                        total_timeout=self._timeout, sink=buf.extend)
        return bytes(buf)

    async def _download_file(self, url: str, dest: Path,
                             expected_size: int) -> tuple[str, int]:
        """
        Stream *url* to *dest* (bounded by the signed size and the global
        cap). Returns (sha256 hex, byte count).
        """
        limit = min(int(expected_size), MAX_PACKAGE_BYTES)
        hasher = hashlib.sha256()
        count = 0
        with dest.open("wb") as fh:
            def sink(chunk: bytes) -> None:
                nonlocal count
                count += len(chunk)
                hasher.update(chunk)
                fh.write(chunk)
            await self._get(url, limit=limit, what="update package",
                            total_timeout=300, sink=sink)
        return hasher.hexdigest(), count

    @staticmethod
    def _verify_sha256(path: Path, expected_hex: str) -> None:
        """
        Compute the SHA-256 digest of *path* and compare to *expected_hex*.
        Raises ValueError if they differ or if the hex string is malformed.
        """
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hex or ""):
            raise ValueError(
                f"Manifest sha256 field is not a valid hex digest: {expected_hex!r}"
            )
        hasher = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(_CHUNK), b""):
                hasher.update(block)
        actual = hasher.hexdigest()
        if not hmac.compare_digest(actual, expected_hex.lower()):
            raise ValueError(
                f"Tarball SHA-256 mismatch -- "
                f"expected={expected_hex.lower()}, got={actual}"
            )
        log.debug("SHA-256 verified OK for %s.", path.name)

    # ----------------------------------------------------------------- archive

    @staticmethod
    def _safe_extract(tarball: Path, dest: Path) -> None:
        """
        Extract *tarball* to *dest* after validating every member:
        regular files/directories only, relative paths without '..',
        bounded member count and total unpacked size. Extraction always uses
        tarfile's "data" filter (Python >= 3.12 required).
        """
        if not hasattr(tarfile, "data_filter"):
            raise RuntimeError(
                "tarfile extraction filters unavailable; Python >= 3.12 required"
            )
        dest.mkdir(parents=True, exist_ok=True)
        dest_resolved = dest.resolve()

        with tarfile.open(tarball, "r:gz") as tf:
            members: list[tarfile.TarInfo] = []
            total = 0
            for member in tf:
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise ValueError(
                        f"Tarball has too many members (> {MAX_ARCHIVE_MEMBERS})"
                    )
                if not (member.isfile() or member.isdir()):
                    raise ValueError(
                        f"Tarball member {member.name!r} is not a regular file "
                        "or directory (links/devices are not allowed)"
                    )
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or member.name.startswith(("/", "\\")):
                    raise ValueError(
                        f"Tarball contains absolute path: {member.name!r}"
                    )
                if ".." in member_path.parts or "\\" in member.name:
                    raise ValueError(
                        f"Tarball path traversal detected: {member.name!r}"
                    )
                target = (dest_resolved / member_path).resolve()
                if target != dest_resolved and \
                   not str(target).startswith(str(dest_resolved) + os.sep):
                    raise ValueError(
                        f"Tarball path traversal detected: {member.name!r}"
                    )
                total += max(member.size, 0)
                if total > MAX_ARCHIVE_UNPACKED_BYTES:
                    raise ValueError(
                        "Tarball unpacked size exceeds "
                        f"{MAX_ARCHIVE_UNPACKED_BYTES} bytes"
                    )
                members.append(member)
            tf.extractall(dest, members=members, filter="data")

    @staticmethod
    def _find_wbs_root(extract_root: Path, version_str: str) -> Path:
        """
        Return the single top-level wbs<version>/ directory of the package.
        Raises FileNotFoundError if the package layout does not match the
        signed version exactly.
        """
        expected = extract_root / f"wbs{version_str}"
        entries = sorted(p.name for p in extract_root.iterdir())
        if entries != [expected.name] or not expected.is_dir():
            raise FileNotFoundError(
                f"Package must contain exactly one top-level directory "
                f"{expected.name!r}; found {entries[:5]!r}"
            )
        log.debug("Using extracted root: %s", expected)
        return expected

    @staticmethod
    def _check_package_version(wbs_root: Path, manifest: UpdateManifest) -> None:
        """The package's own __version__ must equal the signed version."""
        init_py = wbs_root / "src" / "__init__.py"
        try:
            text = init_py.read_text(encoding="utf-8")
        except OSError as exc:
            raise UpdateVerificationError(
                f"package has no readable src/__init__.py: {exc}"
            ) from None
        m = re.search(r"""^__version__\s*=\s*["']([^"'\s]+)["']""", text, re.MULTILINE)
        if not m:
            raise UpdateVerificationError("package src/__init__.py has no __version__")
        try:
            pkg_ver = pkg_version.parse(m.group(1))
        except pkg_version.InvalidVersion:
            raise UpdateVerificationError(
                f"package __version__ {m.group(1)!r} is not a valid version"
            ) from None
        if pkg_ver != manifest.parsed_version:
            raise UpdateVerificationError(
                f"package __version__ {pkg_ver} does not match signed "
                f"version {manifest.version_str}"
            )

    # ----------------------------------------------------------------- install

    def _create_backup(self) -> None:
        """Copy the current src/ directory to _BACKUP_DIR."""
        if _BACKUP_DIR.exists():
            shutil.rmtree(_BACKUP_DIR)
        shutil.copytree(_PKG_DIR, _BACKUP_DIR)
        log.debug("Backup created at %s.", _BACKUP_DIR)

    def _restore_backup(self) -> bool:
        """
        Replace src/ with the contents of _BACKUP_DIR.
        Returns True on success, False if no backup exists.
        """
        if not _BACKUP_DIR.exists():
            log.error("No backup found at %s; cannot roll back.", _BACKUP_DIR)
            return False
        try:
            if _PKG_DIR.exists():
                shutil.rmtree(_PKG_DIR)
            shutil.copytree(_BACKUP_DIR, _PKG_DIR)
            log.info("Rollback successful. src/ restored from backup.")
            return True
        except Exception as exc:
            log.critical("Rollback failed: %s", exc)
            return False

    def _install_files(self, wbs_root: Path) -> None:
        """
        Copy the new src/ from *wbs_root* over the current _PKG_DIR using
        an atomic rename-into-place pattern:
          new files staged -> old moved aside -> new renamed in -> old removed.
        """
        new_src = wbs_root / "src"
        if not new_src.is_dir():
            raise FileNotFoundError(
                f"Expected src/ directory not found at {new_src}"
            )

        staging = _PKG_DIR.with_suffix(".new")
        old_pkg = _PKG_DIR.with_suffix(".old")

        for path in (staging, old_pkg):
            if path.exists():
                shutil.rmtree(path)

        shutil.copytree(new_src, staging)
        _PKG_DIR.rename(old_pkg)
        staging.rename(_PKG_DIR)
        shutil.rmtree(old_pkg, ignore_errors=True)
        log.info("New src/ installed successfully.")

        for rel in _ROOT_INSTALLABLE:
            src_file = wbs_root / rel
            if src_file.exists():
                dest = _ROOT_DIR / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dest)
                log.info("Installed %s", rel)

    async def _pip_install(self, wbs_root: Path) -> None:
        """
        Install the verified package into the running project venv:

          1. <venv>/bin/python -m pip install --require-hashes -r requirements.lock
          2. <venv>/bin/python -m pip install --no-deps <wbs_root>

        Only reached after the package was authenticated and verified.
        Refuses to run outside a venv (UpdateEnvironmentError). Fails closed
        (RuntimeError -> rollback) when the package ships no requirements.lock
        or no pyproject.toml/setup.py, so pip never resolves unpinned
        dependency versions. Minimal sanitised env, 5-minute timeout per step.
        """
        python = venv_python()

        lock = wbs_root / _LOCK_FILE
        if not lock.is_file():
            raise RuntimeError(
                f"full upgrade requested but {_LOCK_FILE} is missing from the "
                "package; refusing an unpinned dependency install."
            )
        if not (wbs_root / "pyproject.toml").is_file() and not (wbs_root / "setup.py").is_file():
            raise RuntimeError(
                f"full upgrade requested but no pyproject.toml or setup.py in {wbs_root}."
            )

        safe_env = {
            k: os.environ[k]
            for k in ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT")
            if k in os.environ
        }
        safe_env["VIRTUAL_ENV"] = sys.prefix
        safe_env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

        pip = [python, "-m", "pip", "install", "--quiet", "--no-input"]
        steps = (
            ("dependencies, hash-verified",
             pip + ["--require-hashes", "-r", str(lock)]),
            ("wbs package, --no-deps",
             pip + ["--no-deps", str(wbs_root)]),
        )
        log.info("Running pip install into venv %s ...", sys.prefix)
        for what, cmd in steps:
            await self._run_pip(what, cmd, safe_env)
        log.info("pip install completed successfully.")

    @staticmethod
    async def _run_pip(what: str, cmd: list[str], env: dict[str, str]) -> None:
        log.info("pip install (%s)...", what)
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                ),
                timeout=_PIP_TIMEOUT,
            )
            _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=_PIP_TIMEOUT)
        except asyncio.TimeoutError:
            raise RuntimeError(f"pip install ({what}) timed out after 5 minutes.")

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"pip install ({what}) failed (exit {proc.returncode}): {err_msg[:500]}"
            )

    # ---------------------------------------------------------------- manifest

    @staticmethod
    def _parse_manifest(raw: bytes | str) -> UpdateManifest:
        """
        Strictly parse the (already signature-verified) RELEASE manifest.

        Raises UpdateVerificationError on: non-UTF-8, malformed or duplicate
        lines, missing required fields, wrong format tag, non-numeric version
        parts, non-https URL, missing/malformed sha256, missing/out-of-range
        size. Unknown keys are ignored. See the module docstring for format.
        """
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise UpdateVerificationError("manifest is not valid UTF-8") from None
        else:
            text = raw

        data: dict[str, str] = {}
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                raise UpdateVerificationError(f"manifest line {lineno} is malformed")
            key, val = parts[0].lower(), parts[1].strip()
            if key not in _KNOWN_FIELDS:
                continue
            if key in data:
                raise UpdateVerificationError(f"manifest repeats field {key!r}")
            data[key] = val

        missing = [k for k in _REQUIRED_FIELDS if k not in data]
        if missing:
            raise UpdateVerificationError(
                f"manifest missing required field(s): {', '.join(missing)}"
            )
        if data["format"] != MANIFEST_FORMAT:
            raise UpdateVerificationError(
                f"unsupported manifest format {data['format']!r} "
                f"(expected {MANIFEST_FORMAT!r})"
            )
        for key in ("version", "versionsub", "versionpatch"):
            if not re.fullmatch(r"\d{1,6}", data[key]):
                raise UpdateVerificationError(f"manifest {key} must be numeric")

        sha = data["sha256"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise UpdateVerificationError("manifest sha256 is not a 64-hex digest")

        if not re.fullmatch(r"\d{1,12}", data["size"]):
            raise UpdateVerificationError("manifest size must be a byte count")
        size = int(data["size"])
        if not 0 < size <= MAX_PACKAGE_BYTES:
            raise UpdateVerificationError(
                f"manifest size {size} outside 1..{MAX_PACKAGE_BYTES} bytes"
            )

        url = require_https_url(data["url"], "package URL")

        full_upgrade_raw = data.get("fullupgrade") or data.get("eggupg") or "no"
        full_upgrade = full_upgrade_raw.lower() in ("yes", "true", "1")

        return UpdateManifest(
            version=data["version"],
            versionsub=data["versionsub"],
            versionpatch=data["versionpatch"],
            full_upgrade=full_upgrade,
            author=data.get("author", "unknown"),
            date=data.get("date", "01012000"),
            url=url,
            prereq=data.get("prereq", "none"),
            sha256=sha,
            platform=data.get("platform", "any"),
            size=size,
        )

    def _is_newer(self, manifest: UpdateManifest) -> bool:
        """Return True if manifest.version > self._current."""
        try:
            return manifest.parsed_version > self._current
        except pkg_version.InvalidVersion:
            log.warning(
                "Remote manifest has unparseable version: %r", manifest.version_str
            )
            return False


async def run_standalone_update(config: dict) -> int:
    """
    Standalone CLI entry point for --update.

    Checks for a newer release and, if found, performs the full update.
    Intended to be called from the wbs launcher outside of a running bot.

    Returns:
        0  -- already up to date, or update applied successfully
        1  -- update available but install failed, or verification failed
        2  -- configuration error (update.host / update.signing_keys not set)
        3  -- unexpected error
    """
    update_cfg = config.get("update", {}) or {}
    if not str(update_cfg.get("host", "") or "").strip():
        print(
            "[wbs-update] ERROR: update.host is not configured in config.json.\n"
            "             Set 'update': {'host': 'https://your-update-server'} first.",
            file=sys.stderr,
        )
        return 2

    mgr = UpdateManager(config)
    if not mgr._trusted_keys:
        print(
            "[wbs-update] ERROR: no update signing key pinned.\n"
            "             Set 'update': {'signing_keys': ['<base64 Ed25519 public key>']}"
            " in config.json.",
            file=sys.stderr,
        )
        return 2

    try:
        print(f"[wbs-update] Current version: {__version__}")
        print("[wbs-update] Checking for updates...")

        manifest = await mgr.check_update()

        if manifest is None:
            if mgr.last_error:
                print(f"[wbs-update] ✗ Update check failed: {mgr.last_error}",
                      file=sys.stderr)
                return 1
            print("[wbs-update] Already up to date.")
            return 0

        print(
            f"[wbs-update] Update available: {__version__} → {manifest.version_str}"
            f"  (by {manifest.author}, dated {manifest.date})"
        )

        ok = await mgr.perform_update(manifest)
        if ok:
            print(
                f"[wbs-update] ✓ Updated to {manifest.version_str}. "
                "Restart wbs to load the new code."
            )
            return 0
        else:
            print(
                "[wbs-update] ✗ Update failed. Previous version preserved. "
                "Check logs for details.",
                file=sys.stderr,
            )
            return 1

    except Exception as exc:
        print(f"[wbs-update] Unexpected error: {exc}", file=sys.stderr)
        log.exception("run_standalone_update: unhandled exception")
        return 3
