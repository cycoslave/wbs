# src/update.py
"""
WBS Update Manager
==================
Handles self-update from a remote release endpoint.

Flow:
  1. check_update()   -- fetch UPDATE manifest, verify platform compat, compare versions
  2. perform_update() -- download tarball, verify SHA-256, safe-extract, backup,
                         install new src/, optionally run pip install
  3. rollback()       -- restore backup if anything goes wrong post-install

Security hardening:
  - All HTTP via TLS (ssl=True, no verify=False ever)
  - Platform compatibility enforced before any download begins
  - SHA-256 checksum of tarball verified before any file is written
  - tarfile path-traversal (Zip Slip) guard on every member
  - Subprocess uses sys.executable, minimal env, timeout enforced
  - No secrets or download URLs written to log at INFO level
  - asyncio.Lock prevents concurrent update races
  - Atomic src/ swap with backup kept for rollback

TODOs:
  - Add GPG/minisign signature verification once a signing key is published
  - Wire check_update() into a scheduled asyncio task in core.py
  - Implement restart signal (SIGUSR1 or process-manager message) after install
"""
import asyncio
import hashlib
import logging
import os
import re
import shutil
import sys
import tarfile
import aiohttp
from pathlib import Path
from typing import Any, NamedTuple, Optional
from packaging import version as pkg_version

from . import __version__

log = logging.getLogger("wbs.update")
_RUNTIME_PLATFORM = "python"
_MIN_PYTHON_MAJOR = 6
_PKG_DIR    = Path(__file__).resolve().parent
_ROOT_DIR   = _PKG_DIR.parent
_TMP_DIR    = _ROOT_DIR / ".tmp" / "update"
_BACKUP_DIR = _ROOT_DIR / ".backup"

class IncompatiblePlatformError(RuntimeError):
    """
    Raised when a remote update manifest targets a different runtime platform
    (e.g., an Eggdrop/Tcl manifest delivered to a Python bot, or a manifest
    whose major version predates the Python rewrite boundary).
    """

class UpdateManifest(NamedTuple):
    """Parsed fields from the remote UPDATE manifest file."""
    version:      str
    versionsub:   str
    versionpatch: str
    full_upgrade: bool    # run `pip install` after extract
    author:       str
    date:         str
    url:          str     # tarball download URL
    prereq:       str     # minimum current version required, or "none"
    sha256:       str     # hex digest of tarball, or "none" (skip check)
    platform:     str     # "python" | "eggdrop" | "any"

    @property
    def version_str(self) -> str:
        return f"{self.version}.{self.versionsub}.{self.versionpatch}"

    @property
    def parsed_version(self) -> pkg_version.Version:
        return pkg_version.parse(self.version_str)

class UpdateManager:
    """
    Manages WBS self-updates from a remote manifest + tarball.

    All public methods are async-safe. Only one update may run at a time;
    concurrent callers block on the internal asyncio.Lock.

    Args:
        config: Dict with keys: auhost, auremotefile, useragent,
                updatetimeout (seconds, default 30).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._lock = asyncio.Lock()
        _update_cfg: dict[str, Any] = config.get("update", {})
        self._auhost: str = _update_cfg.get("host", "").rstrip("/")
        self._auto_updates: bool = bool(_update_cfg.get("auto_updates", False))
        self._auremotefile: str = "/UPDATE"
        self._useragent: str = f"WBS/{__version__}"
        self._timeout: int = 30
        self._current: pkg_version.Version = pkg_version.parse(__version__)

    async def check_update(self) -> Optional[UpdateManifest]:
        """
        Fetch the remote UPDATE manifest and return an UpdateManifest if a
        newer, compatible version is available -- otherwise None.

        Platform compatibility is checked here so the operator gets an
        immediate, descriptive error if auhost/auremotefile is misconfigured
        to point at an Eggdrop-era server.

        Raises nothing -- all errors are logged and None is returned.
        """
        if not self._auhost:
            log.warning("update.check_update: auhost not configured, skipping.")
            return None

        manifest_url = f"{self._auhost}{self._auremotefile}"
        log.info("Checking for WBS updates...")

        try:
            raw = await self._fetch_text(manifest_url)
        except Exception as exc:
            log.error("Failed to fetch update manifest: %s", exc)
            return None

        manifest = self._parse_manifest(raw)
        if manifest is None:
            return None

        try:
            self._check_platform_compatibility(manifest)
        except IncompatiblePlatformError as exc:
            log.error("Platform incompatibility detected: %s", exc)
            return None

        if not self._is_newer(manifest):
            log.info(
                "WBS is up to date (current=%s, remote=%s).",
                self._current,
                manifest.version_str,
            )
            return None

        log.info("Update available: %s -> %s", self._current, manifest.version_str)
        return manifest

    async def perform_update(self, manifest: UpdateManifest) -> bool:
        """
        Download, verify, extract, and install the update described by *manifest*.

        Returns True on success, False on failure. On failure the previous
        installation is restored from backup automatically.

        This method acquires an exclusive lock; concurrent calls will wait.
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

    def _check_platform_compatibility(self, manifest: UpdateManifest) -> None:
        """
        Reject manifests that are incompatible with this Python runtime.
        """
        try:
            remote_major = int(manifest.version)
        except ValueError:
            raise IncompatiblePlatformError(
                f"Remote manifest has non-integer major version: {manifest.version!r}. "
                "Cannot determine platform compatibility. "
                "Verify your auhost/auremotefile configuration."
            )

        if remote_major < _MIN_PYTHON_MAJOR:
            raise IncompatiblePlatformError(
                f"Remote manifest is for WBS {manifest.version_str}, which is an "
                f"Eggdrop/Tcl release (major version < {_MIN_PYTHON_MAJOR}). "
                "This Python bot cannot install Eggdrop-era updates. "
                "Verify your auhost/auremotefile configuration points to a "
                "WBS 6+ release endpoint."
            )

        declared = manifest.platform.lower().strip()
        if declared not in ("python", "any", ""):
            raise IncompatiblePlatformError(
                f"Remote manifest declares platform={manifest.platform!r}, "
                f"which is incompatible with this runtime ({_RUNTIME_PLATFORM!r}). "
                "Update aborted. Check your update server configuration."
            )

    async def _run_update(self, manifest: UpdateManifest) -> bool:
        """Orchestrates the full update pipeline."""

        if manifest.prereq != "none":
            try:
                prereq = pkg_version.parse(manifest.prereq)
                if self._current < prereq:
                    log.error(
                        "Cannot apply update %s: prerequisite %s not satisfied "
                        "(current=%s). Install the intermediate release first.",
                        manifest.version_str,
                        manifest.prereq,
                        self._current,
                    )
                    return False
            except pkg_version.InvalidVersion:
                log.warning("Manifest has unparseable prereq field; ignoring.")

        try:
            self._check_platform_compatibility(manifest)
        except IncompatiblePlatformError as exc:
            log.error("Platform compatibility check failed: %s", exc)
            return False

        if manifest.url == "none":
            log.error("Manifest contains no download URL; aborting update.")
            return False

        _TMP_DIR.mkdir(parents=True, exist_ok=True)
        tarball = _TMP_DIR / "wbs_update.tar.gz"

        try:
            log.info("Downloading update package...")
            await self._download_file(manifest.url, tarball)

            if manifest.sha256 != "none":
                self._verify_sha256(tarball, manifest.sha256)
            else:
                log.warning(
                    "Manifest provides no sha256 -- skipping integrity check. "
                    "Consider publishing checksums for security."
                )

            self._create_backup()

            extract_root = _TMP_DIR / "extracted"
            self._safe_extract(tarball, extract_root)

            wbs_root = self._find_wbs_root(extract_root, manifest.version_str)

            self._install_src(wbs_root)

            if manifest.full_upgrade:
                await self._pip_install(wbs_root)

            log.info(
                "Successfully updated WBS %s -> %s. "
                "Restart the bot to load the new code.",
                self._current,
                manifest.version_str,
            )
            return True

        except Exception as exc:
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

    def _make_headers(self) -> dict[str, str]:
        return {"User-Agent": self._useragent}

    def _make_timeout(self, total: int) -> aiohttp.ClientTimeout:
        return aiohttp.ClientTimeout(total=total, connect=10)

    async def _fetch_text(self, url: str) -> str:
        """GET *url* and return response body as text. TLS always enforced."""
        timeout   = self._make_timeout(self._timeout)
        connector = aiohttp.TCPConnector(ssl=True)
        async with aiohttp.ClientSession(
            headers=self._make_headers(),
            connector=connector,
            timeout=timeout,
        ) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status} fetching manifest")
                return await resp.text()

    async def _download_file(self, url: str, dest: Path) -> None:
        """Stream *url* to *dest*. TLS always enforced."""
        timeout   = self._make_timeout(300)
        connector = aiohttp.TCPConnector(ssl=True)
        async with aiohttp.ClientSession(
            headers=self._make_headers(),
            connector=connector,
            timeout=timeout,
        ) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status} downloading tarball")
                with dest.open("wb") as fh:
                    async for chunk in resp.content.iter_chunked(65_536):
                        fh.write(chunk)

    @staticmethod
    def _verify_sha256(path: Path, expected_hex: str) -> None:
        """
        Compute the SHA-256 digest of *path* and compare to *expected_hex*.
        Raises ValueError if they differ or if the hex string is malformed.
        """
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hex):
            raise ValueError(
                f"Manifest sha256 field is not a valid hex digest: {expected_hex!r}"
            )
        hasher = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(65_536), b""):
                hasher.update(block)
        actual = hasher.hexdigest()
        if actual.lower() != expected_hex.lower():
            raise ValueError(
                f"Tarball SHA-256 mismatch -- "
                f"expected={expected_hex.lower()}, got={actual}"
            )
        log.debug("SHA-256 verified OK for %s.", path.name)

    @staticmethod
    def _safe_extract(tarball: Path, dest: Path) -> None:
        """
        Extract *tarball* to *dest* after validating every member for
        path-traversal attacks (Zip Slip).
        Raises ValueError if any member escapes the destination directory.
        """
        dest.mkdir(parents=True, exist_ok=True)
        dest_resolved = dest.resolve()

        with tarfile.open(tarball, "r:gz") as tf:
            for member in tf.getmembers():
                member_path = Path(member.name)
                if member_path.is_absolute():
                    raise ValueError(
                        f"Tarball contains absolute path: {member.name!r}"
                    )
                target = (dest_resolved / member_path).resolve()
                if not str(target).startswith(str(dest_resolved) + os.sep) and \
                   target != dest_resolved:
                    raise ValueError(
                        f"Tarball path traversal detected: {member.name!r}"
                    )
            extract_kwargs: dict[str, Any] = {}
            if sys.version_info >= (3, 12):
                extract_kwargs["filter"] = "data"
            tf.extractall(dest, **extract_kwargs)  # noqa: S202 -- guarded above

    @staticmethod
    def _find_wbs_root(extract_root: Path, version_str: str) -> Path:
        """
        Locate the top-level wbs<version>/ directory inside the extracted tree.
        Raises FileNotFoundError if not found.
        """
        candidates = sorted(extract_root.glob(f"wbs{version_str}"))
        if not candidates:
            candidates = sorted(extract_root.glob("wbs*"))
        if not candidates:
            raise FileNotFoundError(
                f"No wbs* directory found in extracted package under {extract_root}"
            )
        chosen = candidates[0]
        log.debug("Using extracted root: %s", chosen)
        return chosen

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

    def _install_src(self, wbs_root: Path) -> None:
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

    async def _pip_install(self, wbs_root: Path) -> None:
        """
        Run `pip install .` inside *wbs_root* using the current interpreter.
        Uses sys.executable, minimal sanitised env, 5-minute hard timeout.
        """
        pyproject = wbs_root / "pyproject.toml"
        setup_py  = wbs_root / "setup.py"
        if not pyproject.exists() and not setup_py.exists():
            log.warning(
                "No pyproject.toml or setup.py found in %s; skipping pip install.",
                wbs_root,
            )
            return

        safe_env = {
            k: os.environ[k]
            for k in ("PATH", "HOME", "VIRTUAL_ENV", "USERPROFILE", "SYSTEMROOT")
            if k in os.environ
        }

        cmd = [sys.executable, "-m", "pip", "install", "--quiet", str(wbs_root)]
        log.info("Running pip install for dependency updates...")

        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=safe_env,
                ),
                timeout=300.0,
            )
            stdout, stderr = await proc.communicate()
        except asyncio.TimeoutError:
            raise RuntimeError("pip install timed out after 5 minutes.")

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"pip install failed (exit {proc.returncode}): {err_msg[:500]}"
            )
        log.info("pip install completed successfully.")

    @staticmethod
    def _parse_manifest(raw: str) -> Optional[UpdateManifest]:
        """
        Parse the remote RELEASE manifest into an UpdateManifest.

        Expected format (one key value per line; # lines are comments):

            version 6
            versionsub 1
            versionpatch 0
            fullupgrade no
            author cyco
            date 30052026
            url https://wbsupdate.wcksoft.com/6.1/wbs6.1.0.tgz
            prereq none
            sha256 <64-char hex>
            platform python

        Legacy keys (eggupg) accepted for backward compat.
        Unknown keys are silently ignored.
        Missing keys use safe defaults.
        """
        defaults: dict[str, str] = {
            "version":      "0",
            "versionsub":   "0",
            "versionpatch": "0",
            "fullupgrade":  "no",
            "eggupg":       "no",       # legacy alias for fullupgrade
            "author":       "unknown",
            "date":         "01012000",
            "url":          "none",
            "prereq":       "none",
            "sha256":       "none",
            "platform":     "any",      # safe default for pre-field manifests
        }
        data = dict(defaults)

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].lower(), parts[1].strip()
            if key in data:
                data[key] = val

        # Modern "fullupgrade" wins over legacy "eggupg"
        full_upgrade_raw = data.get("fullupgrade", "no")
        if full_upgrade_raw == "no":
            full_upgrade_raw = data.get("eggupg", "no")
        full_upgrade = full_upgrade_raw.lower() in ("yes", "true", "1")

        try:
            return UpdateManifest(
                version=data["version"],
                versionsub=data["versionsub"],
                versionpatch=data["versionpatch"],
                full_upgrade=full_upgrade,
                author=data["author"],
                date=data["date"],
                url=data["url"],
                prereq=data["prereq"],
                sha256=data["sha256"],
                platform=data["platform"],
            )
        except Exception as exc:
            log.error("Failed to construct UpdateManifest from parsed data: %s", exc)
            return None

    def _is_newer(self, manifest: UpdateManifest) -> bool:
        """Return True if manifest.version > self._current."""
        try:
            return manifest.parsed_version > self._current
        except pkg_version.InvalidVersion:
            log.warning(
                "Remote manifest has unparseable version: %r", manifest.version_str
            )
            return False