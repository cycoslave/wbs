# src/update.py
"""
Update Manager
"""

import aiohttp
import asyncio
import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from packaging import version
from typing import List, Optional, Dict
import logging

logger = logging.getLogger(__name__)

class UpdateManager:
    def __init__(self, config: Dict):
        self.auhost = config.get('auhost', 'https://example.com')
        self.auremotefile = config.get('auremotefile', '/UPDATE')
        self.aulocalfile = Path('.tmp/UPDATE')
        self.useragent = config.get('useragent', 'wbs/6.0.0')
        self.updatetimeout = config.get('updatetimeout', 10)
        ver_str = f"{config['wbsver']}.{config['wbsversub']}.{config['wbsverpatch']}"
        self.current_ver = version.parse(ver_str)
        self.tmp_dir = Path('.tmp')
        self.update_dir = Path('.update')
        self.task_auget = False

    async def check_update(self) -> Optional[List]:
        """Fetch and parse UPDATE file, return [ver, sub, patch, eggupg, author, date, url, prereq] if newer."""
        self.tmp_dir.mkdir(exist_ok=True)
        url = f"{self.auhost.rstrip('/')}{self.auremotefile}"
        try:
            timeout = aiohttp.ClientTimeout(total=self.updatetimeout)
            headers = {'User-Agent': self.useragent}
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        logger.error(f"Failed to download UPDATE: {resp.status}")
                        return None
                    content = await resp.text()
            self.aulocalfile.parent.mkdir(exist_ok=True, parents=True)
            self.aulocalfile.write_text(content)
        except Exception as e:
            logger.error(f"Error fetching UPDATE: {e}")
            return None

        au_data = self._parse_update_file()
        if not au_data or not self._is_newer(au_data[:3]):
            if au_data:
                logger.info(f"No update needed. Remote: {au_data[0]}.{au_data[1]}.{au_data[2]} vs Current: {self.current_ver}")
            return None
        logger.info(f"New update available: {au_data[0]}.{au_data[1]}.{au_data[2]}")
        return au_data

    def _parse_update_file(self) -> Optional[List]:
        """Parse local UPDATE file into [version, versionsub, versionpatch, eggupg, author, date, url, prereq]."""
        try:
            if not self.aulocalfile.exists():
                return None
            lines = self.aulocalfile.read_text().strip().split('\n')
            data = {
                'version': '0', 'versionsub': '0', 'versionpatch': '0', 'eggupg': 'no',
                'author': 'anonymous', 'date': '01012000', 'url': 'none', 'prereq': 'none'
            }
            for line in lines:
                if ':' in line:
                    key, val = line.split(':', 1)
                    data[key.strip()] = val.strip()
            return [
                data['version'], data['versionsub'], data['versionpatch'], data['eggupg'],
                data['author'], data['date'], data['url'], data['prereq']
            ]
        except Exception as e:
            logger.error(f"Error parsing UPDATE file: {e}")
            return None
        finally:
            if self.aulocalfile.exists():
                self.aulocalfile.unlink()

    def _is_newer(self, remote_ver: List[str]) -> bool:
        """Compare current vs remote version."""
        try:
            remote = version.parse('.'.join(remote_ver))
            return remote > self.current_ver
        except Exception:
            return False

    async def perform_update(self, au_data: List):
        """Download, extract, and install update."""
        # Handle prerequisites recursively
        if au_data[7] != 'none':
            try:
                prereq_ver = version.parse(au_data[7])
                if prereq_ver > self.current_ver:
                    logger.info(f"Prerequisite {au_data[7]} required. Checking...")
                    await self.check_update()
                    return
            except Exception:
                logger.warning("Invalid prereq version, skipping.")

        url = au_data[6]
        if url == 'none':
            logger.error("No update URL provided.")
            return

        tgz_path = self.tmp_dir / 'update.tgz'
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={'User-Agent': self.useragent}) as resp:
                    if resp.status != 200:
                        raise ValueError(f"Download failed: {resp.status}")
                    tgz_path.write_bytes(await resp.read())

            self._extract_update(tgz_path)
            self._install_scripts(au_data)

            if au_data[3] == 'yes':
                await self._install_full(au_data)

            logger.info("Update completed successfully!")
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise
        finally:
            for path in [tgz_path, self.update_dir]:
                if path.exists():
                    if path.is_file():
                        path.unlink(missing_ok=True)
                    else:
                        shutil.rmtree(path, ignore_errors=True)

    def _extract_update(self, tgz_path: Path):
        """Extract tgz to .update dir."""
        self.update_dir.mkdir(exist_ok=True)
        with tarfile.open(tgz_path) as tar:
            tar.extractall(self.update_dir)

    def _install_scripts(self, au_data: List):
        """Copy .wbs/* from extracted wbsX.Y.Z/.wbs to .wbs, handling update.tcl specially."""
        wbs_root = next(self.update_dir.glob('wbs*'), None)
        if not wbs_root:
            raise ValueError("No wbs* directory found in update package.")

        src_wbs = wbs_root / '.wbs'
        if not src_wbs.exists():
            raise ValueError("No .wbs directory in extracted package.")

        dst_wbs = Path('.wbs')
        dst_wbs.mkdir(exist_ok=True)

        # Copy all files except old core/update.tcl
        for src_file in src_wbs.rglob('*'):
            if src_file.is_file():
                rel_path = src_file.relative_to(src_wbs)
                if rel_path.parent.name == 'core' and rel_path.name == 'update.tcl':
                    continue  # Skip old update.tcl, handle new one below
                dst_file = dst_wbs / rel_path
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dst_file)

        # Copy new update.tcl if present
        new_update = src_wbs / 'core' / 'update.tcl'
        if new_update.exists():
            dst_update = dst_wbs / 'core' / 'update.tcl'
            dst_update.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(new_update, dst_update)
            logger.info("Updated core/update.tcl")

    async def _install_full(self, au_data: List):
        """Perform full installation (adapt for WBS, e.g., pip install or pyproject.toml)."""
        logger.info(f"Performing full install for {au_data[0]}.{au_data[1]}.{au_data[2]}")
        wbs_root = next(self.update_dir.glob('wbs*'), None)
        if wbs_root:
            # Example: run pip install from extracted dir (customize as needed)
            # proc = await asyncio.create_subprocess_exec(
            #     'pip', 'install', '.', cwd=wbs_root,
            #     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            # )
            # stdout, stderr = await proc.communicate()
            # if proc.returncode != 0:
            #     raise RuntimeError(f"Full install failed: {stderr.decode()}")
            logger.info("Full install placeholder executed (customize for WBS).")
