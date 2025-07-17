"""
ContextManager
==============

• Holds run-time metadata that lives in   <cwd>/metadata.yaml
• Persists updates back to disk.
• Exposes dynamic getters  get_<key>()  for every top-level YAML field.
• Also loads a static JSON “environment” file that lists supported Ubuntu
  releases, workspace paths, etc.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class ContextManager:
    # --------------------------------------------------------------------- init
    def __init__(
        self,
        driver_conf: str = "metadata.yaml",
        env_conf: str = ".env-conf",
        mode: str = "w",                     # 'w' or 'r'
    ) -> None:
        self.cwd = Path.cwd()
        self.driver_conf_path = self.cwd / driver_conf
        self.mode = mode  # if 'r', save() is disabled

        # dynamic YAML state
        self._metadata: Dict[str, Any] = self._load_metadata()

        # static environment state
        self._env = self._load_env(env_conf)
        self.supported_releases: list[str] = self._env["release_list"]
        self.package_workspace: str = self._env["package_workspace"]
        self.uct: str = self._env["ubuntu-cve-tracker"]

        # add dynamic getters for YAML keys
        for key in self._metadata:
            self._declare_getter(key)

    # ----------------------------------------------------------------- public API
    def save(self, key: str, value: Any) -> None:
        """Persist a single key/value back to driver_conf on disk."""
        if self.mode == "r":
            raise PermissionError("ContextManager opened in read-only mode")
        self._metadata[key] = value
        self._save_metadata()

    def value_exists(self, key: str) -> bool:
        return key in self._metadata

    def values_exist(self, *keys: str) -> bool:
        return all(k in self._metadata for k in keys)

    # convenience direct access to entire dict
    @property
    def metadata(self) -> Dict[str, Any]:
        # always reload the yaml file to pick up out-of-process edits
        self._metadata = self._load_metadata()
        return self._metadata

    # ---------------------------------------------------------------- helpers
    # ---- YAML driver_conf
    def _load_metadata(self) -> Dict[str, Any]:
        if not self.driver_conf_path.exists():
            return {}
        with open(self.driver_conf_path, "r") as fp:
            return yaml.safe_load(fp) or {}

    def _save_metadata(self) -> None:
        with open(self.driver_conf_path, "w") as fp:
            yaml.dump(self._metadata, fp)

    # ---- JSON env_conf
    def _load_env(self, env_conf: str) -> Dict[str, Any]:
        env_path = Path(__file__).resolve().parent / env_conf
        if not env_path.exists():
            raise FileNotFoundError(f"Environment file {env_path} not found")
        with open(env_path, "r") as fp:
            return json.load(fp)

    # ---- dynamic getters
    def _declare_getter(self, key: str) -> None:
        def getter(self) -> Optional[Any]:        # noqa: ANN001
            self._metadata = self._load_metadata()
            return self._metadata.get(key)

        setattr(self.__class__, f"get_{key}", getter)

    # ---------------------------------------------------------------- repr
    def __repr__(self) -> str:
        return f"<ContextManager {self.driver_conf_path}>"
