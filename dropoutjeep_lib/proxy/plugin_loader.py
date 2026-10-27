"""YAML plugin loader for proxy content-manipulation rules.

Plugins are declarative YAML files stored in dropoutjeep_lib/proxy/plugins/.
Each plugin contains a list of rules that are merged with a campaign's inline
rules at request time. This mirrors goblin's plugin system:
https://goblin.xiecat.fun/plugin/
"""

import logging
import os
from pathlib import Path

from .engine import Rule

logger = logging.getLogger(__name__)

DEFAULT_PLUGINS_DIR = Path(__file__).parent / "plugins"


def _list_plugin_files(plugins_dir: Path | str | None = None) -> list[Path]:
    """Return all .yaml / .yml files in the plugins directory."""
    directory = Path(plugins_dir) if plugins_dir else DEFAULT_PLUGINS_DIR
    if not directory.exists():
        return []
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml")
    )


def list_plugins(plugins_dir: Path | str | None = None) -> list[dict]:
    """Return metadata for every available plugin without loading full rules."""
    plugins = []
    for path in _list_plugin_files(plugins_dir):
        try:
            import yaml
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            meta = data.get("metadata", {}) if isinstance(data, dict) else {}
            plugins.append({
                "name": path.stem,
                "filename": path.name,
                "path": str(path),
                "title": meta.get("title") or path.stem,
                "description": meta.get("description", ""),
                "author": meta.get("author", ""),
            })
        except Exception as exc:
            logger.warning("Failed to read plugin metadata for %s: %s", path, exc)
    return plugins


def load_plugin(name: str, plugins_dir: Path | str | None = None) -> list[Rule]:
    """Load a single plugin by name (with or without .yaml/.yml suffix).

    Returns a list of Rule objects. Unknown or unsafe paths are rejected.
    """
    directory = Path(plugins_dir) if plugins_dir else DEFAULT_PLUGINS_DIR
    name = name.strip()
    if not name:
        return []

    # Reject path traversal attempts; only bare plugin names are allowed.
    if os.path.sep in name or ".." in name:
        logger.warning("Refusing to load plugin with path separators: %s", name)
        return []

    if not name.lower().endswith((".yaml", ".yml")):
        for ext in (".yaml", ".yml"):
            candidate = directory / f"{name}{ext}"
            if candidate.exists():
                path = candidate
                break
        else:
            logger.warning("Plugin not found: %s", name)
            return []
    else:
        path = directory / name
        if not path.exists():
            logger.warning("Plugin not found: %s", name)
            return []

    try:
        import yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        logger.warning("Failed to parse plugin %s: %s", path, exc)
        return []

    # Plugins may be either a plain list of rules or a dict with a 'rules' key.
    if isinstance(data, list):
        rules_raw = data
    elif isinstance(data, dict):
        rules_raw = data.get("rules", [])
    else:
        logger.warning("Plugin %s has invalid top-level type: %s", path, type(data).__name__)
        return []

    rules = []
    for idx, rule_dict in enumerate(rules_raw):
        try:
            rules.append(Rule(rule_dict))
        except Exception as exc:
            logger.warning("Skipping invalid rule #%d in plugin %s: %s", idx, path, exc)
    return rules


def load_plugins(
    plugin_names: list[str],
    plugins_dir: Path | str | None = None,
) -> list[Rule]:
    """Load multiple plugins and concatenate their rules."""
    rules = []
    for name in plugin_names or []:
        rules.extend(load_plugin(name, plugins_dir))
    return rules
