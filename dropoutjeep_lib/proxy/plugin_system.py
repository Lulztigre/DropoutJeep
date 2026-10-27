"""Python plugin system for the DropoutJeep reverse proxy.

Plugins are plain Python files in dropoutjeep_lib/proxy/plugins_py/. Each file
must export a top-level variable named ``plugin`` that is an instance of a
class inheriting from :class:`ProxyPlugin`.

Plugins run before YAML rules, so YAML rules always apply on top of plugin
output. Plugin hooks that raise exceptions are logged and skipped so a broken
plugin cannot crash the proxy.
"""

import importlib.util
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .types import Request, Response

logger = logging.getLogger(__name__)

DEFAULT_PLUGINS_DIR = Path(__file__).parent / "plugins_py"


@dataclass
class HTTPExchange:
    """Snapshot of a proxied request/response pair passed to on_exchange."""
    method: str
    path: str
    target_url: str
    campaign_id: int
    recipient_token: str | None
    request_headers: dict
    request_body: bytes
    response_status: int
    response_headers: dict
    response_body: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ProxyPlugin:
    """Base class for Python proxy plugins.

    Subclasses override any of the hook methods. Hooks must not block for long;
    heavy work belongs in on_exchange, which runs in a background thread.
    """

    name: str = "unnamed"

    def on_request(self, request: Request, ctx: dict) -> Request:
        """Modify the outgoing request before it is forwarded to the target."""
        return request

    def on_response(self, request: Request, response: Response, ctx: dict) -> Response:
        """Modify the response before it is returned to the victim."""
        return response

    def on_playwright_page(self, page, ctx: dict):
        """Called after the Playwright page has loaded and before DOM capture.

        Plugins can inject JavaScript, fill fields, or click elements here.
        The method should be async-capable: it may return a coroutine.
        """
        pass

    def on_exchange(self, exchange: HTTPExchange):
        """Called after the response has been sent. Non-blocking by convention."""
        pass


# In-memory cache of loaded plugins keyed by directory.
_plugin_cache: dict[Path, list[ProxyPlugin]] = {}
_plugin_lock = threading.Lock()


def _load_plugin_module(path: Path) -> Any:
    """Load a single Python file as a module and return its namespace."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_python_plugins(plugins_dir: Path | str | None = None) -> list[ProxyPlugin]:
    """Discover and load all Python plugins from the configured directory.

    Returns a cached list on subsequent calls unless the directory changes.
    """
    directory = Path(plugins_dir) if plugins_dir else DEFAULT_PLUGINS_DIR
    directory = directory.resolve()

    with _plugin_lock:
        cached = _plugin_cache.get(directory)
        if cached is not None:
            return cached

        plugins: list[ProxyPlugin] = []
        if directory.exists():
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                try:
                    module = _load_plugin_module(path)
                    plugin = getattr(module, "plugin", None)
                    if plugin is None:
                        logger.warning("Plugin %s has no 'plugin' export", path)
                        continue
                    if not isinstance(plugin, ProxyPlugin):
                        logger.warning("Plugin %s export is not a ProxyPlugin instance", path)
                        continue
                    plugins.append(plugin)
                    logger.info("Loaded Python plugin: %s (%s)", plugin.name, path.name)
                except Exception:
                    logger.exception("Failed to load Python plugin %s", path)

        _plugin_cache[directory] = plugins
        return plugins


def reload_python_plugins(plugins_dir: Path | str | None = None) -> list[ProxyPlugin]:
    """Clear the plugin cache and reload from disk."""
    directory = Path(plugins_dir) if plugins_dir else DEFAULT_PLUGINS_DIR
    directory = directory.resolve()
    with _plugin_lock:
        _plugin_cache.pop(directory, None)
    return load_python_plugins(plugins_dir)


def apply_plugin_request_hooks(request: Request, ctx: dict, plugins: list[ProxyPlugin]) -> Request:
    for plugin in plugins:
        try:
            request = plugin.on_request(request, ctx)
        except Exception:
            logger.exception("Plugin %s on_request failed", plugin.name)
    return request


def apply_plugin_response_hooks(request: Request, response: Response, ctx: dict,
                                plugins: list[ProxyPlugin]) -> Response:
    for plugin in plugins:
        try:
            response = plugin.on_response(request, response, ctx)
        except Exception:
            logger.exception("Plugin %s on_response failed", plugin.name)
    return response


async def apply_plugin_playwright_hooks(page, ctx: dict, plugins: list[ProxyPlugin]):
    """Run Playwright page hooks after navigation but before DOM capture."""
    import inspect
    for plugin in plugins:
        try:
            result = plugin.on_playwright_page(page, ctx)
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.exception("Plugin %s on_playwright_page failed", plugin.name)


# Background executor for on_exchange hooks.
_exchange_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="plugin-exchange-")


def fire_plugin_exchange_hooks(exchange: HTTPExchange, plugins: list[ProxyPlugin]):
    for plugin in plugins:
        _exchange_executor.submit(_run_exchange_hook, plugin, exchange)


def _run_exchange_hook(plugin: ProxyPlugin, exchange: HTTPExchange):
    try:
        plugin.on_exchange(exchange)
    except Exception:
        logger.exception("Plugin %s on_exchange failed", plugin.name)
