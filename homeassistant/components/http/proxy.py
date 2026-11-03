"""Control of the Supervisor proxy plugin (Caddy) over its admin socket."""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Final

import aiohttp

from homeassistant.exceptions import HomeAssistantError

from .certificates import CertificatePair

_LOGGER = logging.getLogger(__name__)

# Paths as the proxy container sees them; both directories are mounted into
# it by Supervisor. Core's view of the same sockets comes from its environment.
CADDY_ADMIN_LISTEN: Final = "unix//run/supervisor/proxy/proxy.sock|0600"
CADDY_UPSTREAM: Final = "unix//run/supervisor/core/plugins/proxy/core.sock"
# Selects the one certificate Core pushes regardless of the requested name,
# so HTTPS by IP address works without SNI tricks.
CERTIFICATE_TAG: Final = "core"

LOAD_ATTEMPTS: Final = 5
LOAD_RETRY_DELAY: Final = 2.0
REQUEST_TIMEOUT: Final = aiohttp.ClientTimeout(total=10)


class ProxyUnavailableError(HomeAssistantError):
    """The proxy's admin socket cannot be reached."""


class ProxyConfigError(HomeAssistantError):
    """The proxy rejected the configuration."""


@dataclass(frozen=True, slots=True)
class ProxyPaths:
    """Where Core reaches the proxy and where the proxy reaches Core."""

    admin_socket: Path
    core_socket: Path


def _listen_addresses(hosts: list[str] | None, port: int) -> list[str]:
    """Render Caddy listen addresses for the configured bind hosts."""
    if hosts is None or set(hosts) >= {"0.0.0.0", "::"}:
        # The unspecified address covers both families in Caddy
        return [f":{port}"]
    addresses: list[str] = []
    for host in hosts:
        if host == "0.0.0.0":
            addresses.append(f"0.0.0.0:{port}")
        elif ":" in host:
            addresses.append(f"[{host}]:{port}")
        else:
            addresses.append(f"{host}:{port}")
    return addresses


def render_caddy_config(
    *,
    hosts: list[str] | None,
    http_port: int,
    https_port: int,
    certificate: CertificatePair | None,
    trusted_proxies: list[str],
) -> dict[str, Any]:
    """Render the full Caddy JSON config for the proxy plugin.

    The admin listener must be part of every pushed config, otherwise Caddy
    falls back to its default TCP admin endpoint and Core loses control.
    """
    route = {
        "handle": [
            {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": CADDY_UPSTREAM}],
            }
        ]
    }

    def server(port: int) -> dict[str, Any]:
        conf: dict[str, Any] = {
            "listen": _listen_addresses(hosts, port),
            "routes": [route],
            # Core owns HTTP and HTTPS explicitly; no redirects, no ACME
            "automatic_https": {"disable": True},
        }
        if trusted_proxies:
            # Keep X-Forwarded-For from the user's own proxy in front of us so
            # Core's trusted_proxies handling sees the real chain
            conf["trusted_proxies"] = {"source": "static", "ranges": trusted_proxies}
        return conf

    servers = {"http": server(http_port)}
    apps: dict[str, Any] = {"http": {"servers": servers}}
    if certificate is not None:
        https = server(https_port)
        https["tls_connection_policies"] = [
            {"certificate_selection": {"any_tag": [CERTIFICATE_TAG]}}
        ]
        servers["https"] = https
        apps["tls"] = {
            "certificates": {
                "load_pem": [
                    {
                        "certificate": certificate["certificate"],
                        "key": certificate["key"],
                        "tags": [CERTIFICATE_TAG],
                    }
                ]
            }
        }
    return {
        "admin": {"listen": CADDY_ADMIN_LISTEN},
        "logging": {
            "logs": {
                "default": {
                    "writer": {"output": "stderr"},
                    "encoder": {"format": "console"},
                    "level": "INFO",
                }
            }
        },
        "apps": apps,
    }


class CaddyAdminClient:
    """Minimal client for Caddy's admin API over a Unix socket."""

    def __init__(self, admin_socket: Path) -> None:
        """Initialize the client."""
        self._admin_socket = admin_socket

    async def async_load(self, config: dict[str, Any]) -> None:
        """Replace the running config atomically.

        Raises ``ProxyUnavailableError`` when the socket is not reachable and
        ``ProxyConfigError`` when Caddy rejects the config.
        """
        connector = aiohttp.UnixConnector(path=str(self._admin_socket))
        try:
            async with (
                aiohttp.ClientSession(connector=connector) as session,
                session.post(
                    "http://localhost/load", json=config, timeout=REQUEST_TIMEOUT
                ) as response,
            ):
                if response.status >= 400:
                    raise ProxyConfigError(
                        f"The proxy rejected the configuration: {await response.text()}"
                    )
        except (aiohttp.ClientError, OSError, TimeoutError) as err:
            raise ProxyUnavailableError(
                f"Cannot reach the proxy at {self._admin_socket}: {err}"
            ) from err

    async def async_get_config(self) -> dict[str, Any] | None:
        """Return the running config, ``None`` when none is loaded."""
        connector = aiohttp.UnixConnector(path=str(self._admin_socket))
        try:
            async with (
                aiohttp.ClientSession(connector=connector) as session,
                session.get(
                    "http://localhost/config/", timeout=REQUEST_TIMEOUT
                ) as response,
            ):
                if response.status >= 400:
                    raise ProxyUnavailableError(
                        f"The proxy returned {response.status} for its config"
                    )
                config: dict[str, Any] | None = await response.json()
                return config
        except (aiohttp.ClientError, OSError, TimeoutError) as err:
            raise ProxyUnavailableError(
                f"Cannot reach the proxy at {self._admin_socket}: {err}"
            ) from err
