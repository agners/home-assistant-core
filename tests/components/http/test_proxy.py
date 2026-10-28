"""Test the proxy plugin control."""

from pathlib import Path
import tempfile
from typing import Any

from aiohttp import web
import pytest
import pytest_socket

from homeassistant.components.http.proxy import (
    CADDY_ADMIN_LISTEN,
    CADDY_UPSTREAM,
    CaddyAdminClient,
    ProxyConfigError,
    ProxyUnavailableError,
    render_caddy_config,
)

CERTIFICATE = {"certificate": "CERT", "key": "KEY"}


@pytest.mark.parametrize(
    ("hosts", "port", "expected"),
    [
        pytest.param(None, 80, [":80"], id="all"),
        pytest.param(["0.0.0.0", "::"], 80, [":80"], id="dual_stack"),
        pytest.param(["0.0.0.0"], 80, ["0.0.0.0:80"], id="ipv4_only"),
        pytest.param(
            ["192.0.2.1", "fe80::1"],
            8080,
            ["192.0.2.1:8080", "[fe80::1]:8080"],
            id="specific",
        ),
        pytest.param(
            ["homeassistant.local"], 80, ["homeassistant.local:80"], id="hostname"
        ),
    ],
)
def test_render_listen_addresses(
    hosts: list[str] | None, port: int, expected: list[str]
) -> None:
    """Test the configured bind hosts become Caddy listen addresses."""
    config = render_caddy_config(
        hosts=hosts,
        http_port=port,
        https_port=443,
        certificate=None,
        trusted_proxies=[],
    )
    assert config["apps"]["http"]["servers"]["http"]["listen"] == expected


def test_render_plain_http() -> None:
    """Test a config without certificate has one HTTP server and keeps the admin socket."""
    config = render_caddy_config(
        hosts=None, http_port=80, https_port=443, certificate=None, trusted_proxies=[]
    )
    assert config["admin"] == {"listen": CADDY_ADMIN_LISTEN}
    servers = config["apps"]["http"]["servers"]
    assert list(servers) == ["http"]
    assert servers["http"]["automatic_https"] == {"disable": True}
    assert servers["http"]["routes"][0]["handle"][0] == {
        "handler": "reverse_proxy",
        "upstreams": [{"dial": CADDY_UPSTREAM}],
    }
    assert "trusted_proxies" not in servers["http"]
    assert "tls" not in config["apps"]


def test_render_https_and_trusted_proxies() -> None:
    """Test a certificate adds the HTTPS server selecting it by tag."""
    config = render_caddy_config(
        hosts=None,
        http_port=80,
        https_port=8443,
        certificate=CERTIFICATE,
        trusted_proxies=["10.0.0.0/8"],
    )
    servers = config["apps"]["http"]["servers"]
    assert servers["https"]["listen"] == [":8443"]
    assert servers["https"]["tls_connection_policies"] == [
        {"certificate_selection": {"any_tag": ["core"]}}
    ]
    assert servers["https"]["trusted_proxies"] == {
        "source": "static",
        "ranges": ["10.0.0.0/8"],
    }
    assert config["apps"]["tls"] == {
        "certificates": {
            "load_pem": [{"certificate": "CERT", "key": "KEY", "tags": ["core"]}]
        }
    }


@pytest.fixture
def allow_unix_sockets() -> None:
    """Let the client connect to the Unix socket of the fake admin API."""
    pytest_socket.socket_allow_hosts(["127.0.0.1"], allow_unix_socket=True)


@pytest.fixture
def admin_socket() -> Path:
    """Return a socket path short enough for sun_path."""
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp_dir:
        yield Path(tmp_dir) / "proxy.sock"


async def _run_admin(socket_path: Path, status: int) -> tuple[web.AppRunner, list[Any]]:
    """Serve a fake admin API on the socket, recording loaded configs."""
    loaded: list[Any] = []

    async def load(request: web.Request) -> web.Response:
        loaded.append(await request.json())
        return web.Response(status=status, text="rejected" if status >= 400 else "")

    async def config(request: web.Request) -> web.Response:
        return web.json_response(loaded[-1] if loaded else None)

    app = web.Application()
    app.router.add_post("/load", load)
    app.router.add_get("/config/", config)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.UnixSite(runner, str(socket_path)).start()
    return runner, loaded


@pytest.mark.usefixtures("allow_unix_sockets")
async def test_client_load_and_get(admin_socket: Path) -> None:
    """Test the client pushes the config and reads it back."""
    runner, loaded = await _run_admin(admin_socket, 200)
    client = CaddyAdminClient(admin_socket)
    try:
        await client.async_load({"admin": {}})
        assert loaded == [{"admin": {}}]
        assert await client.async_get_config() == {"admin": {}}
    finally:
        await runner.cleanup()


@pytest.mark.usefixtures("allow_unix_sockets")
async def test_client_rejected_config(admin_socket: Path) -> None:
    """Test a rejected config raises with Caddy's message."""
    runner, _ = await _run_admin(admin_socket, 400)
    client = CaddyAdminClient(admin_socket)
    try:
        with pytest.raises(ProxyConfigError, match="rejected"):
            await client.async_load({"admin": {}})
    finally:
        await runner.cleanup()


@pytest.mark.usefixtures("allow_unix_sockets")
async def test_client_unavailable(admin_socket: Path) -> None:
    """Test a missing socket raises ProxyUnavailableError."""
    client = CaddyAdminClient(admin_socket)
    with pytest.raises(ProxyUnavailableError):
        await client.async_load({"admin": {}})
    with pytest.raises(ProxyUnavailableError):
        await client.async_get_config()
