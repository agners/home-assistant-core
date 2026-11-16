"""Test the public certificate from a shared zone."""

import datetime as dt
from ipaddress import ip_address
import json
import socket
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from acme import challenges, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from freezegun.api import FrozenDateTimeFactory
import josepy as jose
import pytest
from pytest_homeassistant.common import async_fire_time_changed
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant.typing import WebSocketGenerator

from homeassistant.components.http import DOMAIN
from homeassistant.components.http.public_certificate import (
    CHECK_INTERVAL,
    RETRY_DELAY,
    STORAGE_KEY,
    PublicCertificate,
    PublicCertificateSettings,
    _PendingOrder,
    _start_order,
    async_get_public_certificate_manager,
    default_settings,
    generate_account_key,
    host_name,
    instance_id,
    ip_to_label,
    sign_challenge_request,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util

SETTINGS = PublicCertificateSettings(
    zone="ha.example",
    api_url="https://api.ha.example",
    directory_url="https://acme.example/directory",
)
ACCOUNT_KEY = generate_account_key()
INSTANCE = instance_id(
    jose.JWKRSA(
        key=jose.ComparableRSAKey(
            serialization.load_pem_private_key(ACCOUNT_KEY.encode(), password=None)
        )
    )
)
NAME = f"*.{INSTANCE}.ha.example"


def _certificate(name: str, lifetime: dt.timedelta) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = dt_util.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + lifetime)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _public_certificate(
    lifetime: dt.timedelta = dt.timedelta(days=64),
) -> PublicCertificate:
    return PublicCertificate(
        certificate=_certificate(NAME, lifetime), key="KEY", name=NAME
    )


@pytest.mark.parametrize(
    ("address", "label"),
    [
        pytest.param("192.168.1.5", "192-168-1-5", id="ipv4"),
        pytest.param("fd00::1", "fd00--1", id="ipv6"),
        pytest.param("2001:db8::1", "2001-db8--1", id="ipv6_global"),
        pytest.param("::1", "0--1", id="leading_colon"),
        pytest.param("fe80::", "fe80--0", id="trailing_colon"),
    ],
)
def test_ip_to_label(address: str, label: str) -> None:
    """Test addresses become single DNS labels."""
    assert ip_to_label(ip_address(address)) == label
    assert (
        host_name(ip_address(address), "abc", "ha.example") == f"{label}.abc.ha.example"
    )


def test_instance_id_is_key_thumbprint() -> None:
    """Test the instance ID is 32 base32 characters of the RFC 7638 thumbprint."""
    assert len(INSTANCE) == 32
    assert set(INSTANCE) <= set("abcdefghijklmnopqrstuvwxyz234567")
    # The same key gives the same ID, another key another one
    other = serialization.load_pem_private_key(
        generate_account_key().encode(), password=None
    )
    assert instance_id(jose.JWKRSA(key=jose.ComparableRSAKey(other))) != INSTANCE


def test_sign_challenge_request() -> None:
    """Test the challenge request is a JWS over the zone, value and time."""
    key = jose.JWKRSA(
        key=jose.ComparableRSAKey(
            serialization.load_pem_private_key(ACCOUNT_KEY.encode(), password=None)
        )
    )
    jws = jose.JWS.json_loads(sign_challenge_request(key, "ha.example", "x" * 43))
    assert jws.verify(key.public_key())
    assert jws.signature.combined.alg == jose.RS256
    assert jws.signature.combined.jwk == key.public_key()
    payload = json.loads(jws.payload)
    assert payload["zone"] == "ha.example"
    assert payload["txt"] == "x" * 43
    assert isinstance(payload["iat"], int)


def _pending_order(registration: dict[str, Any] | None = None) -> _PendingOrder:
    challenge = Mock()
    challenge.request = sign_challenge_request(
        jose.JWKRSA(
            key=jose.ComparableRSAKey(
                serialization.load_pem_private_key(ACCOUNT_KEY.encode(), password=None)
            )
        ),
        "ha.example",
        "v" * 43,
    )
    return _PendingOrder(
        acme_client=Mock(),
        order=Mock(),
        key_pem=b"KEY",
        name=NAME,
        challenges=[challenge],
        registration=registration
        or {"directory_url": SETTINGS["directory_url"], "registration": {"uri": "u"}},
    )


@pytest.fixture
def acme_flow(aioclient_mock: AiohttpClientMocker) -> dict[str, Mock]:
    """Mock the blocking ACME steps and the zone's challenge API."""
    aioclient_mock.post("https://api.ha.example/challenge", json={"instance": INSTANCE})
    with (
        patch(
            "homeassistant.components.http.public_certificate.generate_account_key",
            return_value=ACCOUNT_KEY,
        ),
        patch(
            "homeassistant.components.http.public_certificate._start_order",
            return_value=_pending_order(),
        ) as start,
        patch(
            "homeassistant.components.http.public_certificate._finish_order",
            return_value=_public_certificate(),
        ) as finish,
    ):
        yield {"start": start, "finish": finish}


async def test_enable_issues_and_stores(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    aioclient_mock: AiohttpClientMocker,
    acme_flow: dict[str, Mock],
) -> None:
    """Test opting in orders a certificate, publishing the challenge at the zone."""
    manager = await async_get_public_certificate_manager(hass)
    assert manager.certificate is None
    assert manager.instance_id is None

    await manager.async_enable(SETTINGS)

    assert manager.enabled
    assert manager.instance_id == INSTANCE
    assert manager.certificate["name"] == NAME
    assert manager.url("192.168.1.5") == f"https://192-168-1-5.{INSTANCE}.ha.example"
    assert manager.url("not an ip") is None
    assert (await manager.async_info())["subject_alt_names"] == [NAME]
    acme_flow["start"].assert_called_once_with(ACCOUNT_KEY, None, SETTINGS)
    assert aioclient_mock.call_count == 1
    request = aioclient_mock.mock_calls[0]
    assert request[3]["Content-Type"] == "application/jose+json"
    assert json.loads(request[2])["protected"]
    data = hass_storage[STORAGE_KEY]["data"]
    assert data["enabled"] is True
    assert data["account_key"] == ACCOUNT_KEY
    assert data["registration"] == {
        "directory_url": SETTINGS["directory_url"],
        "registration": {"uri": "u"},
    }
    assert data["certificate"]["name"] == NAME

    # Keys and the certificate are kept with the owner-only store mode
    assert hass_storage[STORAGE_KEY]  # private store; mode is applied on disk

    await manager.async_disable()
    assert manager.certificate is None
    # The identity survives opting out, so the name stays the same
    assert manager.instance_id == INSTANCE
    assert hass_storage[STORAGE_KEY]["data"]["certificate"] is None


async def test_enable_zone_refuses_challenge(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    acme_flow: dict[str, Mock],
) -> None:
    """Test a refused challenge fails the issuance and is kept as the last error."""
    aioclient_mock.clear_requests()
    aioclient_mock.post(
        "https://api.ha.example/challenge", status=400, json={"error": "stale"}
    )
    manager = await async_get_public_certificate_manager(hass)

    with pytest.raises(HomeAssistantError, match="refused to publish"):
        await manager.async_enable(SETTINGS)

    assert manager.enabled
    assert manager.certificate is None
    assert "refused to publish" in manager.last_error
    acme_flow["finish"].assert_not_called()


async def test_start_order_wraps_ca_errors() -> None:
    """Test an unreachable CA surfaces as a HomeAssistantError."""
    with (
        patch(
            "homeassistant.components.http.public_certificate.client.ClientV2.get_directory",
            side_effect=OSError("down"),
        ),
        pytest.raises(HomeAssistantError, match="not usable"),
    ):
        _start_order(ACCOUNT_KEY, None, SETTINGS)


def test_start_order_registers_and_orders() -> None:
    """Test the order is for the wildcard name and the DNS challenge is prepared."""
    challenge = messages.ChallengeBody(
        chall=challenges.DNS01(token=b"token"),
        status=messages.STATUS_PENDING,
    )
    authorization = Mock()
    authorization.body.status = messages.STATUS_PENDING
    authorization.body.challenges = [challenge]
    order = Mock(authorizations=[authorization])
    account = Mock(uri="https://acme.example/acct/1")
    account.to_json.return_value = {"uri": account.uri}
    with (
        patch(
            "homeassistant.components.http.public_certificate.client.ClientV2.get_directory"
        ),
        patch(
            "homeassistant.components.http.public_certificate.client.ClientV2.new_account",
            return_value=account,
        ) as new_account,
        patch(
            "homeassistant.components.http.public_certificate.client.ClientV2.new_order",
            return_value=order,
        ) as new_order,
    ):
        pending = _start_order(ACCOUNT_KEY, None, SETTINGS)

    new_account.assert_called_once()
    assert pending.registration == {
        "directory_url": SETTINGS["directory_url"],
        "registration": {"uri": account.uri},
    }
    csr = x509.load_pem_x509_csr(new_order.call_args.args[0])
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == [NAME]
    assert pending.name == NAME
    assert len(pending.challenges) == 1
    payload = json.loads(jose.JWS.json_loads(pending.challenges[0].request).payload)
    assert payload["zone"] == "ha.example"
    assert len(payload["txt"]) == 43


async def test_check_renews_when_due(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    freezer: FrozenDateTimeFactory,
    acme_flow: dict[str, Mock],
) -> None:
    """Test the daily check renews once a third of the lifetime is left."""
    hass_storage[STORAGE_KEY] = {
        "version": 1,
        "key": STORAGE_KEY,
        "data": {
            "enabled": True,
            "settings": SETTINGS,
            "account_key": ACCOUNT_KEY,
            "registration": None,
            "certificate": _public_certificate(dt.timedelta(days=60)),
        },
    }
    manager = await async_get_public_certificate_manager(hass)
    current = manager.certificate["certificate"]
    manager.async_start()
    hass.bus.async_fire("homeassistant_started")
    await hass.async_block_till_done()
    # Fresh: nothing to do
    acme_flow["finish"].assert_not_called()

    freezer.tick(dt.timedelta(days=39))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    acme_flow["finish"].assert_not_called()

    freezer.tick(dt.timedelta(days=2))
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    acme_flow["finish"].assert_called_once()
    assert manager.certificate["certificate"] != current

    manager.async_stop()
    freezer.tick(CHECK_INTERVAL)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()
    acme_flow["finish"].assert_called_once()


async def test_check_backs_off_after_failure(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    freezer: FrozenDateTimeFactory,
    acme_flow: dict[str, Mock],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test a failed issuance is not retried before the delay, and the opt-in stays."""
    hass_storage[STORAGE_KEY] = {
        "version": 1,
        "key": STORAGE_KEY,
        "data": {
            "enabled": True,
            "settings": SETTINGS,
            "account_key": ACCOUNT_KEY,
            "registration": None,
            "certificate": None,
        },
    }
    acme_flow["finish"].side_effect = HomeAssistantError("not issued")
    manager = await async_get_public_certificate_manager(hass)

    await manager.async_check()
    assert "Could not get a public certificate: not issued" in caplog.text
    assert manager.last_error == "not issued"
    assert acme_flow["finish"].call_count == 1

    freezer.tick(RETRY_DELAY - dt.timedelta(minutes=1))
    await manager.async_check()
    assert acme_flow["finish"].call_count == 1

    acme_flow["finish"].side_effect = None
    freezer.tick(dt.timedelta(minutes=2))
    await manager.async_check()
    assert acme_flow["finish"].call_count == 2
    assert manager.last_error is None
    assert manager.certificate is not None


def _addrinfo(*addresses: str) -> list[tuple[Any, ...]]:
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
        for address in addresses
    ]


@pytest.mark.parametrize(
    ("answers", "expected"),
    [
        pytest.param({"instance": _addrinfo("192.168.1.5")}, "ok", id="resolves"),
        pytest.param(
            {"instance": OSError("nx"), "api.ha.example": _addrinfo("203.0.113.1")},
            "filtered",
            id="filtered",
        ),
        pytest.param(
            {
                "instance": _addrinfo("203.0.113.9"),
                "api.ha.example": _addrinfo("1.2.3.4"),
            },
            "filtered",
            id="other_answer",
        ),
        pytest.param(
            {"instance": OSError("nx"), "api.ha.example": OSError("nx")},
            "unknown",
            id="offline",
        ),
    ],
)
async def test_probe(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    answers: dict[str, Any],
    expected: str,
) -> None:
    """Test the rebinding probe compares the resolver's answer with the control."""
    hass_storage[STORAGE_KEY] = {
        "version": 1,
        "key": STORAGE_KEY,
        "data": {
            "enabled": True,
            "settings": SETTINGS,
            "account_key": ACCOUNT_KEY,
            "registration": None,
            "certificate": None,
        },
    }
    manager = await async_get_public_certificate_manager(hass)
    probe_name = f"192-168-1-5.{INSTANCE}.ha.example"

    async def getaddrinfo(name: str, *args: Any, **kwargs: Any) -> list[Any]:
        answer = answers["instance" if name == probe_name else name]
        if isinstance(answer, Exception):
            raise answer
        return answer

    with patch.object(hass.loop, "getaddrinfo", side_effect=getaddrinfo):
        assert await manager.async_probe("192.168.1.5") == expected


async def test_probe_without_identity(hass: HomeAssistant) -> None:
    """Test the probe cannot run before an account key exists."""
    manager = await async_get_public_certificate_manager(hass)
    assert await manager.async_probe("192.168.1.5") == "unknown"


async def test_websocket_enable_status_disable(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    acme_flow: dict[str, Mock],
) -> None:
    """Test the websocket commands opt in, report and opt out."""
    assert await async_setup_component(hass, DOMAIN, {})
    await async_setup_component(hass, "websocket_api", {})
    await hass.async_start()
    await hass.async_block_till_done()
    ws_client = await hass_ws_client(hass)

    await ws_client.send_json_auto_id({"type": "http/public_certificate/status"})
    response = await ws_client.receive_json()
    assert response["success"]
    assert response["result"]["enabled"] is False
    assert response["result"]["settings"] == default_settings()
    assert response["result"]["certificate"] is None

    with patch.object(
        hass.loop, "getaddrinfo", AsyncMock(return_value=_addrinfo("203.0.113.1"))
    ):
        await _enable_and_disable(ws_client)


async def _enable_and_disable(ws_client: Any) -> None:
    await ws_client.send_json_auto_id(
        {
            "type": "http/public_certificate/enable",
            "zone": "ha.example",
            "directory_url": SETTINGS["directory_url"],
        }
    )
    response = await ws_client.receive_json()
    assert response["success"]
    result = response["result"]
    assert result["enabled"] is True
    assert result["settings"] == SETTINGS
    assert result["instance_id"] == INSTANCE
    assert result["certificate"]["subject_alt_names"] == [NAME]
    assert result["url"].startswith("https://") and result["url"].endswith(
        f".{INSTANCE}.ha.example"
    )
    assert result["probe"] == "filtered"
    assert result["last_error"] is None

    await ws_client.send_json_auto_id({"type": "http/config"})
    response = await ws_client.receive_json()
    assert response["result"]["certificates"]["public"]["subject_alt_names"] == [NAME]

    await ws_client.send_json_auto_id({"type": "http/public_certificate/disable"})
    response = await ws_client.receive_json()
    assert response["success"]

    await ws_client.send_json_auto_id({"type": "http/public_certificate/status"})
    response = await ws_client.receive_json()
    assert response["result"]["enabled"] is False
    assert response["result"]["certificate"] is None


async def test_websocket_enable_failure(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    acme_flow: dict[str, Mock],
) -> None:
    """Test a failed issuance is reported with its reason."""
    acme_flow["finish"].side_effect = HomeAssistantError("not issued")
    assert await async_setup_component(hass, DOMAIN, {})
    await async_setup_component(hass, "websocket_api", {})
    await hass.async_start()
    await hass.async_block_till_done()
    ws_client = await hass_ws_client(hass)

    await ws_client.send_json_auto_id(
        {"type": "http/public_certificate/enable", "zone": "ha.example"}
    )
    response = await ws_client.receive_json()
    assert not response["success"]
    assert response["error"] == {"code": "issue_failed", "message": "not issued"}
