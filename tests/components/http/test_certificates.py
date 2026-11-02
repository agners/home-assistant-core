"""Test the HTTP certificate store."""

import datetime as dt
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from freezegun.api import FrozenDateTimeFactory
import pytest

from homeassistant.components.http.certificates import (
    STORAGE_KEY,
    CertificateStore,
    async_get_certificate_store,
    generate_ca,
    issue_server_certificate,
    validate_certificate_pair,
)
from homeassistant.components.http.const import CertificateSource
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _self_signed(name: str) -> tuple[str, str]:
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
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
        .sign(key, hashes.SHA256())
    )
    return _pem(cert), _key_pem(key)


def test_validate_certificate_pair() -> None:
    """Test a matching pair validates and describes the certificate."""
    cert, key = _self_signed("example.local")
    info = validate_certificate_pair(cert, key)
    assert info["subject"] == "CN=example.local"
    assert info["subject_alt_names"] == ["example.local"]


@pytest.mark.parametrize(
    ("certificate", "key", "match"),
    [
        pytest.param("not a cert", "KEY", "Invalid certificate", id="bad_cert"),
        pytest.param(
            _self_signed("a")[0], "not a key", "Invalid private key", id="bad_key"
        ),
        pytest.param(
            _self_signed("a")[0], _self_signed("b")[1], "does not match", id="mismatch"
        ),
    ],
)
def test_validate_certificate_pair_invalid(
    certificate: str, key: str, match: str
) -> None:
    """Test invalid input is rejected."""
    with pytest.raises(HomeAssistantError, match=match):
        validate_certificate_pair(certificate, key)


def test_issue_server_certificate() -> None:
    """Test the local CA issues a server certificate with the requested names."""
    ca_cert, ca_key = generate_ca()
    cert, _ = issue_server_certificate(
        ca_cert, ca_key, ["homeassistant.local", "192.0.2.1"]
    )
    assert cert.issuer == ca_cert.subject
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["homeassistant.local"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["192.0.2.1"]
    ca_cert.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
    basic = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True


async def test_store_upload_and_delete(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an uploaded pair is persisted and can be removed."""
    store = await async_get_certificate_store(hass)
    cert, key = _self_signed("example.local")
    info = await store.async_set_uploaded(cert, key)
    assert info["subject"] == "CN=example.local"
    assert hass_storage[STORAGE_KEY]["data"]["uploaded"] == {
        "certificate": cert,
        "key": key,
    }
    assert (await store.async_info(CertificateSource.UPLOADED)) == info
    assert await store.async_info(CertificateSource.FILES) is None

    await store.async_delete(CertificateSource.UPLOADED)
    assert store.uploaded is None
    assert await store.async_info(CertificateSource.UPLOADED) is None


async def test_store_generate_keeps_ca(hass: HomeAssistant) -> None:
    """Test reissuing a certificate keeps the CA so trust is preserved."""
    store = await async_get_certificate_store(hass)
    first = await store.async_generate(["homeassistant.local"])
    assert first["subject_alt_names"] == ["homeassistant.local"]
    assert store.generated is not None
    ca = store.generated["ca_certificate"]

    second = await store.async_generate(["homeassistant.local", "192.0.2.1"])
    assert second["subject_alt_names"] == ["homeassistant.local", "192.0.2.1"]
    assert store.generated["ca_certificate"] == ca
    assert store.generated["subjects"] == ["homeassistant.local", "192.0.2.1"]


async def test_resolve_files(hass: HomeAssistant, tmp_path: Path) -> None:
    """Test the files source is read only on request."""
    store = await async_get_certificate_store(hass)
    cert, key = _self_signed("example.local")
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text(cert)
    key_path.write_text(key)
    conf: dict[str, Any] = {
        "ssl_certificate": str(cert_path),
        "ssl_key": str(key_path),
    }

    assert await store.async_resolve(conf, read_files=False) is None
    assert await store.async_resolve(conf, read_files=True) == {
        "certificate": cert,
        "key": key,
    }
    assert await store.async_resolve({}, read_files=True) is None

    cert_path.unlink()
    with pytest.raises(HomeAssistantError, match="Could not read SSL certificate"):
        await store.async_resolve(conf, read_files=True)


async def test_resolve_uploaded(hass: HomeAssistant) -> None:
    """Test the uploaded source needs an upload."""
    store = await async_get_certificate_store(hass)
    conf: dict[str, Any] = {"certificate": CertificateSource.UPLOADED}
    with pytest.raises(HomeAssistantError, match="No uploaded certificate"):
        await store.async_resolve(conf, read_files=False)

    cert, key = _self_signed("example.local")
    await store.async_set_uploaded(cert, key)
    assert await store.async_resolve(conf, read_files=False) == {
        "certificate": cert,
        "key": key,
    }


async def test_resolve_generated_issues_and_renews(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory
) -> None:
    """Test the generated source issues on first use and renews near expiry."""
    store = await async_get_certificate_store(hass)
    conf: dict[str, Any] = {"certificate": CertificateSource.GENERATED}

    pair = await store.async_resolve(conf, read_files=False)
    assert store.generated is not None
    assert pair == {
        "certificate": store.generated["certificate"],
        "key": store.generated["key"],
    }
    assert store.generated["subjects"] == ["homeassistant.local"]

    # Well before expiry the same certificate is kept
    freezer.tick(dt.timedelta(days=300))
    assert await store.async_resolve(conf, read_files=False) == pair

    # Close to expiry a new one is issued by the same CA
    ca = store.generated["ca_certificate"]
    freezer.tick(dt.timedelta(days=90))
    renewed = await store.async_resolve(conf, read_files=False)
    assert renewed != pair
    assert store.generated["ca_certificate"] == ca


async def test_store_singleton(hass: HomeAssistant) -> None:
    """Test the store is created once."""
    store = await async_get_certificate_store(hass)
    assert isinstance(store, CertificateStore)
    assert await async_get_certificate_store(hass) is store
