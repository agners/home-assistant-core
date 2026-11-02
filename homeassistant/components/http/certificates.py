"""Server certificates for HTTPS: uploaded or issued by a local CA."""

import asyncio
import datetime as dt
from ipaddress import ip_address
import logging
from typing import Final, TypedDict, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    PrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util
from homeassistant.util.hass_dict import HassKey

from .config import ConfData
from .const import (
    CONF_CERTIFICATE,
    CONF_SSL_CERTIFICATE,
    CONF_SSL_KEY,
    DOMAIN,
    CertificateSource,
)

_LOGGER = logging.getLogger(__name__)

STORAGE_KEY: Final = f"{DOMAIN}.certificates"
STORAGE_VERSION: Final = 1

CA_VALIDITY: Final = dt.timedelta(days=10 * 365)
# Apple refuses leaf certificates valid longer than 825 days
LEAF_VALIDITY: Final = dt.timedelta(days=398)
# Reissue the leaf on startup once it is this close to expiry
RENEW_BEFORE: Final = dt.timedelta(days=30)
DEFAULT_SUBJECT: Final = "homeassistant.local"

DATA_CERTIFICATE_STORE: HassKey[CertificateStore] = HassKey(STORAGE_KEY)


class CertificatePair(TypedDict):
    """A PEM certificate chain and its private key."""

    certificate: str
    key: str


class GeneratedCertificates(TypedDict):
    """The local CA and the server certificate it issued."""

    ca_certificate: str
    ca_key: str
    certificate: str
    key: str
    subjects: list[str]


class CertificateInfo(TypedDict):
    """Details of a certificate for display."""

    subject: str
    issuer: str
    not_valid_before: str
    not_valid_after: str
    subject_alt_names: list[str]


class _StoreData(TypedDict):
    uploaded: CertificatePair | None
    generated: GeneratedCertificates | None


def _load_pem_certificates(pem: str) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(pem.encode())
    except ValueError as err:
        raise HomeAssistantError(f"Invalid certificate: {err}") from err


def _load_pem_key(pem: str) -> PrivateKeyTypes:
    try:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as err:
        raise HomeAssistantError(f"Invalid private key: {err}") from err


def validate_certificate_pair(certificate: str, key: str) -> CertificateInfo:
    """Validate a PEM certificate chain and key belong together.

    Blocking, run in executor. Raises ``HomeAssistantError`` on invalid or
    mismatched input.
    """
    certs = _load_pem_certificates(certificate)
    private_key = _load_pem_key(key)
    leaf = certs[0]
    leaf_public = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if leaf_public != key_public:
        raise HomeAssistantError("The private key does not match the certificate")
    return certificate_info(leaf)


def certificate_info(cert: x509.Certificate) -> CertificateInfo:
    """Return display details of a certificate."""
    sans: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        pass
    else:
        sans.extend(san.value.get_values_for_type(x509.DNSName))
        sans.extend(str(ip) for ip in san.value.get_values_for_type(x509.IPAddress))
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_valid_before=cert.not_valid_before_utc.isoformat(),
        not_valid_after=cert.not_valid_after_utc.isoformat(),
        subject_alt_names=sans,
    )


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _subject_alt_names(subjects: list[str]) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = []
    for subject in subjects:
        try:
            names.append(x509.IPAddress(ip_address(subject)))
        except ValueError:
            names.append(x509.DNSName(subject))
    return x509.SubjectAlternativeName(names)


def generate_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Create a local certificate authority. Blocking, run in executor."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Home Assistant"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Home Assistant Local CA"),
        ]
    )
    now = dt_util.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def issue_server_certificate(
    ca_cert: x509.Certificate,
    ca_key: CertificateIssuerPrivateKeyTypes,
    subjects: list[str],
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Issue a server certificate from the local CA. Blocking, run in executor."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt_util.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subjects[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + LEAF_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_subject_alt_names(subjects), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


class CertificateStore:
    """Persist the uploaded and the generated certificates."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the store."""
        self._hass = hass
        self._store = Store[_StoreData](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data = _StoreData(uploaded=None, generated=None)
        self._loaded = False
        self._lock = asyncio.Lock()

    async def async_load(self) -> None:
        """Load the certificates from disk."""
        if self._loaded:
            return
        async with self._lock:
            if self._loaded:
                return  # type: ignore[unreachable]
            if (data := await self._store.async_load()) is not None:
                self._data = data
            self._loaded = True

    @property
    def uploaded(self) -> CertificatePair | None:
        """Return the uploaded certificate pair."""
        return self._data["uploaded"]

    @property
    def generated(self) -> GeneratedCertificates | None:
        """Return the generated CA and server certificate."""
        return self._data["generated"]

    def pair(self, source: CertificateSource) -> CertificatePair | None:
        """Return the stored certificate pair of ``source``, if any."""
        if source is CertificateSource.UPLOADED:
            return self._data["uploaded"]
        if (generated := self._data["generated"]) is None:
            return None
        return CertificatePair(
            certificate=generated["certificate"], key=generated["key"]
        )

    async def async_set_uploaded(self, certificate: str, key: str) -> CertificateInfo:
        """Validate and store an uploaded certificate pair."""
        info = await self._hass.async_add_executor_job(
            validate_certificate_pair, certificate, key
        )
        self._data["uploaded"] = CertificatePair(certificate=certificate, key=key)
        await self._store.async_save(self._data)
        return info

    async def async_delete(self, source: CertificateSource) -> None:
        """Forget the uploaded or the generated certificates."""
        if source is CertificateSource.UPLOADED:
            self._data["uploaded"] = None
        elif source is CertificateSource.GENERATED:
            self._data["generated"] = None
        await self._store.async_save(self._data)

    async def async_generate(self, subjects: list[str]) -> CertificateInfo:
        """Issue a server certificate for ``subjects`` from the local CA.

        The CA is created on first use and kept, so devices that trust it keep
        trusting reissued server certificates.
        """
        generated = await self._hass.async_add_executor_job(
            self._generate, self._data["generated"], subjects
        )
        self._data["generated"] = generated
        await self._store.async_save(self._data)
        return await self._hass.async_add_executor_job(
            self._info_of, generated["certificate"]
        )

    @staticmethod
    def _generate(
        current: GeneratedCertificates | None, subjects: list[str]
    ) -> GeneratedCertificates:
        ca_key: CertificateIssuerPrivateKeyTypes
        if current is None:
            ca_cert, ec_key = generate_ca()
            ca_key = ec_key
            ca_cert_pem, ca_key_pem = _pem(ca_cert), _key_pem(ec_key)
        else:
            ca_cert_pem, ca_key_pem = current["ca_certificate"], current["ca_key"]
            ca_cert = _load_pem_certificates(ca_cert_pem)[0]
            ca_key = cast(CertificateIssuerPrivateKeyTypes, _load_pem_key(ca_key_pem))
        cert, key = issue_server_certificate(ca_cert, ca_key, subjects)
        return GeneratedCertificates(
            ca_certificate=ca_cert_pem,
            ca_key=ca_key_pem,
            certificate=_pem(cert),
            key=_key_pem(key),
            subjects=subjects,
        )

    @staticmethod
    def _info_of(certificate: str) -> CertificateInfo:
        return certificate_info(_load_pem_certificates(certificate)[0])

    async def async_info(self, source: CertificateSource) -> CertificateInfo | None:
        """Return details of the stored certificate of ``source``, if any."""
        if source is CertificateSource.UPLOADED:
            pair = self._data["uploaded"]
        elif source is CertificateSource.GENERATED:
            pair = self._data["generated"]
        else:
            return None
        if pair is None:
            return None
        return await self._hass.async_add_executor_job(
            self._info_of, pair["certificate"]
        )

    def _needs_renewal(self) -> bool:
        if (generated := self._data["generated"]) is None:
            return True
        cert = _load_pem_certificates(generated["certificate"])[0]
        return cert.not_valid_after_utc - dt_util.utcnow() < RENEW_BEFORE

    async def async_resolve(
        self, conf: ConfData, *, read_files: bool
    ) -> CertificatePair | None:
        """Return the certificate pair the config selects, or None for plain HTTP.

        Certificate files are only read with ``read_files``; otherwise the
        server loads the paths itself, keeping its emergency certificate
        handling for unreadable files. A generated certificate is issued on
        first use and reissued when it is about to expire. Raises
        ``HomeAssistantError`` when the selected certificate is unusable.
        """
        source = conf.get(CONF_CERTIFICATE, CertificateSource.FILES)
        if source is CertificateSource.FILES:
            if (cert_path := conf.get(CONF_SSL_CERTIFICATE)) is None or not read_files:
                return None
            return await self._hass.async_add_executor_job(
                self._read_files, cert_path, conf.get(CONF_SSL_KEY)
            )
        if source is CertificateSource.UPLOADED:
            if (uploaded := self._data["uploaded"]) is None:
                raise HomeAssistantError("No uploaded certificate available")
            return uploaded
        if await self._hass.async_add_executor_job(self._needs_renewal):
            subjects = (
                generated["subjects"]
                if (generated := self._data["generated"]) is not None
                else [DEFAULT_SUBJECT]
            )
            _LOGGER.info("Issuing a server certificate for %s", subjects)
            await self.async_generate(subjects)
        generated = self._data["generated"]
        if generated is None:
            raise HomeAssistantError("No generated certificate available")
        return CertificatePair(
            certificate=generated["certificate"], key=generated["key"]
        )

    @staticmethod
    def _read_files(cert_path: str, key_path: str | None) -> CertificatePair:
        try:
            with open(cert_path, encoding="utf-8") as cert_file:
                certificate = cert_file.read()
            # A missing key path means the key is in the certificate file
            key = certificate
            if key_path is not None:
                with open(key_path, encoding="utf-8") as key_file:
                    key = key_file.read()
        except OSError as err:
            raise HomeAssistantError(
                f"Could not read SSL certificate from {cert_path}: {err}"
            ) from err
        return CertificatePair(certificate=certificate, key=key)


async def async_get_certificate_store(hass: HomeAssistant) -> CertificateStore:
    """Return the loaded singleton certificate store."""
    if (store := hass.data.get(DATA_CERTIFICATE_STORE)) is None:
        store = CertificateStore(hass)
        hass.data[DATA_CERTIFICATE_STORE] = store
    await store.async_load()
    return store
