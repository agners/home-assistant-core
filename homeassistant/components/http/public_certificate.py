"""A publicly trusted certificate for a name under a shared zone.

The instance gets a wildcard certificate for ``*.<instance-id>.<zone>`` from
an ACME CA with a DNS-01 challenge. The zone's challenge API publishes the
TXT record on a request signed with the ACME account key, and its DNS
answers ``<ip-label>.<instance-id>.<zone>`` with the encoded address. The
instance ID is derived from the account key, so nothing is registered and
the private keys never leave the instance.
"""

import asyncio
import base64
from dataclasses import dataclass
import datetime as dt
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import logging
import socket
import time
from typing import TYPE_CHECKING, Any, Final, TypedDict

from acme import challenges, client, crypto_util, errors, messages
import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import josepy as jose
import requests
from yarl import URL

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util
from homeassistant.util.hass_dict import HassKey

from .certificates import CertificateInfo, CertificatePair, certificate_info
from .const import DOMAIN

if TYPE_CHECKING:
    from .server import HomeAssistantHTTP

_LOGGER = logging.getLogger(__name__)

STORAGE_KEY: Final = f"{DOMAIN}.public_certificate"
STORAGE_VERSION: Final = 1

# The test zone of the prototype; a vendor would run its own
DEFAULT_ZONE: Final = "ha.printk.io"
LETSENCRYPT_STAGING: Final = "https://acme-staging-v02.api.letsencrypt.org/directory"
LETSENCRYPT_PRODUCTION: Final = "https://acme-v02.api.letsencrypt.org/directory"
# Staging by default: production shares a weekly budget across the zone
DEFAULT_DIRECTORY_URL: Final = LETSENCRYPT_STAGING
USER_AGENT: Final = "HomeAssistant"

# Renew once this share of the lifetime is left; daily checks are enough
RENEW_FRACTION: Final = 1 / 3
CHECK_INTERVAL: Final = dt.timedelta(days=1)
# Back off after a failed issuance, the CA rate limits are weekly
RETRY_DELAY: Final = dt.timedelta(hours=6)
# How long the CA may take to validate and issue
ORDER_TIMEOUT: Final = dt.timedelta(minutes=3)
CHALLENGE_TIMEOUT: Final = aiohttp.ClientTimeout(total=30)

ID_BYTES: Final = 20

DATA_PUBLIC_CERTIFICATE: HassKey[PublicCertificateManager] = HassKey(STORAGE_KEY)


class ProbeResult(StrEnum):
    """Whether the local resolver returns the instance's address for its name."""

    # The name resolves to the encoded address on this network
    OK = "ok"
    # The resolver drops private answers (DNS rebinding protection)
    FILTERED = "filtered"
    # No internet, the service is down, or the test could not run
    UNKNOWN = "unknown"


class PublicCertificateSettings(TypedDict):
    """Where the zone and the CA are."""

    zone: str
    api_url: str
    directory_url: str


class PublicCertificate(CertificatePair):
    """The certificate pair and the name it is issued for."""

    name: str


class _Registration(TypedDict):
    directory_url: str
    registration: dict[str, Any]


class _StoreData(TypedDict):
    enabled: bool
    settings: PublicCertificateSettings | None
    account_key: str | None
    registration: _Registration | None
    certificate: PublicCertificate | None


@dataclass(slots=True)
class _Challenge:
    body: messages.ChallengeBody
    response: challenges.ChallengeResponse
    # The signed request that asks the zone to publish the TXT value
    request: str


@dataclass(slots=True)
class _PendingOrder:
    acme_client: client.ClientV2
    order: messages.OrderResource
    key_pem: bytes
    name: str
    challenges: list[_Challenge]
    registration: _Registration


def default_settings() -> PublicCertificateSettings:
    """Return the settings for the default zone."""
    return PublicCertificateSettings(
        zone=DEFAULT_ZONE,
        api_url=f"https://api.{DEFAULT_ZONE}",
        directory_url=DEFAULT_DIRECTORY_URL,
    )


def instance_id(jwk: jose.JWK) -> str:
    """Return the instance ID of an ACME account key.

    The RFC 7638 SHA-256 thumbprint of the public key, cut to 160 bits and
    base32 encoded: a 32 character DNS label.
    """
    digest = jwk.public_key().thumbprint()
    return base64.b32encode(digest[:ID_BYTES]).decode().lower()


def ip_to_label(ip: IPv4Address | IPv6Address) -> str:
    """Encode an address as a DNS label."""
    if ip.version == 4:
        return str(ip).replace(".", "-")
    label = ip.compressed.replace(":", "-")
    # A label must not start or end with a hyphen
    if label.startswith("-"):
        label = f"0{label}"
    if label.endswith("-"):
        label = f"{label}0"
    return label


def wildcard_name(instance: str, zone: str) -> str:
    """Return the name the certificate is issued for."""
    return f"*.{instance}.{zone}"


def host_name(ip: IPv4Address | IPv6Address, instance: str, zone: str) -> str:
    """Return the name under which the instance is reached at ``ip``."""
    return f"{ip_to_label(ip)}.{instance}.{zone}"


def _account_jwk(key_pem: str) -> jose.JWKRSA:
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    if TYPE_CHECKING:
        assert isinstance(key, rsa.RSAPrivateKey)
    return jose.JWKRSA(key=jose.ComparableRSAKey(key))


def generate_account_key() -> str:
    """Create an ACME account key. Blocking, run in executor."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def sign_challenge_request(account_key: jose.JWK, zone: str, txt_value: str) -> str:
    """Return the signed request that asks the zone to publish a TXT value."""
    payload = json.dumps({"zone": zone, "txt": txt_value, "iat": int(time.time())})
    return jose.JWS.sign(
        payload.encode(),
        key=account_key,
        alg=jose.RS256,
        protect=frozenset({"alg", "jwk"}),
    ).json_dumps()


def _start_order(
    account_key_pem: str,
    registration: _Registration | None,
    settings: PublicCertificateSettings,
) -> _PendingOrder:
    """Register the account if needed and order the certificate.

    Blocking, run in executor. Returns the order with its challenges ready to
    be published. Raises ``HomeAssistantError`` when the CA cannot be used.
    """
    account_key = _account_jwk(account_key_pem)
    directory_url = settings["directory_url"]
    account = None
    if registration is not None and registration["directory_url"] == directory_url:
        account = messages.RegistrationResource.from_json(registration["registration"])
    network = client.ClientNetwork(account_key, account=account, user_agent=USER_AGENT)
    try:
        directory = client.ClientV2.get_directory(directory_url, network)
        acme_client = client.ClientV2(directory=directory, net=network)
        if account is None:
            try:
                account = acme_client.new_account(
                    messages.NewRegistration.from_data(terms_of_service_agreed=True)
                )
            except errors.ConflictError as err:
                account = messages.RegistrationResource(
                    uri=err.location, body=messages.Registration()
                )
                network.account = account
            registration = _Registration(
                directory_url=directory_url, registration=account.to_json()
            )
            _LOGGER.info("Registered the ACME account %s", account.uri)

        # Only the signing request leaves the instance, the key stays here
        key_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        name = wildcard_name(instance_id(account_key), settings["zone"])
        order = acme_client.new_order(crypto_util.make_csr(key_pem, [name]))
    except (errors.Error, requests.RequestException, OSError) as err:
        raise HomeAssistantError(
            f"The certificate authority is not usable: {err}"
        ) from err

    pending: list[_Challenge] = []
    for authorization in order.authorizations:
        if authorization.body.status == messages.STATUS_VALID:
            continue
        body = next(
            (
                challenge
                for challenge in authorization.body.challenges
                if isinstance(challenge.chall, challenges.DNS01)
            ),
            None,
        )
        if body is None:
            raise HomeAssistantError(
                "The certificate authority offers no DNS challenge"
            )
        response, txt_value = body.response_and_validation(account_key)
        pending.append(
            _Challenge(
                body=body,
                response=response,
                request=sign_challenge_request(
                    account_key, settings["zone"], txt_value
                ),
            )
        )
    if TYPE_CHECKING:
        assert registration is not None
    return _PendingOrder(acme_client, order, key_pem, name, pending, registration)


def _finish_order(pending: _PendingOrder) -> PublicCertificate:
    """Answer the challenges and wait for the certificate.

    Blocking, run in executor. Raises ``HomeAssistantError`` when the CA does
    not issue in time.
    """
    try:
        for challenge in pending.challenges:
            pending.acme_client.answer_challenge(challenge.body, challenge.response)
        order = pending.acme_client.poll_and_finalize(
            pending.order, deadline=dt_util.naive_now() + ORDER_TIMEOUT
        )
    except (errors.Error, requests.RequestException, OSError) as err:
        raise HomeAssistantError(f"The certificate was not issued: {err}") from err
    return PublicCertificate(
        certificate=order.fullchain_pem, key=pending.key_pem.decode(), name=pending.name
    )


def _renewal_due(certificate: str) -> bool:
    """Return whether less than ``RENEW_FRACTION`` of the lifetime is left."""
    cert = x509.load_pem_x509_certificates(certificate.encode())[0]
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    remaining = cert.not_valid_after_utc - dt_util.utcnow()
    return remaining < lifetime * RENEW_FRACTION


class PublicCertificateManager:
    """Keep a certificate from the zone's CA issued and renewed."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the manager."""
        self._hass = hass
        self._store = Store[_StoreData](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data = _StoreData(
            enabled=False,
            settings=None,
            account_key=None,
            registration=None,
            certificate=None,
        )
        self._loaded = False
        self._lock = asyncio.Lock()
        self._unsub: list[CALLBACK_TYPE] = []
        self._next_attempt: dt.datetime | None = None
        self.last_error: str | None = None

    async def async_load(self) -> None:
        """Load the state from disk."""
        if self._loaded:
            return
        async with self._lock:
            if self._loaded:
                return  # type: ignore[unreachable]
            if (data := await self._store.async_load()) is not None:
                self._data = data
            self._loaded = True

    @property
    def enabled(self) -> bool:
        """Return whether the instance keeps a public certificate."""
        return self._data["enabled"]

    @property
    def settings(self) -> PublicCertificateSettings:
        """Return the zone settings in use."""
        return self._data["settings"] or default_settings()

    @property
    def certificate(self) -> PublicCertificate | None:
        """Return the certificate to serve, if there is one."""
        if not self._data["enabled"]:
            return None
        return self._data["certificate"]

    @property
    def instance_id(self) -> str | None:
        """Return the instance ID, once an account key exists."""
        if (key_pem := self._data["account_key"]) is None:
            return None
        return instance_id(_account_jwk(key_pem))

    def url(self, address: str) -> str | None:
        """Return the HTTPS URL of the instance at ``address``, once it has a name."""
        if (instance := self.instance_id) is None:
            return None
        try:
            ip = ip_address(address)
        except ValueError:
            return None
        return f"https://{host_name(ip, instance, self.settings['zone'])}"

    async def async_info(self) -> CertificateInfo | None:
        """Return details of the certificate, if there is one."""
        if (certificate := self._data["certificate"]) is None:
            return None
        return await self._hass.async_add_executor_job(
            lambda: certificate_info(
                x509.load_pem_x509_certificates(certificate["certificate"].encode())[0]
            )
        )

    async def async_enable(self, settings: PublicCertificateSettings) -> None:
        """Opt in and get a certificate.

        Raises ``HomeAssistantError`` when the certificate cannot be issued;
        the opt-in is kept and the daily check tries again.
        """
        if (
            self._data["settings"] is not None
            and self._data["settings"]["zone"] != settings["zone"]
        ):
            # A certificate for another zone is of no use
            self._data["certificate"] = None
        self._data["enabled"] = True
        self._data["settings"] = settings
        await self._store.async_save(self._data)
        await self.async_issue()

    async def async_disable(self) -> None:
        """Opt out, forgetting the certificate but keeping the identity."""
        self._data["enabled"] = False
        self._data["certificate"] = None
        self.last_error = None
        await self._store.async_save(self._data)
        await self._async_apply()

    async def async_issue(self) -> None:
        """Get a new certificate and put it into use.

        Raises ``HomeAssistantError`` when the zone or the CA cannot be used.
        """
        async with self._lock:
            try:
                await self._async_issue()
            except HomeAssistantError as err:
                self.last_error = str(err)
                self._next_attempt = dt_util.utcnow() + RETRY_DELAY
                raise
            self.last_error = None
            self._next_attempt = None
        await self._async_apply()

    async def _async_issue(self) -> None:
        settings = self.settings
        if (account_key := self._data["account_key"]) is None:
            account_key = await self._hass.async_add_executor_job(generate_account_key)
            self._data["account_key"] = account_key
            await self._store.async_save(self._data)
        pending = await self._hass.async_add_executor_job(
            _start_order, account_key, self._data["registration"], settings
        )
        if pending.registration != self._data["registration"]:
            self._data["registration"] = pending.registration
            await self._store.async_save(self._data)
        # Deferred: the helper imports zeroconf, which imports back into http
        from homeassistant.helpers.aiohttp_client import async_get_clientsession  # noqa: PLC0415

        session = async_get_clientsession(self._hass)
        for challenge in pending.challenges:
            try:
                async with session.post(
                    f"{settings['api_url'].rstrip('/')}/challenge",
                    data=challenge.request,
                    headers={"Content-Type": "application/jose+json"},
                    timeout=CHALLENGE_TIMEOUT,
                ) as response:
                    if response.status != 200:
                        raise HomeAssistantError(
                            f"The zone refused to publish the challenge"
                            f" ({response.status}): {await response.text()}"
                        )
            except (OSError, TimeoutError) as err:
                raise HomeAssistantError(f"The zone is not reachable: {err}") from err
        certificate = await self._hass.async_add_executor_job(_finish_order, pending)
        self._data["certificate"] = certificate
        await self._store.async_save(self._data)
        _LOGGER.info("Got a certificate for %s", certificate["name"])

    async def _async_apply(self) -> None:
        """Hand the current certificate to the running server."""
        http: HomeAssistantHTTP | None = getattr(self._hass, "http", None)
        if http is None:
            return
        try:
            applied = await http.async_apply_public_certificate(self.certificate)
        except HomeAssistantError as err:
            _LOGGER.warning("The public certificate is not in use yet: %s", err)
            return
        if not applied:
            _LOGGER.info("The public certificate takes effect after a restart")

    async def async_check(self, *_: Any) -> None:
        """Issue or renew when due, backing off after a failure."""
        if not self._data["enabled"]:
            return
        if self._next_attempt is not None and dt_util.utcnow() < self._next_attempt:
            return
        if (certificate := self._data["certificate"]) is not None and not (
            await self._hass.async_add_executor_job(
                _renewal_due, certificate["certificate"]
            )
        ):
            return
        try:
            await self.async_issue()
        except HomeAssistantError as err:
            _LOGGER.warning("Could not get a public certificate: %s", err)

    @callback
    def async_start(self) -> None:
        """Check the certificate once started and then daily."""

        @callback
        def _started(hass: HomeAssistant) -> None:
            hass.async_create_background_task(
                self.async_check(), "http public certificate check"
            )

        self._unsub.append(async_at_started(self._hass, _started))
        self._unsub.append(
            async_track_time_interval(self._hass, self.async_check, CHECK_INTERVAL)
        )

    @callback
    def async_stop(self) -> None:
        """Stop the periodic checks."""
        for unsub in self._unsub:
            unsub()
        self._unsub.clear()

    async def async_probe(self, address: str) -> ProbeResult:
        """Check whether the local resolver returns ``address`` for its name.

        Routers with DNS rebinding protection drop public names that point to
        private addresses; the name is of no use on such a network.
        """
        if (instance := self.instance_id) is None:
            return ProbeResult.UNKNOWN
        try:
            ip = ip_address(address)
        except ValueError:
            return ProbeResult.UNKNOWN
        if await self._async_resolves_to(
            host_name(ip, instance, self.settings["zone"]), ip
        ):
            return ProbeResult.OK
        # The API name has public records and is never filtered
        control = URL(self.settings["api_url"]).host
        if control and await self._async_resolves_to(control, None):
            return ProbeResult.FILTERED
        return ProbeResult.UNKNOWN

    async def _async_resolves_to(
        self, name: str, ip: IPv4Address | IPv6Address | None
    ) -> bool:
        """Return whether ``name`` resolves, to ``ip`` when given."""
        family = socket.AF_UNSPEC
        if ip is not None:
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        try:
            infos = await self._hass.loop.getaddrinfo(
                name, None, family=family, type=socket.SOCK_STREAM
            )
        except OSError:
            return False
        if ip is None:
            return bool(infos)
        return any(ip_address(info[4][0]) == ip for info in infos)


async def async_get_public_certificate_manager(
    hass: HomeAssistant,
) -> PublicCertificateManager:
    """Return the loaded singleton manager."""
    if (manager := hass.data.get(DATA_PUBLIC_CERTIFICATE)) is None:
        manager = PublicCertificateManager(hass)
        hass.data[DATA_PUBLIC_CERTIFICATE] = manager
    await manager.async_load()
    return manager
