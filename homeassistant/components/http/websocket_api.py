"""WebSocket API for the HTTP integration user config."""

from typing import Any, Final

import probatio
from yarl import URL

from homeassistant.components import websocket_api
from homeassistant.components.homeassistant import (
    DOMAIN as HASS_DOMAIN,
    SERVICE_HOMEASSISTANT_RESTART,
)
from homeassistant.core import CoreState, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .certificates import DEFAULT_SUBJECT, CertificateStore, async_get_certificate_store
from .config import HTTP_STORAGE_SCHEMA, ConfData, async_get_and_load_store
from .const import (
    ATTR_CONFIG,
    CONF_CERTIFICATE,
    CONF_HTTPS_PORT,
    CONF_SERVER_HOST,
    CONF_SERVER_PORT,
    CONF_SSL_CERTIFICATE,
    CONF_TRUSTED_PROXIES,
    CONF_USE_X_FORWARDED_FOR,
    CertificateSource,
)
from .server import DEFAULT_BIND, async_verify_can_bind, async_verify_hosts_distinct

ERR_BIND_FAILED: Final = "bind_failed"
ERR_NOT_RUNNING: Final = "not_running"
ERR_INVALID_CERTIFICATE: Final = "invalid_certificate"
ERR_CERTIFICATE_IN_USE: Final = "certificate_in_use"

ATTR_CERTIFICATE: Final = "certificate"
ATTR_KEY: Final = "key"
ATTR_SOURCE: Final = "source"
ATTR_SUBJECTS: Final = "subjects"


def _validate_trusted_proxies(config: ConfData) -> ConfData:
    """Reject trusting X-Forwarded-For without a proxy to trust it from.

    Forwarded requests are refused when no proxy is trusted, so the combination
    breaks the very setup it is meant to enable.
    """
    if config.get(CONF_USE_X_FORWARDED_FOR) and not config.get(CONF_TRUSTED_PROXIES):
        raise probatio.Invalid(
            "at least one trusted proxy is required to use X-Forwarded-For",
            path=[CONF_TRUSTED_PROXIES],
        )

    return config


def _validate_https_port(config: ConfData) -> ConfData:
    """Reject an HTTPS port equal to the HTTP port."""
    if config[CONF_HTTPS_PORT] == config[CONF_SERVER_PORT]:
        raise probatio.Invalid(
            "the HTTPS port must differ from the server port", path=[CONF_HTTPS_PORT]
        )
    return config


def _certificate_available(store: CertificateStore, config: ConfData) -> str | None:
    """Return why the selected certificate source is unusable, if it is."""
    source = config.get(CONF_CERTIFICATE, CertificateSource.FILES)
    if source is CertificateSource.UPLOADED and store.uploaded is None:
        return "No certificate has been uploaded"
    if source is CertificateSource.FILES and config.get(CONF_SSL_CERTIFICATE) is None:
        # Nothing selected is plain HTTP, not an error
        return None
    return None


@callback
def async_register_websocket_commands(hass: HomeAssistant) -> None:
    """Register the HTTP config websocket commands."""
    websocket_api.async_register_command(hass, websocket_get_config)
    websocket_api.async_register_command(hass, websocket_set_config)
    websocket_api.async_register_command(hass, websocket_promote_config)
    websocket_api.async_register_command(hass, websocket_upload_certificate)
    websocket_api.async_register_command(hass, websocket_generate_certificate)
    websocket_api.async_register_command(hass, websocket_delete_certificate)
    websocket_api.async_register_command(hass, websocket_get_ca_certificate)


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "http/config"})
@websocket_api.async_response
async def websocket_get_config(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return the HTTP configuration.

    ``stable`` is the confirmed-working config
    ``pending`` is an unconfirmed config awaiting promotion, or ``None``.
    A pending config that failed its trial is kept with its ``error``
    (and ``error_message``) recorded, but is never applied again.
    ``revert_at`` is when an unconfirmed pending config auto-reverts to
    stable, or ``None`` when no revert is scheduled.
    ``active_config_type`` is the slot the running server was started with.
    ``default`` is the built-in default config.
    ``proxy`` tells whether the Supervisor proxy plugin is available and
    whether the server is currently serving through it.
    ``certificates`` describes the uploaded and generated certificates.
    """
    store = await async_get_and_load_store(hass)
    certificates = await async_get_certificate_store(hass)
    http = hass.http
    connection.send_result(
        msg["id"],
        {
            "stable": store.stable,
            "pending": store.pending,
            "revert_at": store.revert_deadline,
            "active_config_type": store.active_config_type,
            "default": store.default,
            "proxy": {
                "available": http.proxy is not None,
                "active": http.proxy_active,
            },
            "certificates": {
                "uploaded": await certificates.async_info(CertificateSource.UPLOADED),
                "generated": await certificates.async_info(CertificateSource.GENERATED),
            },
        },
    )


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "http/config/configure",
        probatio.Required(ATTR_CONFIG): probatio.Any(
            None,
            probatio.All(
                HTTP_STORAGE_SCHEMA, _validate_trusted_proxies, _validate_https_port
            ),
        ),
    }
)
@websocket_api.async_response
async def websocket_set_config(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Store a new pending HTTP configuration and restart to apply it.

    Only allowed while Home Assistant is running: applying a config means
    restarting, and restarting a start that has not finished yet leaves
    integrations that are still setting up in an undefined state.

    A new config is first verified to be applicable by binding its
    configured address, so an unusable config is rejected here instead of
    being discovered after the restart. The check is skipped when the port
    matches the currently bound one: the running server holds that port
    until the restart releases it, so a probe would always fail against
    ourselves.

    Restart whenever the pending slot changes, so the runtime config is
    refreshed. The result reports whether a restart was triggered via
    ``{"restart": bool}``.
    """
    if hass.state is not CoreState.running:
        connection.send_error(
            msg["id"],
            ERR_NOT_RUNNING,
            "The HTTP configuration can only be changed while Home Assistant "
            f"is running, current state: {hass.state.value}",
        )
        return

    config: ConfData | None = msg[ATTR_CONFIG]
    if config is not None:
        certificates = await async_get_certificate_store(hass)
        if (reason := _certificate_available(certificates, config)) is not None:
            connection.send_error(msg["id"], ERR_INVALID_CERTIFICATE, reason)
            return
        hosts = config.get(CONF_SERVER_HOST, DEFAULT_BIND)
        try:
            if hass.http.proxy_active:
                # The proxy holds the ports; it validates the listeners when
                # the config is pushed after the restart.
                await async_verify_hosts_distinct(hass, hosts)
            elif config[CONF_SERVER_PORT] != hass.http.server_port:
                await async_verify_can_bind(hass, config)
            elif hosts != hass.http.server_host:
                # The running server holds the port, so only the hosts can be
                # checked; a conflict on the port itself is caught when the
                # restarted server binds and falls back to the stable config.
                await async_verify_hosts_distinct(hass, hosts)
        except HomeAssistantError as err:
            connection.send_error(msg["id"], ERR_BIND_FAILED, str(err))
            return

    store = await async_get_and_load_store(hass)
    previous_pending = store.pending
    await store.async_set_pending(config)
    restart = store.pending != previous_pending
    connection.send_result(msg["id"], {"restart": restart})

    if restart:
        await hass.services.async_call(HASS_DOMAIN, SERVICE_HOMEASSISTANT_RESTART)


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "http/config/promote"})
@websocket_api.async_response
async def websocket_promote_config(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Promote the pending HTTP config to stable.

    Called by the user after they have verified Home Assistant is
    working correctly with the pending config. The stable config is
    the one used by recovery mode, so promotion must be explicit.
    """
    store = await async_get_and_load_store(hass)
    try:
        await store.async_promote_pending()
    except HomeAssistantError as err:
        connection.send_error(
            msg["id"],
            websocket_api.const.ERR_NOT_ALLOWED,
            str(err),
        )
        return

    connection.send_result(msg["id"])


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "http/certificate/upload",
        probatio.Required(ATTR_CERTIFICATE): str,
        probatio.Required(ATTR_KEY): str,
    }
)
@websocket_api.async_response
async def websocket_upload_certificate(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Store a PEM certificate chain and private key for the uploaded source.

    The pair is validated but only used once a config selecting the uploaded
    source is applied.
    """
    store = await async_get_certificate_store(hass)
    try:
        info = await store.async_set_uploaded(msg[ATTR_CERTIFICATE], msg[ATTR_KEY])
    except HomeAssistantError as err:
        connection.send_error(msg["id"], ERR_INVALID_CERTIFICATE, str(err))
        return
    connection.send_result(msg["id"], info)


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "http/certificate/generate",
        probatio.Optional(ATTR_SUBJECTS): probatio.All([str], probatio.NonEmpty()),
    }
)
@websocket_api.async_response
async def websocket_generate_certificate(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Issue a server certificate from the local CA, creating the CA on first use."""
    store = await async_get_certificate_store(hass)
    subjects: list[str] = msg.get(ATTR_SUBJECTS) or _default_subjects(hass)
    try:
        info = await store.async_generate(subjects)
    except HomeAssistantError as err:
        connection.send_error(msg["id"], ERR_INVALID_CERTIFICATE, str(err))
        return
    connection.send_result(msg["id"], info)


def _default_subjects(hass: HomeAssistant) -> list[str]:
    """Return the names a generated certificate covers by default."""
    subjects = [DEFAULT_SUBJECT]
    if (api := hass.config.api) is not None and api.local_ip not in (
        "127.0.0.1",
        "::1",
    ):
        subjects.append(api.local_ip)
    if (
        hass.config.internal_url
        and (host := URL(hass.config.internal_url).host)
        and host not in subjects
    ):
        subjects.append(host)
    return subjects


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "http/certificate/delete",
        probatio.Required(ATTR_SOURCE): probatio.In(
            [CertificateSource.UPLOADED, CertificateSource.GENERATED]
        ),
    }
)
@websocket_api.async_response
async def websocket_delete_certificate(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Forget the uploaded certificate or the generated CA and certificate.

    Refused while a stored config selects the source, since the next start
    could not apply that config anymore.
    """
    source = CertificateSource(msg[ATTR_SOURCE])
    config_store = await async_get_and_load_store(hass)
    if any(
        config is not None and config.get(CONF_CERTIFICATE) is source
        for config in (config_store.stable, config_store.pending)
    ):
        connection.send_error(
            msg["id"],
            ERR_CERTIFICATE_IN_USE,
            f"The {source} certificate is selected by the HTTP configuration",
        )
        return
    store = await async_get_certificate_store(hass)
    await store.async_delete(source)
    connection.send_result(msg["id"])


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "http/certificate/ca"})
@websocket_api.async_response
async def websocket_get_ca_certificate(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return the local CA certificate in PEM form, to install on devices."""
    store = await async_get_certificate_store(hass)
    if (generated := store.generated) is None:
        connection.send_error(
            msg["id"],
            websocket_api.const.ERR_NOT_FOUND,
            "No certificate has been generated",
        )
        return
    connection.send_result(msg["id"], {ATTR_CERTIFICATE: generated["ca_certificate"]})
