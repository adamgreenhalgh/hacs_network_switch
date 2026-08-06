"""Network Switch integration for Home Assistant."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity_registry import async_get as async_get_entity_registry

from .const import (
    CONF_COMMUNITY,
    CONF_HOST,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_COMMUNITY,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SERVICE_CREATE_VLAN,
    SERVICE_DELETE_VLAN,
    SERVICE_DUMP_MAC_TABLE,
    SERVICE_SET_ACCESS_VLAN,
    SERVICE_SET_ADMIN_STATUS,
    SERVICE_SET_INTERFACE_MODE,
    SERVICE_SET_LABEL,
)
from .coordinator import NetworkSwitchCoordinator
from .snmp_client import CiscoSwitchSNMP, SNMPError

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor"]

# ---------------------------------------------------------------------------
# Service schemas
# ---------------------------------------------------------------------------

SET_ADMIN_STATUS_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("if_index"): vol.Coerce(int),
        vol.Required("enabled"): cv.boolean,
    }
)

SET_LABEL_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("if_index"): vol.Coerce(int),
        vol.Required("label"): str,
    }
)

SET_ACCESS_VLAN_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("if_index"): vol.Coerce(int),
        vol.Required("vlan_id"): vol.All(vol.Coerce(int), vol.Range(min=1, max=4094)),
    }
)

SET_INTERFACE_MODE_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("if_index"): vol.Coerce(int),
        vol.Required("mode"): vol.In(["access", "trunk"]),
    }
)

CREATE_VLAN_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("vlan_id"): vol.All(vol.Coerce(int), vol.Range(min=2, max=4094)),
        vol.Optional("name", default=""): str,
    }
)

DELETE_VLAN_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
        vol.Required("vlan_id"): vol.All(vol.Coerce(int), vol.Range(min=2, max=4094)),
    }
)

DUMP_MAC_TABLE_SCHEMA = vol.Schema(
    {
        vol.Required("entry_id"): str,
    }
)


# ---------------------------------------------------------------------------
# Setup / teardown
# ---------------------------------------------------------------------------


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Network Switch from a config entry."""
    host = entry.data[CONF_HOST]
    community = entry.data.get(CONF_COMMUNITY, DEFAULT_COMMUNITY)
    port = entry.data.get(CONF_PORT, DEFAULT_PORT)
    scan_interval = entry.options.get(
        CONF_SCAN_INTERVAL,
        entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
    )

    client = CiscoSwitchSNMP(host=host, community=community, port=port)
    coordinator = NetworkSwitchCoordinator(hass, client, scan_interval)

    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _register_services(hass)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------


def _get_coordinator(hass: HomeAssistant, entry_id: str) -> NetworkSwitchCoordinator:
    coordinator = hass.data.get(DOMAIN, {}).get(entry_id)
    if coordinator is None:
        raise ValueError(f"No network switch entry found for entry_id '{entry_id}'")
    return coordinator


def _register_services(hass: HomeAssistant) -> None:
    """Register integration services (idempotent – skips if already registered)."""
    def _async_register_service(
        service: str,
        handler: Any,
        schema: vol.Schema,
    ) -> None:
        if hass.services.has_service(DOMAIN, service):
            return
        hass.services.async_register(
            DOMAIN,
            service,
            handler,
            schema=schema,
        )

    async def handle_set_admin_status(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.set_interface_admin_status,
            call.data["if_index"],
            call.data["enabled"],
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_SET_ADMIN_STATUS,
        handle_set_admin_status,
        SET_ADMIN_STATUS_SCHEMA,
    )

    async def handle_set_label(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.set_interface_label,
            call.data["if_index"],
            call.data["label"],
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_SET_LABEL,
        handle_set_label,
        SET_LABEL_SCHEMA,
    )

    async def handle_set_access_vlan(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.set_interface_access_vlan,
            call.data["if_index"],
            call.data["vlan_id"],
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_SET_ACCESS_VLAN,
        handle_set_access_vlan,
        SET_ACCESS_VLAN_SCHEMA,
    )

    async def handle_set_interface_mode(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.set_interface_mode,
            call.data["if_index"],
            call.data["mode"],
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_SET_INTERFACE_MODE,
        handle_set_interface_mode,
        SET_INTERFACE_MODE_SCHEMA,
    )

    async def handle_create_vlan(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.create_vlan,
            call.data["vlan_id"],
            call.data["name"] or f"VLAN{call.data['vlan_id']}",
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_CREATE_VLAN,
        handle_create_vlan,
        CREATE_VLAN_SCHEMA,
    )

    async def handle_delete_vlan(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        await hass.async_add_executor_job(
            coordinator.client.delete_vlan,
            call.data["vlan_id"],
        )
        await coordinator.async_request_refresh()

    _async_register_service(
        SERVICE_DELETE_VLAN,
        handle_delete_vlan,
        DELETE_VLAN_SCHEMA,
    )

    async def handle_dump_mac_table(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass, call.data["entry_id"])
        mac_table = await hass.async_add_executor_job(
            coordinator.client.get_mac_table
        )
        _LOGGER.info("MAC address table for %s: %s", call.data["entry_id"], mac_table)
        # Fire an event so automations / scripts can consume the data
        hass.bus.async_fire(
            f"{DOMAIN}_mac_table",
            {"entry_id": call.data["entry_id"], "mac_table": mac_table},
        )

    _async_register_service(
        SERVICE_DUMP_MAC_TABLE,
        handle_dump_mac_table,
        DUMP_MAC_TABLE_SCHEMA,
    )
