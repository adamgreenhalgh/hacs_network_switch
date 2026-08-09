"""Config flow for Network Switch integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_COMMUNITY,
    CONF_HOST,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    DEFAULT_COMMUNITY,
    DEFAULT_PORT,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .snmp_client import CiscoSwitchSNMP, SNMPError

_LOGGER = logging.getLogger(__name__)


async def _validate_connection(hass: HomeAssistant, data: dict[str, Any]) -> None:
    """Raise if we cannot connect to the switch."""
    client = CiscoSwitchSNMP(
        host=data[CONF_HOST],
        community=data[CONF_COMMUNITY],
        port=data[CONF_PORT],
    )
    # test_connection raises SNMPError with a descriptive message on failure.
    await hass.async_add_executor_job(client.test_connection)


class NetworkSwitchConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Network Switch."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                await _validate_connection(self.hass, user_input)
            except SNMPError as err:
                _LOGGER.warning("SNMP connection test failed: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during config flow")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(
                    f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_HOST],
                    data=user_input,
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Optional(CONF_COMMUNITY, default=DEFAULT_COMMUNITY): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
                vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): int,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> NetworkSwitchOptionsFlow:
        return NetworkSwitchOptionsFlow()


class NetworkSwitchOptionsFlow(config_entries.OptionsFlow):
    """Handle options for Network Switch."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SCAN_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                    ),
                ): int,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
