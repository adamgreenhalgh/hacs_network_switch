"""Data coordinator for Network Switch integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .snmp_client import CiscoSwitchSNMP, SNMPError

_LOGGER = logging.getLogger(__name__)


class NetworkSwitchCoordinator(DataUpdateCoordinator):
    """Coordinator that polls the switch for interface and VLAN data."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: CiscoSwitchSNMP,
        scan_interval: int,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            interfaces = await self.hass.async_add_executor_job(
                self.client.get_interfaces
            )
            vlans = await self.hass.async_add_executor_job(self.client.get_vlans)
            trunk_info = await self.hass.async_add_executor_job(
                self.client.get_interface_trunk_info
            )
            mac_table = await self.hass.async_add_executor_job(
                self.client.get_mac_table
            )
        except SNMPError as err:
            raise UpdateFailed(f"SNMP error: {err}") from err

        return {
            "interfaces": interfaces,
            "vlans": vlans,
            "trunk_info": trunk_info,
            "mac_table": mac_table,
        }
