"""Sensor platform for Network Switch – interface state sensors."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ADMIN_STATUS_DOWN,
    ADMIN_STATUS_UP,
    DOMAIN,
    OPER_STATUS_DOWN,
    OPER_STATUS_UP,
)
from .coordinator import NetworkSwitchCoordinator

_LOGGER = logging.getLogger(__name__)

OPER_STATUS_MAP = {OPER_STATUS_UP: "up", OPER_STATUS_DOWN: "down"}
ADMIN_STATUS_MAP = {ADMIN_STATUS_UP: "up", ADMIN_STATUS_DOWN: "down"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor entities for each interface."""
    coordinator: NetworkSwitchCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities: list[SensorEntity] = []
    for if_index, iface in coordinator.data["interfaces"].items():
        name = iface.get("name", f"Interface {if_index}")
        entities.append(InterfaceOperStatusSensor(coordinator, entry, if_index, name))
        entities.append(InterfaceAdminStatusSensor(coordinator, entry, if_index, name))

    # MAC table sensor (whole-device)
    entities.append(MacTableSensor(coordinator, entry))

    async_add_entities(entities, update_before_add=True)


def _device_info(entry: ConfigEntry) -> DeviceInfo:
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name=f"Switch {entry.data['host']}",
        manufacturer="Cisco",
        model="Catalyst 3560",
    )


class InterfaceOperStatusSensor(CoordinatorEntity, SensorEntity):
    """Sensor showing the operational status of a switch interface."""

    def __init__(
        self,
        coordinator: NetworkSwitchCoordinator,
        entry: ConfigEntry,
        if_index: int,
        if_name: str,
    ) -> None:
        super().__init__(coordinator)
        self._if_index = if_index
        self._if_name = if_name
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_if{if_index}_oper_status"
        self._attr_name = f"{if_name} Operational Status"
        self._attr_device_info = _device_info(entry)
        self._attr_icon = "mdi:ethernet"

    @property
    def native_value(self) -> str | None:
        iface = self.coordinator.data["interfaces"].get(self._if_index, {})
        return OPER_STATUS_MAP.get(iface.get("oper_status", 0))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        iface = self.coordinator.data["interfaces"].get(self._if_index, {})
        trunk = self.coordinator.data["trunk_info"].get(self._if_index, {})
        return {
            "if_index": self._if_index,
            "label": iface.get("label", ""),
            "admin_status": ADMIN_STATUS_MAP.get(iface.get("admin_status", 0)),
            "trunk_mode": trunk.get("mode"),
            "trunk_dynamic_status": trunk.get("dynamic_status"),
        }


class InterfaceAdminStatusSensor(CoordinatorEntity, SensorEntity):
    """Sensor showing the administrative status of a switch interface."""

    def __init__(
        self,
        coordinator: NetworkSwitchCoordinator,
        entry: ConfigEntry,
        if_index: int,
        if_name: str,
    ) -> None:
        super().__init__(coordinator)
        self._if_index = if_index
        self._if_name = if_name
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_if{if_index}_admin_status"
        self._attr_name = f"{if_name} Admin Status"
        self._attr_device_info = _device_info(entry)
        self._attr_icon = "mdi:ethernet"

    @property
    def native_value(self) -> str | None:
        iface = self.coordinator.data["interfaces"].get(self._if_index, {})
        return ADMIN_STATUS_MAP.get(iface.get("admin_status", 0))


class MacTableSensor(CoordinatorEntity, SensorEntity):
    """Sensor showing a count of MAC address table entries."""

    def __init__(
        self,
        coordinator: NetworkSwitchCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_mac_table_count"
        self._attr_name = "MAC Address Table Count"
        self._attr_device_info = _device_info(entry)
        self._attr_icon = "mdi:table-network"
        self._attr_native_unit_of_measurement = "entries"

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data.get("mac_table", []))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"mac_table": self.coordinator.data.get("mac_table", [])}
