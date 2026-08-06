"""SNMP client for Cisco 3560 switch management."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import threading
from typing import Any

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    bulkWalkCmd,
    getCmd,
    setCmd,
)
from pysnmp.proto.rfc1902 import Integer, OctetString

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OID constants (Cisco / standard MIBs)
# ---------------------------------------------------------------------------

# IF-MIB
OID_IF_DESC = "1.3.6.1.2.1.2.2.1.2"          # ifDescr
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"   # ifOperStatus (1=up, 2=down)
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"  # ifAdminStatus (1=up, 2=down)
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"     # ifAlias (interface label)

# BRIDGE-MIB – MAC address table
OID_DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"   # dot1dTpFdbAddress
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort

# Cisco VLAN MIB (CISCO-VTP-MIB)
OID_VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"   # vtpVlanState
OID_VTP_VLAN_NAME = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"    # vtpVlanName
OID_VTP_VLAN_EDIT_OPERATION = "1.3.6.1.4.1.9.9.46.1.4.1.1.1.1"   # vtpVlanEditOperation (1=apply,2=edit,3=abort)
OID_VTP_VLAN_EDIT_STATE = "1.3.6.1.4.1.9.9.46.1.4.1.1.2.1"       # vtpVlanEditRowStatus
OID_VTP_VLAN_EDIT_NAME = "1.3.6.1.4.1.9.9.46.1.4.1.1.4.1"        # vtpVlanEditName

# Cisco VLAN membership (CISCO-VLAN-MEMBERSHIP-MIB)
OID_VMVLAN_TYPE = "1.3.6.1.4.1.9.9.68.1.2.2.1.1"   # vmVlanType
OID_VMVLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"         # vmVlan (access VLAN)

# Cisco trunk MIB (CISCO-VTP-MIB / CISCO-TRUNK-MIB-like)
OID_VLAN_TRUNK_PORT_DYN_STATUS = "1.3.6.1.4.1.9.9.46.1.6.1.1.14"  # vlanTrunkPortDynamicStatus
OID_VLAN_TRUNK_PORT_ENCAPS_TYPE = "1.3.6.1.4.1.9.9.46.1.6.1.1.3"  # vlanTrunkPortEncapsulationType
OID_VLAN_TRUNK_PORT_MODE = "1.3.6.1.4.1.9.9.46.1.6.1.1.13"        # vlanTrunkPortDynamicState


class SNMPError(Exception):
    """Raised when an SNMP operation fails."""


class CiscoSwitchSNMP:
    """Manage a Cisco 3560 switch via SNMP v2c."""

    def __init__(self, host: str, community: str, port: int = 161, timeout: int = 5) -> None:
        self._host = host
        self._community = community
        self._port = port
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _transport(self) -> UdpTransportTarget | Udp6TransportTarget:
        transport_target = self._transport_target_class()
        try:
            if hasattr(transport_target, "create"):
                try:
                    return await transport_target.create(
                        (self._host, self._port),
                        timeout=self._timeout,
                        retries=1,
                    )
                except NotImplementedError:
                    _LOGGER.debug(
                        "SNMP transport target.create() unsupported for %s, falling back",
                        self._host,
                    )

            return transport_target(
                (self._host, self._port),
                timeout=self._timeout,
                retries=1,
            )
        except SNMPError:
            raise
        except Exception as err:
            raise SNMPError(
                f"Unable to create SNMP transport for {self._host}:{self._port}: {err}"
            ) from err

    def _community_data(self) -> CommunityData:
        return CommunityData(self._community, mpModel=1)

    def _transport_target_class(self) -> type[UdpTransportTarget] | type[Udp6TransportTarget]:
        """Return the best transport target class for the configured host."""
        try:
            address = ipaddress.ip_address(self._host)
        except ValueError:
            try:
                family = socket.getaddrinfo(
                    self._host,
                    self._port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_DGRAM,
                )[0][0]
            except socket.gaierror as err:
                raise SNMPError(
                    f"Unable to resolve SNMP host '{self._host}': {err}"
                ) from err

            if family == socket.AF_INET6:
                return Udp6TransportTarget
            if family == socket.AF_INET:
                return UdpTransportTarget
            raise SNMPError(f"Unsupported address family for host '{self._host}'")

        return Udp6TransportTarget if address.version == 6 else UdpTransportTarget

    def _run_coroutine(self, coroutine: Any) -> Any:
        """Run PySNMP coroutines from sync integration methods."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine)

        result: Any = None
        error: BaseException | None = None

        def _runner() -> None:
            nonlocal result, error
            try:
                result = asyncio.run(coroutine)
            except BaseException as err:  # pragma: no cover - re-raised below
                error = err

        thread = threading.Thread(target=_runner)
        thread.start()
        thread.join()

        if error is not None:
            raise error

        return result

    def _get(self, *oids: str) -> list[tuple[str, Any]]:
        """Perform an SNMP GET for one or more OIDs."""
        async def _get_async() -> list[tuple[str, Any]]:
            objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
            engine = SnmpEngine()
            try:
                error_indication, error_status, error_index, var_binds = await getCmd(
                    engine,
                    self._community_data(),
                    await self._transport(),
                    ContextData(),
                    *objects,
                )
                if error_indication:
                    raise SNMPError(f"GET error: {error_indication}")
                if error_status:
                    raise SNMPError(
                        f"GET error at {error_index}: {error_status.prettyPrint()}"
                    )
                return [(str(vb[0]), vb[1]) for vb in var_binds]
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(f"GET error: {err}") from err
            finally:
                engine.closeDispatcher()

        return self._run_coroutine(_get_async())

    def _bulk_walk(self, oid: str) -> list[tuple[str, Any]]:
        """Walk an OID subtree using BULK requests."""
        async def _bulk_walk_async() -> list[tuple[str, Any]]:
            engine = SnmpEngine()
            results: list[tuple[str, Any]] = []
            try:
                async for error_indication, error_status, error_index, var_binds in bulkWalkCmd(
                    engine,
                    self._community_data(),
                    await self._transport(),
                    ContextData(),
                    0,
                    25,
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False,
                ):
                    if error_indication:
                        raise SNMPError(f"WALK error: {error_indication}")
                    if error_status:
                        raise SNMPError(
                            f"WALK error at {error_index}: {error_status.prettyPrint()}"
                        )
                    results.extend((str(var_bind[0]), var_bind[1]) for var_bind in var_binds)
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(f"WALK error: {err}") from err
            finally:
                engine.closeDispatcher()

            return results

        return self._run_coroutine(_bulk_walk_async())

    def _set(self, *oid_value_pairs: tuple[str, Any]) -> None:
        """Perform an SNMP SET for one or more OID/value pairs."""
        async def _set_async() -> None:
            objects = [ObjectType(ObjectIdentity(oid), value) for oid, value in oid_value_pairs]
            engine = SnmpEngine()
            try:
                error_indication, error_status, error_index, _ = await setCmd(
                    engine,
                    self._community_data(),
                    await self._transport(),
                    ContextData(),
                    *objects,
                )
                if error_indication:
                    raise SNMPError(f"SET error: {error_indication}")
                if error_status:
                    raise SNMPError(
                        f"SET error at {error_index}: {error_status.prettyPrint()}"
                    )
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(f"SET error: {err}") from err
            finally:
                engine.closeDispatcher()

        self._run_coroutine(_set_async())

    # ------------------------------------------------------------------
    # Interface methods
    # ------------------------------------------------------------------

    def get_interfaces(self) -> dict[int, dict[str, Any]]:
        """Return a dict keyed by ifIndex with interface details."""
        interfaces: dict[int, dict[str, Any]] = {}

        for oid_str, value in self._bulk_walk(OID_IF_DESC):
            idx = int(oid_str.split(".")[-1])
            interfaces.setdefault(idx, {})["name"] = str(value)

        for oid_str, value in self._bulk_walk(OID_IF_OPER_STATUS):
            idx = int(oid_str.split(".")[-1])
            interfaces.setdefault(idx, {})["oper_status"] = int(value)

        for oid_str, value in self._bulk_walk(OID_IF_ADMIN_STATUS):
            idx = int(oid_str.split(".")[-1])
            interfaces.setdefault(idx, {})["admin_status"] = int(value)

        for oid_str, value in self._bulk_walk(OID_IF_ALIAS):
            idx = int(oid_str.split(".")[-1])
            interfaces.setdefault(idx, {})["label"] = str(value)

        return interfaces

    def set_interface_admin_status(self, if_index: int, up: bool) -> None:
        """Administratively bring an interface up (True) or down (False)."""
        value = Integer(1 if up else 2)
        self._set((f"{OID_IF_ADMIN_STATUS}.{if_index}", value))

    def set_interface_label(self, if_index: int, label: str) -> None:
        """Set the ifAlias (description/label) for an interface."""
        self._set((f"{OID_IF_ALIAS}.{if_index}", OctetString(label)))

    # ------------------------------------------------------------------
    # MAC address table
    # ------------------------------------------------------------------

    def get_mac_table(self) -> list[dict[str, Any]]:
        """Return the MAC address forwarding table."""
        mac_entries: dict[str, dict] = {}

        for oid_str, value in self._bulk_walk(OID_DOT1D_TP_FDB_ADDRESS):
            # OID suffix encodes the MAC as 6 decimal octets
            suffix = oid_str[len(OID_DOT1D_TP_FDB_ADDRESS) + 1:]
            mac = ":".join(f"{int(o):02x}" for o in suffix.split("."))
            mac_entries[suffix] = {"mac": mac}

        for oid_str, value in self._bulk_walk(OID_DOT1D_TP_FDB_PORT):
            suffix = oid_str[len(OID_DOT1D_TP_FDB_PORT) + 1:]
            if suffix in mac_entries:
                mac_entries[suffix]["port"] = int(value)

        return list(mac_entries.values())

    # ------------------------------------------------------------------
    # VLAN methods
    # ------------------------------------------------------------------

    def get_vlans(self) -> dict[int, dict[str, Any]]:
        """Return existing VLANs keyed by VLAN ID."""
        vlans: dict[int, dict] = {}

        for oid_str, value in self._bulk_walk(OID_VTP_VLAN_STATE):
            vlan_id = int(oid_str.split(".")[-1])
            vlans.setdefault(vlan_id, {})["state"] = int(value)

        for oid_str, value in self._bulk_walk(OID_VTP_VLAN_NAME):
            vlan_id = int(oid_str.split(".")[-1])
            vlans.setdefault(vlan_id, {})["name"] = str(value)

        return vlans

    def create_vlan(self, vlan_id: int, name: str) -> None:
        """Create a VLAN via the VTP edit buffer."""
        # 1 = apply, 2 = edit, 3 = abort
        self._set(
            (OID_VTP_VLAN_EDIT_OPERATION, Integer(2)),
        )
        # Row status 4 = createAndGo
        self._set(
            (f"{OID_VTP_VLAN_EDIT_STATE}.{vlan_id}", Integer(4)),
            (f"{OID_VTP_VLAN_EDIT_NAME}.{vlan_id}", OctetString(name)),
        )
        self._set(
            (OID_VTP_VLAN_EDIT_OPERATION, Integer(1)),
        )

    def delete_vlan(self, vlan_id: int) -> None:
        """Delete a VLAN via the VTP edit buffer."""
        self._set(
            (OID_VTP_VLAN_EDIT_OPERATION, Integer(2)),
        )
        # Row status 6 = destroy
        self._set(
            (f"{OID_VTP_VLAN_EDIT_STATE}.{vlan_id}", Integer(6)),
        )
        self._set(
            (OID_VTP_VLAN_EDIT_OPERATION, Integer(1)),
        )

    # ------------------------------------------------------------------
    # Interface VLAN / trunk methods
    # ------------------------------------------------------------------

    def set_interface_access_vlan(self, if_index: int, vlan_id: int) -> None:
        """Assign an access VLAN to an interface."""
        self._set((f"{OID_VMVLAN}.{if_index}", Integer(vlan_id)))

    def set_interface_mode(self, if_index: int, mode: str) -> None:
        """Set interface to 'access' or 'trunk'.

        vlanTrunkPortDynamicState values:
          1 = trunk, 2 = access, 3 = desirable, 4 = auto, 5 = nonegotiate
        """
        mode_map = {"trunk": 1, "access": 2}
        value = mode_map.get(mode.lower())
        if value is None:
            raise ValueError(f"Invalid mode '{mode}'. Use 'access' or 'trunk'.")
        self._set((f"{OID_VLAN_TRUNK_PORT_MODE}.{if_index}", Integer(value)))

    def get_interface_trunk_info(self) -> dict[int, dict[str, Any]]:
        """Return trunk status for all interfaces."""
        trunk_info: dict[int, dict] = {}

        for oid_str, value in self._bulk_walk(OID_VLAN_TRUNK_PORT_MODE):
            idx = int(oid_str.split(".")[-1])
            trunk_info.setdefault(idx, {})["mode"] = int(value)

        for oid_str, value in self._bulk_walk(OID_VLAN_TRUNK_PORT_DYN_STATUS):
            idx = int(oid_str.split(".")[-1])
            trunk_info.setdefault(idx, {})["dynamic_status"] = int(value)

        return trunk_info

    # ------------------------------------------------------------------
    # Connectivity test
    # ------------------------------------------------------------------

    def test_connection(self) -> bool:
        """Return True if the switch responds to SNMP."""
        try:
            self._get("1.3.6.1.2.1.1.1.0")  # sysDescr
            return True
        except SNMPError:
            return False
