"""SNMP client for Cisco 3560 switch management.

Transport notes
---------------
pysnmp's asyncio HLAPI is used here via a dedicated background thread so that
HA's event loop is never blocked.  A *new* event loop is created in that thread
(``asyncio.run()``) to avoid sharing loop state with Home Assistant.

IPv4 is preferred over IPv6 by default (``_force_ipv4=True``).  Container
environments (Docker bridge / macvlan) commonly only have IPv4 routes to LAN
devices; letting the OS pick an IPv6 address causes silent timeouts even when
the device itself is reachable on IPv4.  Pass ``force_ipv4=False`` to the
constructor only when you need explicit IPv6.
"""
from __future__ import annotations

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

# Conservative LAN defaults: 5 s timeout, 2 retries (3 total attempts).
# CLI tools such as snmpwalk default to 1 s / 5 retries; Home Assistant
# executor threads benefit from fewer, longer waits.
_DEFAULT_TIMEOUT = 5   # seconds per attempt
_DEFAULT_RETRIES = 2   # retry count (total attempts = retries + 1)

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

    def __init__(
        self,
        host: str,
        community: str,
        port: int = 161,
        timeout: int = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
        force_ipv4: bool = True,
    ) -> None:
        """Initialise the SNMP client.

        Args:
            host: Switch hostname or IP address.
            community: SNMP v2c community string.
            port: UDP port (default 161).
            timeout: Per-attempt timeout in seconds (default 5).
            retries: Number of retries after the first attempt (default 2).
            force_ipv4: When True (default), DNS lookups are restricted to
                AF_INET.  This avoids Docker bridge-network failures where the
                host resolves to an IPv6 address that is unreachable inside the
                container.  Set to False only when the target is explicitly
                IPv6.
        """
        self._host = host
        self._community = community
        self._port = port
        self._timeout = timeout
        self._retries = retries
        self._force_ipv4 = force_ipv4

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_transport_class(self) -> tuple[type[UdpTransportTarget] | type[Udp6TransportTarget], str]:
        """Return (transport-class, description) for the configured host.

        DNS resolution is done synchronously here because this method is always
        called from inside a background thread (never from the HA event loop).

        When *force_ipv4* is True the lookup is restricted to AF_INET, which
        prevents inadvertent IPv6 selection in Docker environments where only
        IPv4 routes exist to LAN switches.
        """
        try:
            address = ipaddress.ip_address(self._host)
            # Literal IP address – no DNS resolution needed.
            if address.version == 6:
                return Udp6TransportTarget, "IPv6"
            return UdpTransportTarget, "IPv4"
        except ValueError:
            pass

        # Hostname – resolve with preference for IPv4.
        af = socket.AF_INET if self._force_ipv4 else socket.AF_UNSPEC
        try:
            results = socket.getaddrinfo(
                self._host,
                self._port,
                family=af,
                type=socket.SOCK_DGRAM,
            )
        except socket.gaierror as err:
            raise SNMPError(
                f"Unable to resolve SNMP host '{self._host}' "
                f"(force_ipv4={self._force_ipv4}): {err}"
            ) from err

        if not results:
            raise SNMPError(
                f"No address records for SNMP host '{self._host}' "
                f"(force_ipv4={self._force_ipv4})"
            )

        family = results[0][0]
        if family == socket.AF_INET6:
            return Udp6TransportTarget, "IPv6"
        if family == socket.AF_INET:
            return UdpTransportTarget, "IPv4"
        raise SNMPError(
            f"Unsupported address family {family} for SNMP host '{self._host}'"
        )

    def _build_transport(self) -> tuple[UdpTransportTarget | Udp6TransportTarget, str]:
        """Create and return an (SNMP transport target, transport description).

        Uses explicit timeout and retry values so behaviour is predictable
        regardless of pysnmp version defaults.
        """
        transport_class, transport_desc = self._resolve_transport_class()
        target_desc = f"{self._host}:{self._port} via {transport_desc}"
        try:
            target = transport_class(
                (self._host, self._port),
                timeout=self._timeout,
                retries=self._retries,
            )
            return target, target_desc
        except Exception as err:
            raise SNMPError(
                f"Unable to create SNMP transport for {target_desc}: {err}"
            ) from err

    def _community_data(self) -> CommunityData:
        return CommunityData(self._community, mpModel=1)

    def _run_coroutine(self, coroutine: Any) -> Any:
        """Execute a pysnmp coroutine in a fresh event loop on this thread.

        pysnmp's asyncio HLAPI must run inside an event loop.  We always spin
        up a *new* loop via ``asyncio.run()`` in a dedicated thread so that:
          - HA's own event loop is never blocked or contaminated.
          - pysnmp's transport dispatcher is fully isolated per-call.

        This method is only ever invoked from within an executor thread (the
        sync ``_get``/``_set``/``_bulk_walk`` wrappers), so we do *not* attempt
        to detect or reuse a running loop – doing so would risk the
        ``asyncio.run()`` "cannot be called from a running event loop" error.
        """
        result: Any = None
        error: BaseException | None = None

        def _runner() -> None:
            nonlocal result, error
            try:
                import asyncio  # noqa: PLC0415 – local import keeps top-level clean
                result = asyncio.run(coroutine)
            except BaseException as err:  # noqa: BLE001
                error = err

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if error is not None:
            raise error

        return result

    def _get(self, *oids: str) -> list[tuple[str, Any]]:
        """Perform an SNMP GET for one or more OIDs."""
        async def _get_async() -> list[tuple[str, Any]]:
            import asyncio  # noqa: PLC0415
            objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
            # Build transport inside the async function so the loop is active.
            transport, target_desc = await asyncio.get_event_loop().run_in_executor(
                None, self._build_transport
            )
            engine = SnmpEngine()
            try:
                error_indication, error_status, error_index, var_binds = await getCmd(
                    engine,
                    self._community_data(),
                    transport,
                    ContextData(),
                    *objects,
                )
                if error_indication:
                    raise SNMPError(
                        f"SNMP GET failed for {target_desc}: {error_indication}"
                    )
                if error_status:
                    raise SNMPError(
                        f"SNMP GET error at index {error_index} for {target_desc}: "
                        f"{error_status.prettyPrint()}"
                    )
                return [(str(vb[0]), vb[1]) for vb in var_binds]
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(
                    f"SNMP GET unexpected error for {target_desc}: {err}"
                ) from err
            finally:
                engine.closeDispatcher()

        return self._run_coroutine(_get_async())

    def _bulk_walk(self, oid: str) -> list[tuple[str, Any]]:
        """Walk an OID subtree using BULK requests."""
        async def _bulk_walk_async() -> list[tuple[str, Any]]:
            import asyncio  # noqa: PLC0415
            transport, target_desc = await asyncio.get_event_loop().run_in_executor(
                None, self._build_transport
            )
            engine = SnmpEngine()
            results: list[tuple[str, Any]] = []
            try:
                async for error_indication, error_status, error_index, var_binds in bulkWalkCmd(
                    engine,
                    self._community_data(),
                    transport,
                    ContextData(),
                    0,
                    25,
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False,
                ):
                    if error_indication:
                        raise SNMPError(
                            f"SNMP WALK failed for {target_desc}: {error_indication}"
                        )
                    if error_status:
                        raise SNMPError(
                            f"SNMP WALK error at index {error_index} for {target_desc}: "
                            f"{error_status.prettyPrint()}"
                        )
                    results.extend((str(vb[0]), vb[1]) for vb in var_binds)
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(
                    f"SNMP WALK unexpected error for {target_desc}: {err}"
                ) from err
            finally:
                engine.closeDispatcher()

            return results

        return self._run_coroutine(_bulk_walk_async())

    def _set(self, *oid_value_pairs: tuple[str, Any]) -> None:
        """Perform an SNMP SET for one or more OID/value pairs."""
        async def _set_async() -> None:
            import asyncio  # noqa: PLC0415
            objects = [ObjectType(ObjectIdentity(oid), value) for oid, value in oid_value_pairs]
            transport, target_desc = await asyncio.get_event_loop().run_in_executor(
                None, self._build_transport
            )
            engine = SnmpEngine()
            try:
                error_indication, error_status, error_index, _ = await setCmd(
                    engine,
                    self._community_data(),
                    transport,
                    ContextData(),
                    *objects,
                )
                if error_indication:
                    raise SNMPError(
                        f"SNMP SET failed for {target_desc}: {error_indication}"
                    )
                if error_status:
                    raise SNMPError(
                        f"SNMP SET error at index {error_index} for {target_desc}: "
                        f"{error_status.prettyPrint()}"
                    )
            except SNMPError:
                raise
            except Exception as err:
                raise SNMPError(
                    f"SNMP SET unexpected error for {target_desc}: {err}"
                ) from err
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

    def test_connection(self) -> None:
        """Verify the switch responds to SNMP.

        Raises :class:`SNMPError` with a descriptive message on failure so
        that callers (e.g. config flow) can surface actionable diagnostics to
        the user instead of a generic "cannot connect" message.
        """
        # sysDescr (1.3.6.1.2.1.1.1.0) is universally available on v2c agents.
        self._get("1.3.6.1.2.1.1.1.0")
