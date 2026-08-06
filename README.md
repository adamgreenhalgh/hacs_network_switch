# Network Switch – Home Assistant HACS Integration

A HACS custom integration to manage a **Cisco Catalyst 3560** (and compatible) switch via **SNMP v2c**.

## Features

- 📊 **Interface state sensors** – operational and administrative status for every interface
- 📋 **MAC address table** – dump via service call, result fired as a HA event
- 🏷️ **VLAN management** – create and delete VLANs
- 🔌 **Interface VLAN assignment** – set access VLAN or trunk mode per interface
- ✏️ **Interface labeling** – set `ifAlias` descriptions
- 🔴 **Administrative control** – enable / disable interfaces
- 🔀 **Interface mode** – switch between access and trunk mode

## Installation

1. Install via [HACS](https://hacs.xyz/) by adding this repository as a custom integration.
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for **Network Switch**.
4. Enter your switch IP, SNMP read/write community string, and polling interval.

> **SNMP write access is required** for all configuration services.  
> Configure your switch with `snmp-server community <string> RW`.

## Services

All services require `entry_id` – the config entry ID visible in **Settings → Devices & Services**.

| Service | Description |
|---|---|
| `network_switch.set_interface_admin_status` | Enable / disable an interface |
| `network_switch.set_interface_label` | Set interface description (ifAlias) |
| `network_switch.set_interface_access_vlan` | Assign an access VLAN |
| `network_switch.set_interface_mode` | Set to `access` or `trunk` |
| `network_switch.create_vlan` | Create a VLAN |
| `network_switch.delete_vlan` | Delete a VLAN |
| `network_switch.dump_mac_table` | Fire `network_switch_mac_table` event with MAC table |

### Example: Enable an interface

```yaml
service: network_switch.set_interface_admin_status
data:
  entry_id: "<your_entry_id>"
  if_index: 3
  enabled: true
```

### Example: Create VLAN 100

```yaml
service: network_switch.create_vlan
data:
  entry_id: "<your_entry_id>"
  vlan_id: 100
  name: "IoT"
```

### Example: Dump MAC table

```yaml
service: network_switch.dump_mac_table
data:
  entry_id: "<your_entry_id>"
```

Listen for the `network_switch_mac_table` event in an automation to process the result.

## Cisco Switch Prerequisites

Enable SNMP on your 3560:

```
snmp-server community public RO
snmp-server community private RW
```

Replace `public`/`private` with your own community strings.

## License

MIT
