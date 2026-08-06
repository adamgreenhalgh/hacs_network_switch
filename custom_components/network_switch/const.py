"""Constants for the Network Switch integration."""

DOMAIN = "network_switch"

# Config entry keys
CONF_HOST = "host"
CONF_COMMUNITY = "community"
CONF_PORT = "port"
CONF_SCAN_INTERVAL = "scan_interval"

# Defaults
DEFAULT_PORT = 161
DEFAULT_COMMUNITY = "public"
DEFAULT_SCAN_INTERVAL = 30  # seconds

# ifOperStatus values
OPER_STATUS_UP = 1
OPER_STATUS_DOWN = 2

# ifAdminStatus values
ADMIN_STATUS_UP = 1
ADMIN_STATUS_DOWN = 2

# Interface mode
MODE_ACCESS = "access"
MODE_TRUNK = "trunk"

# Service names
SERVICE_SET_ADMIN_STATUS = "set_interface_admin_status"
SERVICE_SET_LABEL = "set_interface_label"
SERVICE_SET_ACCESS_VLAN = "set_interface_access_vlan"
SERVICE_SET_INTERFACE_MODE = "set_interface_mode"
SERVICE_CREATE_VLAN = "create_vlan"
SERVICE_DELETE_VLAN = "delete_vlan"
SERVICE_DUMP_MAC_TABLE = "dump_mac_table"
