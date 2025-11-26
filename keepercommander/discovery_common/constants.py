# NOTE: The graph_id constant are part of keeper-dag as enums now.

# This should the relationship between Keeper Vault record
RECORD_LINK_GRAPH_ID = 0

#  The rules
DIS_RULES_GRAPH_ID = 10

# The discovery job history
DIS_JOBS_GRAPH_ID = 11

# Discovery infrastructure
DIS_INFRA_GRAPH_ID = 12

# The user-to-services graph
USER_SERVICE_GRAPH_ID = 13

PAM_DIRECTORY = "pamDirectory"
PAM_DATABASE = "pamDatabase"
PAM_MACHINE = "pamMachine"
PAM_USER = "pamUser"
LOCAL_USER = "local"

# These are configuration that could domain users.
# Azure included because of AADDS.
DOMAIN_USER_CONFIGS = [
    "pamDomainConfiguration",
    "pamAzureConfiguration"
]

# The record types to process.
# The order defined the order the user will be presented the new discovery objects.
# The sort defined how the discovery objects for a record type are sorted and presented.
# Cloud-based users are presented first, then directories second.
# We want to prompt about users that may appear on machines before processing the machine.
VERTICES_SORT_MAP = {
    PAM_USER: {"order": 1, "sort": "sort_infra_name", "item": "DiscoveryUser", "key": "user"},
    PAM_DIRECTORY: {"order": 1, "sort": "sort_infra_name", "item": "DiscoveryDirectory", "key": "host_port"},
    PAM_MACHINE: {"order": 2, "sort": "sort_infra_host", "item": "DiscoveryMachine", "key": "host"},
    PAM_DATABASE: {"order": 3, "sort": "sort_infra_host", "item": "DiscoveryDatabase", "key": "host_port"},
}
