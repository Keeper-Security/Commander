"""
Command categorization for better CLI help organization
"""

# Define the new command categories based on functional groupings
COMMAND_CATEGORIES = {
    # Record Commands
    'Record Commands': {
        'list', 'search', 'ls', 'tree', 'cd', 'get', 'find-password', 'clipboard-copy',
        'record-history', 'totp', 'download-attachment', 'upload-attachment', 'delete-attachment',
        'file-report', 'list-sf', 'list-team', 'add', 'edit', 'rm', 'find-duplicate',
        'shortcut', 'trash', 'transform-folder', 'password-report', 'find-ownerless',
        'rmdir', 'rndir', 'record-add', 'mv', 'mkdir', 'record-update', 'append-notes',
        'verify-records', 'verify-shared-folders', 'delete-all', 'blank-records', 'delete-corrupted',
        'ln'
    },
    
    # Sharing Commands
    'Sharing Commands': {
        'share-record', 'share-folder', 'record-permissions', 'record-permission', 'one-time-share',
        'external-shares-report'
    },
    
    # Record Type Commands
    'Record Type Commands': {
        'record-type-info', 'record-type', 'convert'
    },
    
    # Import and Exporting Data
    'Import and Exporting Data': {
        'import', 'export', 'download-membership', 'apply-membership', 'load-record-types',
        'download-record-types', 'license-consumption-report'
    },
    
    # Reporting Commands
    'Reporting Commands': {
        'audit-log', 'audit-report', 'audit-alert', 'user-report', 'security-audit-report',
        'share-report', 'shared-records-report', 'aging-report', 'action-report',
        'compliance-report', 'compliance', 'external-shares-report', 'risk-management',
        'security-audit'
    },
    
    # MSP Management Commands
    'MSP Management Commands': {
        'msp-info', 'msp-down', 'msp-license', 'msp-add', 'msp-remove', 'msp-update',
        'msp-billing-report', 'msp-legacy-report', 'switch-to-mc', 'switch-to-msp',
        'msp-convert-node', 'msp-copy-role', 'distributor'
    },
    
    # Enterprise Management Commands
    'Enterprise Management Commands': {
        'enterprise-info', 'enterprise-user', 'enterprise-role', 'enterprise-team',
        'enterprise-node', 'enterprise-push', 'team-approve', 'device-approve',
        'create-user', 'transfer-user', 'automator', 'scim', 'enterprise-down',
        'public-api-key'
    },

    # Automation Commands
    'Automation Commands': {
        'credential-provision'
    },

    # Secrets Manager Commands
    'Secrets Manager Commands': {
        'secrets-manager'
    },
    
    # BreachWatch Commands
    'BreachWatch Commands': {
        'breachwatch', 'breach-report'
    },
    
    # Device Management Commands
    'Device Management Commands': {
        'device-list', 'device-action', 'device-rename', 'device-admin-list', 'device-admin-action'
    },

    # Domain Management Commands
    'Domain Management Commands': {
        'domain'
    },
    
    # Service Mode REST API
    'Service Mode REST API': {
        'service-create', 'service-add-config', 'service-start', 'service-stop', 'service-status',
        'service-config-add'
    },

    # Email Configuration Commands
    'Email Configuration Commands': {
        'email-config'
    },
    
    # Email Configuration Commands
    'Email Configuration Commands': {
        'email-config'
    },

    # Miscellaneous Commands
    'Miscellaneous Commands': {
        'this-device', 'login', 'login-status', 'biometric', 'whoami', 'logout',
        'help', 'sync-down', 'version', 'clear', 'run-batch', 'generate',
        'reset-password', 'sync-security-data', 'keeper-fill', '2fa', 'create-account',
        'run-as', 'sleep', 'server', 'proxy', 'keep-alive'
    },

    # KeeperPAM Commands
    'KeeperPAM Commands': {
        'pam'
    },
    
    # Legacy Commands
    'Legacy Commands': {
        'rotate', 'connect', 'ssh', 'ssh-agent', 'rdp', 'rsync', 'set', 'echo'
    }
}

def get_command_category(command):
    """Get the category for a given command"""
    for category, commands in COMMAND_CATEGORIES.items():
        if command in commands:
            return category
    
    # Default category for uncategorized commands
    return 'Other'

def get_category_order():
    """Return the preferred order for displaying categories"""
    return [
        'Record Commands',
        'Sharing Commands',
        'Record Type Commands',
        'Import and Exporting Data',
        'Reporting Commands',
        'MSP Management Commands',
        'Enterprise Management Commands',
        'Automation Commands',
        'Secrets Manager Commands',
        'BreachWatch Commands',
        'Device Management Commands',
        'Domain Management Commands',
        'Email Configuration Commands',
        'Service Mode REST API',
        'Email Configuration Commands',
        'Miscellaneous Commands',
        'KeeperPAM Commands',
        'Legacy Commands',
        'Other'
    ]