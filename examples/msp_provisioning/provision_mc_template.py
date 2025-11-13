#!/usr/bin/env python3
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to provision a Managed Company from a YAML template
#
# Usage:
#    python3 provision_mc_template.py template.yaml [--dry-run] [--config config.json]
#

import argparse
import getpass
import logging
import os
import sys
import yaml
from typing import Dict, List, Optional, Any

# Add parent directories to path to import keepercommander
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands import msp, folder, register, enterprise
from keepercommander.commands.enterprise_create_user import CreateEnterpriseUserCommand


class MCProvisioner:
    """Provisions a Managed Company from a YAML template"""

    def __init__(self, params, dry_run=False):
        self.params = params
        self.dry_run = dry_run
        self.mc_id = None
        self.mc_name = None
        self.mc_params = None
        self.root_folder_name = None  # Name of MC root folder
        self.root_folder_uid = None   # UID of MC root folder
        self.folder_prefix = None     # Prefix for subfolder names
        self.folder_uid_map = {}  # Maps folder paths to UIDs

    def load_template(self, template_file):
        """Load and validate YAML template"""
        logging.info(f"Loading template from {template_file}")
        with open(template_file, 'r') as f:
            template = yaml.safe_load(f)

        # Validate required fields
        if 'mc' not in template:
            raise ValueError("Template must contain 'mc' section")
        if 'name' not in template['mc']:
            raise ValueError("MC configuration must include 'name'")
        if 'plan' not in template['mc']:
            raise ValueError("MC configuration must include 'plan'")

        return template

    def create_node(self, mc_config):
        """Create a node for the MC if specified"""
        node_name = mc_config.get('node')
        create_node_flag = mc_config.get('create_node', False)

        # If no node specified or create_node is False, skip
        if not node_name or not create_node_flag:
            return

        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Creating node: {node_name}")

        if self.dry_run:
            return

        # Check if node already exists
        if self.params.enterprise and 'nodes' in self.params.enterprise:
            for node in self.params.enterprise['nodes']:
                if node.get('data', {}).get('displayname') == node_name:
                    logging.info(f"✓ Node '{node_name}' already exists, skipping creation")
                    return

        # Create the node
        try:
            node_add_command = enterprise.EnterpriseNodeCommand()
            # Note: node parameter expects a list, add=True means "add node", parent omitted = use root
            node_add_command.execute(self.params, node=[node_name], add=True)
            logging.info(f"✓ Node created: {node_name}")

            # Refresh enterprise data to get the new node
            api.query_enterprise(self.params)
        except Exception as e:
            logging.warning(f"⚠️  Failed to create node '{node_name}': {e}")
            logging.warning(f"⚠️  Continuing with MC creation...")

    def create_mc(self, mc_config):
        """Create the Managed Company"""
        self.mc_name = mc_config['name']
        plan = mc_config.get('plan', 'businessPlus')
        seats = mc_config.get('seats', -1)
        node = mc_config.get('node')
        file_plan = mc_config.get('file_plan')
        addons = mc_config.get('addons', [])

        # Set root folder name
        # If 'root_folder' is explicitly set, use it (even if empty/False means no root folder)
        # If not set, default to MC name
        if 'root_folder' in mc_config:
            root_folder = mc_config['root_folder']
            self.root_folder_name = root_folder if root_folder else None
        else:
            # Default: use MC name as root folder name
            self.root_folder_name = self.mc_name

        # Set folder prefix for subfolders
        # If 'folder_prefix' is explicitly set, use it (even if empty/False means no prefix)
        # If not set, default to first word of MC name
        if 'folder_prefix' in mc_config:
            prefix = mc_config['folder_prefix']
            self.folder_prefix = prefix if prefix else None
        else:
            # Default: use first word of MC name as prefix
            self.folder_prefix = self.mc_name.split()[0]

        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Creating MC: {self.mc_name}")
        logging.info(f"  Plan: {plan}, Seats: {seats}")
        if self.root_folder_name:
            logging.info(f"  Root Folder: '{self.root_folder_name}'")
        if self.folder_prefix:
            logging.info(f"  Folder Prefix: '{self.folder_prefix}-'")
        if addons:
            logging.info(f"  Add-ons: {', '.join(addons)}")

        if self.dry_run:
            self.mc_id = "DRY_RUN_MC_ID"
            return

        # Create the MC
        mc_add_command = msp.MSPAddCommand()
        kwargs = {
            'name': self.mc_name,
            'plan': plan,
            'seats': seats
        }
        if node:
            kwargs['node'] = node
        if file_plan:
            kwargs['file_plan'] = file_plan
        if addons:
            kwargs['addon'] = addons

        self.mc_id = mc_add_command.execute(self.params, **kwargs)
        logging.info(f"✓ MC created with ID: {self.mc_id}")

    def switch_to_mc(self):
        """Switch to MC context"""
        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Switching to MC: {self.mc_name}")

        if self.dry_run:
            return

        # Switch to MC context
        switch_command = msp.SwitchToMcCommand()
        switch_command.execute(self.params, mc=self.mc_name)

        # Get MC params
        self.mc_params = msp.mc_params_dict.get(self.mc_id)
        if not self.mc_params:
            raise RuntimeError(f"Failed to get MC params for {self.mc_name}")

        logging.info(f"✓ Switched to MC context")

    def create_internal_nodes(self, mc_config):
        """Create internal nodes within the MC for organizational structure"""
        internal_nodes = mc_config.get('internal_nodes', [])

        if not internal_nodes:
            return

        logging.info(f"\n{'[DRY RUN] ' if self.dry_run else ''}Creating internal MC nodes...")

        for node_config in internal_nodes:
            # Support both string format and dict format
            if isinstance(node_config, str):
                node_name = node_config
            elif isinstance(node_config, dict):
                node_name = node_config.get('name')
            else:
                logging.warning(f"Invalid node configuration: {node_config}, skipping")
                continue

            if not node_name:
                logging.warning("Node configuration missing 'name', skipping")
                continue

            logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}  Creating internal node: {node_name}")

            if self.dry_run:
                continue

            # Check if node already exists in MC
            if self.mc_params.enterprise and 'nodes' in self.mc_params.enterprise:
                node_exists = False
                for node in self.mc_params.enterprise['nodes']:
                    if node.get('data', {}).get('displayname') == node_name:
                        logging.info(f"  ✓ Node '{node_name}' already exists, skipping creation")
                        node_exists = True
                        break
                if node_exists:
                    continue

            # Create the node within the MC
            try:
                node_add_command = enterprise.EnterpriseNodeCommand()
                node_add_command.execute(self.mc_params, node=[node_name], add=True)
                logging.info(f"  ✓ Internal node created: {node_name}")

                # Refresh MC enterprise data
                api.query_enterprise(self.mc_params)
            except Exception as e:
                logging.warning(f"  ⚠️  Failed to create internal node '{node_name}': {e}")
                logging.warning(f"  ⚠️  Continuing with provisioning...")

    def create_admin_user(self, user_config):
        """Create the dedicated admin user"""
        if not user_config:
            logging.info("No admin user configuration, skipping")
            return

        email = user_config.get('email')
        name = user_config.get('name', email)
        node = user_config.get('node')  # Don't default to 'Root' - use None for default node

        if not email:
            logging.warning("Admin user email not specified, skipping")
            return

        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Creating admin user: {email}")

        if self.dry_run:
            return

        # Create user
        create_user_command = CreateEnterpriseUserCommand()
        kwargs = {
            'email': email,
            'name': name
        }
        # Only add node if explicitly specified
        if node:
            kwargs['node'] = node

        try:
            create_user_command.execute(self.mc_params, **kwargs)
            logging.info(f"✓ Admin user created: {email}")
        except Exception as e:
            error_msg = str(e)

            # Check if this is a domain reservation error
            if "reserved domain" in error_msg.lower() or "email verification" in error_msg.lower():
                logging.error(f"\n{'='*60}")
                logging.error(f"DOMAIN NOT RESERVED ERROR")
                logging.error(f"{'='*60}")
                logging.error(f"Failed to create admin user: {email}")
                logging.error(f"Reason: {error_msg}")
                logging.error(f"\nThe email domain must be reserved before auto-creating users.")
                logging.error(f"Learn more: https://docs.keeper.io/enterprise-guide/user-and-team-provisioning/email-auto-provisioning")
                logging.error(f"{'='*60}\n")

                # Prompt user to continue
                response = input("Continue provisioning without admin user? (y/n): ").strip().lower()

                if response == 'y' or response == 'yes':
                    logging.warning(f"⚠️  Continuing without admin user. You can add the admin user later.")
                    logging.warning(f"⚠️  Remember to reserve the domain and create the user manually.\n")
                    return  # Continue with the rest of provisioning
                else:
                    logging.error("Provisioning aborted by user.")
                    raise  # Re-raise the exception to stop provisioning
            else:
                # Some other error - re-raise it
                logging.error(f"Failed to create admin user: {error_msg}")
                raise

    def create_root_folder(self, mc_config):
        """Create the MC root folder if specified"""
        if not self.root_folder_name:
            return

        logging.info(f"\n{'[DRY RUN] ' if self.dry_run else ''}Creating MC root folder: {self.root_folder_name}")

        if self.dry_run:
            return

        # Create the root folder as a REGULAR folder (not shared)
        # This allows subfolders inside to be shared folders
        # Note: Keeper does not allow shared folders to be nested inside shared folders
        mkdir_command = folder.FolderMakeCommand()
        kwargs = {
            'folder': self.root_folder_name,
            'shared_folder': False,  # Regular folder for organization
        }

        # Set color if specified in mc_config
        root_folder_color = mc_config.get('root_folder_color')
        if root_folder_color:
            kwargs['color'] = root_folder_color

        try:
            mkdir_command.execute(self.mc_params, **kwargs)

            # Get the root folder UID
            api.sync_down(self.mc_params)
            self.root_folder_uid = self._find_folder_uid(self.root_folder_name)

            if self.root_folder_uid:
                self.folder_uid_map[self.root_folder_name] = self.root_folder_uid
                logging.info(f"✓ MC root folder created: {self.root_folder_name} (UID: {self.root_folder_uid})")
            else:
                logging.warning(f"⚠️  Could not find UID for root folder: {self.root_folder_name}")

            # Note: We cannot share the root folder since it's a regular folder
            # Instead, individual subfolders can be shared with MSP users
            root_folder_sharing = mc_config.get('root_folder_sharing', [])
            if root_folder_sharing:
                logging.warning(f"⚠️  root_folder_sharing is not supported (root folder must be regular to allow nested shared folders)")
                logging.warning(f"⚠️  Share individual subfolders instead using the 'share_with' parameter on each folder")

        except Exception as e:
            logging.error(f"✗ Failed to create MC root folder: {e}")
            raise

    def create_folders(self, folders_config, parent_path=""):
        """Recursively create folder structure"""
        if not folders_config:
            return

        # If we have a root folder, navigate into it first
        if self.root_folder_name and not parent_path:
            if not self.dry_run:
                cd_command = folder.FolderCdCommand()
                cd_command.execute(self.mc_params, folder=self.root_folder_name)
            parent_path = self.root_folder_name

        for folder_config in folders_config:
            self._create_single_folder(folder_config, parent_path)

        # Navigate back to root after creating all folders
        if self.root_folder_name and parent_path == self.root_folder_name:
            if not self.dry_run:
                cd_command = folder.FolderCdCommand()
                cd_command.execute(self.mc_params, folder="..")

    def _create_single_folder(self, folder_config, parent_path=""):
        """Create a single folder and its subfolders"""
        name = folder_config.get('name')
        if not name:
            logging.warning("Folder missing 'name', skipping")
            return

        # Apply prefix to top-level folders (those directly inside root folder)
        # This helps MSP techs identify which client the folder belongs to when shared
        if parent_path == self.root_folder_name and self.folder_prefix:
            folder_name = f"{self.folder_prefix}-{name}"
        else:
            folder_name = name

        # Note: Root folder is created as regular (not shared) to allow shared subfolders
        # Top-level folders inside root should be shared so they can be shared with MSP techs
        # Nested subfolders can be regular or shared depending on needs
        folder_type = folder_config.get('type')
        if folder_type is None:
            # Default: shared for top-level (inside root) or vault root, regular for nested
            folder_type = 'shared' if parent_path == self.root_folder_name or not parent_path else 'regular'

        color = folder_config.get('color')
        permissions = folder_config.get('permissions', {})

        # Build full path for tracking (using prefixed name)
        full_path = f"{parent_path}/{folder_name}" if parent_path else folder_name

        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Creating folder: {full_path}")

        if not self.dry_run:
            # Create the folder (use prefixed name)
            mkdir_command = folder.FolderMakeCommand()
            kwargs = {
                'folder': folder_name,
                'shared_folder': folder_type == 'shared',
                'user_folder': folder_type == 'user'
            }

            if color:
                kwargs['color'] = color

            # Set permissions
            if permissions.get('grant'):
                kwargs['grant'] = True
            if permissions.get('manage_users'):
                kwargs['manage_users'] = True
            if permissions.get('manage_records'):
                kwargs['manage_records'] = True
            if permissions.get('can_share'):
                kwargs['can_share'] = True
            if permissions.get('can_edit'):
                kwargs['can_edit'] = True

            mkdir_command.execute(self.mc_params, **kwargs)

            # Get the folder UID (need to sync and look it up with prefixed name)
            api.sync_down(self.mc_params)
            folder_uid = self._find_folder_uid(folder_name, parent_path)
            if folder_uid:
                self.folder_uid_map[full_path] = folder_uid
                logging.info(f"  ✓ Created: {full_path} (UID: {folder_uid})")
            else:
                logging.warning(f"  Could not find UID for {full_path}")

        # Handle sharing
        share_with = folder_config.get('share_with', [])
        if share_with and not self.dry_run:
            folder_uid = self.folder_uid_map.get(full_path)
            if folder_uid:
                self._share_folder(folder_uid, full_path, share_with)
        elif share_with and self.dry_run:
            for share in share_with:
                logging.info(f"  [DRY RUN] Would share with: {share.get('email')}")

        # Create subfolders
        subfolders = folder_config.get('subfolders', [])
        if subfolders:
            # Change to this folder before creating subfolders (use actual folder name, which may be prefixed)
            if not self.dry_run:
                cd_command = folder.FolderCdCommand()
                cd_command.execute(self.mc_params, folder=folder_name)

            self.create_folders(subfolders, full_path)

            # Always change back after creating subfolders
            if not self.dry_run:
                cd_command = folder.FolderCdCommand()
                cd_command.execute(self.mc_params, folder="..")

    def _find_folder_uid(self, folder_name, parent_path=""):
        """Find folder UID by name in current context"""
        # This is a simplified lookup - in production would need more robust logic
        current_folder = self.mc_params.folder_cache.get(self.mc_params.current_folder)
        if not current_folder:
            return None

        # Look through subfolders
        for subfolder_uid in current_folder.subfolders:
            subfolder = self.mc_params.folder_cache.get(subfolder_uid)
            if subfolder and subfolder.name == folder_name:
                return subfolder_uid

        return None

    def _share_folder(self, folder_uid, folder_path, share_with):
        """Share a folder with specified users"""
        logging.info(f"  Sharing {folder_path} with {len(share_with)} user(s)")

        for share_config in share_with:
            email = share_config.get('email')
            if not email:
                continue

            manage_records = share_config.get('manage_records', False)
            manage_users = share_config.get('manage_users', False)

            logging.info(f"    → {email} (records: {manage_records}, users: {manage_users})")

            try:
                share_command = register.ShareFolderCommand()
                kwargs = {
                    'folder': folder_uid,
                    'user': [email],
                    'action': 'grant'
                }

                if manage_records is not None:
                    kwargs['manage_records'] = 'on' if manage_records else 'off'
                if manage_users is not None:
                    kwargs['manage_users'] = 'on' if manage_users else 'off'

                share_command.execute(self.mc_params, **kwargs)
                logging.info(f"      ✓ Shared with {email}")
            except Exception as e:
                logging.error(f"      ✗ Failed to share with {email}: {e}")

    def switch_back_to_msp(self):
        """Switch back to MSP context"""
        logging.info(f"{'[DRY RUN] ' if self.dry_run else ''}Switching back to MSP")

        if self.dry_run:
            return

        switch_back_command = msp.SwitchToMspCommand()
        switch_back_command.execute(self.params)
        logging.info("✓ Switched back to MSP")

    def provision(self, template_file):
        """Main provisioning workflow"""
        template = self.load_template(template_file)

        logging.info("=" * 60)
        logging.info("MC Provisioning Started")
        logging.info("=" * 60)

        # Step 1: Create MSP-side node (if specified)
        self.create_node(template['mc'])

        # Step 2: Create MC
        self.create_mc(template['mc'])

        # Step 3: Switch to MC
        self.switch_to_mc()

        # Step 4: Create internal nodes within MC (if specified)
        self.create_internal_nodes(template['mc'])

        # Step 5: Create admin user
        if 'admin_user' in template:
            self.create_admin_user(template['admin_user'])

        # Step 6: Create MC root folder (if specified)
        self.create_root_folder(template['mc'])

        # Step 7: Create folders
        if 'folders' in template:
            logging.info("\nCreating folder structure...")
            self.create_folders(template['folders'])

        # Step 7: Switch back
        self.switch_back_to_msp()

        logging.info("\n" + "=" * 60)
        logging.info("MC Provisioning Complete!")
        logging.info("=" * 60)
        logging.info(f"MC Name: {self.mc_name}")
        logging.info(f"MC ID: {self.mc_id}")
        if template.get('admin_user'):
            logging.info(f"Admin User: {template['admin_user'].get('email')}")
        logging.info(f"Folders Created: {len(self.folder_uid_map)}")
        logging.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Provision a Managed Company from a YAML template',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 provision_mc_template.py template.yaml
  python3 provision_mc_template.py template.yaml --dry-run
  python3 provision_mc_template.py template.yaml --config /path/to/config.json
        """
    )
    parser.add_argument('template', help='YAML template file')
    parser.add_argument('--config', dest='config', help='Keeper config file (default: config.json)')
    parser.add_argument('--dry-run', action='store_true', help='Preview actions without making changes')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(message)s'
    )

    # Get Keeper params
    config_file = args.config or os.path.join(os.path.dirname(__file__), 'config.json')
    params = get_params_from_config(config_file)

    while not params.user:
        params.user = input('User (Email): ')

    # Login
    logging.info("Logging in to Keeper...")
    api.login(params)
    if not params.session_token:
        logging.error("Login failed")
        sys.exit(1)

    # Query enterprise
    api.query_enterprise(params)
    if not params.enterprise:
        logging.error("Not an enterprise administrator")
        sys.exit(1)

    # Note: We don't check for existing managed_companies here because
    # an MSP admin might not have any MCs yet. The msp-add command will
    # fail with a proper error if the user doesn't have MSP permissions.

    # Provision MC
    provisioner = MCProvisioner(params, dry_run=args.dry_run)
    try:
        provisioner.provision(args.template)
    except Exception as e:
        logging.error(f"\nProvisioning failed: {e}")
        if args.debug:
            raise
        sys.exit(1)


if __name__ == '__main__':
    main()