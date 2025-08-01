#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse

from .base import BiometricCommand
from ...commands.base import user_choice
from ..utils.constants import get_status_message


class BiometricUpdateNameCommand(BiometricCommand):
    """Update friendly name of a biometric passkey"""

    parser = argparse.ArgumentParser(prog='biometric update-name', description='Update friendly name of a biometric passkey')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """Execute biometric update-name command"""
        def _update_name():
            all_credentials = self._get_available_credentials_or_error(params)
            available_credentials = [cred for cred in all_credentials if cred.get('name') and cred['name'].strip()]
            
            if not available_credentials:
                print("No biometric credentials with friendly names found.")
                print("Use 'biometric register' to create a new credential with a friendly name.")
                return
                
            print(f"Found {len(available_credentials)} biometric credential(s) with friendly names")

            selected_index = self._interactive_credential_selection(available_credentials)

            target_credential = available_credentials[selected_index]

            friendly_name = self._interactive_name_input(target_credential)

            if len(friendly_name) > 32:
                raise Exception("Friendly name must be 32 characters or less")

            if not self._confirm_update(target_credential, friendly_name):
                print("Update cancelled by user")
                return

            result = self.client.update_passkey_name(params, target_credential['id'], target_credential['credential_id'], friendly_name)
            
            self._report_update_results(result, target_credential, friendly_name)

        return self._execute_with_error_handling('update passkey friendly name', _update_name)

    def _interactive_credential_selection(self, available_credentials):
        """Interactive selection of credential to update"""
        if len(available_credentials) == 1:
            credential = available_credentials[0]
            print(f"Found single credential: {credential['name']}")
            answer = user_choice('Use this credential?', 'yn', 'y')
            if answer.lower() == 'y':
                return 0  # Return index instead of ID
            else:
                raise Exception("Operation cancelled by user")
        
        print("\nAvailable Biometric Credentials:")
        print("-" * 50)
        
        for i, credential in enumerate(available_credentials, 1):
            created_date = self._format_timestamp(credential.get('created'))
            last_used = self._format_timestamp(credential.get('last_used'))
            
            print(f"{i:2}. {credential['name']}")
            print(f"    Created: {created_date}")
            print(f"    Last Used: {last_used}")
            print()
        
        while True:
            try:
                choice = input(f"Select credential number (1-{len(available_credentials)}): ")
                if choice.lower() in ['q', 'quit', 'exit']:
                    raise Exception("Operation cancelled by user")
                
                selection = int(choice) - 1
                if 0 <= selection < len(available_credentials):
                    selected_credential = available_credentials[selection]
                    print(f"Selected: {selected_credential['name']}")
                    return selection  # Return index instead of ID
                else:
                    print(f"Invalid selection. Please choose 1-{len(available_credentials)}.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                raise Exception("Operation cancelled by user")

    def _interactive_name_input(self, credential):
        """Interactive input for new friendly name"""
        print(f"\nCurrent Name: {credential['name']}")
        print("Enter a new friendly name (max 32 characters):")
        
        while True:
            try:
                new_name = input("New name: ").strip()
                
                if not new_name:
                    print("Name cannot be empty. Please try again.")
                    continue
                
                if len(new_name) > 32:
                    print(f"Name too long ({len(new_name)} chars). Maximum 32 characters allowed.")
                    continue
                
                if new_name == credential['name']:
                    print("Name is the same as current name. Please enter a different name.")
                    continue
                
                return new_name
                
            except KeyboardInterrupt:
                raise Exception("Operation cancelled by user")

    def _confirm_update(self, credential, new_name):
        """Confirm the update operation"""
        print("\nUpdate Summary:")
        print("-" * 20)
        print(f"Current Name:  {credential['name']}")
        print(f"New Name:      {new_name}")
        print()
        
        answer = user_choice('Proceed with update?', 'yn', 'y')
        return answer.lower() == 'y'

    def _report_update_results(self, result, credential, new_name):
        """Report the update results to the user"""
        print("\nPasskey Update Results:")
        print("=" * 30)
        status_code = result['status']
        status_text = get_status_message(status_code)
        print(f"Status: {status_text}")
        print(f"Old Name: {credential['name']}")
        print(f"New Name: {new_name}")
        print(f"Message: {result['message']}")
        print("=" * 30) 