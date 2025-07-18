import argparse
import json

from .base import BiometricCommand


class BiometricListCommand(BiometricCommand):
    """List biometric authentication methods"""

    parser = argparse.ArgumentParser(prog='biometric list', description='List biometric authentication methods')
    parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table',
                       help='Output format (default: table)')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """List registered biometric methods"""
        def _list():
            passkeys = self.client.get_available_credentials(params)
            self._display_credentials(passkeys, kwargs.get('format', 'table'))

        return self._execute_with_error_handling('list biometric methods', _list)

    def _display_credentials(self, passkeys, format_type):
        """Display credentials in the specified format"""
        if format_type == 'json':
            print(json.dumps(passkeys, indent=2))
        else:
            if not passkeys:
                print("No biometric authentication methods found.")
            else:
                print("\nRegistered Biometric Authentication Methods:")
                print("-" * 70)
                for passkey in passkeys:
                    print(f"Name: {passkey['name']}")
                    print(f"ID: {passkey['id']}")
                    print(f"Created: {passkey['created']}")
                    print(f"Last Used: {passkey['last_used']}")
                    print("-" * 70) 