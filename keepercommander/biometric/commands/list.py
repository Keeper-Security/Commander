import argparse
import json

from .base import BiometricCommand
from ...error import CommandError


class BiometricListCommand(BiometricCommand):
    """List biometric authentication methods"""

    parser = argparse.ArgumentParser(prog='biometric list', description='List biometric authentication methods')
    parser.add_argument('--format', dest='format', choices=['table', 'json'], default='table',
                       help='Output format (default: table)')

    def get_parser(self):
        return self.parser

    def execute(self, params, **kwargs):
        """List registered biometric methods"""
        try:
            passkeys = self.client.get_available_credentials(params)

            if kwargs.get('format') == 'json':
                print(json.dumps(passkeys, indent=2))
            else:
                if not passkeys:
                    print("No biometric authentication methods found.")
                else:
                    print("\n📱 Registered Biometric Authentication Methods:")
                    print("-" * 70)
                    for passkey in passkeys:
                        print(f"Name: {passkey['name']}")
                        print(f"ID: {passkey['id']}")
                        print(f"Created: {passkey['created']}")
                        print(f"Last Used: {passkey['last_used']}")
                        print("-" * 70)

        except Exception as e:
            raise CommandError('biometric list', f'Failed to list biometric methods: {str(e)}') 