# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import getpass
from contextlib import contextmanager

from fido2.client import Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice


class SecurityKeyInteraction(UserInteraction):
    """Interactive user verification without exposing the authenticator PIN."""

    def prompt_up(self):
        print('Touch your security key to continue...')

    def request_pin(self, permissions, rp_id):
        return getpass.getpass('Enter Security Key PIN: ')

    def request_uv(self, permissions, rp_id):
        print('Complete user verification on your security key...')
        return True


@contextmanager
def get_security_key_devices():
    """Enumerate USB HID FIDO authenticators supported by python-fido2."""
    devices = []
    try:
        for device in CtapHidDevice.list_devices():
            devices.append(device)
        yield devices
    finally:
        for device in devices:
            device.close()


def create_security_key_client(data_collector, devices):
    """Select an attached key and keep the normal WebAuthn RP/origin checks."""
    if not devices:
        raise Exception('No USB FIDO2 security key detected. Connect your key and try again.')
    device = devices[0]
    if len(devices) > 1:
        for index, key in enumerate(devices, 1):
            descriptor = key.descriptor
            print(f'{index}: {descriptor.product_name or "FIDO2 security key"} '
                  f'({descriptor.serial_number or index})')
        selection = input('Select security key number: ')
        if not selection.isdigit() or not 1 <= int(selection) <= len(devices):
            raise Exception('Invalid security key selection')
        device = devices[int(selection) - 1]
    return Fido2Client(device, client_data_collector=data_collector,
                      user_interaction=SecurityKeyInteraction())
