# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import queue
import threading
import time
from dataclasses import replace

from fido2.webauthn import AuthenticatorAttachment

from .... import utils
from ..security_key import get_security_key_devices, create_security_key_client
from .webauthn import MacOSTouchIDWebAuthnClient
from ...utils.constants import DEFAULT_BIOMETRIC_TIMEOUT


class MacOSPasskeyWebAuthnClient:
    """Route passkeys to the existing Touch ID client or a USB FIDO2 key."""

    def __init__(self, data_collector, keychain_manager, touch_id_capabilities):
        self.data_collector = data_collector
        self.keychain_manager = keychain_manager
        self.touch_id_capabilities = touch_id_capabilities
        self.touch_id_client = MacOSTouchIDWebAuthnClient(data_collector, keychain_manager)

    def _select_client(self, allow_platform, allow_security_key, devices):
        if allow_platform and devices:
            from ....commands.base import user_choice
            choice = user_choice('Use Touch ID or a security key?', 'ts', default='t')
            if choice.lower() == 's':
                return create_security_key_client(self.data_collector, devices)
        elif allow_security_key and not allow_platform:
            return create_security_key_client(self.data_collector, devices)
        if not allow_platform:
            raise Exception('No supported passkey authenticator is available')
        return self.touch_id_client

    def _perform(self, operation, options, allow_platform, allow_security_key):
        if not allow_security_key:
            return getattr(self._select_client(allow_platform, False, []), operation)(options)
        with get_security_key_devices() as devices:
            client = self._select_client(allow_platform, allow_security_key, devices)
            return getattr(client, operation)(options)

    def make_credential(self, options):
        selection = options.authenticator_selection
        attachment = selection.authenticator_attachment if selection else None
        allow_platform = attachment != AuthenticatorAttachment.CROSS_PLATFORM
        # If there is no Touch ID, an attached security key can still register.
        if allow_platform and attachment is None:
            allow_platform, _ = self.touch_id_capabilities()
        return self._perform('make_credential', options, allow_platform,
                             attachment != AuthenticatorAttachment.PLATFORM)

    def get_assertion(self, options):
        # Only offer Touch ID when the server permits a locally stored credential.
        allow_platform = any(
            self.keychain_manager.credential_exists(
                utils.base64_url_encode(credential.id), options.rp_id,
                options.timeout / 1000 if options.timeout else None)
            for credential in options.allow_credentials or [])
        allow_security_key = not options.allow_credentials or any(
            not credential.transports or any(
                transport != 'internal' for transport in credential.transports)
            for credential in options.allow_credentials)
        if not allow_security_key:
            if not allow_platform:
                raise Exception('No supported passkey authenticator is available')
            return self.touch_id_client.get_assertion(options)
        with get_security_key_devices() as devices:
            if allow_platform and not devices:
                return self.touch_id_client.get_assertion(options)
            if not allow_platform and len(devices) <= 1:
                return create_security_key_client(self.data_collector, devices).get_assertion(options)
            return self._authenticate_with_either(options, allow_platform, devices)

    def _authenticate_with_either(self, options, allow_platform, devices):
        """Listen for Touch ID and USB touches together; only the winner can sign.

        Security keys first perform CTAP authenticator selection, without a PIN
        prompt. Only the touched key proceeds to PIN/UV in the main thread, after
        the other device operations and the Touch ID dialog have been cancelled.
        """
        timeout = options.timeout / 1000 if options.timeout else DEFAULT_BIOMETRIC_TIMEOUT
        deadline = time.monotonic() + timeout
        results = queue.Queue()
        count = len(devices) + int(allow_platform)
        cancelled = [threading.Event() for _ in range(count)]
        lock = threading.Lock()
        selected = None

        def claim(index):
            nonlocal selected
            with lock:
                if cancelled[index].is_set() or selected not in (None, index):
                    raise Exception('Passkey authentication cancelled')
                selected = index
                for other, event in enumerate(cancelled):
                    if other != index:
                        event.set()

        def touch_id(index):
            try:
                response = self.touch_id_client.get_assertion(
                    options, event=cancelled[index], on_verified=lambda: claim(index))
                claim(index)
                results.put(('touch_id', index, response))
            except Exception as error:
                results.put(('error', index, error))

        def security_key(index, device):
            try:
                client = create_security_key_client(self.data_collector, [device])
                # CTAP1's selection fallback creates a dummy U2F registration.
                # Passkey login requires FIDO2; never run that fallback on a
                # touch-only U2F key while waiting for another authenticator.
                if not any(version.startswith('FIDO_2') for version in client.info.versions):
                    raise Exception('Passkey login requires a FIDO2 security key, not a U2F-only key')
                client.selection(event=cancelled[index])
                claim(index)
                results.put(('security_key', index, client))
            except Exception as error:
                results.put(('error', index, error))

        threads = []
        if allow_platform:
            threads.append(threading.Thread(target=touch_id, args=(0,)))
        for offset, device in enumerate(devices, int(allow_platform)):
            threads.append(threading.Thread(target=security_key, args=(offset, device)))

        print('Use Touch ID or touch your security key to authenticate...')
        errors = []
        winner = None
        try:
            for thread in threads:
                thread.start()
            for _ in threads:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Passkey authentication timed out')
                try:
                    kind, index, value = results.get(timeout=remaining)
                except queue.Empty:
                    raise TimeoutError('Passkey authentication timed out')
                if kind != 'error':
                    winner = (kind, value)
                    break
                errors.append((index, value))
            if winner is None:
                # Once selected, surface that authenticator's error, not the
                # KEEPALIVE_CANCEL errors produced by cancelling other keys.
                error = next((error for index, error in errors if index == selected), errors[0][1])
                raise error
        finally:
            for event in cancelled:
                event.set()
            for thread in threads:
                if thread.ident is not None:
                    thread.join()

        kind, value = winner
        if kind == 'touch_id':
            return value
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Passkey authentication timed out')
        # No fallback after the chosen key's PIN/UV fails or is cancelled.
        return value.get_assertion(replace(options, timeout=max(1, int(remaining * 1000))))
