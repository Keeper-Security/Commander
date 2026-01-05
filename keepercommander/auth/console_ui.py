import json
import getpass
import logging
import pyperclip
import re
import webbrowser
from typing import Optional, List

from colorama import Fore, Style
from . import login_steps
from .. import utils
from ..display import bcolors
from ..error import KeeperApiError


class ConsoleLoginUi(login_steps.LoginUi):
    def __init__(self):
        self._show_device_approval_help = True
        self._show_two_factor_help = True
        self._show_password_help = True
        self._show_sso_redirect_help = True
        self._show_sso_data_key_help = True
        self._failed_password_attempt = 0

    def on_device_approval(self, step):
        if self._show_device_approval_help:
            print(f"\n{Style.BRIGHT}Device Approval Required{Style.RESET_ALL}\n")
            print("Select an approval method:")
            print(f"  {Fore.GREEN}1{Fore.RESET}. Email - Send approval link to your email")
            print(f"  {Fore.GREEN}2{Fore.RESET}. Keeper Push - Send notification to an approved device")
            print(f"  {Fore.GREEN}3{Fore.RESET}. 2FA Push - Send code via your 2FA method")
            print()
            print(f"  {Fore.GREEN}c{Fore.RESET}. Enter code - Enter a verification code")
            print(f"  {Fore.GREEN}q{Fore.RESET}. Cancel login")
            print()
            self._show_device_approval_help = False
        else:
            print(f"\n{Style.BRIGHT}Waiting for device approval.{Style.RESET_ALL}")
            print(f"Check email, SMS, or push notification on the approved device.")
            print(f"Enter {Fore.GREEN}c <code>{Fore.RESET} to submit a verification code.\n")

        try:
            selection = input('Selection (or Enter to check status): ').strip().lower()

            if selection == '1' or selection == 'email_send' or selection == 'es':
                step.send_push(login_steps.DeviceApprovalChannel.Email)
                print(f"\n{Fore.GREEN}Email sent to {step.username}{Fore.RESET}")
                print("Click the approval link in the email, then press Enter.\n")

            elif selection == '2' or selection == 'keeper_push' or selection == 'kp':
                step.send_push(login_steps.DeviceApprovalChannel.KeeperPush)
                print(f"\n{Fore.GREEN}Push notification sent.{Fore.RESET}")
                print("Approve on your device, then press Enter.\n")

            elif selection == '3' or selection == '2fa_send' or selection == '2fs':
                step.send_push(login_steps.DeviceApprovalChannel.TwoFactor)
                print(f"\n{Fore.GREEN}2FA code sent.{Fore.RESET}")
                print("Enter the code using option 'c'.\n")

            elif selection == 'c' or selection.startswith('c '):
                # Support both "c" (prompts for code) and "c <code>" (code inline)
                if selection == 'c':
                    code_input = input('Enter verification code: ').strip()
                else:
                    code_input = selection[2:].strip()  # Extract code after "c "

                if code_input:
                    # Try email code first, then 2FA
                    try:
                        step.send_code(login_steps.DeviceApprovalChannel.Email, code_input)
                        print(f"{Fore.GREEN}Successfully verified email code.{Fore.RESET}")
                    except KeeperApiError:
                        try:
                            step.send_code(login_steps.DeviceApprovalChannel.TwoFactor, code_input)
                            print(f"{Fore.GREEN}Successfully verified 2FA code.{Fore.RESET}")
                        except KeeperApiError as e:
                            print(f"{Fore.YELLOW}Invalid code. Please try again.{Fore.RESET}")

            elif selection.startswith("email_code="):
                code = selection.replace("email_code=", "")
                step.send_code(login_steps.DeviceApprovalChannel.Email, code)
                print(f"{Fore.GREEN}Successfully verified email code.{Fore.RESET}")

            elif selection.startswith("2fa_code="):
                code = selection.replace("2fa_code=", "")
                step.send_code(login_steps.DeviceApprovalChannel.TwoFactor, code)
                print(f"{Fore.GREEN}Successfully verified 2FA code.{Fore.RESET}")

            elif selection == 'q':
                step.cancel()

            elif selection == '':
                step.resume()

            else:
                print(f"{Fore.YELLOW}Invalid selection. Enter 1, 2, 3, c, q, or press Enter.{Fore.RESET}")

        except KeyboardInterrupt:
            step.cancel()
        except KeeperApiError as kae:
            print()
            print(bcolors.WARNING + kae.message + bcolors.ENDC)
            pass

    @staticmethod
    def two_factor_channel_to_desc(channel):   # type: (login_steps.TwoFactorChannel) -> str
        if channel == login_steps.TwoFactorChannel.Authenticator:
            return 'TOTP (Google and Microsoft Authenticator)'
        if channel == login_steps.TwoFactorChannel.TextMessage:
            return 'Send SMS Code'
        if channel == login_steps.TwoFactorChannel.DuoSecurity:
            return 'DUO'
        if channel == login_steps.TwoFactorChannel.RSASecurID:
            return 'RSA SecurID'
        if channel == login_steps.TwoFactorChannel.SecurityKey:
            return 'WebAuthN (FIDO2 Security Key)'
        if channel == login_steps.TwoFactorChannel.KeeperDNA:
            return 'Keeper DNA (Watch)'
        if channel == login_steps.TwoFactorChannel.Backup:
            return 'Backup Codes'

    def on_two_factor(self, step):
        channels = step.get_channels()

        if self._show_two_factor_help:
            print("\nThis account requires 2FA Authentication\n")
            for i in range(len(channels)):
                channel = channels[i]
                print(f"{i+1:>3}. {ConsoleLoginUi.two_factor_channel_to_desc(channel.channel_type)} {channel.channel_name} {channel.phone}")
            print(f"{'q':>3}. Quit login attempt and return to Commander prompt")
            self._show_device_approval_help = False

        channel = None    # type: Optional[login_steps.TwoFactorChannelInfo]
        while channel is None:
            selection = input('Selection: ')
            if selection == 'q':
                raise KeyboardInterrupt()

            if selection.isnumeric():
                idx = int(selection)
                if 1 <= idx <= len(channels):
                    channel = channels[idx-1]
                    logging.debug(f"Selected {idx}. {ConsoleLoginUi.two_factor_channel_to_desc(channel.channel_type)}")
                else:
                    print("Invalid entry, additional factors of authentication shown may be configured if not currently enabled.")
            else:
                print("Invalid entry, additional factors of authentication shown may be configured if not currently enabled.")

        mfa_prompt = False

        if channel.channel_type == login_steps.TwoFactorChannel.Other:
            pass
        elif channel.channel_type == login_steps.TwoFactorChannel.TextMessage:
            mfa_prompt = True
            try:
                step.send_push(channel.channel_uid, login_steps.TwoFactorPushAction.TextMessage)
                print(bcolors.OKGREEN + "\nSuccessfully sent SMS.\n" + bcolors.ENDC)
            except KeeperApiError:
                print("Was unable to send SMS.")
        elif channel.channel_type == login_steps.TwoFactorChannel.SecurityKey:
            try:
                from ..yubikey.yubikey import yubikey_authenticate
                challenge = json.loads(channel.challenge)
                response = yubikey_authenticate(challenge)

                if response:
                    signature = {
                        "id": response.id,
                        "rawId": utils.base64_url_encode(response.raw_id),
                        "response": {
                            "authenticatorData": utils.base64_url_encode(response.response.authenticator_data),
                            "clientDataJSON": response.response.client_data.b64,
                            "signature": utils.base64_url_encode(response.response.signature),
                        },
                        "type": "public-key",
                        "clientExtensionResults": dict(response.client_extension_results) if response.client_extension_results else {}
                    }
                    step.duration = login_steps.TwoFactorDuration.EveryLogin
                    step.send_code(channel.channel_uid, json.dumps(signature))
                    print(bcolors.OKGREEN + "Verified Security Key." + bcolors.ENDC)

            except ImportError as e:
                from ..yubikey import display_fido2_warning
                display_fido2_warning()
                logging.warning(e)
            except KeeperApiError:
                print(bcolors.FAIL + "Unable to verify code generated by security key" + bcolors.ENDC)
            except Exception as e:
                logging.error(e)

        elif channel.channel_type in {login_steps.TwoFactorChannel.Authenticator,
                                      login_steps.TwoFactorChannel.DuoSecurity,
                                      login_steps.TwoFactorChannel.RSASecurID,
                                      login_steps.TwoFactorChannel.KeeperDNA,
                                      login_steps.TwoFactorChannel.Backup}:
            mfa_prompt = True
        else:
            raise NotImplementedError(f"Unhandled channel type {ConsoleLoginUi.two_factor_channel_to_desc(channel.channel_type)}")

        if mfa_prompt:
            config_expiration = step.get_max_duration()
            mfa_expiration = step.duration

            if mfa_expiration > config_expiration:
                mfa_expiration = config_expiration

            allowed_expirations = ['login']     # type: List[str]
            if channel.max_expiration >= login_steps.TwoFactorDuration.Every12Hours:
                allowed_expirations.append('12_hours')
            if channel.max_expiration >= login_steps.TwoFactorDuration.Every24Hours:
                allowed_expirations.append('24_hours')
            if channel.max_expiration >= login_steps.TwoFactorDuration.Every30Days:
                allowed_expirations.append('30_days')
            if channel.max_expiration >= login_steps.TwoFactorDuration.Forever:
                allowed_expirations.append('forever')

            otp_code = ''
            show_duration = True
            mfa_pattern = re.compile(r'2fa_duration\s*=\s*(.+)', re.IGNORECASE)
            while not otp_code:
                if show_duration:
                    show_duration = False
                    prompt_exp = '\n2FA Code Duration: {0}.\nTo change duration: 2fa_duration={1}'.format(
                        'Require Every Login' if mfa_expiration == login_steps.TwoFactorDuration.EveryLogin else
                        'Save on this Device Forever' if mfa_expiration == login_steps.TwoFactorDuration.Forever else
                        'Ask Every 12 hours' if mfa_expiration == login_steps.TwoFactorDuration.Every12Hours else
                        'Ask Every 24 hours' if mfa_expiration == login_steps.TwoFactorDuration.Every24Hours else
                        'Ask Every 30 days',
                        "|".join(allowed_expirations))
                    print(prompt_exp)

                try:
                    answer = input('\nEnter 2FA Code or Duration: ')
                except KeyboardInterrupt:
                    step.cancel()
                    return

                m_duration = re.match(mfa_pattern, answer)
                if m_duration:
                    answer = m_duration.group(1).strip().lower()
                    if answer not in allowed_expirations:
                        print(f'Invalid 2FA Duration: {answer}')
                        answer = ''

                if answer == 'login':
                    show_duration = True
                    mfa_expiration = login_steps.TwoFactorDuration.EveryLogin
                elif answer == '12_hours':
                    show_duration = True
                    mfa_expiration = login_steps.TwoFactorDuration.Every12Hours
                elif answer == '24_hours':
                    show_duration = True
                    mfa_expiration = login_steps.TwoFactorDuration.Every24Hours
                elif answer == '30_days':
                    show_duration = True
                    mfa_expiration = login_steps.TwoFactorDuration.Every30Days
                elif answer == 'forever':
                    show_duration = True
                    mfa_expiration = login_steps.TwoFactorDuration.Forever
                else:
                    otp_code = answer

            step.duration = mfa_expiration
            try:
                step.send_code(channel.channel_uid, otp_code)
                print(bcolors.OKGREEN + "Successfully verified 2FA Code." + bcolors.ENDC)
            except KeeperApiError:
                warning_msg = bcolors.WARNING + f"Unable to verify 2FA code. Regenerate the code and try again." + bcolors.ENDC
                print(warning_msg)

    def on_password(self, step):
        if self._show_password_help:
            print(f'Enter master password for {step.username}')

        if self._failed_password_attempt > 0:
            print('Forgot password? Type "recover"<Enter>')

        password = getpass.getpass(prompt='Password: ', stream=None)
        if not password:
            step.cancel()
        elif password == 'recover':
            step.forgot_password()
        else:
            try:
                step.verify_password(password)
            except KeeperApiError as kae:
                print(kae.message)
            except KeyboardInterrupt:
                step.cancel()

    def on_sso_redirect(self, step):
        try:
            wb = webbrowser.get()
            wrappers = set('xdg-open|gvfs-open|gnome-open|x-www-browser|www-browser'.split('|'))
            browsers = set(webbrowser._browsers if hasattr(webbrowser, '_browsers') else {})
            standalones = browsers - wrappers
            if browsers and not standalones:     # show browser-launch option only if effectively supported
                wb = None
        except:
            wb = None

        sp_url = step.sso_login_url
        print(f'\nSSO Login URL:\n{sp_url}\n')
        if self._show_sso_redirect_help:
            print('Navigate to SSO Login URL with your browser and complete login.')
            print('Copy a returned SSO Token into clipboard.')
            print('Paste that token into Commander')
            print('NOTE: To copy SSO Token please click "Copy login token" button on "SSO Connect" page.')
            print('')
            print('  a. SSO User with a Master Password')
            print('  c. Copy SSO Login URL to clipboard')
            if wb:
                print('  o. Navigate to SSO Login URL with the default web browser')
            print('  p. Paste SSO Token from clipboard')
            print('  q. Quit SSO login attempt and return to Commander prompt')
            self._show_sso_redirect_help = False

        while True:
            try:
                token = input('Selection: ')
            except KeyboardInterrupt:
                step.cancel()
                return
            if token == 'q':
                step.cancel()
                return
            if token == 'a':
                step.login_with_password()
                return
            if token == 'c':
                token = None
                try:
                    pyperclip.copy(sp_url)
                    print('SSO Login URL is copied to clipboard.')
                except:
                    print('Failed to copy SSO Login URL to clipboard.')
            elif token == 'o':
                token = None
                if wb:
                    try:
                        wb.open_new_tab(sp_url)
                    except:
                        print('Failed to open web browser.')
            elif token == 'p':
                try:
                    token = pyperclip.paste()
                except:
                    token = ''
                    logging.info('Failed to paste from clipboard')
            else:
                if len(token) < 10:
                    print(f'Unsupported menu option: {token}')
                    token = None
            if token:
                step.set_sso_token(token)
                break

    def on_sso_data_key(self, step):
        if self._show_sso_data_key_help:
            print('\nApprove this device by selecting a method below:')
            print('  1. Keeper Push. Send a push notification to your device.')
            print('  2. Admin Approval. Request your admin to approve this device.')
            print('')
            print('  r. Resume SSO login after device is approved.')
            print('  q. Quit SSO login attempt and return to Commander prompt.')
            self._show_sso_data_key_help = False

        while True:
            try:
                answer = input('Selection: ')
            except KeyboardInterrupt:
                answer = 'q'

            if answer == 'q':
                step.cancel()
                break
            elif answer == 'r':
                step.resume()
                break
            elif answer == '1':
                step.request_data_key(login_steps.DataKeyShareChannel.KeeperPush)
            elif answer == '2':
                step.request_data_key(login_steps.DataKeyShareChannel.AdminApproval)
            else:
                print(f'Action \"{answer}\" is not supported.')
