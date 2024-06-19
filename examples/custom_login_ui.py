import logging

from keepercommander.auth import login_steps
from keepercommander import api
from keepercommander.__main__ import get_params_from_config


class CustomUi(login_steps.LoginUi):
    def on_device_approval(self, step):
        try:
            step.send_push(login_steps.DeviceApprovalChannel.Email)
        except Exception as e:
            logging.error(e)
        verification_code = wait_for_verification_code()
        step.send_code(login_steps.DeviceApprovalChannel.Email, verification_code)

    def on_two_factor(self, step):
        raise NotImplementedError()

    def on_password(self, step):
        password = wait_for_password()
        try:
            step.verify_password(password)
        except Exception as e:
            logging.error(e)

    def on_sso_redirect(self, step):
        raise NotImplementedError()

    def on_sso_data_key(self, step):
        raise NotImplementedError()


my_params = get_params_from_config('config.json')
while not my_params.user:
    my_params.user = input('User(Email): ')

ui = CustomUi()
api.login(my_params, login_ui=ui)

if not my_params.session_token:
    exit(1)