import abc
import base64
import json
from keepercommander import crypto


class RouterRequest:

    def __init__(self, message_id, to, payload):
        self.id = message_id
        self.to = to
        self.payload = payload

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


# ACTION INPUTS


class GatewayActionDiscoverInputs:

    def __init__(self, shared_folder_uid, provider_record_uid):
        self.shared_folder_uid = shared_folder_uid
        self.provider_record_uid = provider_record_uid

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


# ACTIONS

class GatewayAction(metaclass=abc.ABCMeta):

    def __init__(self, action, gateway_destination=None, inputs=None, message_id=None, is_scheduled=True):
        self.action = action
        self.is_scheduled = is_scheduled
        self.gateway_destination = gateway_destination
        self.inputs = inputs
        self.messageId = message_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    @staticmethod
    def generate_message_id(is_bytes=False):
        message_id_bytes = crypto.get_random_bytes(16)
        if is_bytes:
            return message_id_bytes
        else:
            message_id = base64.b64encode(message_id_bytes).decode()
            return message_id


class GatewayActionInfo(GatewayAction):

    def __init__(self, message_id=None, is_scheduled=True):
        super().__init__(
            'info',
            message_id=message_id,
            is_scheduled=is_scheduled
        )

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscover(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverInputs, message_id=None):
        super().__init__('discover', inputs=inputs, message_id=message_id)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfoInputs:

    def __init__(self, job_id):
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

class GatewayActionJobCancel(GatewayAction):

    def __init__(self, inputs: GatewayActionJobInfoInputs, message_id=None):
        super().__init__('job-cancel', inputs=inputs, message_id=message_id)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfo(GatewayAction):

    def __init__(self, inputs: GatewayActionJobInfoInputs, message_id=None):
        super().__init__('job-info', inputs=inputs, message_id=message_id)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRotateInputs:

    def __init__(self, record_uid, configuration_uid):
        self.recordUid = record_uid
        self.configurationUid = configuration_uid

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRotate(GatewayAction):

    def __init__(self, inputs: GatewayActionRotateInputs, message_id=None, gateway_destination=None):
        super().__init__('rotate', inputs=inputs, message_id=message_id, gateway_destination=gateway_destination)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionGetConfigsInputs:

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionGetConfigs(GatewayAction):

    def __init__(self, message_id=None):
        super().__init__('get-configs', message_id=message_id)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionListAccessRecords(GatewayAction):

    def __init__(self, message_id=None):
        super().__init__('list-access-records', message_id=message_id)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
