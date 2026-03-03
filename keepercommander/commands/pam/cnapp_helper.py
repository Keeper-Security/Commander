"""CNAPP Krouter API communication helpers.

All functions use _post_request_to_router() to send encrypted
protobuf requests to Krouter's /api/user/cnapp/* endpoints.
"""
import logging

from .router_helper import _post_request_to_router
from ... import utils
from ...proto import pam_pb2

logger = logging.getLogger(__name__)


def cnapp_create_webhook(params, network_uid, provider, client_id, client_secret,
                         api_url, auth_url, encryption_record_key_id, controller_uid,
                         webhook_id=None):
    """POST /api/user/cnapp/webhook - Create CNAPP integration."""
    rq = pam_pb2.CnappWebhookRequest()
    rq.networkUid = utils.base64_url_decode(network_uid)
    rq.provider = provider.upper()
    rq.clientId = client_id
    rq.clientSecret = client_secret
    rq.apiEndpointUrl = api_url
    rq.authUrl = auth_url
    rq.encryptionRecordKeyId = utils.base64_url_decode(encryption_record_key_id)
    rq.controllerUid = utils.base64_url_decode(controller_uid)
    if webhook_id:
        rq.webhookId = webhook_id
    return _post_request_to_router(params, 'cnapp/webhook', rq_proto=rq,
                                   rs_type=pam_pb2.CnappWebhookResponse)


def cnapp_update_webhook(params, network_uid, **kwargs):
    """PUT /api/user/cnapp/webhook - Update CNAPP credentials."""
    rq = pam_pb2.CnappWebhookRequest()
    rq.networkUid = utils.base64_url_decode(network_uid)
    if kwargs.get('client_id'):
        rq.clientId = kwargs['client_id']
    if kwargs.get('client_secret'):
        rq.clientSecret = kwargs['client_secret']
    if kwargs.get('api_url'):
        rq.apiEndpointUrl = kwargs['api_url']
    if kwargs.get('auth_url'):
        rq.authUrl = kwargs['auth_url']
    return _post_request_to_router(params, 'cnapp/webhook', rq_proto=rq,
                                   rs_type=pam_pb2.CnappWebhookResponse, method='put')


def cnapp_get_integration(params, network_uid):
    """POST /api/user/cnapp/integration - Get CNAPP integration details."""
    rq = pam_pb2.CnappGetIntegrationRequest()
    rq.networkUid = utils.base64_url_decode(network_uid)
    return _post_request_to_router(params, 'cnapp/integration', rq_proto=rq,
                                   rs_type=pam_pb2.CnappGetIntegrationResponse)


def cnapp_delete_webhook(params, network_uid):
    """DELETE /api/user/cnapp/webhook - Remove CNAPP integration."""
    rq = pam_pb2.CnappDeleteWebhookRequest()
    rq.networkUid = utils.base64_url_decode(network_uid)
    return _post_request_to_router(params, 'cnapp/webhook', rq_proto=rq, method='delete')


def cnapp_test_credentials(params, provider, client_id, client_secret, api_url, auth_url):
    """POST /api/user/cnapp/test-credentials - Test CNAPP provider credentials."""
    rq = pam_pb2.CnappTestCredentialsRequest()
    rq.provider = provider.upper()
    rq.clientId = client_id
    rq.clientSecret = client_secret
    rq.apiEndpointUrl = api_url
    rq.authUrl = auth_url
    return _post_request_to_router(params, 'cnapp/test-credentials', rq_proto=rq,
                                   rs_type=pam_pb2.CnappTestCredentialsResponse)


def cnapp_list_queue(params, network_uid, status_filter=None, limit=50, offset=0):
    """POST /api/user/cnapp/queue - List CNAPP queue items."""
    rq = pam_pb2.CnappQueueListRequest()
    rq.networkUid = utils.base64_url_decode(network_uid)
    if status_filter is not None:
        rq.statusFilter = status_filter
    rq.limit = limit
    rq.offset = offset
    return _post_request_to_router(params, 'cnapp/queue', rq_proto=rq,
                                   rs_type=pam_pb2.CnappQueueListResponse)


def cnapp_get_queue_item(params, queue_id):
    """POST /api/user/cnapp/queue/{id}/detail - Get queue item detail."""
    return _post_request_to_router(params, f'cnapp/queue/{queue_id}/detail',
                                   rs_type=pam_pb2.CnappQueueItemResponse)


def cnapp_associate_record(params, queue_id, record_uid, execute_after_setup=False):
    """POST /api/user/cnapp/queue/{id}/associate - Link PAM record."""
    rq = pam_pb2.CnappAssociateRequest()
    rq.recordUid = utils.base64_url_decode(record_uid)
    rq.executeAfterSetup = execute_after_setup
    return _post_request_to_router(params, f'cnapp/queue/{queue_id}/associate', rq_proto=rq,
                                   rs_type=pam_pb2.CnappAssociateResponse)


def cnapp_remediate(params, queue_id, action_type):
    """POST /api/user/cnapp/queue/{id}/remediate - Trigger remediation."""
    rq = pam_pb2.CnappRemediateRequest()
    rq.actionType = action_type
    return _post_request_to_router(params, f'cnapp/queue/{queue_id}/remediate', rq_proto=rq,
                                   rs_type=pam_pb2.CnappRemediateResponse)


def cnapp_resolve(params, queue_id, notes=None):
    """PUT /api/user/cnapp/queue/{id}/resolve - Mark as resolved."""
    rq = pam_pb2.CnappResolveRequest()
    if notes:
        rq.resolutionNotes = notes
    return _post_request_to_router(params, f'cnapp/queue/{queue_id}/resolve',
                                   rq_proto=rq, method='put')


def cnapp_ignore(params, queue_id, reason=None):
    """DELETE /api/user/cnapp/queue/{id} - Dismiss queue item."""
    rq = pam_pb2.CnappIgnoreRequest()
    if reason:
        rq.reason = reason
    return _post_request_to_router(params, f'cnapp/queue/{queue_id}', rq_proto=rq, method='delete')


def cnapp_list_behaviors(params, network_uid=None):
    """POST /api/user/cnapp/default-behavior/list - List behavior rules."""
    rq = pam_pb2.CnappBehaviorListRequest()
    if network_uid:
        rq.networkUid = utils.base64_url_decode(network_uid)
    return _post_request_to_router(params, 'cnapp/default-behavior/list', rq_proto=rq,
                                   rs_type=pam_pb2.CnappBehaviorListResponse)


def cnapp_create_behavior(params, control_key, action_type_id, network_uid,
                          provider_id, auto_execute=True):
    """POST /api/user/cnapp/default-behavior - Create behavior rule."""
    rq = pam_pb2.CnappDefaultBehaviorRequest()
    rq.networkId = utils.base64_url_decode(network_uid)
    rq.cnappProviderId = provider_id
    rq.controlKey = control_key
    rq.cnappActionTypeId = action_type_id
    rq.autoExecute = auto_execute
    return _post_request_to_router(params, 'cnapp/default-behavior', rq_proto=rq,
                                   rs_type=pam_pb2.CnappDefaultBehaviorResponse)


def cnapp_update_behavior(params, behavior_id, control_key=None, action_type_id=None,
                          auto_execute=None, enabled=None):
    """PUT /api/user/cnapp/default-behavior - Update behavior rule."""
    rq = pam_pb2.CnappBehaviorUpdateRequest()
    rq.cnappDefaultBehaviorId = behavior_id
    if control_key:
        rq.controlKey = control_key
    if action_type_id is not None:
        rq.cnappActionTypeId = action_type_id
    if auto_execute is not None:
        rq.autoExecute = auto_execute
    if enabled is not None:
        rq.enabled = enabled
    return _post_request_to_router(params, 'cnapp/default-behavior', rq_proto=rq, method='put')


def cnapp_delete_behavior(params, behavior_id):
    """DELETE /api/user/cnapp/default-behavior - Delete behavior rule."""
    rq = pam_pb2.CnappBehaviorDeleteRequest()
    rq.cnappDefaultBehaviorId = behavior_id
    return _post_request_to_router(params, 'cnapp/default-behavior', rq_proto=rq, method='delete')
