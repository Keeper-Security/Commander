import json
import unittest
from unittest import mock

from keepercommander import crypto, notification_center, utils
from keepercommander.commands import notification
from keepercommander.params import KeeperParams
from keepercommander.proto import GraphSync_pb2, NotificationCenter_pb2 as NC, enterprise_pb2, pedm_pb2


def _wrapper(uid: bytes, timestamp: int, **content):
    w = NC.NotificationWrapper()
    w.uid = uid
    w.timestamp = timestamp
    for key, value in content.items():
        if key == 'notification':
            w.content.notification.CopyFrom(value)
        else:
            setattr(w.content, key, value)
    return w


def _notification(n_type, **kwargs):
    n = NC.Notification()
    n.type = n_type
    n.sender.type = GraphSync_pb2.RFT_USER
    n.sender.name = kwargs.get('sender', 'someone@company.com')
    for key, data in (kwargs.get('parameters') or {}).items():
        p = n.parameters.add()
        p.key = key
        p.data = data
    for ref_type, value in kwargs.get('refs') or []:
        r = n.refs.add()
        r.type = ref_type
        r.value = value
    return n


class TestNotificationReplay(unittest.TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.uid1, self.uid2, self.uid3 = (bytes([i]) * 16 for i in (1, 2, 3))

    def _sync(self, *wrappers):
        notification_center.process_notification_sync(self.params, wrappers)

    def _entry(self, uid: bytes):
        return self.params.notification_cache[utils.base64_url_encode(uid)]

    def test_statuses_apply_by_uid_last_write_wins(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARE_APPROVAL)),
                   _wrapper(self.uid1, 110, readStatus=NC.NRS_READ),
                   _wrapper(self.uid1, 120, readStatus=NC.NRS_UNREAD),
                   _wrapper(self.uid1, 130, approvalStatus=NC.NAS_APPROVED))
        entry = self._entry(self.uid1)
        self.assertFalse(entry.is_read)
        self.assertEqual(NC.NAS_APPROVED, entry.approval_status)
        self.assertFalse(notification_center.is_actionable(entry))

    def test_last_read_marks_older_notifications_read(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 200, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid3, 300, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 250, readStatus=NC.NRS_LAST))
        self.assertTrue(self._entry(self.uid1).is_read)
        self.assertTrue(self._entry(self.uid2).is_read)
        self.assertFalse(self._entry(self.uid3).is_read)

    def test_unread_after_last_read_stays_unread(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 200, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 250, readStatus=NC.NRS_LAST),
                   _wrapper(self.uid1, 260, readStatus=NC.NRS_UNREAD))
        self.assertFalse(self._entry(self.uid1).is_read)

    def test_trimming_point_drops_it_and_older(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 200, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid3, 300, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid2, 400, trimmingPoint=True))
        self.assertEqual([utils.base64_url_encode(self.uid3)], list(self.params.notification_cache.keys()))

    def test_unsupported_type_is_dropped(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(999)))
        self.assertNotIn(utils.base64_url_encode(self.uid1), self.params.notification_cache)
        self.assertEqual([], notification_center.get_notifications(self.params))

    def test_wrapper_without_uid_is_skipped(self):
        self._sync(_wrapper(b'', 100, notification=_notification(NC.NT_SHARED)),
                   _wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARED)))
        self.assertEqual(1, len(self.params.notification_cache))

    def test_local_read_status(self):
        self._sync(_wrapper(self.uid1, 100, notification=_notification(NC.NT_SHARED)))
        notification_center.apply_local_read_status(self.params, [utils.base64_url_encode(self.uid1)], NC.NRS_READ)
        self.assertTrue(self._entry(self.uid1).is_read)


class TestNotificationPayloads(unittest.TestCase):
    def setUp(self):
        self.params = KeeperParams()

    def test_device_approval_decrypts_with_user_ecc_key(self):
        private_key, public_key = crypto.generate_ec_key()
        self.params.ecc_key = private_key
        data = {'notification_device': 'Commander', 'location': 'Paris', 'ip_address': '1.2.3.4', 'publicKey': 'AAAA'}
        n = _notification(NC.NT_DEVICE_APPROVAL)
        n.encryptedData.data = crypto.encrypt_ec(json.dumps(data).encode(), public_key)
        entry = notification_center.NotificationEntry('x')
        entry.notification = n
        self.assertIn('Paris', notification_center.get_message(self.params, entry))

    def test_workflow_reason_decrypts_with_record_key(self):
        record_uid = utils.generate_uid()
        r_key = utils.generate_aes_key()
        self.params.record_cache[record_uid] = {'record_key_unencrypted': r_key}
        n = _notification(NC.NT_APPROVAL_REQUEST,
                          parameters={'reason': crypto.encrypt_aes_v2(b'need access', r_key)},
                          refs=[(GraphSync_pb2.RFT_REC, utils.base64_url_decode(record_uid))])
        self.assertEqual('need access', notification_center.decrypt_record_parameter(self.params, n, 'reason'))


class TestPedmApprovalNotification(unittest.TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.agent_key = utils.generate_aes_key()
        self.approval_uid = bytes([7]) * 16
        envelope = pedm_pb2.ApprovalEnvelope()
        envelope.enterprise_id = 42
        envelope.approval.approvalUid = self.approval_uid
        envelope.approval.approvalType = 1
        envelope.approval.accountInfo = crypto.encrypt_aes_v2(json.dumps({'user': 'bob'}).encode(), self.agent_key)
        envelope.approval.applicationInfo = crypto.encrypt_aes_v2(json.dumps({'app': 'cmd.exe'}).encode(), self.agent_key)
        self.notification = _notification(NC.NT_PEDM_APPROVAL_REQUEST, sender='Acme Corp',
                                          refs=[(GraphSync_pb2.RFT_GENERAL, self.approval_uid)])
        self.notification.encryptedData.data = envelope.SerializeToString()
        self.plugin = mock.Mock()
        self.plugin.get_mc_agent_key.side_effect = lambda x: self.agent_key if x == 42 else None
        self.action = None

    def _communicate_rest(self, params, rq, endpoint, rs_type=None):
        self.assertEqual('enterprise/get_mcs_info', endpoint)
        rs = enterprise_pb2.GetMCsInfoResponse()
        rs.mcInfo.add().enterpriseId = 42
        return rs

    def _execute_router(self, params, endpoint, rq, rs_type=None):
        self.assertEqual('pedm/msp_approval_action', endpoint)
        self.action = rq
        return pedm_pb2.PedmStatusResponse()

    def test_envelope_is_parsed(self):
        envelope = notification_center.get_pedm_approval(self.notification)
        self.assertEqual(42, envelope.enterprise_id)
        self.assertEqual(self.approval_uid, envelope.approval.approvalUid)

    def test_details_decrypt_with_mc_agent_key(self):
        with mock.patch('keepercommander.api.communicate_rest', side_effect=self._communicate_rest), \
                mock.patch('keepercommander.pedm.admin_plugin.get_pedm_plugin', return_value=self.plugin):
            details = notification._get_pedm_approval_details(self.params, self.notification)
        self.assertEqual({'user': 'bob'}, details['account_info'])
        self.assertEqual({'app': 'cmd.exe'}, details['application_info'])
        self.assertEqual(42, details['enterprise_id'])

    def test_inaccessible_mc_is_reported(self):
        self.plugin.get_mc_agent_key.side_effect = lambda x: None
        with mock.patch('keepercommander.api.communicate_rest', side_effect=self._communicate_rest), \
                mock.patch('keepercommander.pedm.admin_plugin.get_pedm_plugin', return_value=self.plugin):
            details = notification._get_pedm_approval_details(self.params, self.notification)
        self.assertIn('not accessible', details['error'])

    def test_deny_sends_msp_approval_action(self):
        with mock.patch('keepercommander.api.execute_router', side_effect=self._execute_router):
            notification._act_pedm_approval(self.params, self.notification, deny=True)
        self.assertEqual(0, len(self.action.approve))
        self.assertEqual(42, self.action.deny[0].enterprise_id)
        self.assertEqual(self.approval_uid, self.action.deny[0].approval_uid)
