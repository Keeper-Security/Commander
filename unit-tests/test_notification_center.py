import json
import unittest
from unittest import mock

from keepercommander import crypto, notification_center, utils
from keepercommander.commands import notification
from keepercommander.params import KeeperParams
from keepercommander.proto import GraphSync_pb2, NotificationCenter_pb2 as NC, pedm_pb2


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


class TestPedmAudienceApproval(unittest.TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.team_private, self.team_public = crypto.generate_ec_key()
        self.team_uid = utils.generate_uid()
        self.params.team_cache[self.team_uid] = {
            'team_uid': self.team_uid, 'name': 'Approvers',
            'team_ec_private_key_unencrypted': crypto.unload_ec_private_key(self.team_private)}
        self.approval_uid = utils.generate_uid()
        self.approval_key = utils.generate_aes_key()
        self.token = utils.generate_aes_key()
        self.notification = _notification(NC.NT_PEDM_APPROVAL_REQUEST, parameters={
            'approvalUid': utils.base64_url_decode(self.approval_uid),
            'audienceType': bytes([pedm_pb2.AUT_TEAM]),
            'audienceUid': utils.base64_url_decode(self.team_uid)})

    def _router(self, params, endpoint, request, rs_type=None):
        if endpoint == 'pedm/get_audience_approvals':
            rs = pedm_pb2.GetAudienceApprovalsResponse()
            node = rs.approvals.add()
            node.approvalUid = utils.base64_url_decode(self.approval_uid)
            node.approvalType = 1
            node.encryptedData = crypto.encrypt_aes_v2(json.dumps({'user': 'john'}).encode(), self.approval_key)
            access = node.access.add()
            access.audience.audienceType = pedm_pb2.AUT_TEAM
            access.audience.audienceUid = utils.base64_url_decode(self.team_uid)
            access.encryptedKey = crypto.encrypt_ec(self.approval_key, self.team_public)
            access.encryptedToken = crypto.encrypt_ec(self.token, self.team_public)
            return rs
        if endpoint == 'pedm/audience_approval_action':
            self.action = request.actions[0]
            return pedm_pb2.PedmStatusResponse()
        raise AssertionError(endpoint)

    def test_details_decrypt_approval_data(self):
        with mock.patch('keepercommander.api.execute_router', side_effect=self._router):
            details = notification._get_pedm_approval_details(self.params, self.notification)
        self.assertEqual('john', details.get('user'))

    def test_action_sends_decrypted_token(self):
        with mock.patch('keepercommander.api.execute_router', side_effect=self._router):
            notification._act_pedm_approval(self.params, self.notification, deny=True)
        self.assertEqual(self.token, self.action.token)
        self.assertEqual(pedm_pb2.AST_DENIED, self.action.approvalStatus)


if __name__ == '__main__':
    unittest.main()
