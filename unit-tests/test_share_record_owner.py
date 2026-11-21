from unittest import TestCase, mock

from keepercommander import utils
from keepercommander.commands.register import ShareRecordCommand
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams, RecordOwner
from keepercommander.proto import record_pb2


class TestShareRecordOwnerTransferSync(TestCase):
    def _make_uid_bytes(self):
        return b'\x11' * 16

    def test_parser_accepts_revoke_previous_owner(self):
        parser = ShareRecordCommand().get_parser()
        args = parser.parse_args(['-a', 'owner', '--revoke-previous-owner', '-e', 'alice@acme.com', 'REC1'])
        self.assertEqual(args.action, 'owner')
        self.assertTrue(args.revoke_previous_owner)

    def test_revoke_previous_owner_rejected_when_action_not_owner(self):
        params = KeeperParams()
        with self.assertRaises(CommandError) as ctx:
            ShareRecordCommand().execute(
                params,
                action='grant',
                revoke_previous_owner=True,
                email=['alice@acme.com'],
                record='REC1',
            )
        self.assertIn('--revoke-previous-owner is only valid with -a owner', str(ctx.exception))

    @mock.patch('keepercommander.commands.register.api.communicate_rest')
    @mock.patch('keepercommander.commands.register.ShareRecordCommand.prep_request')
    def test_owner_transfer_updates_owner_cache_and_sets_sync_data(self, mock_prep, mock_comm_rest):
        uid_bytes = self._make_uid_bytes()
        uid_str = utils.base64_url_encode(uid_bytes)

        rq = record_pb2.RecordShareUpdateRequest()
        sr = record_pb2.SharedRecord()
        sr.toUsername = 'alice@acme.com'
        sr.recordUid = uid_bytes
        sr.transfer = True
        rq.updateSharedRecord.append(sr)
        mock_prep.return_value = rq

        rs = record_pb2.RecordShareUpdateResponse()
        st = rs.updateSharedRecordStatus.add()
        st.recordUid = uid_bytes
        st.username = 'alice@acme.com'
        st.status = 'success'
        mock_comm_rest.return_value = rs

        params = KeeperParams()
        params.user = 'admin@acme.com'
        params.sync_data = False
        params.record_owner_cache[uid_str] = RecordOwner(True, 'admin@acme.com')

        ShareRecordCommand().execute(
            params,
            action='owner',
            email=['alice@acme.com'],
            record=uid_str,
        )

        self.assertTrue(params.sync_data)
        self.assertEqual(params.record_owner_cache[uid_str], RecordOwner(False, 'alice@acme.com'))
        mock_comm_rest.assert_called_once()

    @mock.patch('keepercommander.commands.register.api.communicate_rest')
    @mock.patch('keepercommander.commands.register.ShareRecordCommand.prep_request')
    def test_owner_transfer_with_revoke_previous_owner_sends_followup_remove(self, mock_prep, mock_comm_rest):
        uid_bytes = self._make_uid_bytes()
        uid_str = utils.base64_url_encode(uid_bytes)

        rq = record_pb2.RecordShareUpdateRequest()
        sr = record_pb2.SharedRecord()
        sr.toUsername = 'alice@acme.com'
        sr.recordUid = uid_bytes
        sr.transfer = True
        rq.addSharedRecord.append(sr)
        mock_prep.return_value = rq

        rs1 = record_pb2.RecordShareUpdateResponse()
        st1 = rs1.addSharedRecordStatus.add()
        st1.recordUid = uid_bytes
        st1.username = 'alice@acme.com'
        st1.status = 'success'

        rs2 = record_pb2.RecordShareUpdateResponse()
        st2 = rs2.removeSharedRecordStatus.add()
        st2.recordUid = uid_bytes
        st2.username = 'admin@acme.com'
        st2.status = 'success'

        sent_requests = []

        def _side_effect(p, req, endpoint, rs_type=None):
            sent_requests.append((
                list(req.addSharedRecord),
                list(req.updateSharedRecord),
                list(req.removeSharedRecord),
            ))
            return rs1 if len(sent_requests) == 1 else rs2

        mock_comm_rest.side_effect = _side_effect

        params = KeeperParams()
        params.user = 'admin@acme.com'
        params.sync_data = False
        params.record_owner_cache[uid_str] = RecordOwner(True, 'admin@acme.com')

        ShareRecordCommand().execute(
            params,
            action='owner',
            revoke_previous_owner=True,
            email=['alice@acme.com'],
            record=uid_str,
        )

        self.assertEqual(len(sent_requests), 2)
        # First request: transfer ownership to alice@acme.com
        self.assertEqual(len(sent_requests[0][0]), 1)
        self.assertEqual(sent_requests[0][0][0].toUsername, 'alice@acme.com')
        self.assertTrue(sent_requests[0][0][0].transfer)
        # Second request: remove previous owner's (admin@acme.com) direct share
        self.assertEqual(len(sent_requests[1][2]), 1)
        self.assertEqual(sent_requests[1][2][0].toUsername, 'admin@acme.com')
        self.assertEqual(sent_requests[1][2][0].recordUid, uid_bytes)
        self.assertEqual(params.record_owner_cache[uid_str], RecordOwner(False, 'alice@acme.com'))
