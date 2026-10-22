import unittest
from unittest.mock import MagicMock, patch

from keepercommander.commands.helpers.enterprise import execute_batch_confirming_ksm_cascade


def refused():
    return {'result': 'fail', 'result_code': 'access_denied', 'additional_info': 'KSM_CASCADE_REQUIRED',
            'message': 'denied'}


def ok():
    return {'result': 'success'}


class TestExecuteBatchConfirmingKsmCascade(unittest.TestCase):
    def setUp(self):
        self.params = MagicMock()

    @patch('keepercommander.commands.base.user_choice')
    @patch('keepercommander.api.execute_batch')
    def test_no_refusal_runs_once_without_prompting(self, execute_batch, user_choice):
        batch = [{'command': 'team_enterprise_user_remove', 'team_uid': 't', 'enterprise_user_id': 1}]
        execute_batch.return_value = [ok()]

        result = execute_batch_confirming_ksm_cascade(self.params, batch)

        self.assertEqual([ok()], result)
        execute_batch.assert_called_once()
        user_choice.assert_not_called()
        self.assertNotIn('force_remove_share', batch[0])

    @patch('keepercommander.commands.base.user_choice', return_value='y')
    @patch('keepercommander.api.execute_batch')
    def test_refusal_confirmed_retries_only_refused_requests_with_flag(self, execute_batch, user_choice):
        batch = [
            {'command': 'team_enterprise_user_remove', 'team_uid': 't1', 'enterprise_user_id': 1},
            {'command': 'team_delete', 'team_uid': 't2'},
        ]
        execute_batch.side_effect = [[ok(), refused()], [ok()]]

        result = execute_batch_confirming_ksm_cascade(self.params, batch)

        self.assertEqual([ok(), ok()], result)
        self.assertEqual(2, execute_batch.call_count)
        retried = execute_batch.call_args_list[1].args[1]
        self.assertEqual(1, len(retried))
        self.assertEqual('team_delete', retried[0]['command'])
        self.assertTrue(retried[0]['force_remove_share'])
        self.assertNotIn('force_remove_share', batch[0])
        user_choice.assert_called_once()

    @patch('keepercommander.commands.base.user_choice', return_value='n')
    @patch('keepercommander.api.execute_batch')
    def test_refusal_declined_does_not_retry_and_explains_how_to_confirm(self, execute_batch, user_choice):
        batch = [
            {'command': 'team_enterprise_user_update', 'team_uid': 't', 'enterprise_user_id': 1, 'user_type': 2},
            {'command': 'team_delete', 'team_uid': 't2'},
        ]
        execute_batch.return_value = [refused(), ok()]

        result = execute_batch_confirming_ksm_cascade(self.params, batch)

        execute_batch.assert_called_once()
        self.assertIn('--force-remove-share', result[0]['message'])
        self.assertEqual(ok(), result[1])
        self.assertNotIn('force_remove_share', batch[0])

    @patch('keepercommander.commands.base.user_choice')
    @patch('keepercommander.api.execute_batch')
    def test_force_sets_flag_up_front_on_cascade_commands_only(self, execute_batch, user_choice):
        batch = [
            {'command': 'team_delete', 'team_uid': 't'},
            {'command': 'team_enterprise_user_remove', 'team_uid': 't', 'enterprise_user_id': 1},
            {'command': 'team_enterprise_user_update', 'team_uid': 't', 'enterprise_user_id': 1},
            {'command': 'team_add', 'team_uid': 'n'},
        ]
        execute_batch.return_value = [ok(), ok(), ok(), ok()]

        execute_batch_confirming_ksm_cascade(self.params, batch, force=True)

        execute_batch.assert_called_once()
        self.assertTrue(all(rq['force_remove_share'] for rq in batch[:3]))
        self.assertNotIn('force_remove_share', batch[3])
        user_choice.assert_not_called()

    @patch('keepercommander.commands.base.user_choice')
    @patch('keepercommander.api.execute_batch')
    def test_other_failures_are_not_treated_as_cascade_refusals(self, execute_batch, user_choice):
        batch = [
            {'command': 'team_delete', 'team_uid': 't'},
            {'command': 'role_add', 'role_id': 1},
        ]
        other_denied = {'result': 'fail', 'result_code': 'access_denied', 'additional_info': 'user',
                        'message': 'denied'}
        wrong_command = refused()
        execute_batch.return_value = [other_denied, wrong_command]

        result = execute_batch_confirming_ksm_cascade(self.params, batch)

        self.assertEqual([other_denied, wrong_command], result)
        execute_batch.assert_called_once()
        user_choice.assert_not_called()

    @patch('keepercommander.api.execute_batch')
    def test_empty_response_is_returned_unchanged(self, execute_batch):
        execute_batch.return_value = []

        self.assertEqual([], execute_batch_confirming_ksm_cascade(self.params, []))


if __name__ == '__main__':
    unittest.main()
