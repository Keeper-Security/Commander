from data_vault import VaultEnvironment


class KeeperApiHelper:
    _expected_commands = []
    _vault_env = VaultEnvironment()

    @staticmethod
    def communicate_expect(actions):
        # type: (list) -> None
        KeeperApiHelper._expected_commands.clear()
        KeeperApiHelper._expected_commands.extend(actions)

    @staticmethod
    def is_expect_empty():
        # type: () -> bool
        return len(KeeperApiHelper._expected_commands) == 0

    @staticmethod
    def communicate_command(_, request):
        # type: (any, dict) -> dict
        rs = {
            'result': 'success',
            'result_code': '',
            'message': ''
        }
        action = KeeperApiHelper._expected_commands.pop(0)

        if callable(action):
            props = action(request)
            if type(props) == dict:
                rs.update(props)
            return rs

        if type(action) == str:
            if action == request['command']:
                return rs

        raise Exception()
