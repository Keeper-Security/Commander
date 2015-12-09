from keepercommander.imp_exp import parse_line, parse_json

class TestImpExp:

    def assert_sample_record(self, record):
        assert record.folder == 'folder'
        assert record.title == 'title'
        assert record.login == 'login'
        assert record.password == 'password'
        assert record.login_url == 'login_url'
        assert record.notes == 'line1\nline2\nline3'
        assert record.custom_fields == [
             {'name':'cf1', 'value': 'cf1val', 'type': 'text'},
             {'name':'cf2', 'value': 'cf2val', 'type': 'text'}]

    def test_parse_line(self):
        record = parse_line('folder\ttitle\tlogin\tpassword\tlogin_url\tline1\\\\nline2\\\\nline3\tcf1\tcf1val\tcf2\tcf2val')
        self.assert_sample_record(record)

    def test_parse_json(self):
        record = parse_json({
            'folder': 'folder',
            'title': 'title',
            'login': 'login',
            'password': 'password',
            'login_url': 'login_url',
            'notes': 'line1\nline2\nline3',
            'custom_fields': [
                {'name': 'cf1', 'value': 'cf1val', 'type': 'text'},
                {'name': 'cf2', 'value': 'cf2val', 'type': 'text'}],
        })
        self.assert_sample_record(record)